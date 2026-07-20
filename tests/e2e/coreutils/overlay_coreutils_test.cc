// Write-overlay VFS end-to-end tests against hermetic uutils/coreutils.
//
// Each test runs a single "BazelSandbox --write-overlay -W <ws> -- cmd /c
// <bat>" invocation whose .bat sequences real coreutils ops (they must share
// one invocation because the overlay backing store is per invocation), then
// asserts:
//   1. read-after-write - the marker written via `cp` reads back through `cat`;
//   2. enumeration splice - the overlay-only file(s) appear in `ls`;
//   3. execroot unchanged - nothing the tools "wrote" leaked onto real disk.
//
// The tools ride as `data`; their rlocationpaths arrive via E2E_UU_* env vars.
// cmd.exe is only the sequencer, not a tool under test.

#include <windows.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/e2e/e2e_harness.h"

namespace bsxe2e {
namespace {

std::wstring Q(const std::wstring& s) { return L"\"" + s + L"\""; }

bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// Resolves a coreutils tool or skips the test when it is not in runfiles.
#define REQUIRE_TOOL(var, env)                                     \
    std::wstring var = OverlayTest::ToolFromEnv(env);              \
    if (var.empty()) GTEST_SKIP() << "coreutils tool missing: " env

// cp copies a real in-cone input into an overlay directory; the copy reads back
// through cat (overlay read-after-write) and shows up in ls (enumeration
// splice), while the real execroot keeps only the seeded input.
TEST_F(OverlayTest, CoreutilsCpReadBackAndListing) {
    REQUIRE_TOOL(mkdir, "E2E_UU_MKDIR");
    REQUIRE_TOOL(cp, "E2E_UU_CP");
    REQUIRE_TOOL(ls, "E2E_UU_LS");
    REQUIRE_TOOL(cat, "E2E_UU_CAT");

    auto ws = NewWorkspace();
    auto in = Join(ws, L"in.txt");
    WriteText(in, "OVUU-CP");  // real, in-cone input (allowed read)

    auto wd = Join(ws, L"wd");
    auto out = Join(wd, L"out.txt");
    auto r = RunOverlayBat(ws, {
        Q(mkdir) + L" " + Q(wd),
        Q(cp) + L" " + Q(in) + L" " + Q(out),
        Q(ls) + L" " + Q(wd),
        Q(cat) + L" " + Q(out),
    });

    EXPECT_TRUE(Contains(r.out, "out.txt")) << "ls did not splice overlay file:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "OVUU-CP")) << "cat did not read back overlay copy:\n" << r.out;

    // Nothing leaked onto the real execroot: only the seeded input remains.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "unexpected on-disk entries under execroot";
    EXPECT_EQ(L"in.txt", snap[0]);
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
    EXPECT_FALSE(Exists(out)) << "overlay copy leaked onto real disk";
}

// Multiple overlay-only files all splice into a single directory listing, and
// none of them touch the real execroot.
TEST_F(OverlayTest, CoreutilsMultipleFilesEnumerated) {
    REQUIRE_TOOL(mkdir, "E2E_UU_MKDIR");
    REQUIRE_TOOL(cp, "E2E_UU_CP");
    REQUIRE_TOOL(ls, "E2E_UU_LS");

    auto ws = NewWorkspace();
    auto in = Join(ws, L"seed.txt");
    WriteText(in, "SEED");

    auto wd = Join(ws, L"wd");
    auto r = RunOverlayBat(ws, {
        Q(mkdir) + L" " + Q(wd),
        Q(cp) + L" " + Q(in) + L" " + Q(Join(wd, L"a.txt")),
        Q(cp) + L" " + Q(in) + L" " + Q(Join(wd, L"b.txt")),
        Q(ls) + L" " + Q(wd),
    });

    EXPECT_TRUE(Contains(r.out, "a.txt")) << "a.txt missing from listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "b.txt")) << "b.txt missing from listing:\n" << r.out;

    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "unexpected on-disk entries under execroot";
    EXPECT_EQ(L"seed.txt", snap[0]);
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
}

// Enumeration's hardest case: a directory that already holds REAL on-disk
// entries must, in a single `ls`, also show the OVERLAY-only entries copied
// into it this invocation - the merged (spliced) view - while the real execroot
// keeps only its seeded files. (Only overlay entries are created here; a real
// visible in-cone file is immutable - delete/rename is denied by design, see
// docs/design/detours-write-overlay-vfs.md §6.3.1 - so this exercises the
// merge, not a mutation of the real entries.)
TEST_F(OverlayTest, CoreutilsMixedRealOverlayEnumerated) {
    REQUIRE_TOOL(mkdir, "E2E_UU_MKDIR");
    REQUIRE_TOOL(cp, "E2E_UU_CP");
    REQUIRE_TOOL(ls, "E2E_UU_LS");
    REQUIRE_TOOL(cat, "E2E_UU_CAT");

    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files, plus a real input to copy.
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");
    auto in = Join(ws, L"in.txt");
    WriteText(in, "OVX");

    // Under the overlay, splice overlay-only entries (a file + a subdir) into
    // the SAME directory that already holds the real entries, then enumerate.
    auto ovsub = Join(mix, L"ovsub");
    auto r = RunOverlayBat(ws, {
        Q(cp) + L" " + Q(in) + L" " + Q(Join(mix, L"ovX.txt")),
        Q(mkdir) + L" " + Q(ovsub),
        Q(ls) + L" " + Q(mix),
        Q(cat) + L" " + Q(Join(mix, L"ovX.txt")),
        Q(cat) + L" " + Q(Join(mix, L"realA.txt")),
    });

    // Merged view: both real entries AND both overlay entries appear together.
    EXPECT_TRUE(Contains(r.out, "realA.txt")) << "real entry missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "realB.txt")) << "real entry missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "ovX.txt")) << "overlay file missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "ovsub")) << "overlay subdir missing from merged listing:\n" << r.out;
    // Read-back through both halves of the merge.
    EXPECT_TRUE(Contains(r.out, "OVX")) << "overlay read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "REALA")) << "real passthrough read failed:\n" << r.out;

    // The real execroot is untouched: only the seeded input + the mix/ dir with
    // its two real files remain (in.txt, mix, mix\realA.txt, mix\realB.txt = 4);
    // no overlay entry leaked to disk.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(4u, snap.size()) << "overlay entries leaked onto the real execroot";
    EXPECT_TRUE(Exists(Join(mix, L"realA.txt"))) << "seeded real file vanished";
    EXPECT_TRUE(Exists(Join(mix, L"realB.txt"))) << "seeded real file vanished";
    EXPECT_FALSE(Exists(Join(mix, L"ovX.txt"))) << "overlay copy leaked onto real disk";
    EXPECT_FALSE(Exists(ovsub)) << "overlay subdir leaked onto real disk";
}

}  // namespace
}  // namespace bsxe2e
