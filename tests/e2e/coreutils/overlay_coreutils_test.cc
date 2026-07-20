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

// Input-filtering (the mode Bazel uses in production): only declared -r inputs
// are visible. A real tool reading + listing the execroot must see the declared
// input (both its content via cat and its name via ls) but NEITHER read nor
// enumerate an undeclared sibling - it is masked NOT_FOUND and hidden from the
// directory listing.
TEST_F(OverlayTest, CoreutilsFilterInputsHidesUndeclared) {
    REQUIRE_TOOL(ls, "E2E_UU_LS");
    REQUIRE_TOOL(cat, "E2E_UU_CAT");

    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    auto secret = Join(ws, L"secret.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(secret, "TOP-SECRET");

    // Enumeration: the declared input appears, the undeclared sibling does not.
    // (ls runs alone so its listing can't be contaminated by cat's error text,
    // which necessarily echoes the masked path.)
    auto lsr = RunFiltered(ws, {decl}, {ls, ws});
    EXPECT_TRUE(Contains(lsr.out, "decl.txt")) << "declared input missing from listing:\n" << lsr.out;
    EXPECT_FALSE(Contains(lsr.out, "secret.txt")) << "undeclared file leaked into listing:\n" << lsr.out;

    // Content: the declared input reads back; the undeclared sibling is masked
    // NOT_FOUND, so its content never appears.
    auto declR = RunFiltered(ws, {decl}, {cat, decl});
    EXPECT_TRUE(Contains(declR.out, "DECLARED-VISIBLE")) << "declared input not readable:\n" << declR.out;
    auto secR = RunFiltered(ws, {decl}, {cat, secret});
    EXPECT_FALSE(Contains(secR.out, "TOP-SECRET")) << "undeclared file was readable:\n" << secR.out;
}

// COMBINED --filter-inputs --write-overlay: a coreutils output whose name collides
// with a HIDDEN undeclared input. A declared -r src.txt is the (visible) copy
// source; secret.txt is the masked undeclared real input. cp/mv/rm go through the
// Rust std::fs path-based CopyFile/MoveFileEx/DeleteFile hooks. Every op must land
// in the overlay and leave the real secret.txt unchanged; after deleting or
// renaming away the overlay copy, reading secret.txt must NOT re-reveal either the
// overlay content (OVUU-NEW) or the masked real bytes (REAL-SECRET).
TEST_F(OverlayTest, CoreutilsFilterOverlayMutations) {
    REQUIRE_TOOL(cp, "E2E_UU_CP");
    REQUIRE_TOOL(mv, "E2E_UU_MV");
    REQUIRE_TOOL(rm, "E2E_UU_RM");
    REQUIRE_TOOL(cat, "E2E_UU_CAT");

    // Fresh workspace per op: seeds a HIDDEN real secret.txt and a declared -r
    // src.txt (the only visible file), returns the workspace + secret path.
    auto seed = [&](std::wstring& src, std::wstring& secret) {
        auto ws = NewWorkspace();
        secret = Join(ws, L"secret.txt");
        src = Join(ws, L"src.txt");
        WriteText(secret, "REAL-SECRET");  // undeclared -> masked
        WriteText(src, "OVUU-NEW");         // declared -r -> visible copy source
        return ws;
    };
    auto real = [&](const std::wstring& secret) { return ReadText(secret); };

    // create over hidden: cp the visible src onto the masked name -> overlay copy.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(src) + L" " + Q(secret),
            Q(cat) + L" " + Q(secret),
        });
        EXPECT_TRUE(Contains(r.out, "OVUU-NEW")) << "create over hidden failed:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
    }
    // rename ONTO hidden: cp src->tmp, mv tmp onto the masked name.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto tmp = Join(ws, L"tmp.txt");
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(src) + L" " + Q(tmp),
            Q(mv) + L" " + Q(tmp) + L" " + Q(secret),
            Q(cat) + L" " + Q(secret),
        });
        EXPECT_TRUE(Contains(r.out, "OVUU-NEW")) << "rename onto hidden failed:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
        EXPECT_FALSE(Exists(tmp)) << "overlay source leaked to real disk";
    }
    // create then rename AWAY: the moved copy carries the bytes; reading the
    // original masked name must be GONE (no OVUU-NEW, no REAL-SECRET).
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto moved = Join(ws, L"moved.txt");
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(src) + L" " + Q(secret),
            Q(mv) + L" " + Q(secret) + L" " + Q(moved),
            Q(cat) + L" " + Q(moved),
            Q(cat) + L" " + Q(secret),
        });
        EXPECT_TRUE(Contains(r.out, "OVUU-NEW")) << "rename away lost the moved content:\n" << r.out;
        EXPECT_FALSE(Contains(r.out, "REAL-SECRET")) << "masked real input re-revealed after rename away:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
        EXPECT_FALSE(Exists(moved)) << "overlay dest leaked to real disk";
    }
    // create then delete: reading the name afterwards must be GONE (leak guard).
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(src) + L" " + Q(secret),
            Q(rm) + L" " + Q(secret),
            Q(cat) + L" " + Q(secret),
        });
        EXPECT_FALSE(Contains(r.out, "OVUU-NEW")) << "overlay copy survived delete:\n" << r.out;
        EXPECT_FALSE(Contains(r.out, "REAL-SECRET")) << "masked real input re-revealed after delete:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
    }
    // bare delete of the hidden name (no overlay copy): NOT_FOUND no-op, real survives.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        RunFilteredOverlayBat(ws, {src}, {Q(rm) + L" " + Q(secret)});
        EXPECT_EQ("REAL-SECRET", real(secret)) << "undeclared input deleted via the sandbox";
        EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
    }
    // bare rename of the hidden name away (no overlay copy): NOT_FOUND no-op.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto moved = Join(ws, L"moved.txt");
        RunFilteredOverlayBat(ws, {src}, {Q(mv) + L" " + Q(secret) + L" " + Q(moved)});
        EXPECT_EQ("REAL-SECRET", real(secret)) << "undeclared input renamed via the sandbox";
        EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
        EXPECT_FALSE(Exists(moved)) << "bare rename produced a real dest";
    }
}

}  // namespace
}  // namespace bsxe2e
