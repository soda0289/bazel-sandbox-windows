// Write-overlay VFS end-to-end tests against hermetic msys2 GNU coreutils.
//
// Same shape as tests/e2e/coreutils, but the tools are the msys2 applets
// (cp/ls/cat/mkdir) fetched from the official msys2-base release archive (see
// MODULE.bazel) rather than a machine install - so this lane is HERMETIC. It
// adds coverage the hermetic uutils build cannot: the overlay is exercised
// against the MSYS (Cygwin) runtime's POSIX file ops and its Windows<->POSIX
// path translation. msys2 applets want forward-slash paths, so every path
// handed to a tool is normalized with Fwd(); cmd.exe is only the op sequencer.
//
// The applets ride as `data` and their rlocationpaths arrive via E2E_MSYS_*
// env vars; the MSYS runtime DLLs they load (:runtime_dlls) ride alongside them
// so they resolve by the applet's full runfiles path.
//
// Each test runs a single "BazelSandbox --write-overlay -W <ws> -- cmd /c <bat>"
// invocation (the overlay backing store is per invocation, so a write and its
// read-back must share one) and asserts: (1) read-after-write, (2) an
// enumeration splice, and (3) an unchanged real execroot.

#include <windows.h>

#include <algorithm>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/e2e/e2e_harness.h"

namespace bsxe2e {
namespace {

// msys2 coreutils treat backslashes as escapes; hand them forward-slash paths.
std::wstring Fwd(const std::wstring& p) {
    std::wstring r = p;
    std::replace(r.begin(), r.end(), L'\\', L'/');
    return r;
}

std::wstring Q(const std::wstring& s) { return L"\"" + s + L"\""; }

bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// Resolves a hermetic msys2 applet from runfiles, or skips if it is missing
// (should not happen once the msys2_base archive is fetched).
#define REQUIRE_MSYS(var, env)                                            \
    std::wstring var = OverlayTest::ToolFromEnv(env);                     \
    if (var.empty()) GTEST_SKIP() << "msys2 applet not resolved from runfiles: " env

// cp copies a real in-cone input into an overlay directory; the copy reads back
// through cat (overlay read-after-write) and shows up in ls (enumeration
// splice), while the real execroot keeps only the seeded input.
TEST_F(OverlayTest, Msys2CpReadBackAndListing) {
    REQUIRE_MSYS(mkdir, "E2E_MSYS_MKDIR");
    REQUIRE_MSYS(cp, "E2E_MSYS_CP");
    REQUIRE_MSYS(ls, "E2E_MSYS_LS");
    REQUIRE_MSYS(cat, "E2E_MSYS_CAT");

    auto ws = NewWorkspace();
    auto in = Join(ws, L"in.txt");
    WriteText(in, "OVMSYS-CP");  // real, in-cone input (allowed read)

    auto wd = Join(ws, L"wd");
    auto out = Join(wd, L"out.txt");
    auto r = RunOverlayBat(ws, {
        Q(mkdir) + L" " + Q(Fwd(wd)),
        Q(cp) + L" " + Q(Fwd(in)) + L" " + Q(Fwd(out)),
        Q(ls) + L" " + Q(Fwd(wd)),
        Q(cat) + L" " + Q(Fwd(out)),
    });

    EXPECT_TRUE(Contains(r.out, "out.txt")) << "ls did not splice overlay file:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "OVMSYS-CP")) << "cat did not read back overlay copy:\n" << r.out;

    // Nothing leaked onto the real execroot: only the seeded input remains.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "unexpected on-disk entries under execroot";
    EXPECT_EQ(L"in.txt", snap[0]);
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
    EXPECT_FALSE(Exists(out)) << "overlay copy leaked onto real disk";
}

// Multiple overlay-only files all splice into a single directory listing, and
// none of them touch the real execroot.
TEST_F(OverlayTest, Msys2MultipleFilesEnumerated) {
    REQUIRE_MSYS(mkdir, "E2E_MSYS_MKDIR");
    REQUIRE_MSYS(cp, "E2E_MSYS_CP");
    REQUIRE_MSYS(ls, "E2E_MSYS_LS");

    auto ws = NewWorkspace();
    auto in = Join(ws, L"seed.txt");
    WriteText(in, "SEED");

    auto wd = Join(ws, L"wd");
    auto r = RunOverlayBat(ws, {
        Q(mkdir) + L" " + Q(Fwd(wd)),
        Q(cp) + L" " + Q(Fwd(in)) + L" " + Q(Fwd(Join(wd, L"a.txt"))),
        Q(cp) + L" " + Q(Fwd(in)) + L" " + Q(Fwd(Join(wd, L"b.txt"))),
        Q(ls) + L" " + Q(Fwd(wd)),
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
TEST_F(OverlayTest, Msys2MixedRealOverlayEnumerated) {
    REQUIRE_MSYS(mkdir, "E2E_MSYS_MKDIR");
    REQUIRE_MSYS(cp, "E2E_MSYS_CP");
    REQUIRE_MSYS(ls, "E2E_MSYS_LS");
    REQUIRE_MSYS(cat, "E2E_MSYS_CAT");

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
        Q(cp) + L" " + Q(Fwd(in)) + L" " + Q(Fwd(Join(mix, L"ovX.txt"))),
        Q(mkdir) + L" " + Q(Fwd(ovsub)),
        Q(ls) + L" " + Q(Fwd(mix)),
        Q(cat) + L" " + Q(Fwd(Join(mix, L"ovX.txt"))),
        Q(cat) + L" " + Q(Fwd(Join(mix, L"realA.txt"))),
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

// grep reads file content through the overlay: cp seeds an overlay-only file,
// then grep -r scans the overlay directory and matches a marker line. grep's
// recursive walk enumerates the overlay dir (splice) AND opens+reads the
// overlay file (read-after-write), so a match proves both paths resolve to the
// backing store. The real execroot keeps only the seeded input.
TEST_F(OverlayTest, Msys2GrepSearch) {
    REQUIRE_MSYS(mkdir, "E2E_MSYS_MKDIR");
    REQUIRE_MSYS(cp, "E2E_MSYS_CP");
    REQUIRE_MSYS(grep, "E2E_MSYS_GREP");

    auto ws = NewWorkspace();
    auto in = Join(ws, L"in.txt");
    WriteText(in, "alpha\nOVGREP-NEEDLE\nomega\n");  // real, in-cone input

    auto wd = Join(ws, L"wd");
    auto out = Join(wd, L"a.txt");
    auto r = RunOverlayBat(ws, {
        Q(mkdir) + L" " + Q(Fwd(wd)),
        Q(cp) + L" " + Q(Fwd(in)) + L" " + Q(Fwd(out)),
        Q(grep) + L" -r OVGREP-NEEDLE " + Q(Fwd(wd)),
    });

    EXPECT_TRUE(Contains(r.out, "OVGREP-NEEDLE")) << "grep did not match through the overlay:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "a.txt")) << "grep -r did not enumerate the overlay file:\n" << r.out;

    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "unexpected on-disk entries under execroot";
    EXPECT_EQ(L"in.txt", snap[0]);
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
}

// Input-filtering (the mode Bazel uses in production): only declared -r inputs
// enumeration, cat for reads - the declared input is fully visible while the
// undeclared sibling is masked NOT_FOUND. Each op runs in its own invocation so
// cat's error text for the masked path cannot contaminate the ls listing check.
TEST_F(OverlayTest, Msys2FilterInputsHidesUndeclared) {
    REQUIRE_MSYS(ls, "E2E_MSYS_LS");
    REQUIRE_MSYS(cat, "E2E_MSYS_CAT");

    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    auto secret = Join(ws, L"secret.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(secret, "TOP-SECRET");

    // Enumeration: declared input present, undeclared sibling hidden.
    auto lsr = RunFiltered(ws, {decl}, {ls, Fwd(ws)});
    EXPECT_TRUE(Contains(lsr.out, "decl.txt")) << "declared input missing from listing:\n" << lsr.out;
    EXPECT_FALSE(Contains(lsr.out, "secret.txt")) << "undeclared file leaked into listing:\n" << lsr.out;

    // Content: declared input reads back; undeclared sibling is masked NOT_FOUND.
    auto declR = RunFiltered(ws, {decl}, {cat, Fwd(decl)});
    EXPECT_TRUE(Contains(declR.out, "DECLARED-VISIBLE")) << "declared input not readable:\n" << declR.out;
    auto secR = RunFiltered(ws, {decl}, {cat, Fwd(secret)});
    EXPECT_FALSE(Contains(secR.out, "TOP-SECRET")) << "undeclared file was readable:\n" << secR.out;
}

// COMBINED --filter-inputs --write-overlay against the MSYS runtime: an output
// whose name collides with a HIDDEN undeclared input. A declared -r src.txt is
// the visible copy source; secret.txt is the masked undeclared real input. Every
// cp/mv/rm must land in the overlay and leave the real secret.txt unchanged;
// after deleting or renaming away the overlay copy, reading the name must NOT
// re-reveal the overlay content (OVMSYS-NEW) or the masked real bytes (REAL-SECRET).
TEST_F(OverlayTest, Msys2FilterOverlayMutations) {
    REQUIRE_MSYS(cp, "E2E_MSYS_CP");
    REQUIRE_MSYS(mv, "E2E_MSYS_MV");
    REQUIRE_MSYS(rm, "E2E_MSYS_RM");
    REQUIRE_MSYS(cat, "E2E_MSYS_CAT");

    auto seed = [&](std::wstring& src, std::wstring& secret) {
        auto ws = NewWorkspace();
        secret = Join(ws, L"secret.txt");
        src = Join(ws, L"src.txt");
        WriteText(secret, "REAL-SECRET");  // undeclared -> masked
        WriteText(src, "OVMSYS-NEW");       // declared -r -> visible copy source
        return ws;
    };
    auto real = [&](const std::wstring& secret) { return ReadText(secret); };

    // create over hidden -> overlay copy.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(Fwd(src)) + L" " + Q(Fwd(secret)),
            Q(cat) + L" " + Q(Fwd(secret)),
        });
        EXPECT_TRUE(Contains(r.out, "OVMSYS-NEW")) << "create over hidden failed:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
    }
    // rename ONTO hidden.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto tmp = Join(ws, L"tmp.txt");
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(Fwd(src)) + L" " + Q(Fwd(tmp)),
            Q(mv) + L" " + Q(Fwd(tmp)) + L" " + Q(Fwd(secret)),
            Q(cat) + L" " + Q(Fwd(secret)),
        });
        EXPECT_TRUE(Contains(r.out, "OVMSYS-NEW")) << "rename onto hidden failed:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
        EXPECT_FALSE(Exists(tmp)) << "overlay source leaked to real disk";
    }
    // create then rename AWAY: original masked name must be GONE.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto moved = Join(ws, L"moved.txt");
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(Fwd(src)) + L" " + Q(Fwd(secret)),
            Q(mv) + L" " + Q(Fwd(secret)) + L" " + Q(Fwd(moved)),
            Q(cat) + L" " + Q(Fwd(moved)),
            Q(cat) + L" " + Q(Fwd(secret)),
        });
        EXPECT_TRUE(Contains(r.out, "OVMSYS-NEW")) << "rename away lost the moved content:\n" << r.out;
        EXPECT_FALSE(Contains(r.out, "REAL-SECRET")) << "masked real input re-revealed after rename away:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
        EXPECT_FALSE(Exists(moved)) << "overlay dest leaked to real disk";
    }
    // create then delete: reading the name afterwards must be GONE.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto r = RunFilteredOverlayBat(ws, {src}, {
            Q(cp) + L" " + Q(Fwd(src)) + L" " + Q(Fwd(secret)),
            Q(rm) + L" " + Q(Fwd(secret)),
            Q(cat) + L" " + Q(Fwd(secret)),
        });
        EXPECT_FALSE(Contains(r.out, "OVMSYS-NEW")) << "overlay copy survived delete:\n" << r.out;
        EXPECT_FALSE(Contains(r.out, "REAL-SECRET")) << "masked real input re-revealed after delete:\n" << r.out;
        EXPECT_EQ("REAL-SECRET", real(secret)) << "real undeclared input mutated";
    }
    // bare delete of the hidden name (no overlay copy): NOT_FOUND no-op.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        RunFilteredOverlayBat(ws, {src}, {Q(rm) + L" " + Q(Fwd(secret))});
        EXPECT_EQ("REAL-SECRET", real(secret)) << "undeclared input deleted via the sandbox";
        EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
    }
    // bare rename of the hidden name away (no overlay copy): NOT_FOUND no-op.
    {
        std::wstring src, secret; auto ws = seed(src, secret);
        auto moved = Join(ws, L"moved.txt");
        RunFilteredOverlayBat(ws, {src}, {Q(mv) + L" " + Q(Fwd(secret)) + L" " + Q(Fwd(moved))});
        EXPECT_EQ("REAL-SECRET", real(secret)) << "undeclared input renamed via the sandbox";
        EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
        EXPECT_FALSE(Exists(moved)) << "bare rename produced a real dest";
    }
}

}  // namespace
}  // namespace bsxe2e
