// Write-overlay VFS end-to-end tests against a hermetic Go binary.
//
// A single stdlib-only go_binary (ops.go, op dispatched on argv[1]) is driven
// under the sandbox. It validates the overlay against the Go runtime's own
// OS-API calls (os.Create/os.Rename/os.Remove/os.ReadDir), and - uniquely -
// exercises the CreateProcess *working-directory* overlay redirect:
//
//   GoFsMutationOps          write/read/rename/move/delete, each op visible to
//                            the next through the overlay.
//   GoEnumerationSplice      splice overlay-only entries into a directory of
//                            real files, via os.ReadDir.
//   GoSpawnOverlayOnlyCwd    os/exec a child whose cwd is a directory that
//                            exists ONLY in the overlay backing store (the
//                            rules_go GoStdlib pattern). Without the cwd overlay
//                            redirect the child fails to launch (ERROR_DIRECTORY
//                            267); with it, it runs and its relative write reads
//                            back through the overlay.
//   GoSpawnOverlayOnlyCwdRelativeReadWrite  as above, but the child touches files
//                            by cwd-RELATIVE names (write to overlay + read a real
//                            "..\seedrel.txt" input) - exercises the reverse-map.
//   GoFilterInputsHidesUndeclared    declared -r input visible, undeclared masked.
//   GoFilterOverlayMutations         combined filter+overlay collision edge cases.
//
// Every test asserts the overlay invariants (read-after-write, enumeration
// splice, unchanged real execroot) and skips if its tool env var is missing.

#include <windows.h>

#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "tests/e2e/e2e_harness.h"

namespace bsxe2e {
namespace {

bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

std::wstring OpsExe() { return OverlayTest::ToolFromEnv("E2E_GO_OPS"); }

// Narrow an ASCII/UTF-8 wide path for substring assertions against tool output.
std::string Narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// write/read/rename/delete/move, each op visible to the next through the
// overlay in a single invocation, none of it touching the real execroot.
TEST_F(OverlayTest, GoFsMutationOps) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {ops, L"fsops", ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "READ=OVOPS")) << "read-after-write failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERRENAME=b.txt")) << "rename not reflected in listing:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "AFTERDELETE=b.txt,c.txt")) << "delete not reflected in listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERDELETE=b.txt")) << "delete removed too much:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "MOVED=OVOPS")) << "move + read-back failed:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "go writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// A single os.ReadDir must splice overlay-only entries into a directory that
// already has real on-disk entries (no duplicates), reflect the removal of an
// overlay-created entry, and let prefix filters resolve against the merged set -
// all without disturbing the immutable real execroot.
TEST_F(OverlayTest, GoEnumerationSplice) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlay(ws, {ops, L"enum", ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "LIST1=realA.txt,realB.txt")) << "real passthrough enumeration failed:\n" << r.out;
    // Sort is by code point: uppercase 'X' < lowercase 's', so ovX.txt < ovsub.
    EXPECT_TRUE(Contains(r.out, "LIST2=ovX.txt,ovsub,realA.txt,realB.txt")) << "enumeration splice failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBOV=ovX.txt,ovsub")) << "filter missed overlay entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBREAL=realA.txt,realB.txt")) << "filter missed real entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READOV=OVX")) << "overlay read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READREAL=REALA")) << "real passthrough read failed:\n" << r.out;

    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(3u, snap.size()) << "overlay entries leaked onto the real execroot";
    EXPECT_TRUE(Exists(Join(mix, L"realA.txt"))) << "seeded real file vanished";
    EXPECT_TRUE(Exists(Join(mix, L"realB.txt"))) << "seeded real file vanished";
    EXPECT_FALSE(Exists(Join(mix, L"ovX.txt"))) << "overlay create leaked to the real disk";
    EXPECT_FALSE(Exists(Join(mix, L"ovsub"))) << "overlay subdir leaked to the real disk";
}

// The rules_go GoStdlib regression, through the Go runtime. The program creates
// a directory that exists ONLY in the overlay backing store, then os/exec's a
// child (itself) with that overlay-only dir as its working directory. Without
// the CreateProcess working-directory overlay redirect the OS cannot resolve the
// absent real dir and the child fails to launch (ERROR_DIRECTORY 267); with it
// the child launches from the concrete backing dir and writes its output (an
// absolute path under the virtual execroot, the way rules_go's compiler does)
// into the overlay, which reads back here. The real execroot stays untouched.
TEST_F(OverlayTest, GoSpawnOverlayOnlyCwd) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {ops, L"spawncwd", ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Child launched from the overlay-only cwd (no 267) and ran its code.
    EXPECT_TRUE(Contains(r.out, "SPAWN=CHILD=OK")) << "child failed to launch from overlay-only cwd:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "SPAWN=ERR:")) << "child launch errored:\n" << r.out;
    // The child's cwd-relative write landed in the overlay and reads back.
    EXPECT_TRUE(Contains(r.out, "READBACK=CHILDWROTE")) << "cwd-relative child write not visible in overlay:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "spawn writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"spawndir"))) << "overlay cwd leaked onto real disk";
}

// Like GoSpawnOverlayOnlyCwd, but the child touches files through cwd-RELATIVE
// names from an overlay-only cwd. This exercises the hook-layer reverse-map on the
// real Go runtime: a relative write to an undeclared name lands in the overlay and
// reads back, AND a relative read of a REAL declared input one level up
// ("..\seedrel.txt", seeded on the real disk here) reaches it via the overlay's
// real-fallback. Without the reverse-map the relative input read resolves against
// the private backing store and misses (INERR).
TEST_F(OverlayTest, GoSpawnOverlayOnlyCwdRelativeReadWrite) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    // A real on-disk declared input the child reads via "..\seedrel.txt".
    WriteText(Join(ws, L"seedrel.txt"), "SEEDIN");

    auto r = RunOverlay(ws, {ops, L"spawncwdrel", ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Child launched from the overlay-only cwd and completed all relative ops.
    EXPECT_TRUE(Contains(r.out, "CHILD=OK")) << "child failed from overlay-only cwd:\n" << r.out;
    // Relative write to an undeclared name landed in the overlay and read back.
    EXPECT_TRUE(Contains(r.out, "WROTE=RELWROTE")) << "cwd-relative overlay write/read-back failed:\n" << r.out;
    // Relative read of the REAL declared input resolved via the reverse-map + real-fallback.
    EXPECT_TRUE(Contains(r.out, "INPUT=SEEDIN")) << "cwd-relative read of a real input did not resolve:\n" << r.out;
    // Parent reads the child's overlay write back through the absolute virtual path.
    EXPECT_TRUE(Contains(r.out, "READBACK=RELWROTE")) << "child's overlay write not visible to parent:\n" << r.out;

    EXPECT_FALSE(Exists(Join(ws, L"spawnreldir"))) << "overlay cwd leaked onto real disk";
    EXPECT_FALSE(Exists(Join(ws, L"childrel.txt"))) << "cwd-relative overlay write leaked onto real disk";
    EXPECT_TRUE(Exists(Join(ws, L"seedrel.txt"))) << "real declared input was disturbed";
}

// Input-filtering (production mode): only declared -r inputs are visible. Driven
// through Go's own os.ReadDir + os.ReadFile - the declared input is listed and
// readable while the undeclared sibling is masked NOT_FOUND (absent from the
// listing, os.ReadFile returns a not-exist error).
TEST_F(OverlayTest, GoFilterInputsHidesUndeclared) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(Join(ws, L"secret.txt"), "TOP-SECRET");

    auto r = RunFiltered(ws, {decl}, {ops, L"filter", ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "decl.txt")) << "declared input missing from listing:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "secret.txt")) << "undeclared file leaked into listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READDECL=DECLARED-VISIBLE")) << "declared input not readable:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READSECRET=ERR:NotFound")) << "undeclared read not masked NOT_FOUND:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "TOP-SECRET")) << "undeclared content leaked:\n" << r.out;
}

// COMBINED --filter-inputs --write-overlay: a Go tool output whose name collides
// with a HIDDEN undeclared input (masked, seeded real secret.txt, NO -r). Every
// op lands in the overlay and leaves the real file byte-for-byte unchanged;
// deleting or renaming away the overlay copy must NOT re-reveal the masked real
// input. Go's os.Rename/os.Remove take the path-based MoveFileEx/DeleteFile hooks.
TEST_F(OverlayTest, GoFilterOverlayMutations) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto seed = [&](const wchar_t* op) {
        auto ws = NewWorkspace();
        WriteText(Join(ws, L"secret.txt"), "REAL-SECRET");
        auto r = RunFilteredOverlay(ws, /*declared*/ {}, {ops, L"filteroverlay", ws, op});
        EXPECT_EQ(0, r.code) << op << ":\n" << r.out;
        EXPECT_EQ("REAL-SECRET", ReadText(Join(ws, L"secret.txt")))
            << op << ": real undeclared input was mutated";
        return std::make_pair(ws, r.out);
    };

    {
        auto [ws, out] = seed(L"create");
        EXPECT_TRUE(Contains(out, "CREATE=OVERLAY-NEW")) << "create over hidden failed:\n" << out;
    }
    {
        auto [ws, out] = seed(L"renameonto");
        EXPECT_TRUE(Contains(out, "RENAMEONTO=OVERLAY-ONTO")) << "rename onto hidden failed:\n" << out;
        EXPECT_FALSE(Exists(Join(ws, L"tmp.txt"))) << "overlay source leaked to real disk";
    }
    {
        auto [ws, out] = seed(L"renameaway");
        EXPECT_TRUE(Contains(out, "RENAMEAWAY=OVERLAY-AWAY")) << "rename away failed:\n" << out;
        EXPECT_TRUE(Contains(out, "SRCAFTER=ERR:NotFound")) << "source re-revealed after rename away:\n" << out;
        EXPECT_FALSE(Contains(out, "SRCAFTER=REAL-SECRET")) << "masked real input leaked:\n" << out;
        EXPECT_FALSE(Exists(Join(ws, L"moved.txt"))) << "overlay dest leaked to real disk";
    }
    {
        auto [ws, out] = seed(L"delete");
        EXPECT_TRUE(Contains(out, "AFTERDEL=ERR:NotFound")) << "name re-revealed after delete:\n" << out;
        EXPECT_FALSE(Contains(out, "AFTERDEL=REAL-SECRET")) << "masked real input leaked:\n" << out;
    }
    {
        auto [ws, out] = seed(L"deletebare");
        EXPECT_TRUE(Contains(out, "DELETEBARE=ERR:NotFound")) << "bare delete not a NOT_FOUND no-op:\n" << out;
        EXPECT_TRUE(Exists(Join(ws, L"secret.txt"))) << "undeclared input vanished";
    }
    {
        auto [ws, out] = seed(L"renamefrombare");
        EXPECT_TRUE(Contains(out, "RENAMEFROMBARE=ERR:NotFound")) << "bare rename not a NOT_FOUND no-op:\n" << out;
        EXPECT_TRUE(Exists(Join(ws, L"secret.txt"))) << "undeclared input vanished";
        EXPECT_FALSE(Exists(Join(ws, L"moved.txt"))) << "bare rename produced a real dest";
    }
}

// Declared outputs (-w) under --write-overlay write THROUGH to the real execroot
// (that is how Bazel collects an action's declared outputs), while an undeclared
// sibling write is redirected into the process-private overlay. Driven through
// the real Go runtime's os.WriteFile (CreateFileW): both files read back
// in-process (overlay read-after-write covers the redirected sibling), but on the
// real disk only the declared output appears - the undeclared sibling does not.
TEST_F(OverlayTest, GoDeclaredOutputWritesThrough) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto out = Join(ws, L"out.txt");
    auto sib = Join(ws, L"sibling.txt");

    auto r = RunOverlayWithWritable(ws, {out}, {ops, L"writeout", out, sib});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OUT=DECLARED-OUT")) << "declared output not readable in-process:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "SIB=UNDECLARED-SIB")) << "sibling not readable through the overlay:\n" << r.out;

    // Declared -w output wrote through to real disk; undeclared sibling did not.
    EXPECT_TRUE(Exists(out)) << "declared -w output did not reach the real execroot";
    EXPECT_EQ("DECLARED-OUT", ReadText(out));
    EXPECT_FALSE(Exists(sib)) << "undeclared write leaked onto the real execroot";
    std::vector<std::wstring> snap = Snapshot(ws);
    EXPECT_EQ(1u, snap.size()) << "unexpected entries on the real execroot (only the -w output should be there)";
}

// GetCurrentDirectory overlay reverse-map. The program spawns a child (itself) whose
// working directory is set to a directory that exists ONLY in the overlay backing store;
// the parent's CreateProcess cwd redirect points the child at the concrete backing dir,
// so the child inherits the backing path as its OS current directory. The child reports
// os.Getwd (which on Windows always calls GetCurrentDirectory). Without the reverse-map
// hook it observes the private backing path; with it, the logical execroot path
// (ws\cwddir). An in-process os.Chdir would NOT reproduce the leak (SetCurrentDirectory
// stores the input string verbatim), so this deliberately uses an inherited child cwd -
// the same path the GoStdlib cwd fix targets. Real execroot stays untouched.
TEST_F(OverlayTest, GoGetCurrentDirectoryReportsVirtualPath) {
    std::wstring ops = OpsExe();
    if (ops.empty()) GTEST_SKIP() << "go ops binary missing from runfiles (E2E_GO_OPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {ops, L"getcwd", ws});

    EXPECT_EQ(0, r.code) << r.out;
    // The child, launched from the overlay-only cwd, reports the virtual execroot path.
    EXPECT_TRUE(Contains(r.out, ("WD=" + Narrow(Join(ws, L"cwddir"))).c_str()))
        << "child os.Getwd did not report the virtual execroot cwd:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "WD=ERR:")) << "child launch errored:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "getcwd writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"cwddir"))) << "overlay cwd leaked onto real disk";
}

}  // namespace
}  // namespace bsxe2e