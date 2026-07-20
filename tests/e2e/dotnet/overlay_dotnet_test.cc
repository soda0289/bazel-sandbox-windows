// Write-overlay VFS end-to-end test against a hermetic .NET 10 C# binary.
//
// This is the .NET analogue of tests/e2e/nodejs' NodeFsMutationOps case: a
// single "BazelSandbox --write-overlay -W <ws> -- cmd /c <launcher> <ws>"
// invocation runs a compiled csharp_binary (fs_ops.cs) that drives the full
// read/write/rename/move/delete sequence through System.IO. Because those ops
// go through the .NET runtime's own OS-API calls (CreateFileW / MoveFileEx /
// DeleteFile / FindFirstFile), they exercise the overlay against a different
// caller than node or the coreutils tools.
//
// The csharp_binary launcher (a .bat that runs `dotnet exec fs_ops.dll`) rides
// as `data`; its rlocationpath arrives via E2E_DOTNET_FSOPS and it resolves the
// hermetic dotnet.exe + fs_ops.dll from the test's runfiles manifest (the env
// the sandbox inherits and forwards to the child). cmd.exe is only used to run
// the .bat launcher.
//
// The test asserts the three overlay invariants: read-after-write, an
// enumeration splice (rename/delete reflected in a directory listing), and an
// unchanged real execroot (every write redirected into the backing store).

#include <windows.h>

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/e2e/e2e_harness.h"

namespace bsxe2e {
namespace {

bool Contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

TEST_F(OverlayTest, DotnetFsMutationOps) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_DOTNET_FSOPS");
    if (launcher.empty())
        GTEST_SKIP() << "fs_ops csharp_binary launcher missing (E2E_DOTNET_FSOPS)";

    auto ws = NewWorkspace();
    // cmd /c <launcher.bat> <ws>: the launcher shells to the hermetic dotnet
    // runtime and runs fs_ops.dll with the execroot as its only argument.
    auto r = RunOverlay(ws, {OverlayTest::CmdExe(), L"/c", launcher, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // write -> read-back through the overlay.
    EXPECT_TRUE(Contains(r.out, "READ=OVNET")) << "read-after-write failed:\n" << r.out;
    // rename a.txt -> b.txt: listing shows b.txt and no longer a.txt.
    EXPECT_TRUE(Contains(r.out, "AFTERRENAME=b.txt")) << "rename not reflected in listing:\n" << r.out;
    // create + delete c.txt: listing no longer contains c.txt.
    EXPECT_FALSE(Contains(r.out, "AFTERDELETE=b.txt,c.txt")) << "delete not reflected in listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERDELETE=b.txt")) << "delete removed too much:\n" << r.out;
    // move b.txt into sub/ then read it back at its new path.
    EXPECT_TRUE(Contains(r.out, "MOVED=OVNET")) << "move + read-back failed:\n" << r.out;

    // The whole wd/ tree lived only in the overlay: the real execroot is empty.
    EXPECT_TRUE(Snapshot(ws).empty()) << ".NET writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Enumeration is the overlay's hardest area: a single directory listing must
// splice overlay-only entries into a directory that already has real on-disk
// entries (without duplicates), reflect the removal of an overlay-created
// entry, and honor wildcard filters over the merged set - all without
// disturbing the immutable real execroot. (Deleting/renaming a REAL visible
// file is denied by design - see docs/design/detours-write-overlay-vfs.md
// §6.3.1 - so this exercises the merge, not a mutation of real entries.)
TEST_F(OverlayTest, DotnetEnumerationSplice) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_DOTNET_ENUMOPS");
    if (launcher.empty())
        GTEST_SKIP() << "enum_ops csharp_binary launcher missing (E2E_DOTNET_ENUMOPS)";

    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files (allowed in-cone reads). The
    // sandboxed program splices overlay-only entries alongside these.
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlay(ws, {OverlayTest::CmdExe(), L"/c", launcher, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Baseline: both seeded real entries enumerate through the passthrough.
    EXPECT_TRUE(Contains(r.out, "LIST1=realA.txt,realB.txt")) << "real passthrough enumeration failed:\n" << r.out;
    // Merged view: overlay-only file + subdir spliced in alongside the reals,
    // with the deleted overlay entry (ovY.txt) gone. Ordinal sort: uppercase
    // 'X' < lowercase 's', so ovX.txt < ovsub, then the real* entries.
    EXPECT_TRUE(Contains(r.out, "LIST2=ovX.txt,ovsub,realA.txt,realB.txt")) << "enumeration splice failed:\n" << r.out;
    // Wildcard enumeration (FindFirstFile pattern) resolves against the merged
    // set: "ov*" finds only the overlay entries, "real*" only the real ones.
    EXPECT_TRUE(Contains(r.out, "GLOBOV=ovX.txt,ovsub")) << "wildcard missed overlay entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBREAL=realA.txt,realB.txt")) << "wildcard missed real entries:\n" << r.out;
    // Read-back through both halves of the merge.
    EXPECT_TRUE(Contains(r.out, "READOV=OVX")) << "overlay read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READREAL=REALA")) << "real passthrough read failed:\n" << r.out;

    // The real execroot is untouched: only the seeded mix/ dir + its two real
    // files remain; no overlay entry leaked to disk.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(3u, snap.size()) << "overlay entries leaked onto the real execroot";
    EXPECT_TRUE(Exists(Join(mix, L"realA.txt"))) << "seeded real file vanished";
    EXPECT_TRUE(Exists(Join(mix, L"realB.txt"))) << "seeded real file vanished";
    EXPECT_FALSE(Exists(Join(mix, L"ovX.txt"))) << "overlay create leaked to the real disk";
    EXPECT_FALSE(Exists(Join(mix, L"ovsub"))) << "overlay subdir leaked to the real disk";
}

}  // namespace
}  // namespace bsxe2e
