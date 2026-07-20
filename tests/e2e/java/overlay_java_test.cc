// Write-overlay VFS end-to-end tests against a hermetic Java (JDK) binary.
//
// This is the Java analogue of tests/e2e/dotnet: a single
// "BazelSandbox --write-overlay -W <ws> -- <launcher> <ws>" invocation runs a
// java_binary that drives the full read/write/rename/move/delete sequence (and,
// in the other cases, an enumeration splice and input-filtering) through
// java.nio.file. Because those ops go through the JVM's own OS-API calls
// (CreateFileW / MoveFileEx / DeleteFile / FindFirstFile), they exercise the
// overlay against a different caller than node, python, coreutils, or .NET.
//
// The java_binary launcher (a native .exe that runs the classpath jar on the
// hermetic remote JDK) rides as `data`; its rlocationpath arrives via an env
// var and it resolves the JDK runtime + jars from the test's runfiles manifest
// (the env the sandbox inherits and forwards to the child). The launcher is run
// directly (it is a real executable, not a .bat) with the execroot as argv[0].
//
// Every test asserts the overlay invariants: read-after-write, an enumeration
// splice (rename/delete/glob reflected in a directory listing), an unchanged
// real execroot, and - for the filtering case - declared inputs visible while
// undeclared siblings are masked NOT_FOUND.

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

// write/read/rename/delete/move, each op visible to the next through the
// overlay in a single invocation, none of it touching the real execroot.
TEST_F(OverlayTest, JavaFsMutationOps) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_FSOPS");
    if (launcher.empty())
        GTEST_SKIP() << "fs_ops java_binary launcher missing (E2E_JAVA_FSOPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {launcher, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // write -> read-back through the overlay.
    EXPECT_TRUE(Contains(r.out, "READ=OVJAVA")) << "read-after-write failed:\n" << r.out;
    // rename a.txt -> b.txt: listing shows b.txt and no longer a.txt.
    EXPECT_TRUE(Contains(r.out, "AFTERRENAME=b.txt")) << "rename not reflected in listing:\n" << r.out;
    // create + delete c.txt: listing no longer contains c.txt.
    EXPECT_FALSE(Contains(r.out, "AFTERDELETE=b.txt,c.txt")) << "delete not reflected in listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERDELETE=b.txt")) << "delete removed too much:\n" << r.out;
    // move b.txt into sub/ then read it back at its new path.
    EXPECT_TRUE(Contains(r.out, "MOVED=OVJAVA")) << "move + read-back failed:\n" << r.out;

    // The whole wd/ tree lived only in the overlay: the real execroot is empty.
    EXPECT_TRUE(Snapshot(ws).empty()) << "java writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Enumeration is the overlay's hardest area: a single directory listing must
// splice overlay-only entries into a directory that already has real on-disk
// entries (without duplicates), reflect the removal of an overlay-created
// entry, and honor glob filters over the merged set - all without disturbing
// the immutable real execroot. (Deleting/renaming a REAL visible file is denied
// by design - see docs/design/detours-write-overlay-vfs.md §6.3.1 - so this
// exercises the merge, not a mutation of real entries.)
TEST_F(OverlayTest, JavaEnumerationSplice) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_ENUMOPS");
    if (launcher.empty())
        GTEST_SKIP() << "enum_ops java_binary launcher missing (E2E_JAVA_ENUMOPS)";

    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files (allowed in-cone reads). The
    // sandboxed program splices overlay-only entries alongside these.
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlay(ws, {launcher, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Baseline: both seeded real entries enumerate through the passthrough.
    EXPECT_TRUE(Contains(r.out, "LIST1=realA.txt,realB.txt")) << "real passthrough enumeration failed:\n" << r.out;
    // Merged view: overlay-only file + subdir spliced in alongside the reals,
    // with the deleted overlay entry (ovY.txt) gone. Lexicographic sort:
    // uppercase 'X' < lowercase 's', so ovX.txt < ovsub, then the real* entries.
    EXPECT_TRUE(Contains(r.out, "LIST2=ovX.txt,ovsub,realA.txt,realB.txt")) << "enumeration splice failed:\n" << r.out;
    // Glob enumeration resolves against the merged set: "ov*" finds only the
    // overlay entries, "real*" only the real ones.
    EXPECT_TRUE(Contains(r.out, "GLOBOV=ovX.txt,ovsub")) << "glob missed overlay entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBREAL=realA.txt,realB.txt")) << "glob missed real entries:\n" << r.out;
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

// Input-filtering (the mode Bazel uses in production): only declared -r inputs
// are visible. Driven through the JVM's own APIs - Files.list for enumeration
// and Files.readString for reads - the declared input is fully visible while
// the undeclared sibling is masked NOT_FOUND (readString throws
// NoSuchFileException, and it never appears in the listing).
TEST_F(OverlayTest, JavaFilterInputsHidesUndeclared) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_FILTEROPS");
    if (launcher.empty())
        GTEST_SKIP() << "filter_ops java_binary launcher missing (E2E_JAVA_FILTEROPS)";

    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(Join(ws, L"secret.txt"), "TOP-SECRET");

    auto r = RunFiltered(ws, {decl}, {launcher, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Enumeration: declared input present, undeclared sibling hidden.
    EXPECT_TRUE(Contains(r.out, "decl.txt")) << "declared input missing from listing:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "secret.txt")) << "undeclared file leaked into listing:\n" << r.out;
    // Reads: declared input readable; undeclared sibling masked NOT_FOUND.
    EXPECT_TRUE(Contains(r.out, "READDECL=DECLARED-VISIBLE")) << "declared input not readable:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READSECRET=ERR:NotFound")) << "undeclared read not masked NOT_FOUND:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "TOP-SECRET")) << "undeclared content leaked:\n" << r.out;
}

}  // namespace
}  // namespace bsxe2e
