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

// Quotes a path for a command line built by hand (the raw java/javac cases).
std::wstring Q(const std::wstring& s) { return L"\"" + s + L"\""; }

// Runs a command line to completion OUTSIDE the sandbox (used to seed a real,
// in-cone compiled .class before the sandboxed java run). Returns the child
// exit code, or -1 if the process could not be started.
int RunLocalWait(const std::wstring& cmdline) {
    std::wstring mut = cmdline;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(code);
}

// java loads a class from an in-cone `-cp` entry: javac compiles T.class OUTSIDE
// the sandbox (a real in-cone input), then `java -cp <ws> T` runs UNDER the
// overlay and must resolve + read that real .class through the classpath. This
// guards the classpath-canonicalization path: an in-place classpath dir must
// canonicalize to the real file, not a masked one).
TEST_F(OverlayTest, JavaClasspathLoadInCone) {
    std::wstring java = OverlayTest::ToolFromEnv("E2E_JAVA_JAVA");
    std::wstring javac = OverlayTest::ToolFromEnv("E2E_JAVA_JAVAC");
    if (java.empty()) GTEST_SKIP() << "hermetic java missing (E2E_JAVA_JAVA)";
    if (javac.empty()) GTEST_SKIP() << "hermetic javac missing (E2E_JAVA_JAVAC)";

    auto ws = NewWorkspace();
    auto src = Join(ws, L"T.java");
    WriteText(src, "public class T { public static void main(String[] a){ System.out.println(\"T-OK\"); } }");

    // Seed T.class as a REAL in-cone input (compiled outside the sandbox).
    int seed = RunLocalWait(Q(javac) + L" -d " + Q(ws) + L" " + Q(src));
    ASSERT_EQ(0, seed) << "seed javac failed";
    ASSERT_TRUE(Exists(Join(ws, L"T.class"))) << "seed did not produce a real T.class";

    // Load the real class through an in-cone -cp entry, under the overlay.
    auto r = RunOverlay(ws, {java, L"-cp", ws, L"T"});
    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "T-OK")) << "class not loaded from in-cone classpath:\n" << r.out;

    // The real execroot keeps only the two seeded inputs; java wrote nothing.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(2u, snap.size()) << "java run leaked onto the real execroot";
}

// javac compiles INTO the overlay, then java runs the result - both in one
// invocation (the overlay backing store is per invocation). javac writes
// U.class into the overlay; `java -cp <ws> U` reads it back through the
// classpath and prints U-OK. The compiled class must never touch the real
// execroot.
TEST_F(OverlayTest, JavacCompileIntoOverlay) {
    std::wstring java = OverlayTest::ToolFromEnv("E2E_JAVA_JAVA");
    std::wstring javac = OverlayTest::ToolFromEnv("E2E_JAVA_JAVAC");
    if (java.empty()) GTEST_SKIP() << "hermetic java missing (E2E_JAVA_JAVA)";
    if (javac.empty()) GTEST_SKIP() << "hermetic javac missing (E2E_JAVA_JAVAC)";

    auto ws = NewWorkspace();
    auto src = Join(ws, L"U.java");
    WriteText(src, "public class U { public static void main(String[] a){ System.out.println(\"U-OK\"); } }");

    // Compile into the overlay, then run - one invocation, shared backing store.
    auto r = RunOverlayBat(ws, {
        Q(javac) + L" -d " + Q(ws) + L" " + Q(src) +
            L" && " + Q(java) + L" -cp " + Q(ws) + L" U",
    });

    EXPECT_TRUE(Contains(r.out, "U-OK")) << "javac->java through the overlay failed:\n" << r.out;

    // The real execroot keeps only U.java; U.class lived only in the overlay.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "javac output leaked onto the real execroot";
    EXPECT_EQ(L"U.java", snap[0]);
    EXPECT_FALSE(Exists(Join(ws, L"U.class"))) << "overlay .class leaked onto real disk";
}

// COMBINED --filter-inputs --write-overlay: a Java tool output whose name collides
// with a HIDDEN undeclared input (seeded real secret.txt, NO -r). Every op lands
// in the overlay and leaves the real file unchanged; deleting or renaming away the
// overlay copy must NOT re-reveal the masked real input (SRCAFTER/AFTERDEL
// NotFound). Files.move/Files.delete take the path-based MoveFileEx/DeleteFile hooks.
TEST_F(OverlayTest, JavaFilterOverlayMutations) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_FILTEROVERLAYOPS");
    if (launcher.empty())
        GTEST_SKIP() << "filter_overlay_ops java_binary launcher missing (E2E_JAVA_FILTEROVERLAYOPS)";

    auto seed = [&](const wchar_t* op) {
        auto ws = NewWorkspace();
        WriteText(Join(ws, L"secret.txt"), "REAL-SECRET");
        auto r = RunFilteredOverlay(ws, /*declared*/ {}, {launcher, ws, op});
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

// The rules_go GoStdlib regression, through Java's ProcessBuilder (the Python/
// Node/.NET analogue of GoSpawnOverlayOnlyCwd). spawn_ops launches itself with a
// working directory that exists only in the overlay backing store (CreateProcessW
// lpCurrentDirectory, no preceding SetCurrentDirectory). Without the working-
// directory overlay redirect the child cannot launch (ERROR_DIRECTORY 267); with
// it the child launches from the concrete backing dir, writes its output into
// the overlay, and the parent reads it back. Real execroot untouched.
TEST_F(OverlayTest, JavaSpawnOverlayOnlyCwd) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_SPAWNOPS");
    if (launcher.empty())
        GTEST_SKIP() << "spawn_ops java_binary launcher missing (E2E_JAVA_SPAWNOPS)";

    auto ws = NewWorkspace();
    // The child re-enters the same launcher; pass its path so ProcessBuilder can
    // re-launch it with the overlay-only working directory.
    auto r = RunOverlay(ws, {launcher, L"spawncwd", ws, launcher});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "SPAWN=CHILD=OK")) << "child failed to launch from overlay-only cwd:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "SPAWN=ERR:")) << "child launch errored:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READBACK=CHILDWROTE")) << "child write not visible in overlay:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "spawn writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"spawndir"))) << "overlay cwd leaked onto real disk";
}

// Declared outputs (-w) under --write-overlay write THROUGH to the real execroot
// (how Bazel collects an action's declared outputs), while an undeclared sibling
// write is redirected into the process-private overlay. Driven through
// java.nio.file.Files.writeString (CreateFileW): both files read back in-process,
// but on the real disk only the declared output appears - the sibling does not.
TEST_F(OverlayTest, JavaDeclaredOutputWritesThrough) {
    std::wstring launcher = OverlayTest::ToolFromEnv("E2E_JAVA_WRITEOUTOPS");
    if (launcher.empty())
        GTEST_SKIP() << "writeout_ops java_binary launcher missing (E2E_JAVA_WRITEOUTOPS)";

    auto ws = NewWorkspace();
    auto out = Join(ws, L"out.txt");
    auto sib = Join(ws, L"sibling.txt");

    auto r = RunOverlayWithWritable(ws, {out}, {launcher, out, sib});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OUT=DECLARED-OUT")) << "declared output not readable in-process:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "SIB=UNDECLARED-SIB")) << "sibling not readable through the overlay:\n" << r.out;

    EXPECT_TRUE(Exists(out)) << "declared -w output did not reach the real execroot";
    EXPECT_EQ("DECLARED-OUT", ReadText(out));
    EXPECT_FALSE(Exists(sib)) << "undeclared write leaked onto the real execroot";
    EXPECT_EQ(1u, Snapshot(ws).size()) << "unexpected entries on the real execroot (only the -w output should be there)";
}

}  // namespace
}  // namespace bsxe2e
