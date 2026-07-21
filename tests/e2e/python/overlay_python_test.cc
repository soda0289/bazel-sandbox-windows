// Write-overlay VFS end-to-end tests against a hermetic CPython.
//
// The Python each test runs lives in real .py files under scripts/ (carried as
// cc_test data, resolved from runfiles via env vars) rather than inline in this
// TU, so the scripts are lintable, editable, and reusable.
//
//   PythonFsMutationOps       scripts/fs_ops.py   - write/read/rename/move/
//                             delete, each op visible to the next.
//   PythonEnumerationSplice   scripts/enum_ops.py - splice overlay-only entries
//                             into a directory of real files, via os.scandir.
//
// Listings deliberately go through os.scandir (CPython's readdir loop ->
// FindFirstFile/FindNextFile), the overlay's historical enumeration trouble spot
// (a stale last-error / WinError 203). Every
// test asserts the three overlay invariants: read-after-write, an enumeration
// splice, and an unchanged real execroot (skips if its tool/data env var is
// missing).

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

std::wstring PythonExe() { return OverlayTest::ToolFromEnv("E2E_PYTHON"); }

// Resolves a .py script carried as cc_test data from its runfiles env var.
std::wstring Script(const char* envName) { return OverlayTest::ToolFromEnv(envName); }

// write/read/rename/delete/move, each op visible to the next through the
// overlay in a single invocation, none of it touching the real execroot.
TEST_F(OverlayTest, PythonFsMutationOps) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_FSOPS");
    if (script.empty()) GTEST_SKIP() << "fs_ops.py missing (E2E_PY_FSOPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {py, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // write -> read-back through the overlay.
    EXPECT_TRUE(Contains(r.out, "READ=OVOPS")) << "read-after-write failed:\n" << r.out;
    // rename a.txt -> b.txt: listing shows b.txt and no longer a.txt.
    EXPECT_TRUE(Contains(r.out, "AFTERRENAME=b.txt")) << "rename not reflected in listing:\n" << r.out;
    // create + delete c.txt: listing no longer contains c.txt.
    EXPECT_FALSE(Contains(r.out, "AFTERDELETE=b.txt,c.txt")) << "delete not reflected in listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "AFTERDELETE=b.txt")) << "delete removed too much:\n" << r.out;
    // move b.txt into sub/ then read it back at its new path.
    EXPECT_TRUE(Contains(r.out, "MOVED=OVOPS")) << "move + read-back failed:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "python writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Enumeration is the overlay's hardest area: a single os.scandir of one
// directory must splice overlay-only entries into a directory that already has
// real on-disk entries (without duplicates), reflect the removal of an
// overlay-created entry, and let prefix filters resolve against the merged set -
// all without disturbing the immutable real execroot. (Deleting/renaming a REAL
// visible file is denied by design - see docs/design/detours-write-overlay-vfs.md
// §6.3.1 - so this exercises the merge, not a mutation of real entries.)
TEST_F(OverlayTest, PythonEnumerationSplice) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_ENUMOPS");
    if (script.empty()) GTEST_SKIP() << "enum_ops.py missing (E2E_PY_ENUMOPS)";

    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files (allowed in-cone reads). The
    // sandboxed script splices overlay-only entries alongside these.
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlay(ws, {py, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Baseline: both seeded real entries enumerate through the passthrough.
    EXPECT_TRUE(Contains(r.out, "LIST1=realA.txt,realB.txt")) << "real passthrough enumeration failed:\n" << r.out;
    // Merged view: overlay-only file + subdir spliced in alongside the reals,
    // with the deleted overlay entry (ovY.txt) gone. Sort is by code point:
    // uppercase 'X' < lowercase 's', so ovX.txt < ovsub, then real*.
    EXPECT_TRUE(Contains(r.out, "LIST2=ovX.txt,ovsub,realA.txt,realB.txt")) << "enumeration splice failed:\n" << r.out;
    // Prefix filters resolve against the merged set: "ov" only the overlay
    // entries, "real" only the real ones.
    EXPECT_TRUE(Contains(r.out, "GLOBOV=ovX.txt,ovsub")) << "filter missed overlay entries:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "GLOBREAL=realA.txt,realB.txt")) << "filter missed real entries:\n" << r.out;
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

// shutil.copy (the stdlib file-copy tool) copies a real
// in-cone input into an overlay directory; the copy reads back through open()
// (overlay read-after-write) and appears in os.scandir (enumeration splice),
// while nothing lands on the real execroot.
TEST_F(OverlayTest, PythonShutilCopyOverlay) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_COPYOPS");
    if (script.empty()) GTEST_SKIP() << "copy_ops.py missing (E2E_PY_COPYOPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {py, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "READ=OVPYCOPY")) << "shutil.copy read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "LIST=out.txt")) << "copied file missing from listing:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "python copy leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Input-filtering (the mode Bazel uses in production): only declared -r inputs
// are visible. Driven through CPython's own APIs - os.scandir for enumeration
// and open() for reads - the declared input is fully visible while the
// undeclared sibling is masked NOT_FOUND (open raises FileNotFoundError, and it
// never appears in the scandir listing).
TEST_F(OverlayTest, PythonFilterInputsHidesUndeclared) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_FILTEROPS");
    if (script.empty()) GTEST_SKIP() << "filter_ops.py missing (E2E_PY_FILTEROPS)";

    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(Join(ws, L"secret.txt"), "TOP-SECRET");

    auto r = RunFiltered(ws, {decl}, {py, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    // Enumeration: declared input present, undeclared sibling hidden.
    EXPECT_TRUE(Contains(r.out, "decl.txt")) << "declared input missing from scandir:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "secret.txt")) << "undeclared file leaked into scandir:\n" << r.out;
    // Reads: declared input readable; undeclared sibling masked NOT_FOUND.
    EXPECT_TRUE(Contains(r.out, "READDECL=DECLARED-VISIBLE")) << "declared input not readable:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READSECRET=ERR:NotFound")) << "undeclared read not masked NOT_FOUND:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "TOP-SECRET")) << "undeclared content leaked:\n" << r.out;
}

// COMBINED --filter-inputs --write-overlay: a Python tool output whose name
// collides with a HIDDEN undeclared input (masked, seeded real secret.txt, NO -r).
// Every op must land in the overlay and leave the real file byte-for-byte
// unchanged; crucially, deleting or renaming away the overlay copy must NOT
// re-reveal the masked real input (the SRCAFTER/AFTERDEL read must be NOT_FOUND).
// Python's os.replace/os.remove take the path-based MoveFileEx/DeleteFile hooks,
// complementing the native module's handle-based ren/move coverage.
TEST_F(OverlayTest, PythonFilterOverlayMutations) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_FILTEROVERLAYOPS");
    if (script.empty()) GTEST_SKIP() << "filter_overlay_ops.py missing (E2E_PY_FILTEROVERLAYOPS)";

    // Each op runs in a fresh workspace with a freshly seeded HIDDEN real input.
    auto seed = [&](const wchar_t* op) {
        auto ws = NewWorkspace();
        WriteText(Join(ws, L"secret.txt"), "REAL-SECRET");
        auto r = RunFilteredOverlay(ws, /*declared*/ {}, {py, script, ws, op});
        EXPECT_EQ(0, r.code) << op << ":\n" << r.out;
        EXPECT_EQ("REAL-SECRET", ReadText(Join(ws, L"secret.txt")))
            << op << ": real undeclared input was mutated";
        return std::make_pair(ws, r.out);
    };

    // create over hidden -> overlay (not ACCESS_DENIED); real untouched.
    {
        auto [ws, out] = seed(L"create");
        EXPECT_TRUE(Contains(out, "CREATE=OVERLAY-NEW")) << "create over hidden failed:\n" << out;
    }
    // rename ONTO hidden (path-based MoveFileEx dest redirect).
    {
        auto [ws, out] = seed(L"renameonto");
        EXPECT_TRUE(Contains(out, "RENAMEONTO=OVERLAY-ONTO")) << "rename onto hidden failed:\n" << out;
        EXPECT_FALSE(Exists(Join(ws, L"tmp.txt"))) << "overlay source leaked to real disk";
    }
    // create then rename AWAY: dest gets the bytes; the source name re-masks to
    // NOT_FOUND (leak guard), never re-revealing REAL-SECRET.
    {
        auto [ws, out] = seed(L"renameaway");
        EXPECT_TRUE(Contains(out, "RENAMEAWAY=OVERLAY-AWAY")) << "rename away failed:\n" << out;
        EXPECT_TRUE(Contains(out, "SRCAFTER=ERR:NotFound")) << "source re-revealed after rename away:\n" << out;
        EXPECT_FALSE(Contains(out, "SRCAFTER=REAL-SECRET")) << "masked real input leaked:\n" << out;
        EXPECT_FALSE(Exists(Join(ws, L"moved.txt"))) << "overlay dest leaked to real disk";
    }
    // create then delete: the name re-masks to NOT_FOUND (leak guard).
    {
        auto [ws, out] = seed(L"delete");
        EXPECT_TRUE(Contains(out, "AFTERDEL=ERR:NotFound")) << "name re-revealed after delete:\n" << out;
        EXPECT_FALSE(Contains(out, "AFTERDEL=REAL-SECRET")) << "masked real input leaked:\n" << out;
    }
    // bare delete of the hidden name (no overlay copy) is a NOT_FOUND no-op.
    {
        auto [ws, out] = seed(L"deletebare");
        EXPECT_TRUE(Contains(out, "DELETEBARE=ERR:NotFound")) << "bare delete not a NOT_FOUND no-op:\n" << out;
        EXPECT_TRUE(Exists(Join(ws, L"secret.txt"))) << "undeclared input vanished";
    }
    // bare rename of the hidden name away (no overlay copy) is a NOT_FOUND no-op.
    {
        auto [ws, out] = seed(L"renamefrombare");
        EXPECT_TRUE(Contains(out, "RENAMEFROMBARE=ERR:NotFound")) << "bare rename not a NOT_FOUND no-op:\n" << out;
        EXPECT_TRUE(Exists(Join(ws, L"secret.txt"))) << "undeclared input vanished";
        EXPECT_FALSE(Exists(Join(ws, L"moved.txt"))) << "bare rename produced a real dest";
    }
}

// The rules_go GoStdlib regression, through CPython's subprocess (the .NET/Java/
// Node analogue of GoSpawnOverlayOnlyCwd). spawn_ops.py creates an overlay-only
// directory and subprocess-spawns itself with cwd= set to it (CreateProcessW
// lpCurrentDirectory, no preceding SetCurrentDirectory). Without the working-
// directory overlay redirect the child cannot launch (ERROR_DIRECTORY 267);
// with it the child launches from the concrete backing dir, writes its output
// into the overlay, and the parent reads it back. Real execroot untouched.
TEST_F(OverlayTest, PythonSpawnOverlayOnlyCwd) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_SPAWNOPS");
    if (script.empty()) GTEST_SKIP() << "spawn_ops.py missing (E2E_PY_SPAWNOPS)";

    auto ws = NewWorkspace();
    auto r = RunOverlay(ws, {py, script, ws});

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "SPAWN=CHILD=OK")) << "child failed to launch from overlay-only cwd:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "SPAWN=ERR:")) << "child launch errored:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "READBACK=CHILDWROTE")) << "child write not visible in overlay:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "spawn writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(Join(ws, L"spawndir"))) << "overlay cwd leaked onto real disk";
}

// Declared outputs (-w) under --write-overlay write THROUGH to the real execroot
// (how Bazel collects an action's declared outputs), while an undeclared sibling
// write is redirected into the process-private overlay. Driven through CPython's
// open()/write (CreateFileW): both files read back in-process, but on the real
// disk only the declared output appears - the undeclared sibling does not.
TEST_F(OverlayTest, PythonDeclaredOutputWritesThrough) {
    std::wstring py = PythonExe();
    if (py.empty()) GTEST_SKIP() << "python missing from runfiles (E2E_PYTHON)";
    std::wstring script = Script("E2E_PY_WRITEOUTOPS");
    if (script.empty()) GTEST_SKIP() << "writeout_ops.py missing (E2E_PY_WRITEOUTOPS)";

    auto ws = NewWorkspace();
    auto out = Join(ws, L"out.txt");
    auto sib = Join(ws, L"sibling.txt");

    auto r = RunOverlayWithWritable(ws, {out}, {py, script, out, sib});

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