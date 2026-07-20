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

}  // namespace
}  // namespace bsxe2e
