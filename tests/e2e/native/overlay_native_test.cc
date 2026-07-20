// Write-overlay VFS end-to-end tests against native Windows built-ins.
//
// No tool is fetched: these tests drive Windows' own always-present programs -
// cmd.exe's internal commands (mkdir/ren/del/move/rmdir/dir/type/mklink) and
// the in-box xcopy.exe - so unlike the other e2e modules there is nothing to
// download and nothing to skip. cmd.exe is only the op sequencer (resolved by
// the harness from the OS system directory); the commands it runs are the tools
// under test. Every path is backslash-native (the cmd/xcopy convention).
//
// Each test runs a single "BazelSandbox --write-overlay -W <ws> -- cmd /c <bat>"
// invocation (the overlay backing store is per invocation, so a write and its
// read-back must share one) and asserts: (1) read-after-write, (2) an
// enumeration splice (via `dir`), and (3) an unchanged real execroot. Structural
// checks use `if exist ... (echo OK) else (echo FAIL)` so a mutation's effect is
// probed through the overlay rather than parsed out of multi-line `dir` output.

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

// write/read/delete/rmdir sequenced in one cmd invocation, each op visible to
// the next through the overlay, none of it touching the real execroot. Rename/
// move are covered separately by NativeCmdRenameMoveOverlay below.
TEST_F(OverlayTest, NativeCmdFsMutationOps) {
    auto ws = NewWorkspace();
    auto wd = Join(ws, L"wd");
    auto a = Join(wd, L"a.txt");
    auto c = Join(wd, L"c.txt");
    auto scratch = Join(wd, L"scratchd");

    auto r = RunOverlayBat(ws, {
        L"mkdir " + Q(wd),
        // write + read-back (no space before '>' so no trailing space is written)
        L"echo OVOPS>" + Q(a),
        L"type " + Q(a),
        // create + delete c.txt; it must no longer exist
        L"echo TMP>" + Q(c),
        L"del " + Q(c),
        L"if exist " + Q(c) + L" (echo DELFAIL) else (echo DELOK)",
        // mkdir + rmdir round-trip (RemoveDirectory redirect in the overlay)
        L"mkdir " + Q(scratch),
        L"rmdir " + Q(scratch),
        L"if exist " + Q(scratch) + L" (echo RMFAIL) else (echo RMDIROK)",
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OVOPS")) << "read-after-write failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "DELOK")) << "delete not reflected through the overlay:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "DELFAIL")) << r.out;
    EXPECT_TRUE(Contains(r.out, "RMDIROK")) << "rmdir not reflected through the overlay:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "RMFAIL")) << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "cmd writes leaked onto the real execroot";
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
}

// cmd's `ren` and `move` of an overlay-created file/dir. cmd renames via the
// handle-based FileRenameInformation path (open the source handle, then
// SetFileInformationByHandle/NtSetInformationFile naming the destination), NOT
// the path-based MoveFileEx hook. That handle path now redirects the rename
// DESTINATION name into the backing store (HandleFileRenameInformation /
// RenameUsingSetFileInformationByHandle), so the whole move stays in the overlay:
// it reads back through the merged view and never leaks onto the real execroot.
// Previously the destination was left as the virtual path and leaked onto disk.
TEST_F(OverlayTest, NativeCmdRenameMoveOverlay) {
    auto ws = NewWorkspace();
    auto wd = Join(ws, L"wd");
    auto a = Join(wd, L"a.txt");
    auto b = Join(wd, L"b.txt");
    auto sub = Join(wd, L"sub");

    auto r = RunOverlayBat(ws, {
        L"mkdir " + Q(wd),
        L"echo OVOPS>" + Q(a),
        // rename a.txt -> b.txt (same dir), then read back through the overlay
        L"ren " + Q(a) + L" b.txt",
        L"if exist " + Q(a) + L" (echo RENFAIL) else (echo RENOK)",
        L"type " + Q(b),
        // move b.txt into an overlay-created subdir
        L"mkdir " + Q(sub),
        L"move " + Q(b) + L" " + Q(sub),
        L"if exist " + Q(b) + L" (echo MOVEFAIL) else (echo MOVEOK)",
        L"type " + Q(Join(sub, L"b.txt")),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "RENOK")) << "rename not reflected through the overlay:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "RENFAIL")) << r.out;
    EXPECT_TRUE(Contains(r.out, "MOVEOK")) << "move not reflected through the overlay:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "MOVEFAIL")) << r.out;
    EXPECT_TRUE(Contains(r.out, "OVOPS")) << "renamed/moved file did not read back:\n" << r.out;
    EXPECT_TRUE(Snapshot(ws).empty()) << "cmd rename/move leaked onto the real execroot";
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
}

// xcopy copies a real in-cone tree (a dir with a file + a subdir with a file)
// into an overlay-only destination; the copied files read back through the
// overlay and show up in `dir`, while the real execroot keeps only the source.
TEST_F(OverlayTest, NativeXcopyTreeCopy) {
    auto ws = NewWorkspace();
    // Seed a real source tree on disk (allowed in-cone reads).
    auto src = Join(ws, L"src");
    auto srcSub = Join(src, L"subdir");
    ASSERT_TRUE(CreateDirectoryW(src.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    ASSERT_TRUE(CreateDirectoryW(srcSub.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(src, L"f1.txt"), "XC1");
    WriteText(Join(srcSub, L"f2.txt"), "XC2");

    auto dest = Join(ws, L"dest");
    auto r = RunOverlayBat(ws, {
        // /E all subdirs incl. empty, /I dest is a dir, /Y no overwrite prompt
        L"xcopy /E /I /Y " + Q(src) + L" " + Q(dest) + L" >nul",
        L"dir /b " + Q(dest),
        L"type " + Q(Join(dest, L"f1.txt")),
        L"type " + Q(Join(dest, L"subdir\\f2.txt")),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "f1.txt")) << "dir did not splice the copied file:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "subdir")) << "dir did not splice the copied subdir:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "XC1")) << "top-level copy did not read back:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "XC2")) << "nested copy did not read back:\n" << r.out;

    // The real execroot keeps only the seeded source tree: src, src\f1.txt,
    // src\subdir, src\subdir\f2.txt = 4 entries; the dest tree stayed virtual.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(4u, snap.size()) << "xcopy output leaked onto the real execroot";
    EXPECT_FALSE(Exists(dest)) << "overlay copy destination leaked onto real disk";
}

// mklink /H creates a hardlink to an overlay-written target: both endpoints live
// in the backing store (same volume), the link reads back through the overlay
// and enumerates in `dir`, and neither lands on the real execroot.
TEST_F(OverlayTest, NativeHardlink) {
    auto ws = NewWorkspace();
    auto tgt = Join(ws, L"tgt.txt");
    auto lnk = Join(ws, L"lnk.txt");

    auto r = RunOverlayBat(ws, {
        L"echo OVHL>" + Q(tgt),
        L"mklink /H " + Q(lnk) + L" " + Q(tgt) + L" >nul",
        L"dir /b " + Q(ws),
        L"type " + Q(lnk),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "lnk.txt")) << "dir did not splice the hardlink:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "OVHL")) << "hardlink did not read back through the overlay:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "hardlink / target leaked onto the real execroot";
    EXPECT_FALSE(Exists(lnk)) << "overlay hardlink leaked onto real disk";
    EXPECT_FALSE(Exists(tgt)) << "overlay target leaked onto real disk";
}

// Enumeration is the overlay's hardest area: a single `dir` of one directory
// must splice overlay-only entries into a directory that already has real
// on-disk entries (without duplicates), reflect the removal of an
// overlay-created entry, and let `dir <pattern>` wildcards resolve against the
// merged set - all without disturbing the immutable real execroot. `dir` drives
// the raw FindFirstFile/FindNextFile path. (Deleting/renaming a REAL visible
// file is denied by design - see docs/design/detours-write-overlay-vfs.md
// §6.3.1 - so this exercises the merge, not a mutation of real entries.)
TEST_F(OverlayTest, NativeEnumerationSplice) {
    auto ws = NewWorkspace();
    // Seed a directory with two REAL on-disk files (allowed in-cone reads).
    auto mix = Join(ws, L"mix");
    ASSERT_TRUE(CreateDirectoryW(mix.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(mix, L"realA.txt"), "REALA");
    WriteText(Join(mix, L"realB.txt"), "REALB");

    auto r = RunOverlayBat(ws, {
        // splice overlay-only entries (files + a subdir) into the SAME dir that
        // already holds the real entries
        L"echo OVXCONTENT>" + Q(Join(mix, L"ovX.txt")),
        L"echo OVYCONTENT>" + Q(Join(mix, L"ovY.txt")),
        L"mkdir " + Q(Join(mix, L"ovsub")),
        L"echo INNER>" + Q(Join(mix, L"ovsub\\inner.txt")),
        // delete one overlay-created entry: it must drop out of the merged view
        L"del " + Q(Join(mix, L"ovY.txt")),
        // merged listing (FindFirstFile/FindNextFile), then wildcard filters
        L"dir /b " + Q(mix),
        L"dir /b " + Q(Join(mix, L"ov*")),
        L"dir /b " + Q(Join(mix, L"real*")),
        // read-back through both halves of the merge
        L"type " + Q(Join(mix, L"ovX.txt")),
        L"type " + Q(Join(mix, L"realA.txt")),
    });

    EXPECT_EQ(0, r.code) << r.out;
    // Merged view: both real entries AND the surviving overlay entries appear.
    EXPECT_TRUE(Contains(r.out, "realA.txt")) << "real entry missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "realB.txt")) << "real entry missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "ovX.txt")) << "overlay file missing from merged listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "ovsub")) << "overlay subdir missing from merged listing:\n" << r.out;
    // The deleted overlay entry is gone from the merge (and never typed).
    EXPECT_FALSE(Contains(r.out, "ovY.txt")) << "deleted overlay entry still enumerated:\n" << r.out;
    // Read-back through both halves (content markers are distinct from the
    // lowercase filenames, so these match the typed bytes, not the listing).
    EXPECT_TRUE(Contains(r.out, "OVXCONTENT")) << "overlay read-back failed:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "REALA")) << "real passthrough read failed:\n" << r.out;

    // The real execroot is untouched: only the seeded mix/ dir + its two real
    // files remain (mix, mix\realA.txt, mix\realB.txt = 3); no overlay leak.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(3u, snap.size()) << "overlay entries leaked onto the real execroot";
    EXPECT_TRUE(Exists(Join(mix, L"realA.txt"))) << "seeded real file vanished";
    EXPECT_TRUE(Exists(Join(mix, L"realB.txt"))) << "seeded real file vanished";
    EXPECT_FALSE(Exists(Join(mix, L"ovX.txt"))) << "overlay create leaked to the real disk";
    EXPECT_FALSE(Exists(Join(mix, L"ovsub"))) << "overlay subdir leaked to the real disk";
}

// Input-filtering (the mode Bazel uses in production): only declared -r inputs
// are visible. Driven through cmd's own paths - `dir /b` (FindFirstFile) for
// enumeration, `type`/`if exist` for reads/probes - the declared input is fully
// visible while the undeclared sibling is masked NOT_FOUND (`if exist` reports
// it absent, and it never appears in the `dir` listing). With @echo off the
// command lines are not echoed, so only their output reaches the transcript -
// which is why the masked path never appears as a literal in the output.
TEST_F(OverlayTest, NativeFilterInputsHidesUndeclared) {
    auto ws = NewWorkspace();
    auto decl = Join(ws, L"decl.txt");
    auto secret = Join(ws, L"secret.txt");
    WriteText(decl, "DECLARED-VISIBLE");
    WriteText(secret, "TOP-SECRET");

    auto r = RunFilteredBat(ws, {decl}, {
        // Enumeration: the listing must show decl.txt but not secret.txt.
        L"dir /b " + Q(ws),
        // Read-back of the declared input.
        L"type " + Q(decl),
        // Visibility probe of the undeclared sibling (masked NOT_FOUND). `type`
        // is deliberately avoided here: its error text would echo the path.
        L"if exist " + Q(secret) + L" (echo SECRETVISIBLE) else (echo SECRETHIDDEN)",
    });

    EXPECT_EQ(0, r.code) << r.out;
    // Declared input: name in the listing, content via type.
    EXPECT_TRUE(Contains(r.out, "decl.txt")) << "declared input missing from listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "DECLARED-VISIBLE")) << "declared input not readable:\n" << r.out;
    // Undeclared sibling: absent from the listing and probed as not-existing.
    EXPECT_FALSE(Contains(r.out, "secret.txt")) << "undeclared file leaked into listing:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, "SECRETHIDDEN")) << "undeclared file was visible to `if exist`:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "SECRETVISIBLE")) << r.out;
    EXPECT_FALSE(Contains(r.out, "TOP-SECRET")) << "undeclared content leaked:\n" << r.out;
}

}  // namespace
}  // namespace bsxe2e
