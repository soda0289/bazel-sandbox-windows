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

#include <algorithm>
#include <filesystem>
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

// Resolves an always-present in-box tool from the OS system directory (env-
// independent). Empty if the file is absent (older Windows without it).
std::wstring SysTool(const wchar_t* name) {
    wchar_t sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return std::wstring();
    std::wstring p = (std::filesystem::path(sysdir) / name).make_preferred().wstring();
    return OverlayTest::Exists(p) ? p : std::wstring();
}

// Windows PowerShell 5.1 (always present) lives under System32\WindowsPowerShell.
std::wstring WindowsPowerShell() {
    return SysTool(L"WindowsPowerShell\\v1.0\\powershell.exe");
}

// PowerShell 7 (pwsh.exe) via PATH; empty if it is not installed (skip then).
std::wstring Pwsh7() {
    wchar_t buf[MAX_PATH];
    DWORD n = SearchPathW(nullptr, L"pwsh.exe", nullptr, MAX_PATH, buf, nullptr);
    if (n == 0 || n >= MAX_PATH) return std::wstring();
    return std::wstring(buf, n);
}

// The gci/Copy-Item body shared by Windows PowerShell 5.1 and pwsh 7: create a
// dir, write in.txt, list it (LIST=), Copy-Item to out.txt (which goes through
// .NET File.Copy -> CopyFileEx, the kernel-copy path the overlay must intercept),
// then read the copy back (READ=). Written ConstrainedLanguage-safe (cmdlets +
// primitive operators only). ws uses backslashes; inside single quotes those are
// literal.
std::wstring PsBody(const std::wstring& ws, const std::wstring& mark) {
    return L"$d = Join-Path '" + ws + L"' 'wd'\n"
           L"New-Item -ItemType Directory -Force $d | Out-Null\n"
           L"Set-Content -LiteralPath (Join-Path $d 'in.txt') -Value '" + mark + L"'\n"
           L"'LIST=' + ((Get-ChildItem $d).Name -join ',')\n"
           L"Copy-Item -LiteralPath (Join-Path $d 'in.txt') -Destination (Join-Path $d 'out.txt')\n"
           L"'READ=' + (Get-Content -Raw -LiteralPath (Join-Path $d 'out.txt'))\n";
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

// cmd's single-file `copy` (CopyFileW under the hood) into an overlay dest, then
// `findstr` reads the copy back through the overlay. This covers the CopyFile
// family separately from the `xcopy` tree case: the kernel copy opens the source
// and writes the destination itself, so the overlay must intercept those opens
// and redirect the write into the backing store (a leak would land out.txt on
// the real execroot). `findstr` proves the copied bytes read back through the
// overlay.
TEST_F(OverlayTest, NativeCmdCopySingleFileAndFindstr) {
    std::wstring findstr = SysTool(L"findstr.exe");
    if (findstr.empty()) GTEST_SKIP() << "findstr.exe not present";

    auto ws = NewWorkspace();
    auto wd = Join(ws, L"wd");
    auto in = Join(wd, L"in.txt");
    auto out = Join(wd, L"out.txt");

    auto r = RunOverlayBat(ws, {
        L"mkdir " + Q(wd),
        L"echo OVCOPY>" + Q(in),
        L"copy /y " + Q(in) + L" " + Q(out) + L" >nul",
        L"type " + Q(out),
        Q(findstr) + L" OVCOPY " + Q(out),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OVCOPY")) << "single-file copy did not read back:\n" << r.out;

    EXPECT_TRUE(Snapshot(ws).empty()) << "cmd copy leaked onto the real execroot";
    EXPECT_FALSE(Exists(wd)) << "overlay directory leaked onto real disk";
}

// In-box `tar.exe` (bsdtar/libarchive): create an archive from a real in-cone
// source tree, then extract it into an overlay-only dir and read a file back.
// The archive (a.tar) and the extracted tree are overlay writes; the source is a
// real allowed input. tar's bulk read + write + its mtime-preserving
// SetFileInformationByHandle(FileBasicInformation) metadata path all stay in the
// backing store. Always present on modern Windows; skipped otherwise.
TEST_F(OverlayTest, NativeTarCreateExtract) {
    std::wstring tar = SysTool(L"tar.exe");
    if (tar.empty()) GTEST_SKIP() << "tar.exe not present";

    auto ws = NewWorkspace();
    // Real in-cone source tree (allowed reads).
    auto src = Join(ws, L"src");
    ASSERT_TRUE(CreateDirectoryW(src.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    WriteText(Join(src, L"hello.txt"), "OVTAR");

    auto arc = Join(ws, L"a.tar");
    auto ext = Join(ws, L"ext");
    auto r = RunOverlayBat(ws, {
        Q(tar) + L" -cf " + Q(arc) + L" -C " + Q(ws) + L" src",
        L"mkdir " + Q(ext),
        Q(tar) + L" -xf " + Q(arc) + L" -C " + Q(ext),
        L"type " + Q(Join(ext, L"src\\hello.txt")),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OVTAR")) << "tar extract did not read back through the overlay:\n" << r.out;

    // The real execroot keeps only the seeded source tree: src, src\hello.txt.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(2u, snap.size()) << "tar output leaked onto the real execroot";
    EXPECT_FALSE(Exists(arc)) << "overlay archive leaked onto real disk";
    EXPECT_FALSE(Exists(ext)) << "overlay extract dir leaked onto real disk";
}

// In-box `curl.exe`: fetch a real in-cone file via a file:// URL and write the
// result into the overlay, then read it back. curl reads the source through
// WinHTTP/file scheme (CreateFile on the real input) and writes the output into
// the backing store; the output must not leak onto the real execroot.
TEST_F(OverlayTest, NativeCurlFileUrl) {
    std::wstring curl = SysTool(L"curl.exe");
    if (curl.empty()) GTEST_SKIP() << "curl.exe not present";

    auto ws = NewWorkspace();
    auto srcfile = Join(ws, L"srcfile.txt");
    WriteText(srcfile, "OVCURL");

    // file:///C:/.../srcfile.txt (forward slashes).
    std::wstring fwd = srcfile;
    std::replace(fwd.begin(), fwd.end(), L'\\', L'/');
    std::wstring url = L"file:///" + fwd;
    auto got = Join(ws, L"got.txt");

    auto r = RunOverlayBat(ws, {
        Q(curl) + L" -s -o " + Q(got) + L" " + Q(url),
        L"type " + Q(got),
    });

    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "OVCURL")) << "curl output did not read back through the overlay:\n" << r.out;

    // The real execroot keeps only the seeded source file.
    std::vector<std::wstring> snap = Snapshot(ws);
    ASSERT_EQ(1u, snap.size()) << "curl output leaked onto the real execroot";
    EXPECT_EQ(L"srcfile.txt", snap[0]);
    EXPECT_FALSE(Exists(got)) << "overlay curl output leaked onto real disk";
}

// Runs the shared gci/Copy-Item PowerShell body under the overlay and asserts
// the listing + copy read-back, with no real-execroot leak. Copy-Item goes
// through .NET File.Copy (CopyFileEx), so this validates the kernel-copy
// interception from a PowerShell caller.
static void RunPowerShellCopyCase(OverlayTest& t, const std::wstring& ws,
                                  const std::wstring& shell, const std::wstring& mark) {
    auto r = t.RunOverlay(ws, {shell, L"-NoProfile", L"-NonInteractive", L"-Command",
                               PsBody(ws, mark)});
    std::string want = "READ=" + std::string(mark.begin(), mark.end());
    EXPECT_EQ(0, r.code) << r.out;
    EXPECT_TRUE(Contains(r.out, "in.txt")) << "Get-ChildItem did not splice overlay file:\n" << r.out;
    EXPECT_TRUE(Contains(r.out, want.c_str())) << "Copy-Item read-back failed:\n" << r.out;
    EXPECT_TRUE(OverlayTest::Snapshot(ws).empty()) << "PowerShell writes leaked onto the real execroot";
    EXPECT_FALSE(OverlayTest::Exists(OverlayTest::Join(ws, L"wd"))) << "overlay directory leaked onto real disk";
}

// Windows PowerShell 5.1 (always present in System32) - the .NET Framework host.
TEST_F(OverlayTest, NativeWindowsPowerShellCopyItem) {
    std::wstring wps = WindowsPowerShell();
    if (wps.empty()) GTEST_SKIP() << "Windows PowerShell 5.1 not present";
    RunPowerShellCopyCase(*this, NewWorkspace(), wps, L"OVWPS");
}

// PowerShell 7 (pwsh.exe) - the .NET (Core) host; non-hermetic, skipped if absent.
TEST_F(OverlayTest, NativePwsh7CopyItem) {
    std::wstring pwsh = Pwsh7();
    if (pwsh.empty()) GTEST_SKIP() << "pwsh (PowerShell 7) not on PATH";
    RunPowerShellCopyCase(*this, NewWorkspace(), pwsh, L"OVPWSH");
}

// ---------------------------------------------------------------------------
// Combined --filter-inputs --write-overlay: a tool output name colliding with an
// UNDECLARED (masked) real input. The real `secret.txt` is seeded on disk but
// never declared with -r, so it is masked NOT_FOUND. Every case must leave that
// real file byte-for-byte unchanged. cmd is the richest driver here: its `ren`
// takes the handle-based FileRenameInformation path while `move` takes the
// path-based MoveFileEx path, so both destination-redirect hooks get covered.
// ---------------------------------------------------------------------------

// create over the hidden name -> lands in the overlay, reads back, and does NOT
// come back ACCESS_DENIED; the real undeclared file is untouched.
TEST_F(OverlayTest, NativeFilterOverlayCreateOverHidden) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    WriteText(secret, "REAL-SECRET");  // real, UNDECLARED (masked) input

    auto r = RunFilteredOverlayBat(ws, /*declared*/ {}, {
        L"echo OVERLAY-NEW>" + Q(secret),
        L"type " + Q(secret),
    });

    EXPECT_TRUE(Contains(r.out, "OVERLAY-NEW")) << "create over masked name failed:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "Access is denied")) << "create wrongly denied:\n" << r.out;
    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "real undeclared input was mutated";
}

// rename ONTO the hidden name (cmd `ren`, handle path): an overlay file renamed
// onto the masked name lands in the backing store; real file untouched.
TEST_F(OverlayTest, NativeFilterOverlayRenameOntoHidden) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    auto tmp = Join(ws, L"tmp.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"echo OVERLAY-MOVED>" + Q(tmp),
        L"ren " + Q(tmp) + L" secret.txt",
        L"type " + Q(secret),
    });

    EXPECT_TRUE(Contains(r.out, "OVERLAY-MOVED")) << "rename onto masked name failed:\n" << r.out;
    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "real undeclared input was mutated";
    EXPECT_FALSE(Exists(tmp)) << "overlay source leaked onto real disk";
}

// move ONTO the hidden name (cmd `move`, path-based MoveFileEx): same guarantee
// through the other rename hook.
TEST_F(OverlayTest, NativeFilterOverlayMoveOntoHidden) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    auto tmp = Join(ws, L"tmp.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"echo OVERLAY-MV>" + Q(tmp),
        L"move /y " + Q(tmp) + L" " + Q(secret) + L" >nul",
        L"type " + Q(secret),
    });

    EXPECT_TRUE(Contains(r.out, "OVERLAY-MV")) << "move onto masked name failed:\n" << r.out;
    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "real undeclared input was mutated";
    EXPECT_FALSE(Exists(tmp)) << "overlay source leaked onto real disk";
}

// create over the hidden name, THEN rename that overlay copy AWAY: the move
// operates on the backing copy (source AND dest resolve into the backing store),
// so it succeeds and the real undeclared file is untouched.
TEST_F(OverlayTest, NativeFilterOverlayCreateThenRenameAway) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    auto moved = Join(ws, L"moved.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"echo OVERLAY-AWAY>" + Q(secret),
        L"ren " + Q(secret) + L" moved.txt",
        L"type " + Q(moved),
    });

    EXPECT_TRUE(Contains(r.out, "OVERLAY-AWAY")) << "rename away from masked name failed:\n" << r.out;
    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "real undeclared input was mutated";
    EXPECT_FALSE(Exists(moved)) << "overlay rename dest leaked onto real disk";
}

// create over the hidden name, THEN delete that overlay copy: the delete removes
// the backing copy (RedirectToBacking) and the merged view shows the name gone,
// while the real undeclared file stays on disk untouched.
TEST_F(OverlayTest, NativeFilterOverlayCreateThenDelete) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"echo OVERLAY-DEL>" + Q(secret),
        L"del " + Q(secret),
        L"if exist " + Q(secret) + L" (echo STILL) else (echo GONE)",
    });

    EXPECT_TRUE(Contains(r.out, "GONE")) << "overlay copy not removed from merged view:\n" << r.out;
    EXPECT_FALSE(Contains(r.out, "STILL")) << "overlay copy still visible after delete:\n" << r.out;
    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "real undeclared input was deleted/mutated";
}

// SAFETY GUARD: a BARE delete of the undeclared name (no overlay copy) is a
// NOT_FOUND no-op - an undeclared input can never be destroyed. The real file
// must survive on disk.
TEST_F(OverlayTest, NativeFilterOverlayBareDeleteUndeclaredNoop) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"del " + Q(secret),
    });

    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "undeclared input was deleted via the sandbox";
    EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
}

// SAFETY GUARD: a BARE rename of the undeclared name (no overlay copy) is a
// NOT_FOUND no-op - the source reads as absent, so the move fails and neither the
// real source nor a real dest is produced.
TEST_F(OverlayTest, NativeFilterOverlayBareRenameUndeclaredNoop) {
    auto ws = NewWorkspace();
    auto secret = Join(ws, L"secret.txt");
    auto moved = Join(ws, L"moved.txt");
    WriteText(secret, "REAL-SECRET");

    auto r = RunFilteredOverlayBat(ws, {}, {
        L"ren " + Q(secret) + L" moved.txt",
    });

    EXPECT_EQ("REAL-SECRET", ReadText(secret)) << "undeclared input was renamed via the sandbox";
    EXPECT_TRUE(Exists(secret)) << "real undeclared input vanished";
    EXPECT_FALSE(Exists(moved)) << "rename produced a real dest from a masked source";
}

}  // namespace
}  // namespace bsxe2e
