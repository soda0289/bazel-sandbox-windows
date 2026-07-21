// Model W write-overlay (experimental): write/read redirection + directory-
// enumeration insertion. The overlay redirects undeclared writes in the
// execroot cone into a process-private backing store, so the real
// execroot is never mutated, yet overlay-only files still APPEAR when the tool
// lists the directory it "wrote" them into. Everything is gated by the
// --write-overlay kill-switch.
//
// gtest port of tests/enforce/overlay.ps1. Uses RunProbeRaw (no implicit -H).

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// The DLL reads BAZEL_SANDBOX_OVERLAY_TEST_NAMES once per child process; each
// sandbox invocation is a fresh child, so setting it here re-takes effect.
void SetOverlayNames(const wchar_t* v) {
    SetEnvironmentVariableW(L"BAZEL_SANDBOX_OVERLAY_TEST_NAMES", v);
}

bool StartsWithSeedData(const std::wstring& p) {
    std::string s = EnforceTest::ReadText(p);
    return s.rfind("seed-data", 0) == 0;
}

bool ContainsFileNamed(const std::wstring& dir, const std::wstring& name) {
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::path(dir), ec)) return false;
    for (auto it = std::filesystem::recursive_directory_iterator(
             std::filesystem::path(dir), ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        if (it->is_regular_file(ec) && it->path().filename().wstring() == name) return true;
    }
    return false;
}

// --- Kill-switch: no insertion unless --write-overlay is passed ---------------
TEST_F(EnforceTest, OverlayKillSwitchSyntheticEntry) {
    SetOverlayNames(L"ghost.txt");
    auto ws = NewWorkspace();
    // Flag ON: the synthetic entry appears even though no such file exists.
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"enumfindntdirect", ws, L"ghost.txt"}));
    auto ws2 = NewWorkspace();
    // Flag OFF: identical env, but the shipped path is untouched - not found.
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws2}, {L"enumfindntdirect", ws2, L"ghost.txt"}));
}

TEST_F(EnforceTest, OverlayRealEntriesPreserved) {
    SetOverlayNames(L"ghost.txt");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"enumfindntdirect", ws, L"a.txt"}));
}

// Empty result after filtering: exhaustion branch still inserts.
TEST_F(EnforceTest, OverlayEmptyAfterFilterStillInserts) {
    SetOverlayNames(L"ghost.txt");
    auto ws = NewWorkspace();
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"},
                                     {L"enumfindntdirect", ws, L"a.txt"}));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"enumfindntdirect", ws2, L"ghost.txt"}));
}

// No env var => nothing injected even with the flag on.
TEST_F(EnforceTest, OverlayNoNamesNothingInjected) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                                     {L"enumfindntdirect", ws, L"ghost.txt"}));
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"enumfindntdirect", ws, L"a.txt"}));
}

// --- Write redirection: real execroot is never mutated ------------------------
TEST_F(EnforceTest, OverlayNewFileWriteRedirected) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"write", Join(ws, L"novel.txt"), L"x"}));
    EXPECT_FALSE(Exists(Join(ws, L"novel.txt")));
}

TEST_F(EnforceTest, OverlayWriteReadBack) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeread", Join(ws, L"rw.txt")}));
    EXPECT_FALSE(Exists(Join(ws, L"rw.txt")));
}

TEST_F(EnforceTest, OverlayNoClobberPreExisting) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"write", Join(ws, L"seed.txt"), L"x"}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

TEST_F(EnforceTest, OverlayEnumMap) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeenum", ws, L"mapped.txt"}));
    EXPECT_FALSE(Exists(Join(ws, L"mapped.txt")));
}

// Cross-process enumeration: a separate child sees the parent's overlay file.
TEST_F(EnforceTest, OverlayCrossProcessEnum) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writespawnenum", ws, L"xpenum.txt", ProbePath()}));
    EXPECT_FALSE(Exists(Join(ws, L"xpenum.txt")));
}

// Working directory that exists only in the overlay: a child can be launched with its
// cwd set to an overlay-only scratch dir (rules_go GoStdlib builder pattern). Without
// the CreateProcess working-directory overlay redirect this fails with ERROR_DIRECTORY
// (267). The scratch dir must not leak onto the real execroot.
TEST_F(EnforceTest, OverlaySpawnWithOverlayOnlyCwd) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    auto scratch = Join(ws, L"pkgout");
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"mkdirspawncwd", scratch, ProbePath()}));
    EXPECT_FALSE(Exists(scratch));
}

// Multi-call enumeration cursor stress: each spliced overlay entry appears once.
TEST_F(EnforceTest, OverlayMultiCallEnum) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writeenummulti", ws, L"256", L"aa.txt", L"bbbbbbbb.txt",
                                L"c.txt", L"dddddddddddddddd.txt", L"ee.txt", L"f.txt"}));
}

// CREATE_NEW merged-view semantics.
TEST_F(EnforceTest, OverlayCreateNewBrandNew) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"createnew", Join(ws, L"fresh.txt")}));
    EXPECT_FALSE(Exists(Join(ws, L"fresh.txt")));
}

TEST_F(EnforceTest, OverlayCreateNewOverVisiblePreExistingFails) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kOtherError, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"createnew", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

TEST_F(EnforceTest, OverlayCreateNewOverHiddenPreExistingSucceeds) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"},
                               {L"createnew", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

// Overlay-only directory: a file written into a subdir absent from real disk.
TEST_F(EnforceTest, OverlayOnlyDirEnum) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovdirenum", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovsub")));
}

TEST_F(EnforceTest, OverlayOnlyDirEnumFilter) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"}, {L"writeovdirenum", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovsub")));
}

// --- Delete/rename redirection (mw-delete-rename) -----------------------------
TEST_F(EnforceTest, OverlayDeleteOwnFile) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovdelete", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovdel.txt")));
}

TEST_F(EnforceTest, OverlayDeleteHiddenLowerFileNotFound) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"},
                                     {L"delete", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

// Create-then-delete over a HIDDEN undeclared input: writing the masked name lands
// in the overlay backing store; deleting that overlay copy must leave the merged
// view showing the name GONE. The subsequent read must return NOT_FOUND - it must
// NOT re-reveal the masked real file. Regression guard for the overlay created-set leak:
// once the backing copy is removed, HasOverlayBackingShadow must stop reporting a
// backing shadow so the read re-masks to the hidden real input.
TEST_F(EnforceTest, OverlayCreateThenDeleteHiddenStaysMaskedNotFound) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"},
                                     {L"writedeleteread", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

// Create-then-rename-away over a HIDDEN undeclared input: the overlay copy is moved
// off the masked name, so reading the ORIGINAL name must return NOT_FOUND (the real
// hidden input must not resurface under it). The rename-source companion to the
// create-then-delete guard above.
TEST_F(EnforceTest, OverlayCreateThenRenameAwayHiddenStaysMaskedNotFound) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kNotFound, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"},
                                     {L"writerenameawayread", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

TEST_F(EnforceTest, OverlayDeleteVisibleLowerFileDenied) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds seed.txt = "seed-data"
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"delete", Join(ws, L"seed.txt")}));
    EXPECT_TRUE(StartsWithSeedData(Join(ws, L"seed.txt")));
}

// Handle-based delete (SetFileInformationByHandle + FILE_DISPOSITION_INFO) of an
// overlay-created file must remove the backing copy without touching the real
// execroot (the sibling of writeovdelete on the handle path).
TEST_F(EnforceTest, OverlayDeleteByHandleOwnFile) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovdeleteh", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovdelh.txt")));
}

// A read-only (-r) input must NEVER be deletable via the handle path, even under the
// write overlay (mirrors the rename guarantee). The declared input carries a
// read-only scope; the overlay cone is writable (-w) as in Bazel Mode 2.
TEST_F(EnforceTest, OverlayDeleteByHandleReadonlyInputDenied) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds a.txt = "x"
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"-w", ws, L"-r", Join(ws, L"a.txt"), L"--write-overlay"},
                                   {L"deleteh", Join(ws, L"a.txt")}));
    EXPECT_TRUE(Exists(Join(ws, L"a.txt")));
}

TEST_F(EnforceTest, OverlayRenameOwnFile) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovrename", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovr_src.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"ovr_dst.txt")));
}

// Regression: rename an overlay-created file via a HANDLE (SetFileInformationByHandle
// + FILE_RENAME_INFO) - the path cmd's `ren`/`move` take. The move must stay inside
// the backing store (probe read-back of the dest succeeds -> kOk) and never leak
// either name onto the real execroot. Previously the destination NAME was left as the
// virtual path, so the handle-based move leaked the destination onto real disk.
TEST_F(EnforceTest, OverlayRenameByHandleOwnFile) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovrenameh", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovrh_src.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"ovrh_dst.txt")));
}

// A read-only (-r) input must NEVER be renamable, even under the write overlay. The
// handle-based rename opens the source for DELETE access, which the more-specific
// read-only scope denies up front, so the whole op is refused and the real input
// stays intact. The overlay cone is writable (-w) as in Bazel Mode 2; only the
// declared input a.txt carries the read-only scope. Guards against the overlay
// redirect ever being extended to real -r inputs (design §6.3.1).
TEST_F(EnforceTest, OverlayRenameByHandleReadonlyInputDenied) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds a.txt = "x"
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"-w", ws, L"-r", Join(ws, L"a.txt"), L"--write-overlay"},
                                   {L"renameh", Join(ws, L"a.txt"), Join(ws, L"a_renamed.txt")}));
    EXPECT_TRUE(Exists(Join(ws, L"a.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"a_renamed.txt")));
}

// The same guarantee for the path-based MoveFileEx rename (ResolveOverlayDelete's
// DenyAccess branch): a real -r input in a writable overlay cone cannot be moved.
TEST_F(EnforceTest, OverlayRenamePathReadonlyInputDenied) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds a.txt = "x"
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"-w", ws, L"-r", Join(ws, L"a.txt"), L"--write-overlay"},
                                   {L"rename", Join(ws, L"a.txt"), Join(ws, L"a_moved.txt")}));
    EXPECT_TRUE(Exists(Join(ws, L"a.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"a_moved.txt")));
}

// A file inside a declared-input (-r) directory cone is itself a declared input and is
// strictly read-only, even under --write-overlay: overwriting it is DENIED and the real
// bytes are untouched. Mirrors linux-sandbox, where materialized files under a declared
// input dir are read-only symlinks. (New scratch paths inside a -r input dir are likewise
// denied - the write-overlay bits are granted only to the execroot cone, not to declared
// inputs.)
TEST_F(EnforceTest, OverlayExistingFileInReadonlyDirConeReadOnly) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds an empty sub/ directory
    auto sub = Join(ws, L"sub");
    auto input = Join(sub, L"input.txt");
    {
        std::ofstream(std::filesystem::path(input), std::ios::binary) << "orig-input";
    }
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"--write-overlay", L"-r", sub},
                                   {L"write", input, L"x"}));
    EXPECT_EQ("orig-input", ReadText(input));
}

// --- Declared outputs (-w) under --write-overlay ------------------------------
// A DECLARED OUTPUT (-w) is how Bazel names the files/dirs an action is allowed
// to produce; Bazel collects them from the real execroot after the action. So a
// write to a -w path must NOT be redirected into the process-private overlay -
// it must write THROUGH to the real disk. Mechanically, -w grants
// Policy_AllowAll, which lacks the OverrideAllowWriteForExistingFiles bit that
// ShouldRedirectToOverlay keys on, so its more-specific scope suppresses the
// execroot cone's overlay redirect for that subtree. Undeclared writes elsewhere
// in the cone still land in the overlay. These pin that split for both a -w FILE
// and a -w DIRECTORY.

// A -w FILE writes through to the real execroot (and the launcher pre-creates its
// parent dirs, linux-sandbox parity), even under --write-overlay.
TEST_F(EnforceTest, OverlayDeclaredOutputFileWritesThroughToRealDisk) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    auto out = Join(ws, L"outdir\\out.txt");  // nested: also exercises parent auto-create
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay", L"-w", out},
                               {L"write", out}));
    EXPECT_TRUE(Exists(out)) << "declared -w output was not written through to the real execroot";
}

// With the SAME manifest, an UNDECLARED sibling write (no -w) is still redirected
// into the overlay - it must not appear on the real execroot. The contrast to the
// test above: the -w bit is what selects write-through vs. redirect.
TEST_F(EnforceTest, OverlayUndeclaredWriteAlongsideDeclaredOutputRedirected) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    auto out = Join(ws, L"outdir\\out.txt");
    auto stray = Join(ws, L"stray.txt");  // undeclared
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay", L"-w", out},
                               {L"write", stray}));
    EXPECT_FALSE(Exists(stray)) << "undeclared write leaked onto the real execroot";
}

// A -w DIRECTORY is a cone: files written anywhere under it write through to the
// real execroot, proving -w supports directories, not just individual files.
TEST_F(EnforceTest, OverlayDeclaredOutputDirWritesThroughToRealDisk) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    auto dir = Join(ws, L"odir");
    ASSERT_TRUE(CreateDirectoryW(dir.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS);
    auto f = Join(dir, L"f.txt");
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay", L"-w", dir},
                               {L"write", f}));
    EXPECT_TRUE(Exists(f)) << "write inside a declared -w output directory did not reach the real execroot";
}

// --- Composite-op redirect (mw-composite-ops) ---------------------------------
TEST_F(EnforceTest, OverlayHardlink) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovhardlink", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovhl_tgt.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"ovhl_lnk.txt")));
}

TEST_F(EnforceTest, OverlaySymlink) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    int rc = RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovsymlink", ws});
    if (rc == kOtherError) GTEST_SKIP() << "symlink privilege unavailable";
    EXPECT_EQ(kOk, rc);
    EXPECT_FALSE(Exists(Join(ws, L"ovsl_tgt.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"ovsl_lnk.txt")));
}

TEST_F(EnforceTest, OverlayReplace) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovreplace", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovrep_dst.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"ovrep_src.txt")));
}

TEST_F(EnforceTest, OverlayRmdirOwnDir) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovrmdir", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovrmdir")));
}

TEST_F(EnforceTest, OverlayRmdirRealInConeDirDenied) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();  // seeds sub/ (empty dir)
    EXPECT_EQ(kDenied, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"rmdir", Join(ws, L"sub")}));
    EXPECT_TRUE(Exists(Join(ws, L"sub")));
}

// --- Metadata redirect (mw-metadata) ------------------------------------------
TEST_F(EnforceTest, OverlayMetadataStat) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovstat", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovstat.txt")));
}

TEST_F(EnforceTest, OverlayMetadataStatFilter) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"}, {L"writeovstat", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovstat.txt")));
}

// --- NT-layer redirect (mw-nt-layer) ------------------------------------------
TEST_F(EnforceTest, OverlayNtLayer) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"ntwriteread", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ntov.txt")));
}

TEST_F(EnforceTest, OverlayNtLayerFilter) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--filter-inputs", L"--write-overlay"}, {L"ntwriteread", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ntov.txt")));
}

// --- Configurable backing dir (--overlay-dir) ---------------------------------
TEST_F(EnforceTest, OverlayCustomBackingDir) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    auto ovDir = (TempRoot() / L"ov-custom").wstring();
    auto dbg = (TempRoot() / L"ovdbg.txt").wstring();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay", L"--overlay-dir", ovDir, L"-D", dbg},
                               {L"write", Join(ws, L"custom.txt"), L"x"}));
    EXPECT_FALSE(Exists(Join(ws, L"custom.txt")));
    EXPECT_TRUE(Exists(ovDir) && ContainsFileNamed(ovDir, L"custom.txt"));
}

// --- Enum-classes: overlay insertion across all enumeration APIs --------------
TEST_F(EnforceTest, OverlayEnumGfibhe) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeenumgfibhe", ws, L"egfibhe.txt"}));
    EXPECT_FALSE(Exists(Join(ws, L"egfibhe.txt")));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumgfibhe", ws2, L"egfibhe.txt"}));
}

TEST_F(EnforceTest, OverlayEnumWin32Find) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeenumfind", ws, L"efind.txt"}));
    EXPECT_FALSE(Exists(Join(ws, L"efind.txt")));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumfind", ws2, L"efind.txt"}));
}

TEST_F(EnforceTest, OverlayEnumNtEx) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeenumex", ws, L"eex.txt"}));
    EXPECT_FALSE(Exists(Join(ws, L"eex.txt")));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumex", ws2, L"eex.txt"}));
}

// Synthetic-record metadata is real (file size + directory attribute).
TEST_F(EnforceTest, OverlayEnumMetadataReal) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeenummeta", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"meta.txt")));
    EXPECT_FALSE(Exists(Join(ws, L"metadir")));
}

// CreateDirectoryW redirect + parent splice.
TEST_F(EnforceTest, OverlayCreateDirParentSplice) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovsubdirenum", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovsubdir")));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeovsubdirenum", ws2}));
}

// Enumerating INSIDE an overlay-only subdirectory.
TEST_F(EnforceTest, OverlayEnumInsideOverlayOnlySubdir) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"}, {L"writeovsubdirinnerenum", ws}));
    EXPECT_FALSE(Exists(Join(ws, L"ovinner")));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeovsubdirinnerenum", ws2}));
}

// Wildcard filtering of spliced overlay entries (gap #1).
TEST_F(EnforceTest, OverlayWildcardWin32Find) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writeenumfilterfind", ws, L"*.txt", L"foo.txt", L"bar.log"}));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumfilterfind", ws2, L"*.txt", L"foo.txt", L"bar.log"}));
}

TEST_F(EnforceTest, OverlayWildcardNtDirect) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writeenumfilternt", ws, L"*.txt", L"foo.txt", L"bar.log"}));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumfilternt", ws2, L"*.txt", L"foo.txt", L"bar.log"}));
}

// Narrow-filter FindFirstFile synthesis (gap #2).
TEST_F(EnforceTest, OverlaySynthWin32Find) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writeenumsynth", ws, L"*.log", L"only.log"}));
    auto ws2 = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws2, L"--filter-inputs", L"--write-overlay"},
                               {L"writeenumsynth", ws2, L"*.log", L"only.log"}));
}

}  // namespace
}  // namespace bsx
