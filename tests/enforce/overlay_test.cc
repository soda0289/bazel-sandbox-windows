// Model W write-overlay (experimental): write/read redirection + directory-
// enumeration insertion. The overlay redirects undeclared writes in the
// execroot-writable cone into a process-private backing store, so the real
// execroot is never mutated, yet overlay-only files still APPEAR when the tool
// lists the directory it "wrote" them into. Everything is gated by the
// --write-overlay kill-switch.
//
// gtest port of tests/enforce/overlay.ps1. Uses RunProbeRaw (no implicit -H).

#include <windows.h>

#include <filesystem>
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

// Control: without --write-overlay (but execroot-writable), the same new-file
// write lands on the REAL disk.
TEST_F(EnforceTest, OverlayControlWriteLandsOnDisk) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--execroot-writable"}, {L"write", Join(ws, L"onreal.txt"), L"x"}));
    EXPECT_TRUE(Exists(Join(ws, L"onreal.txt")));
}

// Cross-process enumeration: a separate child sees the parent's overlay file.
TEST_F(EnforceTest, OverlayCrossProcessEnum) {
    SetOverlayNames(L"");
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbeRaw({L"-W", ws, L"--write-overlay"},
                               {L"writespawnenum", ws, L"xpenum.txt", ProbePath()}));
    EXPECT_FALSE(Exists(Join(ws, L"xpenum.txt")));
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
// NOT re-reveal the masked real file. Regression guard for the SHM created-set leak:
// once the backing copy is removed, WasCreatedInThisProcess must stop reporting the
// path "created this action" so the read re-masks to the hidden real input.
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
