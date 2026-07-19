// Filesystem operation enforcement across the intercepted API surface: mutations
// (delete/mkdir/rename/rename-by-handle/copy/rmdir/hardlink), attribute and ANSI
// variants, GetTempFileName, the native NtCreateFile path, and the absent-file
// read-only-vs-writable distinction.
//
// gtest port of tests/enforce/filesystem.ps1 (one It -> one TEST_F).

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

using WS = std::vector<std::wstring>;  // arg list helper

// --- delete / mkdir / rmdir -------------------------------------------------

TEST_F(EnforceTest, DeleteInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"delete", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, DeleteInWritableWorkdirAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"delete", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, MkdirInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"mkdir", Join(ws, L"newdir")}));
}

TEST_F(EnforceTest, MkdirInWritableWorkdirAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"mkdir", Join(ws, L"newdir")}));
}

TEST_F(EnforceTest, RmdirInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"rmdir", Join(ws, L"sub")}));
}

TEST_F(EnforceTest, RmdirInWritableWorkdirAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"rmdir", Join(ws, L"sub")}));
}

// --- rename (Win32 and handle-based) ---------------------------------------

TEST_F(EnforceTest, RenameWithinWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws},
                            {L"rename", Join(ws, L"src.txt"), Join(ws, L"dst.txt")}));
}

TEST_F(EnforceTest, RenameToBlockedDestDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", Join(ws, L"dst.txt")},
                       {L"rename", Join(ws, L"src.txt"), Join(ws, L"dst.txt")}));
}

// Handle-based rename (SetFileInformationByHandle + FILE_RENAME_INFO) is the
// path Bazel's own filesystem uses; it must enforce like a plain rename.
TEST_F(EnforceTest, HandleRenameWithinWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws},
                            {L"renameh", Join(ws, L"src.txt"), Join(ws, L"dsth.txt")}));
}

TEST_F(EnforceTest, HandleRenameToBlockedDestDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", Join(ws, L"dsth.txt")},
                       {L"renameh", Join(ws, L"src.txt"), Join(ws, L"dsth.txt")}));
}

// --- copy / hardlink --------------------------------------------------------

TEST_F(EnforceTest, CopyToBlockedDestDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", Join(ws, L"cpy.txt")},
                       {L"copy", Join(ws, L"src.txt"), Join(ws, L"cpy.txt")}));
}

TEST_F(EnforceTest, CopyToWritableDestAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", ws},
                            {L"copy", Join(ws, L"src.txt"), Join(ws, L"cpy.txt")}));
}

// probe usage is: hardlink <newlink> <existing>.
TEST_F(EnforceTest, HardlinkWithinWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", ws},
                            {L"hardlink", Join(ws, L"hl.txt"), Join(ws, L"src.txt")}));
}

// --- alternate deletion / mutation mechanisms -------------------------------
// Beyond DeleteFileW, modern runtimes delete through other APIs the engine hooks
// separately. Each must enforce like a plain write: denied under a read-only -r
// scope, allowed under -w.

// Handle-based delete (SetFileInformationByHandle + FILE_DISPOSITION_INFO) - the
// path .NET's File.Delete uses.
TEST_F(EnforceTest, HandleDeleteUnderReadonlyDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws}, {L"deleteh", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, HandleDeleteUnderWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"deleteh", Join(ws, L"a.txt")}));
}

// Delete-on-close (CreateFile with FILE_FLAG_DELETE_ON_CLOSE).
TEST_F(EnforceTest, DeleteOnCloseUnderReadonlyDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws}, {L"delonclose", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, DeleteOnCloseUnderWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"delonclose", Join(ws, L"a.txt")}));
}

// Atomic replace (ReplaceFileW) - editors/tools use it for safe saves.
TEST_F(EnforceTest, ReplaceToBlockedTargetDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", Join(ws, L"keep.txt")},
                       {L"replace", Join(ws, L"keep.txt"), Join(ws, L"src.txt")}));
}

TEST_F(EnforceTest, ReplaceWithinWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", ws},
                            {L"replace", Join(ws, L"keep.txt"), Join(ws, L"src.txt")}));
}

// Directory rename (MoveFileExW on a directory).
TEST_F(EnforceTest, DirectoryRenameWithinWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws},
                            {L"rename", Join(ws, L"sub"), Join(ws, L"subx")}));
}

TEST_F(EnforceTest, DirectoryRenameUnderReadonlyDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws},
                                {L"rename", Join(ws, L"sub"), Join(ws, L"subx")}));
}

// --- attribute queries, ANSI variants, native NtCreateFile -----------------

TEST_F(EnforceTest, StatInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"stat", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, StatUnderReadonlyAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws}, {L"stat", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, StatAnsiInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"stata", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, ReadAnsiInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"reada", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, ReadAnsiUnderReadonlyAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws}, {L"reada", Join(ws, L"a.txt")}));
}

// The native NtCreateFile syscall (bypassing the Win32 wrapper) is enforced
// identically - the engine hooks the Nt* layer, not just kernel32.
TEST_F(EnforceTest, NativeNtCreateFileInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"ntread", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, NativeNtCreateFileUnderReadonlyAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws}, {L"ntread", Join(ws, L"a.txt")}));
}

// --- GetTempFileName --------------------------------------------------------

TEST_F(EnforceTest, GetTempFileNameInWritableAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"tempfile", ws}));
}

TEST_F(EnforceTest, GetTempFileNameInDeniedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"tempfile", ws}));
}

// --- absent-file probing ----------------------------------------------------
// Opening a NON-existent file for read reports FILE_NOT_FOUND (not-found, 11)
// under BOTH read-only and writable scopes (Policy_AllowReadIfNonExistent),
// matching the linux default sandbox: probing an absent optional input yields
// ENOENT, not a spurious ACCESS_DENIED.

TEST_F(EnforceTest, ReadAbsentFileUnderReadonlyReportsNotFound) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kNotFound, RunProbe({L"-W", ws, L"-r", ws}, {L"read", Join(ws, L"nope.txt")}));
}

TEST_F(EnforceTest, ReadAbsentFileUnderWritableReportsNotFound) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kNotFound, RunProbe({L"-W", ws, L"-w", ws}, {L"read", Join(ws, L"nope.txt")}));
}

}  // namespace
}  // namespace bsx
