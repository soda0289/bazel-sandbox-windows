// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "DataTypes.h"
#include "DetouredFunctionTypes.h"
#include "DetouredProcessInjector.h"
#include "UtilityHelpers.h"
#include <vector>

using std::vector;

// ----------------------------------------------------------------------------
// DEFINES
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// FORWARD DECLARATIONS
// ----------------------------------------------------------------------------
class TranslatePathTuple;
struct BreakawayChildProcess;

// ----------------------------------------------------------------------------
// GLOBALS
// ----------------------------------------------------------------------------

extern SpecialProcessKind  g_ProcessKind;

extern HANDLE g_hPrivateHeap;

extern DWORD g_manifestSize;

extern DWORD g_currentProcessId;
extern PCWSTR g_currentProcessCommandLine;

extern FileAccessManifestFlag g_fileAccessManifestFlags;
extern FileAccessManifestExtraFlag g_fileAccessManifestExtraFlags;

extern PCManifestRecord g_manifestTreeRoot;

extern PManifestChildProcessesToBreakAwayFromJob g_manifestChildProcessesToBreakAwayFromJob;
extern vector<BreakawayChildProcess>* g_breakawayChildProcesses;
extern PManifestTranslatePathsStrings g_manifestTranslatePathsStrings;
extern vector<TranslatePathTuple*>* g_pManifestTranslatePathTuples;
extern std::unordered_set<std::wstring>* g_pManifestTranslatePathLookupTable;

extern PManifestInternalDetoursErrorNotificationFileString g_manifestInternalDetoursErrorNotificationFileString;
extern LPCTSTR g_internalDetoursErrorNotificationFile;

extern HANDLE g_reportFileHandle;

extern unsigned long g_injectionTimeoutInMinutes;

extern bool g_BreakOnAccessDenied;

extern LPCSTR g_lpDllNameX86;
extern LPCSTR g_lpDllNameX64;

extern DetouredProcessInjector* g_pDetouredProcessInjector;

// Bazel fork (Model W write-overlay): absolute path to the launcher-created
// per-invocation overlay backing directory. Undeclared writes in the execroot
// cone are redirected under here (mirroring the virtual path) instead of touching
// the real execroot, giving per-action write isolation. Parsed from the manifest
// payload so it rides the re-copied payload to every child. Null unless
// --write-overlay was passed. CODESYNC: ManifestBuilder::SetWriteOverlayRoot.
extern wchar_t* g_bazelWriteOverlayRoot;

// Bazel fork (Model W write-overlay): absolute path to the overlay SOURCE root -
// the real directory subtree whose undeclared writes are redirected into the
// backing store (g_bazelWriteOverlayRoot). Today this equals the launcher working
// directory (-W). It is stripped from a virtual path to compute the backing path,
// e.g. with source root C:\ws and backing \\?\<root>, C:\ws\a\b.txt maps to
// \\?\<root>\a\b.txt (no redundant drive-letter mirror). Parsed from the manifest
// payload (rides the re-copied payload like g_bazelWriteOverlayRoot). Null unless
// --write-overlay was passed. CODESYNC: ManifestBuilder::SetOverlaySourceRoot.
extern wchar_t* g_bazelOverlaySourceRoot;

// ----------------------------------------------------------------------------
// Real Windows API function pointers
// ----------------------------------------------------------------------------

extern CreateProcessW_t Real_CreateProcessW;
extern CreateProcessA_t Real_CreateProcessA;
extern CreateProcessAsUserW_t Real_CreateProcessAsUserW;
extern CreateProcessAsUserA_t Real_CreateProcessAsUserA;
extern CreateFileW_t Real_CreateFileW;

extern RtlFreeHeap_t Real_RtlFreeHeap;
extern RtlAllocateHeap_t Real_RtlAllocateHeap;
extern RtlReAllocateHeap_t Real_RtlReAllocateHeap;
extern VirtualAlloc_t Real_VirtualAlloc;

extern CreateFileA_t Real_CreateFileA;
extern GetVolumePathNameW_t Real_GetVolumePathNameW;
extern GetFileAttributesA_t Real_GetFileAttributesA;
extern GetFileAttributesW_t Real_GetFileAttributesW;
extern GetCurrentDirectoryW_t Real_GetCurrentDirectoryW;
extern GetFileAttributesExW_t Real_GetFileAttributesExW;
extern GetFileAttributesExA_t Real_GetFileAttributesExA;
extern CloseHandle_t Real_CloseHandle;

extern GetFileInformationByHandle_t Real_GetFileInformationByHandle;
extern GetFileInformationByHandleEx_t Real_GetFileInformationByHandleEx;
extern SetFileInformationByHandle_t Real_SetFileInformationByHandle;

extern CopyFileW_t Real_CopyFileW;
extern CopyFileA_t Real_CopyFileA;
extern CopyFileExW_t Real_CopyFileExW;
extern CopyFileExA_t Real_CopyFileExA;
extern CopyFile2_t Real_CopyFile2;
extern CopyFileTransactedW_t Real_CopyFileTransactedW;
extern CopyFileTransactedA_t Real_CopyFileTransactedA;
extern MoveFileW_t Real_MoveFileW;
extern MoveFileA_t Real_MoveFileA;
extern MoveFileExW_t Real_MoveFileExW;
extern MoveFileExA_t Real_MoveFileExA;
extern MoveFileWithProgressW_t Real_MoveFileWithProgressW;
extern MoveFileWithProgressA_t Real_MoveFileWithProgressA;
extern MoveFileTransactedW_t Real_MoveFileTransactedW;
extern MoveFileTransactedA_t Real_MoveFileTransactedA;
extern ReplaceFileW_t Real_ReplaceFileW;
extern ReplaceFileA_t Real_ReplaceFileA;
extern DeleteFileA_t Real_DeleteFileA;
extern DeleteFileW_t Real_DeleteFileW;

extern CreateHardLinkW_t Real_CreateHardLinkW;
extern CreateHardLinkA_t Real_CreateHardLinkA;
extern CreateSymbolicLinkW_t Real_CreateSymbolicLinkW;
extern CreateSymbolicLinkA_t Real_CreateSymbolicLinkA;
extern FindFirstFileW_t Real_FindFirstFileW;
extern FindFirstFileA_t Real_FindFirstFileA;
extern FindFirstFileExW_t Real_FindFirstFileExW;
extern FindFirstFileExA_t Real_FindFirstFileExA;
extern FindNextFileA_t Real_FindNextFileA;
extern FindNextFileW_t Real_FindNextFileW;
extern FindClose_t Real_FindClose;
extern OpenFileMappingW_t Real_OpenFileMappingW;
extern OpenFileMappingA_t Real_OpenFileMappingA;
extern GetTempFileNameW_t Real_GetTempFileNameW;
extern GetTempFileNameA_t Real_GetTempFileNameA;
extern CreateDirectoryW_t Real_CreateDirectoryW;
extern CreateDirectoryA_t Real_CreateDirectoryA;
extern CreateDirectoryExW_t Real_CreateDirectoryExW;
extern CreateDirectoryExA_t Real_CreateDirectoryExA;
extern RemoveDirectoryW_t Real_RemoveDirectoryW;
extern RemoveDirectoryA_t Real_RemoveDirectoryA;
extern DecryptFileW_t Real_DecryptFileW;
extern DecryptFileA_t Real_DecryptFileA;
extern EncryptFileW_t Real_EncryptFileW;
extern EncryptFileA_t Real_EncryptFileA;
extern OpenEncryptedFileRawW_t Real_OpenEncryptedFileRawW;
extern OpenEncryptedFileRawA_t Real_OpenEncryptedFileRawA;
extern OpenFileById_t Real_OpenFileById;
extern GetFinalPathNameByHandleW_t Real_GetFinalPathNameByHandleW;
extern GetFinalPathNameByHandleA_t Real_GetFinalPathNameByHandleA;

extern NtClose_t Real_NtClose;
extern NtCreateFile_t Real_NtCreateFile;
extern NtOpenFile_t Real_NtOpenFile;
extern NtQueryAttributesFile_t Real_NtQueryAttributesFile;
extern NtQueryFullAttributesFile_t Real_NtQueryFullAttributesFile;
extern GetFileInformationByName_t Real_GetFileInformationByName;
extern ZwCreateFile_t Real_ZwCreateFile;
extern ZwOpenFile_t Real_ZwOpenFile;
extern NtQueryDirectoryFile_t Real_NtQueryDirectoryFile;
extern NtQueryDirectoryFileEx_t Real_NtQueryDirectoryFileEx;
extern ZwQueryDirectoryFile_t Real_ZwQueryDirectoryFile;
extern ZwSetInformationFile_t Real_ZwSetInformationFile;

extern CreatePipe_t Real_CreatePipe;
extern DeviceIoControl_t Real_DeviceIoControl;


