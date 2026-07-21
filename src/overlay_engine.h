// overlay_engine.h - Bazel write-overlay (Model W) redirect + input-filter helpers.
//
// Project-owned code. This is NOT part of the vendored Microsoft BuildXL
// DetoursServices engine under vendor/; it implements the write-overlay
// backing-store redirection and the input-filter visibility predicates used by the
// file-system hooks in vendor/detours-services/DetouredFunctions.cpp. Extracted
// from that translation unit to keep project-authored logic out of the vendored
// code and shrink the vendor patch. See docs/design/detours-write-overlay-vfs.md.
//
// Licensed under this repository's own terms (see README "License"). No Microsoft
// MIT grant applies to this file.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "FileAccessHelpers.h"
#include "PolicyResult.h"

// HandleOverlayRef is std::shared_ptr<HandleOverlay>. HandleOverlay.h has no include
// guard, so this widely-included header forward-declares the struct instead of
// including it (the .cpp pulls the full definition). The typedef matches the one in
// HandleOverlay.h; an identical typedef redeclaration is legal.
struct HandleOverlay;
typedef std::shared_ptr<HandleOverlay> HandleOverlayRef;

// How a delete / rename-source of an in-cone path must be handled so the real
// execroot is never mutated. See ResolveOverlayDelete (src/overlay_engine.cpp).
enum class OverlayDeleteAction { PassThrough, RedirectToBacking, DenyAccess, NotFound };

// Model W write-overlay redirect + input-filter helpers. All policy/reporting runs
// on the VIRTUAL path; these only compute the path handed to the Real_ call and the
// filter-visibility of a real file. Everything is gated by ShouldWriteOverlay() /
// ShouldDeniedReadsAsNotFound(). (OverlayBackingExists is declared in PolicyResult.h.)
bool ShouldRedirectToOverlay(const PolicyResult& pr);
std::wstring OverlayBackingPath(const std::wstring& virtualPath);
bool ReverseOverlayFinalPath(const std::wstring& finalPath, std::wstring& out);
void EnsureBackingParentDirs(const std::wstring& backingPath);
bool OverlayPathExists(const std::wstring& p);
bool OverlayIsDirectory(const std::wstring& p);
void ListBackingChildren(const std::wstring& virtualDir, std::vector<std::wstring>& out);
bool OverlayRealFileHiddenByFilter(const PolicyResult& policyResult);
std::wstring ResolveOverlayOpenPath(const PolicyResult& policyResult, DWORD dwDesiredAccess, DWORD dwCreationDisposition);
// Resolves a child process's working directory through the write-overlay. Returns the
// concrete backing directory when `workingDirectory` names a process-private overlay
// scratch dir that has no counterpart on the real execroot (so CreateProcess would
// otherwise fail with ERROR_DIRECTORY / 267); returns "" when the directory exists on
// the real disk, is outside the overlay cone, or the overlay is disabled.
std::wstring ResolveOverlayWorkingDirectory(const wchar_t* workingDirectory);
OverlayDeleteAction ResolveOverlayDelete(PolicyResult& policyResult, std::wstring& backingOut);
std::wstring ResolveOverlayRenameDest(PolicyResult& policyResult);
std::wstring ResolveOverlayProbePath(PolicyResult& policyResult);

// ---------------------------------------------------------------------------
// Directory-enumeration input filtering + write-overlay enumeration splice.
//
// Under ShouldFilterDirectoryEnumeration() the enumeration hooks hide entries that
// are not declared inputs (linux-sandbox symlink-forest parity); under
// ShouldWriteOverlay() they also splice this action's process-private backing-store
// entries into listings. These helpers are called from the FindFirst/FindNext and
// NtQueryDirectoryFile(Ex) hooks in the vendored DetouredFunctions.cpp.
// ---------------------------------------------------------------------------

// Real NtQueryDirectoryFile / NtQueryDirectoryFileEx signatures (the hooks pass the
// captured Real_ pointer so the filter can re-issue the query on a private buffer).
typedef NTSTATUS(NTAPI* QueryDirectoryFileFn)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
typedef NTSTATUS(NTAPI* QueryDirectoryFileExFn)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);

bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name, size_t nameChars);
bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name);
bool TryMapHandleDirInfoClass(FILE_INFO_BY_HANDLE_CLASS handleClass, ULONG& ntInfoClass, FILE_INFO_BY_HANDLE_CLASS& continueClass);
size_t FilterDirectoryInformation(PVOID buffer, ULONG infoClass, ULONG bufferLen, const PolicyResult& directoryPolicyResult);
void ApplyEnumerationFilterNt(
    QueryDirectoryFileFn realFn, HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult, NTSTATUS& result, DWORD& reportedError, DWORD& lastError);
void ApplyEnumerationFilterNtEx(
    QueryDirectoryFileExFn realFn, HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    ULONG QueryFlags, PUNICODE_STRING FileName, PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult, NTSTATUS& result, DWORD& reportedError, DWORD& lastError);
std::wstring JoinDirAndName(const std::wstring& dir, const std::wstring& name);
void EnsureOverlayEnumSnapshot(const std::wstring& enumDir, HandleOverlayRef& overlay);
bool NextOverlayFindDataW(const std::wstring& enumDir, HandleOverlayRef& overlay, LPWIN32_FIND_DATAW data);
void CaptureOverlayEnumFilter(HandleOverlayRef& overlay, PUNICODE_STRING FileName, bool restartScan);
void InsertOverlayEntries(
    PVOID FileInformation, ULONG Length, PIO_STATUS_BLOCK IoStatusBlock, ULONG infoClass, BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan, const std::wstring& enumDir, HandleOverlayRef& overlay, NTSTATUS& result);
HANDLE TrySynthesizeOverlayFindFirstW(
    const std::wstring& dirPath, const std::wstring& filterExpr, AccessCheckResult const& dirAccessCheck,
    PolicyResult const& dirPolicy, LPWIN32_FIND_DATAW lpFindFileData, FINDEX_INFO_LEVELS fInfoLevelId,
    FINDEX_SEARCH_OPS fSearchOp, DWORD dwAdditionalFlags);
bool TryAppendOverlayFindDataW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
