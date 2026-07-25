// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"

#include "DebuggingHelpers.h"
#include "DetoursHelpers.h"
#include "DetoursServices.h"
#include "globals.h"
#include "buildXL_mem.h"
#include "SendReport.h"
#include "StringOperations.h"
#include "CanonicalizedPath.h"
#include "PolicyResult.h"
#include <list>
#include <string>
#include <stdio.h>
#include <stack>
#include <algorithm>
#include <cwctype>

using std::unique_ptr;
using std::basic_string;
using std::wstring;



// ----------------------------------------------------------------------------
// FUNCTION DEFINITIONS
// ----------------------------------------------------------------------------

bool GetSpecialCaseRulesForWindows(
    __in  PCWSTR absolutePath,
    __in  size_t absolutePathLength,
    __out FileAccessPolicy& policy)
{
    assert(absolutePath);
    assert(absolutePathLength == wcslen(absolutePath));

    size_t rootLength = GetRootLength(absolutePath);
    if (HasPrefix(absolutePath + rootLength, L"$Extend\\$Deleted"))
    {
        // Windows can have an "unlink" behavior where deleted files are not really deleted if there's an opened handle.
        // This behavior is possible because a process can open a file with FILE_SHARE_DELETE that makes other processes able to delete it.
        // If a file is opened by specifying the FILE_SHARE_DELETE flag for the CreateFile function and another process tries to delete it,
        // the file is actually moved to the “\$Extend\$Deleted” directory on the same volume. When the last handle to such a file is closed,
        // it's deleted as usual. When the file system is mounted, all existing files in the “\$Extend\$Deleted” directory, if any, are deleted,
        // The same logic also applies to deleted directories.
        // Details can be found in this unofficial documentation: https://dfir.ru/2020/03/21/the-extenddeleted-directory/
        policy = FileAccessPolicy::FileAccessPolicy_AllowAll;
        return true;
    }

    return false;
}

// This functions allows file accesses for special undeclared files.
// In the special set set we include:
//     1. Code coverage runs
//     2. Te drive devices
//     3. Dos devices and special system devices/names (pipes, null dev etc).
// These accesses now should be allowlisted, but many users have deployed products that have specs not declaring such accesses.
bool GetSpecialCaseRulesForCoverageAndSpecialDevices(
    __in  PCWSTR absolutePath,
    __in  size_t absolutePathLength,
    __in  PathType pathType,
    __out FileAccessPolicy& policy)
{
    assert(absolutePath);
    assert(absolutePathLength == wcslen(absolutePath));

    if (pathType == PathType::LocalDevice || pathType == PathType::Win32Nt) {
        bool maybeStartsWithDrive = absolutePathLength >= 2 && IsDriveLetter(absolutePath[0]) && absolutePath[1] == L':';

        // For a normal Win32 path, C: means C:<current directory on C> or C:\ if one is not set. But \\.\C:, \\?\C:, and \??\C:
        // mean 'the device C:'. We don't care to model access to devices (volumes in this case).
        if (maybeStartsWithDrive && absolutePathLength == 2) {
            policy = FileAccessPolicy_AllowAll;
            return true;
        }

        // maybeStartsWithDrive => absolutePathLength >= 3
        assert(!maybeStartsWithDrive || absolutePathLength >= 3);

        // We do not provide a special case for e.g. \\.\C:\foo (equivalent to the Win32 C:\foo) but we do want to allow access
        // to non-drive DosDevices. For example, the Windows DNS API ends up(indirectly) calling CreateFile("\\\\.\\Nsi").
        // Note that this also allows access to the named pipe filesystem under \\.\pipe.
        bool startsWithDriveRoot = maybeStartsWithDrive && absolutePath[2] == L'\\';
        if (!startsWithDriveRoot) {
            policy = FileAccessPolicy_AllowAll;
            return true;
        }
    }

    if (IsPathToNamedStream(absolutePath, absolutePathLength)) {
        policy = FileAccessPolicy_AllowAll;
        return true;
    }

    return false;
}

bool WantsWriteAccess(DWORD access)
{
    return (access & (GENERIC_ALL | GENERIC_WRITE | DELETE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA)) != 0;
}

bool WantsReadAccess(DWORD access)
{
    return (access & (GENERIC_READ | FILE_READ_DATA)) != 0;
}

bool WantsReadOnlyAccess(DWORD access)
{
    return WantsReadAccess(access) && !WantsWriteAccess(access);
}

bool WantsProbeOnlyAccess(DWORD access)
{
    return !WantsReadAccess(access)
        && !WantsWriteAccess(access)
        && (access == 0 || (access & (FILE_READ_ATTRIBUTES | FILE_READ_EA)) != 0);
}

bool WantsDeleteOnlyAccess(DWORD access)
{
    return access == DELETE;
}

/* Indicates if a path contains a wildcard that may be interpreted by FindFirstFile / FindFirstFileEx. */
bool PathContainsWildcard(LPCWSTR path) {
    for (WCHAR const* pch = path; *pch != L'\0'; pch++) {
        if (*pch == L'?' || *pch == L'*') {
            return true;
        }
    }

    return false;
}

bool ParseUInt64Arg(
    __inout PCWSTR& pos,
    int radix,
    __out ulong& value)
{
    PWSTR nextPos;
    value = _wcstoui64(pos, &nextPos, radix);
    if (nextPos == NULL) {
        return false;
    }

    if (*nextPos == L',') {
        ++nextPos;
    }
    else if (*nextPos != 0) {
        return false;
    }

    pos = nextPos;
    return true;
}

bool LocateFileAccessManifest(
    __out const void*& manifest,
    __out DWORD& manifestSize)
{
    manifest = NULL;
    manifestSize = 0;

    HMODULE previousModule = NULL;
    for (;;) {
        HMODULE currentModule = DetourEnumerateModules(previousModule);
        if (currentModule == NULL) {
            Dbg(L"Did not find Detours payload.");
            return false;
        }

        previousModule = currentModule;
        DWORD payloadSize;
        const void* payload = DetourFindPayload(currentModule, __uuidof(IDetourServicesManifest), &payloadSize);
        if (payload != NULL) {
            manifest = payload;
            manifestSize = payloadSize;
            return true;
        }
    }
}

/// VerifyManifestRoot
///
/// Check that the root is a valid root record by checking that
/// the path of the root scope is an empty string.
#pragma warning( push )
#pragma warning( disable: 4100 ) // in release builds, root is unused
inline void VerifyManifestRoot(PCManifestRecord const root)
{
    assert(root->GetPartialPath()[0] == 0); // the root path should be an empty string
}
#pragma warning( pop )

static inline byte ParseByte(const byte* payloadBytes, size_t& offset)
{
    byte b = payloadBytes[offset];
    offset += sizeof(byte);
    return b;
}

static inline uint32_t ParseUint32(const byte *payloadBytes, size_t &offset)
{
    uint32_t i = *(uint32_t*)(&payloadBytes[offset]);
    offset += sizeof(uint32_t);
    return i;
}

/// Decodes a length plus UTF-16 non-null-terminated string written by FileAccessManifest.WriteChars()
/// and appends it to the given result string.
void AppendStringFromWriteChars(const byte* payloadBytes, size_t& offset, _Out_ std::wstring& result)
{
    uint32_t len = ParseUint32(payloadBytes, offset);
    if (len == 0)
    {
        return;
    }

    result.append((wchar_t*)(&payloadBytes[offset]), len);
    offset += sizeof(wchar_t) * len;
}


/// <summary>
/// Gets the final full path by handle.
/// </summary>
/// <remarks>
/// This function encapsulates calls to <code>GetFinalPathNameByHandleW</code> and allocates memory as needed.
/// </remarks>
static DWORD DetourGetFinalPathByHandle(_In_ HANDLE hFile, _Inout_ std::wstring& fullPath)
{
    // First, try with a fixed-sized buffer which should be good enough for all practical cases.
    wchar_t wszBuffer[MAX_PATH];
    DWORD nBufferLength = std::extent<decltype(wszBuffer)>::value;

    DWORD result = GetFinalPathNameByHandleW(hFile, wszBuffer, nBufferLength, FILE_NAME_NORMALIZED);
    if (result == 0)
    {
        DWORD ret = GetLastError();
        return ret;
    }

    if (result < nBufferLength)
    {
        // The buffer was big enough. The return value indicates the length of the full path, NOT INCLUDING the terminating null character.
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364962(v=vs.85).aspx
        fullPath.assign(wszBuffer, static_cast<size_t>(result));
    }
    else
    {
        // Second, if that buffer wasn't big enough, we try again with a dynamically allocated buffer with sufficient size.
        // Note that in this case, the return value indicates the required buffer length, INCLUDING the terminating null character.
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364962(v=vs.85).aspx
        unique_ptr<wchar_t[]> buffer(new wchar_t[result]);
        assert(buffer.get());

        DWORD next_result = GetFinalPathNameByHandleW(hFile, buffer.get(), result, FILE_NAME_NORMALIZED);
        if (next_result == 0)
        {
            DWORD ret = GetLastError();
            return ret;
        }

        if (next_result < result)
        {
            fullPath.assign(buffer.get(), next_result);
        }
        else
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    return ERROR_SUCCESS;
}

bool ParseFileAccessManifest(
    const void* payload,
    DWORD)
{
    //
    // Parse the file access manifest payload
    //

    assert(payload != nullptr);

    std::wstring initErrorMessage;
    uint32_t payloadSize;
    LPCBYTE payloadBytes = nullptr;

    if (!g_pDetouredProcessInjector->Init(reinterpret_cast<const byte *>(payload), initErrorMessage, &payloadBytes, payloadSize))
    {
        // Error initializing injector due to incorrect content of payload.
        std::wstring errorMsg = DebugStringFormat(L"ParseFileAccessManifest: Error initializing process injector: %s", initErrorMessage.c_str());
        HandleDetoursInjectionAndCommunicationErrors(DETOURS_PAYLOAD_PARSE_FAILED_19, errorMsg.c_str(), DETOURS_WINDOWS_LOG_MESSAGE_19);
        return false;
    }

    assert(payloadSize > 0);
    assert(payloadBytes != nullptr);

    g_currentProcessId = GetCurrentProcessId();

    g_lpDllNameX86 = NULL;
    g_lpDllNameX64 = NULL;

    size_t offset = 0;

    PCManifestFlags flags = reinterpret_cast<PCManifestFlags>(&payloadBytes[offset]);
    g_fileAccessManifestFlags = static_cast<FileAccessManifestFlag>(flags->Flags);
    offset += flags->GetSize();

    PCManifestExtraFlags extraFlags = reinterpret_cast<PCManifestExtraFlags>(&payloadBytes[offset]);
    g_fileAccessManifestExtraFlags = static_cast<FileAccessManifestExtraFlag>(extraFlags->ExtraFlags);
    g_pDetouredProcessInjector->SetPayload(payloadBytes, payloadSize);
    offset += extraFlags->GetSize();

    PCManifestReport report = reinterpret_cast<PCManifestReport>(&payloadBytes[offset]);

    if (report->IsReportPresent()) {
        {
            // Report-PIPE mode was removed together with the injector handshake;
            // this launcher only ever emits a report-FILE path.
            // NOTE: This calls the real CreateFileW(), not our detoured version, because we have not yet installed
            // our detoured functions.
            g_reportFileHandle = CreateFileW(
                report->ReportPath,
                FILE_WRITE_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_ALWAYS,
                0,
                NULL);

            if (g_reportFileHandle == INVALID_HANDLE_VALUE) {
                DWORD error = GetLastError();
                g_reportFileHandle = NULL;
                // No need to call Dbg since calling Dbg with invalid or NULL report handle is noop.
                std::wstring errorMsg = DebugStringFormat(L"ParseFileAccessManifest: Failed to open report file '%s' (error code: 0x%08X)", report->ReportPath, (int)error);
                HandleDetoursInjectionAndCommunicationErrors(DETOURS_PAYLOAD_PARSE_FAILED_17, errorMsg.c_str(), DETOURS_WINDOWS_LOG_MESSAGE_17);
                return false;
            }

        }
    }
    else {
        g_reportFileHandle = NULL;
    }

    offset += report->GetSize();

    PCManifestDllBlock dllBlock = reinterpret_cast<PCManifestDllBlock>(&payloadBytes[offset]);

    g_lpDllNameX86 = dllBlock->GetDllString(0);
    g_lpDllNameX64 = dllBlock->GetDllString(1);

    // Update the injector with the DLLs
    g_pDetouredProcessInjector->SetDlls(g_lpDllNameX86, g_lpDllNameX64);
    offset += dllBlock->GetSize();

    // Bazel fork (Model W write-overlay): overlay backing-store root. A padded
    // WCHAR block (same layout as the report block) written by ManifestBuilder
    // immediately before the manifest tree so the tree stays 4-byte aligned. The
    // length word is the padded byte count of the path region; 0 means no overlay
    // (--write-overlay not passed). Parsing here (rather than an environment
    // variable) means the path propagates through the payload that is re-copied
    // verbatim to every child. CODESYNC: ManifestBuilder::SetWriteOverlayRoot.
    {
        uint32_t rootBytes = ParseUint32(payloadBytes, offset);
        if (rootBytes != 0) {
            g_bazelWriteOverlayRoot = _wcsdup(reinterpret_cast<const wchar_t*>(&payloadBytes[offset]));
            offset += rootBytes;
        }
    }

    // Bazel fork (Model W write-overlay): overlay SOURCE root. Same padded WCHAR
    // block layout, serialized right after the backing-root block and before the
    // manifest tree so the tree stays 4-byte aligned. The length word is the
    // padded byte count of the path region; 0 means no source root. This is the
    // virtual subtree stripped to compute a backing path. CODESYNC:
    // ManifestBuilder::SetOverlaySourceRoot.
    {
        uint32_t rootBytes = ParseUint32(payloadBytes, offset);
        if (rootBytes != 0) {
            g_bazelOverlaySourceRoot = _wcsdup(reinterpret_cast<const wchar_t*>(&payloadBytes[offset]));
            offset += rootBytes;
        }
    }

    g_manifestTreeRoot = reinterpret_cast<PCManifestRecord>(&payloadBytes[offset]);
    VerifyManifestRoot(g_manifestTreeRoot);

    //
    // Try to read module file and check permissions.
    //

    WCHAR wszFileName[MAX_PATH];
    DWORD nFileName = GetModuleFileNameW(NULL, wszFileName, MAX_PATH);
    if (nFileName == 0 || nFileName == MAX_PATH) {
        FileOperationContext fileOperationContextWithoutModuleName(
            L"Process",
            GENERIC_READ,
            FILE_SHARE_READ,
            OPEN_EXISTING,
            0,
            nullptr);

        ReportFileAccess(
            fileOperationContextWithoutModuleName,
            FileAccessStatus::FileAccessStatus_CannotDeterminePolicy,
            PolicyResult(), // Indeterminate
            AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report),
            GetLastError());
        return true;
    }

    FileOperationContext fileOperationContext = FileOperationContext::CreateForRead(L"Process", wszFileName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(wszFileName)) {
        policyResult.ReportIndeterminatePolicyAndSetLastError(fileOperationContext);
        return true;
    }

    FileReadContext fileReadContext;
    fileReadContext.Existence = FileExistence::Existent; // Clearly this process started somehow.
    fileReadContext.OpenedDirectory = false;

    AccessCheckResult readCheck = policyResult.CheckReadAccess(RequestedReadAccess::Read, fileReadContext);

    ReportFileAccess(
        fileOperationContext,
        readCheck.GetFileAccessStatus(),
        policyResult,
        readCheck,
        ERROR_SUCCESS); // No interesting error code to observe or return to anyone.

    return true;
}

bool LocateAndParseFileAccessManifest()
{
    const void* manifest;
    DWORD manifestSize;

    if (!LocateFileAccessManifest(/*out*/ manifest, /*out*/ manifestSize)) {
        HandleDetoursInjectionAndCommunicationErrors(
            DETOURS_NO_PAYLOAD_FOUND_8,
            L"LocateAndParseFileAccessManifest: Failed to find payload coming from Detours",
            DETOURS_WINDOWS_LOG_MESSAGE_8);
        return false;
    }

    return ParseFileAccessManifest(manifest, manifestSize);
}

DWORD GetReportedError(BOOL result, DWORD error)
{
    return result ? ERROR_SUCCESS : error;
}

void ReportIfNeeded(
    AccessCheckResult const& checkResult,
    FileOperationContext const& context,
    PolicyResult const& policyResult,
    DWORD error,
    wchar_t const* filter)
{
    ReportIfNeeded(checkResult, context, policyResult, error, error, filter);
}

void ReportIfNeeded(
    AccessCheckResult const& checkResult,
    FileOperationContext const& context,
    PolicyResult const& policyResult,
    DWORD error,
    DWORD rawError,
    wchar_t const* filter) 
{
    if (!checkResult.ShouldReport()) {
        return;
    }

    ReportFileAccess(
        context,
        checkResult.GetFileAccessStatus(),
        policyResult,
        checkResult,
        error,
        rawError,
        filter);
}

bool EnumerateDirectory(
    const std::wstring& directoryPath,
    const std::wstring& filter,
    bool recursive,
    bool treatReparsePointAsFile,
    _Inout_ std::vector<std::pair<std::wstring, DWORD>>& filesAndDirectories)
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
    std::stack<std::wstring> directoriesToEnumerate;

    directoriesToEnumerate.push(directoryPath);
    filesAndDirectories.clear();

    while (!directoriesToEnumerate.empty()) {
        std::wstring directoryToEnumerate = directoriesToEnumerate.top();
        std::wstring spec = PathCombine(directoryToEnumerate, filter.c_str());

        directoriesToEnumerate.pop();

        hFind = FindFirstFileW(NormalizePath(spec).c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return false;
        }

        do {
            if (wcscmp(ffd.cFileName, L".") != 0 &&
                wcscmp(ffd.cFileName, L"..") != 0) {

                std::wstring path = PathCombine(directoryToEnumerate, ffd.cFileName);

                filesAndDirectories.push_back(std::make_pair(path, ffd.dwFileAttributes));

                if (recursive) {

                    bool isDirectory = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                    if (isDirectory && treatReparsePointAsFile) {
                        isDirectory = (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
                    }

                    if (isDirectory) {
                        directoriesToEnumerate.push(path);
                    }
                }
            }
        } while (FindNextFile(hFind, &ffd) != 0);

        if (GetLastError() != ERROR_NO_MORE_FILES) {
            FindClose(hFind);
            return false;
        }

        FindClose(hFind);
        hFind = INVALID_HANDLE_VALUE;
    }

    return true;
}

bool ExistsAsFile(_In_ PCWSTR path)
{
    DWORD dwAttrib = GetFileAttributesW(path);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

static DWORD SearchFullPath(
    _In_ LPCWSTR lpPath,
    _In_ LPCWSTR lpFileName,
    _In_ LPCWSTR lpExtension,
    _Inout_ std::wstring& fullPath)
{
    // First, we try with a fixed-sized buffer, which should be good enough for all practical cases.

    wchar_t wszBuffer[MAX_PATH];
    DWORD nBufferLength = std::extent<decltype(wszBuffer)>::value;
    LPWSTR filePart;

    DWORD result = SearchPathW(lpPath, lpFileName, lpExtension, nBufferLength, wszBuffer, &filePart);

    if (result == 0)
    {
        DWORD ret = GetLastError();
        return ret;
    }

    if (result < nBufferLength)
    {
        fullPath.assign(wszBuffer, static_cast<size_t>(result));
    }
    else
    {
        // Second, if that buffer wasn't big enough, we try again with a dynamically allocated buffer with sufficient size.

        // Note that in this case, the return value indicates the required buffer length, INCLUDING the terminating null character.
        // https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-searchpathw
        unique_ptr<wchar_t[]> buffer(new wchar_t[result]);
        assert(buffer.get());

        DWORD result2 = SearchPathW(lpPath, lpFileName, lpExtension, result, buffer.get(), &filePart);

        if (result2 == 0)
        {
            DWORD ret = GetLastError();
            return ret;
        }

        if (result2 < result)
        {
            fullPath.assign(buffer.get(), result2);
        }
        else
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    return ERROR_SUCCESS;
}

static bool ExistsImageFile(_In_ CanonicalizedPath& candidatePath)
{
    if (candidatePath.IsNull())
    {
        return false;
    }

    return ExistsAsFile(candidatePath.GetPathString());
}

static bool TryFindImagePath(_In_ std::wstring& candidatePath, _Out_opt_ CanonicalizedPath& imagePath)
{
    imagePath = CanonicalizedPath::Canonicalize(candidatePath.c_str());
    if (ExistsImageFile(imagePath))
    {
        return true;
    }

    if (HasSuffix(candidatePath.c_str(), candidatePath.length(), L".exe"))
    {
        // Candidate path has .exe already, and it does not exist.
        return false;
    }

    std::wstring candidatePathExe(candidatePath);
    candidatePathExe.append(L".exe");
    imagePath = CanonicalizedPath::Canonicalize(candidatePathExe.c_str());

    return ExistsImageFile(imagePath);
}

static CanonicalizedPath GetCanonicalizedApplicationPath(_In_ LPCWSTR lpApplicationName)
{
    if (GetRootLength(lpApplicationName) > 0)
    {
        // Path is rooted.
        return CanonicalizedPath::Canonicalize(lpApplicationName);
    }

    // Path is not rooted.
    // For example, lpApplicationName can be just "cmd.exe". In this case, we rely on SearchPathW
    // to find the full path. We cannot rely on GetFullPathNameW (as in CanonicalizedPath) because
    // GetFullPathNameW will simply prepend the file name with the current directory, which result in
    // a non-existent path for executables like "cmd.exe".
    std::wstring applicationPath;
    return SearchFullPath(nullptr, lpApplicationName, L".exe", applicationPath) != ERROR_SUCCESS
        ? CanonicalizedPath()
        : CanonicalizedPath::Canonicalize(applicationPath.c_str());;
}

CanonicalizedPath GetImagePath(_In_opt_ LPCWSTR lpApplicationName, _In_opt_ LPWSTR lpCommandLine)
{
    if (lpApplicationName != nullptr)
    {
        return GetCanonicalizedApplicationPath(lpApplicationName);
    }

    if (lpCommandLine == nullptr)
    {
        return CanonicalizedPath();
    }

    LPWSTR cursor = lpCommandLine;
    LPWSTR start = lpCommandLine;
    size_t length = 0;
    std::wstring applicationNamePath(L"");

    if (*cursor == L'\"')
    {
        start = ++cursor;

        while (*cursor && *cursor != L'\"')
        {
            ++cursor;
            ++length;
        }

        // Unlike the implementation of CreateProcessW that runs the expanded path logic (as in the else branch below),
        // we simply search for the ending quote and use the found path as the application path.
        // We do this because we don't want to slow down 99% cases by going to the file system to check file existence.
        applicationNamePath.assign(start, length);
        return GetCanonicalizedApplicationPath(applicationNamePath.c_str());
    }
    else
    {
        // Skip past space and tab.
        while (*cursor && (*cursor == L' ' || *cursor == L'\t'))
        {
            ++cursor;
        }

        do
        {
            start = cursor;
            length = 0;

            // Skip past space and tab.
            while (*cursor && (*cursor == L' ' || *cursor == L'\t'))
            {
                ++cursor;
                ++length;
            }

            // Look for the first whitespace/tab.
            while (*cursor && *cursor != L' ' && *cursor != L'\t')
            {
                ++cursor;
                ++length;
            }

            CanonicalizedPath imagePath;
            applicationNamePath.append(start, length);

            if (GetRootLength(applicationNamePath.c_str()) > 0)
            {
                if (TryFindImagePath(applicationNamePath, imagePath))
                {
                    return imagePath;
                }
            }
            else
            {
                // For non-rooted path, check path existence using SearchFullPath.
                imagePath = GetCanonicalizedApplicationPath(applicationNamePath.c_str());
                if (!imagePath.IsNull())
                {
                    return imagePath;
                }
            }
        } while (*cursor);

        return CanonicalizedPath();
    }
}
