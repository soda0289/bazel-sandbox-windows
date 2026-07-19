// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"

#include "DetouredFunctions.h"
#include "DetouredScope.h"
#include "HandleOverlay.h"
#include "MetadataOverrides.h"
#include "ResolvedPathCache.h"
#include "SendReport.h"
#include "StringOperations.h"
#include "SubstituteProcessExecution.h"
#include "UnicodeConverter.h"

// BazelSandbox: -n network hardening at the syscall layer (deny \Device\Afd).
#include "network_detours.h"

#include <Pathcch.h>
#include <algorithm>

using std::map;
using std::vector;
using std::wstring;

#if _MSC_VER >= 1200
#pragma warning(disable:26812) // Disable: The enum type ‘X’ is unscoped warnings originating from the WinSDK
#endif

// ----------------------------------------------------------------------------
// FUNCTION DEFINITIONS
// ----------------------------------------------------------------------------

#define IMPLEMENTED(x) // bookeeping to remember which functions have been fully implemented and which still need to be done
#define RETRY_DETOURING_PROCESS_COUNT 5 // How many times to retry detouring a process.
#define RETRY_DETOURING_PROCESS_SLEEP_MS 1000 // How long to sleep between retries.
#define DETOURS_STATUS_ACCESS_DENIED (NTSTATUS)0xC0000022L;
#define INITIAL_REPARSE_DATA_BUILDXL_DETOURS_BUFFER_SIZE_FOR_FILE_NAMES 1024
#define SYMLINK_FLAG_RELATIVE 0x00000001

#define _MAX_EXTENDED_PATH_LENGTH 32768 // see https://docs.microsoft.com/en-us/cpp/c-runtime-library/path-field-limits?view=vs-2019
#define _MAX_EXTENDED_DIR_LENGTH (_MAX_EXTENDED_PATH_LENGTH - _MAX_DRIVE - _MAX_FNAME - _MAX_EXT - 4)

#define NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE 4096

static bool IgnoreFullReparsePointResolvingForPath(const PolicyResult& policyResult)
{
    return IgnoreFullReparsePointResolving() && !policyResult.EnableFullReparsePointParsing();
}

/// <summary>
/// Given a policy result, get the level of the file path where the path should start to be checked for reparse points.
/// d: is level 0, d:\a is level 1, etc...
/// Every level >= the returned level should be checked for a reparse point.
/// If a reparse point is found, all levels of the newly resolved path should be checked for reparse points again.
/// Calls <code>IgnoreFullReparsePointResolving</code> and <code>PolicyResult.GetFirstLevelForFileAccessPolicy</code> to determine the level.
/// </summary>
static size_t GetLevelToEnableFullReparsePointParsing(const PolicyResult& policyResult)
{
    return IgnoreFullReparsePointResolving()
        ? policyResult.FindLowestConsecutiveLevelThatStillHasProperty(FileAccessPolicy::FileAccessPolicy_EnableFullReparsePointParsing)
        : 0;
}

/// <summary>
/// Checks if a file is a reparse point by calling <code>GetFileAttributesW</code>.
/// </summary>
static bool IsReparsePoint(_In_ LPCWSTR lpFileName, _In_ HANDLE hFile)
{
    DWORD lastError = GetLastError();
    if (hFile != INVALID_HANDLE_VALUE)
    {
        BY_HANDLE_FILE_INFORMATION fileInfo;
        BOOL result = GetFileInformationByHandle(hFile, &fileInfo);
        if (result)
        {
            SetLastError(lastError);
            return (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        }
    }

    DWORD attributes;
    bool result = lpFileName != nullptr
        && ((attributes = GetFileAttributesW(lpFileName)) != INVALID_FILE_ATTRIBUTES)
        && ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);

    SetLastError(lastError);

    return result;
}

/// <summary>
/// Gets reparse point type of a file name by querying <code>dwReserved0</code> field of <code>WIN32_FIND_DATA</code>.
/// </summary>
static DWORD GetReparsePointType(_In_ LPCWSTR lpFileName, _In_ HANDLE hFile)
{
    DWORD ret = 0;
    DWORD lastError = GetLastError();

    if (IsReparsePoint(lpFileName, hFile))
    {
        WIN32_FIND_DATA findData;

        HANDLE findDataHandle = FindFirstFileW(lpFileName, &findData);
        if (findDataHandle != INVALID_HANDLE_VALUE)
        {
            ret = findData.dwReserved0;
            FindClose(findDataHandle);
        }
    }

    SetLastError(lastError);
    return ret;
}

/// <summary>
/// Checks if a reparse point type is actionable, i.e., it is either <code>IO_REPARSE_TAG_SYMLINK</code> or <code>IO_REPARSE_TAG_MOUNT_POINT</code>.
/// </summary>
static bool IsActionableReparsePointType(_In_ const DWORD reparsePointType)
{
    return reparsePointType == IO_REPARSE_TAG_SYMLINK || reparsePointType == IO_REPARSE_TAG_MOUNT_POINT;
}

/// <summary>
/// Checks if the flags or attributes field contains the reparse point flag.
/// </summary>
static bool FlagsAndAttributesContainReparsePointFlag(_In_ DWORD dwFlagsAndAttributes)
{
    return (dwFlagsAndAttributes & FILE_FLAG_OPEN_REPARSE_POINT) != 0;
}

/// <summary>
/// Check if file access is trying to access reparse point target.
/// </summary>
static bool AccessReparsePointTarget(
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_     HANDLE                hFile)
{
    return !FlagsAndAttributesContainReparsePointFlag(dwFlagsAndAttributes) && IsReparsePoint(lpFileName, hFile);
}

/// <summary>
/// Gets the final full path by handle.
/// </summary>
/// <remarks>
/// This function encapsulates calls to <code>GetFinalPathNameByHandleW</code> and allocates memory as needed.
/// </remarks>
static DWORD DetourGetFinalPathByHandle(_In_ HANDLE hFile, _Inout_ wstring& fullPath)
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

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// Resolved path cache /////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static void PathCache_Invalidate(const std::wstring& path, bool isDirectory, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return;
    }

    ResolvedPathCache::Instance().Invalidate(path, isDirectory);
}

static const Possible<std::pair<std::wstring, DWORD>> PathCache_GetResolvedPathAndType(const std::wstring& path, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        Possible<std::pair<std::wstring, DWORD>> p;
        p.Found = false;
        return p;
    }

    return ResolvedPathCache::Instance().GetResolvedPathAndType(path);
}

static bool PathCache_InsertResolvedPathWithType(const std::wstring& path, std::wstring& resolved, DWORD reparsePointType, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return true;
    }

    return ResolvedPathCache::Instance().InsertResolvedPathWithType(path, resolved, reparsePointType);
}

static const Possible<bool> PathCache_GetResolvingCheckResult(const std::wstring& path, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        Possible<bool> p;
        p.Found = false;
        return p;
    }

    return ResolvedPathCache::Instance().GetResolvingCheckResult(path);
}

static bool PathCache_InsertResolvingCheckResult(const std::wstring& path, bool result, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return true;
    }

    return ResolvedPathCache::Instance().InsertResolvingCheckResult(path, result);
}

static bool PathCache_InsertResolvedPaths(
    const std::wstring& path,
    bool preserveLastReparsePointInPath,
    std::shared_ptr<std::vector<std::wstring>>& insertionOrder,
    std::shared_ptr<std::map<std::wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>& resolvedPaths, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return true;
    }

    return ResolvedPathCache::Instance().InsertResolvedPaths(path, preserveLastReparsePointInPath, insertionOrder, resolvedPaths);
}

static const Possible<ResolvedPathCacheEntries> PathCache_GetResolvedPaths(const std::wstring& path, bool preserveLastReparsePointInPath, const PolicyResult& policyResult)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        Possible<ResolvedPathCacheEntries> p;
        p.Found = false;
        return p;
    }

    return ResolvedPathCache::Instance().GetResolvedPaths(path, preserveLastReparsePointInPath);
}

/// <summary>
/// Gets target name from <code>REPARSE_DATA_BUFFER</code>.
/// </summary>
static void GetTargetNameFromReparseData(_In_ PREPARSE_DATA_BUFFER pReparseDataBuffer, _In_ DWORD reparsePointType, _Out_ wstring& name)
{
    // In what follows, we first try to extract target name in the path buffer using the PrintNameOffset.
    // If it is empty or a single space, we try to extract target name from the SubstituteNameOffset.
    // This is pretty much guess-work. Tools like mklink and CreateSymbolicLink API insert the target name
    // from the PrintNameOffset. But others may use DeviceIoControl directly to insert the target name from SubstituteNameOffset.
    if (reparsePointType == IO_REPARSE_TAG_SYMLINK)
    {
        name.assign(
            pReparseDataBuffer->SymbolicLinkReparseBuffer.PathBuffer + pReparseDataBuffer->SymbolicLinkReparseBuffer.PrintNameOffset / sizeof(WCHAR),
            (size_t)pReparseDataBuffer->SymbolicLinkReparseBuffer.PrintNameLength / sizeof(WCHAR));

        if (name.size() == 0 || name == L" ")
        {
            name.assign(
                pReparseDataBuffer->SymbolicLinkReparseBuffer.PathBuffer + pReparseDataBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR),
                (size_t)pReparseDataBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
        }
    }
    else if (reparsePointType == IO_REPARSE_TAG_MOUNT_POINT)
    {
        name.assign(
            pReparseDataBuffer->MountPointReparseBuffer.PathBuffer + pReparseDataBuffer->MountPointReparseBuffer.PrintNameOffset / sizeof(WCHAR),
            (size_t)pReparseDataBuffer->MountPointReparseBuffer.PrintNameLength / sizeof(WCHAR));

        if (name.size() == 0 || name == L" ")
        {
            name.assign(
                pReparseDataBuffer->MountPointReparseBuffer.PathBuffer + pReparseDataBuffer->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR),
                (size_t)pReparseDataBuffer->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
        }
    }
}

/// <summary>
/// Sets target name on <code>REPARSE_DATA_BUFFER</code> for both print and substitute names. 
/// See https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer for details.
/// Assumes the provided buffer is large enough to hold the target name.
/// Sets both the print name and the substitute name (depending on the consumer, one or both may be used).
/// </summary>
static void SetTargetNameFromReparseData(_In_ PREPARSE_DATA_BUFFER pReparseDataBuffer, _In_ DWORD reparsePointType, _In_ wstring& target)
{
    USHORT targetLengthInBytes = (USHORT)(target.length() * sizeof(WCHAR));

    // In both cases we put the print name at the beginning of the buffer, followed by the substitute name.
    // The order of these is up to the implementation.
    if (reparsePointType == IO_REPARSE_TAG_SYMLINK)
    {
        memcpy(
            pReparseDataBuffer->SymbolicLinkReparseBuffer.PathBuffer,
            target.c_str(),
            targetLengthInBytes);
        pReparseDataBuffer->SymbolicLinkReparseBuffer.PrintNameLength = targetLengthInBytes;
        pReparseDataBuffer->SymbolicLinkReparseBuffer.PrintNameOffset = 0;

        memcpy(
            pReparseDataBuffer->SymbolicLinkReparseBuffer.PathBuffer + targetLengthInBytes / sizeof(WCHAR),
            target.c_str(),
            targetLengthInBytes);
        pReparseDataBuffer->SymbolicLinkReparseBuffer.SubstituteNameLength = targetLengthInBytes;
        pReparseDataBuffer->SymbolicLinkReparseBuffer.SubstituteNameOffset = targetLengthInBytes;
    }
    else if (reparsePointType == IO_REPARSE_TAG_MOUNT_POINT)
    {
        memcpy(
            pReparseDataBuffer->MountPointReparseBuffer.PathBuffer,
            target.c_str(),
            targetLengthInBytes);
        pReparseDataBuffer->MountPointReparseBuffer.PrintNameLength = targetLengthInBytes;
        pReparseDataBuffer->MountPointReparseBuffer.PrintNameOffset = 0;

        memcpy(
            pReparseDataBuffer->MountPointReparseBuffer.PathBuffer + targetLengthInBytes / sizeof(WCHAR),
            target.c_str(),
            targetLengthInBytes);
        pReparseDataBuffer->MountPointReparseBuffer.SubstituteNameLength = targetLengthInBytes;
        pReparseDataBuffer->MountPointReparseBuffer.SubstituteNameOffset = targetLengthInBytes;
    }
}

/// <summary>
/// Get the reparse point target via DeviceIoControl
/// </summary>
static bool TryGetReparsePointTarget(_In_ const wstring& path, _In_ HANDLE hInput, _Inout_ wstring& target, const PolicyResult& policyResult)
{
    bool isReparsePoint;
    auto result = PathCache_GetResolvingCheckResult(path, policyResult);
    if (result.Found)
    {
        isReparsePoint = result.Value;
    }
    else
    {
        isReparsePoint = IsReparsePoint(path.c_str(), hInput);
        PathCache_InsertResolvingCheckResult(path, isReparsePoint, policyResult);
    }

    if (!isReparsePoint)
    {
        return false;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD lastError = GetLastError();
    DWORD reparsePointType = 0;
    vector<char> buffer;
    bool status = false;
    DWORD bufferSize = INITIAL_REPARSE_DATA_BUILDXL_DETOURS_BUFFER_SIZE_FOR_FILE_NAMES;
    DWORD errorCode = ERROR_INSUFFICIENT_BUFFER;
    DWORD bufferReturnedSize = 0;
    PREPARSE_DATA_BUFFER pReparseDataBuffer;

    auto io_result = PathCache_GetResolvedPathAndType(path, policyResult);
    if (io_result.Found)
    {

#if MEASURE_REPARSEPOINT_RESOLVING_IMPACT
        InterlockedIncrement(&g_reparsePointTargetCacheHitCount);
#endif // MEASURE_REPARSEPOINT_RESOLVING_IMPACT

        target = io_result.Value.first;
        reparsePointType = io_result.Value.second;
        if (reparsePointType == 0x0)
        {
            goto Epilogue;
        }
        goto Success;
    }

    hFile = hInput != INVALID_HANDLE_VALUE
        ? hInput
        : CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        goto Error;
    }

    while (errorCode == ERROR_MORE_DATA || errorCode == ERROR_INSUFFICIENT_BUFFER)
    {
        buffer.clear();
        buffer.resize(bufferSize);

        BOOL success = DeviceIoControl(
            hFile,
            FSCTL_GET_REPARSE_POINT,
            nullptr,
            0,
            buffer.data(),
            bufferSize,
            &bufferReturnedSize,
            nullptr);

        if (success)
        {
            errorCode = ERROR_SUCCESS;
        }
        else
        {
            bufferSize *= 2; // Increase buffer size
            errorCode = GetLastError();
        }
    }

    if (errorCode != ERROR_SUCCESS)
    {
        goto Error;
    }

    pReparseDataBuffer = (PREPARSE_DATA_BUFFER)buffer.data();
    reparsePointType = pReparseDataBuffer->ReparseTag;

    if (!IsActionableReparsePointType(reparsePointType))
    {
        goto Error;
    }

    GetTargetNameFromReparseData(pReparseDataBuffer, reparsePointType, target);
    PathCache_InsertResolvedPathWithType(path, target, reparsePointType, policyResult);

Success:

    status = true;
    goto Epilogue;

Error:

    // Also add dummy cache entry for paths that are not reparse points, so we can avoid calling DeviceIoControl repeatedly
    PathCache_InsertResolvedPathWithType(path, target, 0x0, policyResult);

Epilogue:

    if (hFile != INVALID_HANDLE_VALUE && hFile != hInput)
    {
        CloseHandle(hFile);
    }

    SetLastError(lastError);
    return status;
}

/// <summary>
/// Checks if Detours should resolve all reparse points contained in a path.
/// </summary>
/// <remarks>
/// Given a path this function traverses it from left to right, checking if any components
/// are of type 'reparse point'. As soon as an entry of that type is found, a positive result
/// is returned, indicating that the path needs further processing to properly indicate all
/// potential reparse point targets as file accesses upstream.
/// </remarks>
static bool ShouldResolveReparsePointsInPath(
    _In_     const CanonicalizedPath& path,
    _In_     DWORD                    dwFlagsAndAttributes,
    _In_     const PolicyResult&      policyResult)
{
    if (IgnoreReparsePoints())
    {
        return false;
    }

    if (IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return AccessReparsePointTarget(path.GetPathString(), dwFlagsAndAttributes, INVALID_HANDLE_VALUE);
    }

    // Untracked scopes never need full reparse point resolution
    if (policyResult.IndicateUntracked() && IgnoreUntrackedPathsInFullReparsePointResolving())
    {
        return false;
    }

    auto result = PathCache_GetResolvingCheckResult(path.GetPathStringWithoutTypePrefix(), policyResult);
    if (result.Found)
    {
#if MEASURE_REPARSEPOINT_RESOLVING_IMPACT
        InterlockedIncrement(&g_shouldResolveReparsePointCacheHitCount);
#endif // MEASURE_REPARSEPOINT_RESOLVING_IMPACT
        return result.Value;
    }

    std::vector<std::wstring> atoms;
    int err = TryDecomposePath(path.GetPathStringWithoutTypePrefix(), atoms);
    if (err != 0)
    {
        Dbg(L"ShouldResolveReparsePointsInPath: _wsplitpath_s failed, not resolving path: %d", err);
        return false;
    }

    wstring target;
    wstring resolver;
    size_t level = 0;
    size_t levelToEnforceReparsePointParsingFrom = GetLevelToEnableFullReparsePointParsing(policyResult);
    for (auto iter = atoms.begin(); iter != atoms.end(); iter++)
    {
        resolver.append(*iter);

        if (level >= levelToEnforceReparsePointParsingFrom && TryGetReparsePointTarget(resolver, INVALID_HANDLE_VALUE, target, policyResult))
        {
            return true;
        }

        level++;

        resolver.append(L"\\");
    }

    // remove the trailing backslash
    resolver.pop_back();

    if (level >= levelToEnforceReparsePointParsingFrom && TryGetReparsePointTarget(resolver, INVALID_HANDLE_VALUE, target, policyResult))
    {
        return true;
    }

    return false;
}

// If the given path does not contain reparse points but the handle was open for write and open reparse point flag was passed,
// then this may be the step previous to turning that directory into a reparse point. We don't detour the actual ioctl call, but conservatively we
// invalidate the path from the cache. Otherwise, if the ioctl call actually happens, all subsequent reads on the path won't be resolved.
static void InvalidateReparsePointCacheIfNeeded(
    bool pathContainsReparsePoints,
    DWORD desiredAccess,
    DWORD flagsAndAttributes,
    bool isDirectory,
    const wchar_t* path,
    const PolicyResult& policyResult)
{
    if (!pathContainsReparsePoints
        && !IgnoreReparsePoints()
        && !IgnoreFullReparsePointResolvingForPath(policyResult)
        && WantsWriteAccess(desiredAccess)
        && FlagsAndAttributesContainReparsePointFlag(flagsAndAttributes))
    {
        PathCache_Invalidate(path, isDirectory, policyResult);
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Symlink traversal utilities /////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/// <summary>
/// Split paths into path atoms and insert them into <code>atoms</code> in reverse order.
/// </summary>
static void SplitPathsReverse(_In_ const wstring& path, _Inout_ vector<wstring>& atoms)
{
    size_t length = path.length();

    if (length >= 2 && IsDirectorySeparator(path[length - 1]))
    {
        // Skip ending directory separator without trimming the path.
        --length;
    }

    size_t rootLength = GetRootLength(path.c_str());

    if (length <= rootLength)
    {
        return;
    }

    size_t i = length - 1;
    wstring dir = path;

    while (i >= rootLength)
    {
        while (i > rootLength && !IsDirectorySeparator(dir[i]))
        {
            --i;
        }

        if (i >= rootLength)
        {
            atoms.push_back(dir.substr(i));
        }

        dir = dir.substr(0, i);

        if (i == 0)
        {
            break;
        }

        --i;
    }

    if (!dir.empty())
    {
        atoms.push_back(dir);
    }
}

/// <summary>
/// Resolves a reparse point path with respect to its relative target.
/// </summary>
/// <remarks>
/// Given a reparse point path A\B\C and its relative target D\E\F, this method
/// simply "combines" A\B and D\E\F. The symlink C is essentially replaced by the relative target D\E\F.
/// </remarks>
static bool TryResolveRelativeTarget(
    _Inout_ wstring& result,
    _In_ const wstring& relativeTarget,
    _In_ vector<wstring> *processed,
    _In_ vector<wstring> *needToBeProcessed)
{
    // Trim directory separator ending.
    if (result[result.length() - 1] == L'\\')
    {
        result = result.substr(0, result.length() - 1);
    }

    // Skip last path atom.
    size_t lastSeparator = result.find_last_of(L'\\');
    if (lastSeparator == std::string::npos)
    {
        return false;
    }

    if (processed != nullptr)
    {
        if (processed->empty())
        {
            return false;
        }

        processed->pop_back();
    }

    // Handle '.' and '..' in the relative target.
    size_t pos = 0;
    size_t length = relativeTarget.length();
    bool startWithDotSlash = length >= 2 && relativeTarget[pos] == L'.' && relativeTarget[pos + 1] == L'\\';
    bool startWithDotDotSlash = length >= 3 && relativeTarget[pos] == L'.' && relativeTarget[pos + 1] == L'.' && relativeTarget[pos + 2] == L'\\';

    while ((startWithDotDotSlash || startWithDotSlash) && lastSeparator != std::string::npos)
    {
        if (startWithDotSlash)
        {
            pos += 2;
            length -= 2;
        }
        else
        {
            pos += 3;
            length -= 3;
            lastSeparator = result.find_last_of(L'\\', lastSeparator - 1);
            if (processed != nullptr && !processed->empty())
            {
                if (processed->empty())
                {
                    return false;
                }

                processed->pop_back();
            }
        }

        startWithDotSlash = length >= 2 && relativeTarget[pos] == L'.' && relativeTarget[pos + 1] == L'\\';
        startWithDotDotSlash = length >= 3 && relativeTarget[pos] == L'.' && relativeTarget[pos + 1] == L'.' && relativeTarget[pos + 2] == L'\\';
    }

    if (lastSeparator == std::string::npos && startWithDotDotSlash)
    {
        return false;
    }

    wstring slicedTarget;
    slicedTarget.append(relativeTarget, pos, length);

    result = result.substr(0, lastSeparator != std::string::npos ? lastSeparator : 0);

    if (needToBeProcessed != nullptr)
    {
        SplitPathsReverse(slicedTarget, *needToBeProcessed);
    }
    else
    {
        result.push_back(L'\\');
        result.append(slicedTarget);
    }

    return true;
}

/// <summary>
/// Resolves the reparse points with relative target.
/// </summary>
/// <remarks>
/// This method resolves reparse points that occur in the path prefix. This method should only be called when path itself
/// is an actionable reparse point whose target is a relative path.
/// This method traverses each prefix starting from the shortest one. Every time it encounters a directory symlink, it uses GetFinalPathNameByHandle to get the final path.
/// However, if the prefix itself is a junction, then it leaves the current resolved path intact.
/// The following example show the needs for this method as a prerequisite in getting
/// the immediate target of a reparse point. Suppose that we have the following file system layout:
///
///    repo
///    |
///    +---intermediate
///    |   \---current
///    |         symlink1.link ==> ..\..\target\file1.txt
///    |         symlink2.link ==> ..\target\file2.txt
///    |
///    +---source ==> intermediate\current (case 1: directory symlink, case 2: junction)
///    |
///    \---target
///          file1.txt
///          file2.txt
///
/// **CASE 1**: source ==> intermediate\current is a directory symlink.
///
/// If a tool accesses repo\source\symlink1.link (say 'type repo\source\symlink1.link'), then the tool should get the content of repo\target\file1.txt.
/// If the tool accesses repo\source\symlink2.link, then the tool should get path-not-found error because the resolved path will be repo\intermediate\target\file2.txt.
/// Now, if we try to resolve repo\source\symlink1.link by simply combining it with ..\..\target\file1.txt, then we end up with target\file1.txt (not repo\target\file1.txt),
/// which is a non-existent path. To resolve repo\source\symlink1, we need to resolve the reparse points of its prefix, i.e., repo\source. For directory symlinks,
/// we need to resolve the prefix to its target. I.e., repo\source is resolved to repo\intermediate\current, and so, given repo\source\symlink1.link, this method returns
/// repo\intermediate\current\symlink1.link. Combining repo\intermediate\current\symlink1.link with ..\..\target\file1.txt will give the correct path, i.e., repo\target\file1.txt.
///
/// Similarly, given repo\source\symlink2.link, the method returns repo\intermediate\current\symlink2.link, and combining it with ..\target\file2.txt, will give us
/// repo\intermediate\target\file2.txt, which is a non-existent path. This corresponds to the behavior of symlink accesses above.
///
/// **CASE 2**: source ==> intermediate\current is a junction.
///
/// If a tool accesses repo\source\symlink1.link (say 'type repo\source\symlink1.link'), then the tool should get path-not-found error because the resolve path will be target\file1.txt (not repo\target\file1).
/// If the tool accesses repo\source\symlink2.link, then the tool should the content of repo\target\file2.txt.
/// Unlike directory symlinks, when we try to resolve repo\source\symlink2.link, the prefix repo\source is left intact because it is a junction. Thus, combining repo\source\symlink2.link
/// with ..\target\file2.txt results in a correct path, i.e., repo\target\file2.txt. The same reasoning can be given for repo\source\symlink1.link, and its resolution results in
/// a non-existent path target\file1.txt.
/// </remarks>
static bool TryResolveRelativeTarget(_In_ const wstring& path, _In_ const wstring& relativeTarget, _Inout_ wstring& result, _In_ const PolicyResult& policyResult)
{
    vector<wstring> needToBeProcessed;
    vector<wstring> processed;

    // Split path into atoms that need to be processed one-by-one.
    // For example, C:\P1\P2\P3\symlink --> symlink, P3, P1, P2, C:
    SplitPathsReverse(path, needToBeProcessed);

    while (!needToBeProcessed.empty())
    {
        wstring atom = needToBeProcessed.back();
        needToBeProcessed.pop_back();
        processed.push_back(atom);

        if (!result.empty())
        {
            // Append directory separator as necessary.
            if (result[result.length() - 1] != L'\\' && atom[0] != L'\\')
            {
                result.append(L"\\");
            }
        }

        result.append(atom);

        if (needToBeProcessed.empty())
        {
            // The last atom is the symlink that we are going to replace.
            break;
        }

        if (GetReparsePointType(result.c_str(), INVALID_HANDLE_VALUE) == IO_REPARSE_TAG_SYMLINK)
        {
            // Prefix path is a directory symlink.
            // For example, C:\P1\P2 is a directory symlink.

            // Get the next target of the directory symlink.
            wstring target;
            if (!TryGetReparsePointTarget(result, INVALID_HANDLE_VALUE, target, policyResult))
            {
                return false;
            }

            if (GetRootLength(target.c_str()) > 0)
            {
                // The target of the directory symlink is a rooted path:
                // - clear result so far,
                // - restart all the processed atoms,
                // - initialize the atoms to be processed.
                result.clear();
                processed.clear();
                SplitPathsReverse(target, needToBeProcessed);
            }
            else
            {
                // The target of the directory symlink is a relative path, then resolve it by "combining"
                // the directory symlink (stored in the result) and the relative target.
                if (!TryResolveRelativeTarget(result, target, &processed, &needToBeProcessed))
                {
                    return false;
                }
            }
        }
    }

    // Finally, resolve the last atom, i.e., the symlink atom.
    if (!TryResolveRelativeTarget(result, relativeTarget, nullptr, nullptr))
    {
        return false;
    }

    return true;
}

/// <summary>
/// Get the next path of a reparse point path.
/// </summary>
static bool TryGetNextPath(_In_ const wstring& path, _In_ HANDLE hInput, _Inout_ wstring& result, _In_ const PolicyResult& policyResult)
{
    wstring target;

    // Get the next target of a reparse point path.
    if (!TryGetReparsePointTarget(path, hInput, target, policyResult))
    {
        return false;
    }

    if (GetRootLength(target.c_str()) > 0)
    {
        // The next target is a rooted path, then return it as is.
        result.assign(target);
    }
    else
    {
        // The next target is a relative path, then resolve it first.
        if (!TryResolveRelativeTarget(path, target, result, policyResult))
        {
            return false;
        }
    }

    return true;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Symlink traversal utilities /////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/// <summary>
/// Gets chains of the paths leading to and including the final path given the file name.
/// </summary>
static void DetourGetFinalPaths(_In_ const CanonicalizedPath& path, _In_ HANDLE hInput, _Inout_ std::shared_ptr<vector<wstring>>& order, _Inout_ std::shared_ptr<map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>& finalPaths, _In_ const PolicyResult& policyResult)
{
    HANDLE handle = hInput;
    wstring currentPath = path.GetPathString();

    while (true)
    {
        order->push_back(currentPath);

        wstring nextPath;
        auto nextPathResult = TryGetNextPath(currentPath, handle, nextPath, policyResult);
        handle = INVALID_HANDLE_VALUE;

        if (nextPathResult)
        {
            // If there's a next path, then the current path is an intermediate path.
            finalPaths->emplace(currentPath, ResolvedPathType::Intermediate);
            currentPath = CanonicalizedPath::Canonicalize(nextPath.c_str()).GetPathString();
        }
        else
        {
            // If the next path was not found, then the current path is considered fully resolved (although full symlink resolution is not enabled here).
            finalPaths->emplace(currentPath, ResolvedPathType::FullyResolved);
            break;
        }

        if (std::find(order->begin(), order->end(), currentPath) != order->end())
        {
            // If a cycle was detected in the chain of symlinks, we will log it, and return back the symlinks up to the last resolved path, not including any duplicates.
            WriteWarningOrErrorF(L"Cycle found when attempting to resolve symlink path '%s'.", path.GetPathString());
            break;
        }
    }
}

/// <summary>
/// Gets the file attributes for a given path. Returns false if no valid attributes were found or if a NULL path is provided.
/// </summary>
static bool GetFileAttributesByPath(_In_ LPCWSTR lpFileName, _Out_ DWORD& attributes)
{
    DWORD lastError = GetLastError();
    if (lpFileName == NULL)
    {
        attributes = INVALID_FILE_ATTRIBUTES;
    }
    else
    {
        attributes = GetFileAttributesW(lpFileName);
    }

    SetLastError(lastError);

    return INVALID_FILE_ATTRIBUTES != attributes;
}

/// <summary>
/// Gets the file attributes for a given handle. Returns false if the GetFileInformationCall fails.
/// </summary>
static bool GetFileAttributesByHandle(_In_ HANDLE hFile, _Out_ DWORD& attributes)
{
    DWORD lastError = GetLastError();
    BY_HANDLE_FILE_INFORMATION fileInfo;
    BOOL res = GetFileInformationByHandle(hFile, &fileInfo);
    SetLastError(lastError);

    attributes = res ? fileInfo.dwFileAttributes : INVALID_FILE_ATTRIBUTES;

    return res;
}

static bool ShouldTreatDirectoryReparsePointAsFile(
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_     const PolicyResult&   policyResult)
{
    // Directory reparse point is treated as file if
    // 1. full reparse point resolution is enabled globally or by the access policy, and
    // 2. the operation performed specifies FILE_FLAG_OPEN_REPARSE_POINT attribute, or the operation is a write operation, and
    // 3. the policy does not mandate directory symlink to be treated as directory, and
    // 4. either the operation is not a probe operation, or it is set globally that directory symlink probe should not be treated as directory.
    //
    // The first condition of the enablement of full reparse point resolution is required because customers who have not enabled full reparse point resolution
    // have not specified directory symlinks as files in their spec files. Thus, if those symlinks are treated as files, they will start getting
    // disallowed file access violations.
    //
    // The check for FILE_FLAG_OPEN_REPARSE_POINT is needed to handle operations like CreateFile variants that will access the target directory
    // if FILE_FLAG_OPEN_REPARSE_POINT is not specified, even though the access is only FILE_READ_ATTRIBUTES. In such a case, the CreateFile call
    // is often used to probe the existence of the target directory.
    //
    // If the operation is a write operation, then the write is done to the directory symlink itself, and not to the target directory, and thus
    // the directory symlink should be treated as a file. We cannot do the same for read operations, because the read operation could often be used
    // as a probe operation to check if the target directory exists. Thus, for read operations, we need to check for FILE_FLAG_OPEN_REPARSE_POINT.
    //
    // Directory paths specified in the directory translator can be directory symlinks or junctions that are meant to be directories in normal circumstances
    // Those paths should be marked as being treated as directories in the file access manifest, and thus will be reflected in the policy result.
    //
    // If the operation is a probe-only operation, then this is a million dollar question. Ideally, if FILE_FLAG_OPEN_REPARSE_POINT is used, then
    // the directory symlink should be treated as a directory. However, many Windows tools tend to emit many such innocuous probes through, for example,
    // FindFirstFile or GetFileAttributes variants. If treated as a file, then the access can be denied (see CheckReadAccess in PolicyResult_common.cpp).
    // This access denial can break many tools or cause a lot of disallowed file access violations. Thus, we have a global flag whether to treat probed
    // directory symlinks as a directory or not; for now, the flag is set to true.

    return !IgnoreFullReparsePointResolvingForPath(policyResult)            // Full reparse point resolving is enabled,
        && (FlagsAndAttributesContainReparsePointFlag(dwFlagsAndAttributes) // and open attribute contains reparse point flag,
            || WantsWriteAccess(dwDesiredAccess))                           //   or write access is requested,
        && !policyResult.TreatDirectorySymlinkAsDirectory()                 // and policy does not mandate directory symlink to be treated as directory
        && (!WantsProbeOnlyAccess(dwDesiredAccess)                          // and either it is not a probe access,
            || !ProbeDirectorySymlinkAsDirectory());                        //   or it is set globally that directory symlink probe should not be treated as directory.
}

/// <summary>
/// Checks if a path is a directory given a set of attributes. Note that fileOrDirectoryAttribute is not affected by treatReparsePointAsFile.
/// </summary>
static bool IsDirectoryFromAttributes(_In_ DWORD attributes, _In_ bool treatReparsePointAsFile)
{
    bool isDirectory = attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    return isDirectory && (!treatReparsePointAsFile || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
}

/// <summary>
/// Returns file attributes for a file or directory based on the isDirectory condition.
/// </summary>
static DWORD GetAttributesForFileOrDirectory(bool isDirectory)
{
    return FILE_ATTRIBUTE_NORMAL | (isDirectory ? FILE_ATTRIBUTE_DIRECTORY : 0UL);
}

/// <summary>
/// Checks if a path or handle is a directory given a set of attributes. Note that fileOrDirectoryAttribute is not affected by treatReparsePointAsFile.
/// </summary>
static bool IsHandleOrPathToDirectory(
    _In_     HANDLE                hFile,
    _In_     LPCWSTR               lpFileName,
    _In_     bool                  treatReparsePointAsFile,
    _Out_    DWORD&                fileOrDirectoryAttribute)
{
    fileOrDirectoryAttribute = INVALID_FILE_ATTRIBUTES;
    bool attributesFromHandleResult = false;

    if (INVALID_HANDLE_VALUE != hFile)
    {
        attributesFromHandleResult = GetFileAttributesByHandle(hFile, /*ref*/ fileOrDirectoryAttribute);
    }

    if (!attributesFromHandleResult)
    {
        GetFileAttributesByPath(lpFileName, /*ref*/ fileOrDirectoryAttribute);
    }

    return IsDirectoryFromAttributes(fileOrDirectoryAttribute, treatReparsePointAsFile);
}

/// <summary>
/// Checks if a path or handle is a directory given a set of attributes. Note that fileOrDirectoryAttribute is not affected by treatReparsePointAsFile.
/// </summary>
static bool IsHandleOrPathToDirectory(
    _In_     HANDLE                hFile,
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_     const PolicyResult&   policyResult,
    _Out_    DWORD&                fileOrDirectoryAttribute)
{
    bool treatReparsePointAsFile = ShouldTreatDirectoryReparsePointAsFile(dwDesiredAccess, dwFlagsAndAttributes, policyResult);
    return IsHandleOrPathToDirectory(hFile, lpFileName, treatReparsePointAsFile, fileOrDirectoryAttribute);
}

/// <summary>
/// Enforces allowed access for a particular path that leads to the target of a reparse point.
/// </summary>
static bool EnforceReparsePointAccess(
    const wstring& reparsePointPath,
    const DWORD dwDesiredAccess,
    const DWORD dwShareMode,
    const DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    NTSTATUS* pNtStatus = nullptr,
    const bool enforceAccess = true,
    const bool isCreateDirectory = false,
    const bool isFullyResolvedPath = false,
    const wstring& contextOperationName = L"ReparsePointTarget")
{
    DWORD lastError = GetLastError();
    const wchar_t* lpReparsePointPath = reparsePointPath.c_str();

    // Start with allow / ignore (no access requested) and then restrict based on read / write (maybe both, maybe neither!)
    AccessCheckResult accessCheck(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);

    // Use the original context when the path is fully resolved, otherwise use the reparse point read context (the CreateFile invocation to get reparse point target).
    FileOperationContext opContext(
        contextOperationName.c_str(),
        isFullyResolvedPath ? dwDesiredAccess       : GENERIC_READ,
        isFullyResolvedPath ? dwShareMode           : FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
        isFullyResolvedPath ? dwCreationDisposition : OPEN_EXISTING,
        isFullyResolvedPath ? dwFlagsAndAttributes  : FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
        lpReparsePointPath);

    PolicyResult policyResult;
    bool initPolicySuccess = policyResult.Initialize(lpReparsePointPath);

    if (!initPolicySuccess)
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        SetLastError(lastError);
        return false;
    }

    bool ret = true;

    if (enforceAccess)
    {
        if (WantsWriteAccess(opContext.DesiredAccess))
        {
            if (isCreateDirectory)
            {
                accessCheck = policyResult.CheckCreateDirectoryAccess();
            }
            else
            {
                accessCheck = policyResult.CheckWriteAccess();
            }
        }

        if (WantsReadAccess(opContext.DesiredAccess) || WantsProbeOnlyAccess(opContext.DesiredAccess))
        {
            FileReadContext readContext;

            // When enforcing reparse point access, we want to make sure to report and treat any intermediate reparse points
            // in a path as file open actions and only indicate either a file or directory open action once the input is fully resolved.
            // The general design idea is:
            //
            // {rootDir}
            // │
            // ├── Versions
            // │   │
            // │   ├── A
            // │   │   └── file
            // │   │
            // │   ├── sym-A     -> A
            // │   └── sym-sym-A -> sym-A
            // │
            // ├── sym-Versions_A_file     -> Versions/A/file
            // └── sym-Versions_sym-A_file -> Versions/sym-A/file
            //
            // Example #1: Reading a directory via symlink: Versions/sym-sym-A should report the following accesses:
            //
            // ReparsePointTarget -> Versions/sym-sym-A (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/sym-A (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/A (OpenedDirectory: true)
            //
            // Example #2: Reading a file via several symlinks: Versions/sym-sym-A/file should report only the following accesses:
            //
            // ReparsePointTarget -> Versions/sym-sym-A (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/sym-A (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/A/file (OpenedDirectory: false)
            //
            // Example #3: Reading via a symlink file: sym-Versions_sym-A_file should report only the following accesses:
            //
            // ReparsePointTarget -> sym-Versions_sym-A_file (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/sym-A (OpenedDirectory: false)
            // ReparsePointTarget -> Versions/A/file (OpenedDirectory: false)
            //
            // Design Document: https://bit.ly/2XBqVWy

            readContext.OpenedDirectory = IsHandleOrPathToDirectory(
                INVALID_HANDLE_VALUE,
                lpReparsePointPath,
                opContext.DesiredAccess,
                opContext.FlagsAndAttributes,
                policyResult,
                /*ref*/ opContext.OpenedFileOrDirectoryAttributes);
            readContext.Existence = GetFileAttributesW(lpReparsePointPath) != INVALID_FILE_ATTRIBUTES
                ? FileExistence::Existent
                : FileExistence::Nonexistent;

            accessCheck = AccessCheckResult::Combine(
                accessCheck,
                policyResult.CheckReadAccess(
                    WantsProbeOnlyAccess(opContext.DesiredAccess) ? RequestedReadAccess::Probe : RequestedReadAccess::Read,
                    readContext));
        }

        if (accessCheck.ShouldDenyAccess())
        {
            const bool maskRead = ShouldDeniedReadsAsNotFound();
            lastError = accessCheck.DenialError(maskRead);

            if (pNtStatus != nullptr)
            {
                *pNtStatus = accessCheck.DenialNtStatus(maskRead);
            }

            ret = false;
        }
    }

    // Report access to target.
    // If access to target were not reported, then we could have under-build. Suppose that the symlink and the target
    // are under a sealed directory, then BuildXL relies on observations (reports from Detours) to discover dynamic inputs.
    // If a pip launches a tool, and the tool accesses the target via the symlink only, and access to target were not reported, BuildXL would
    // discover the symlink as the only dynamic input. Thus, if the target is modified, BuildXL does not rebuild the corresponding pip.
    ReportIfNeeded(accessCheck, opContext, policyResult, lastError);

    SetLastError(lastError);
    return ret;
}

static inline bool PathContainedInPathTranslations(wstring path, bool canonicalize = false)
{
    if (path.empty())
    {
        return false;
    }

    if (canonicalize)
    {
        CanonicalizedPath normalized = CanonicalizedPath::Canonicalize(path.c_str());
        path = std::wstring(normalized.GetPathStringWithoutTypePrefix());
    }

    if (path.back() == L'\\')
    {
        path.pop_back();
    }

    std::transform(path.begin(), path.end(), path.begin(), std::towupper);

    return g_pManifestTranslatePathLookupTable->find(path) != g_pManifestTranslatePathLookupTable->end();
}

/// <summary>
/// Resolves all reparse points potentially contained in a path and enforces allowed accesses for all found matches and optionally the final resolved path.
/// </summary>
/// <remarks>
/// This function first canonicalizes the input path, then splits it by its path components to then analyze each component to check if it is a reparse
/// point. If that is the case, the target of the reparse point is used to gradually resolve the input and transform it into its final form.
/// </remarks>
static bool ResolveAllReparsePointsAndEnforceAccess(
    const CanonicalizedPath& path,
    const DWORD dwDesiredAccess,
    const DWORD dwShareMode,
    const DWORD dwCreationDisposition,
    const DWORD dwFlagsAndAttributes,
    const PolicyResult& policyResult,
    NTSTATUS* pNtStatus = nullptr,
    const bool enforceAccess = true,
    const bool isCreateDirectory = false,
    wstring* resolvedPath = nullptr,
    const bool enforceAccessForResolvedPath = true,
    const bool preserveLastReparsePointInPath = false)
{
    bool success = true;
    auto normalized = std::make_unique<wchar_t[]>(_MAX_EXTENDED_PATH_LENGTH);
    const wchar_t* input = (wchar_t*)path.GetPathStringWithoutTypePrefix();

    std::shared_ptr<vector<wstring>> order = std::make_shared<vector<wstring>>();
    std::shared_ptr< map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>> resolvedPaths = std::make_shared<map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>();

    auto drive = std::make_unique<wchar_t[]>(_MAX_DRIVE);
    auto directory = std::make_unique<wchar_t[]>(_MAX_EXTENDED_DIR_LENGTH);
    auto file_name = std::make_unique<wchar_t[]>(_MAX_FNAME);
    auto extension = std::make_unique<wchar_t[]>(_MAX_EXT);

    // levelToEnforceReparsePointParsingFrom is only valid for the path associated with policyResult.
    // Once we follow that symlink, the next path has to be checked at each level.
    bool first = true;
    size_t level = 0;
    size_t levelToEnforceReparsePointParsingFrom = GetLevelToEnableFullReparsePointParsing(policyResult);
    while (true)
    {
        errno_t err = _wsplitpath_s(
            GetPathWithoutPrefix(input),
            drive.get(),     _MAX_DRIVE,
            directory.get(), _MAX_EXTENDED_DIR_LENGTH,
            file_name.get(), _MAX_FNAME,
            extension.get(), _MAX_EXT);

        if (err != 0)
        {
            Dbg(L"ResolveAllReparsePointsAndEnforceAccess: _wsplitpath_s failed: %d", err);
            return false;
        }

        bool foundReparsePoint = false;

        wstring target = L"";
        wstring resolved = drive.get();

        wchar_t* context = nullptr;
        wchar_t* next = wcstok_s(directory.get(), L"\\/", &context);

        // Fist lets resolve the part of path that consists of directories e.g. XXXX:\a\b\c\XXXX -> resolve 'a\b\c'
        while (next)
        {
            resolved += L"\\";
            resolved += next;
            level++;

            // Avoid opening handle by not calling TryGetReparsePointTarget when reparse point has been fouond (foundReparsePoint == true).
            if ((!first || level >= levelToEnforceReparsePointParsingFrom) && !foundReparsePoint)
            {
                bool result = TryGetReparsePointTarget(resolved, INVALID_HANDLE_VALUE, target, policyResult);
                bool isFilteredPath = PathContainedInPathTranslations(resolved) || PathContainedInPathTranslations(target, true);
                if (result && !isFilteredPath)
                {
                    order->push_back(resolved);
                    resolvedPaths->emplace(resolved, ResolvedPathType::Intermediate);

                    success &= EnforceReparsePointAccess(
                        resolved,
                        dwDesiredAccess,
                        dwShareMode,
                        dwCreationDisposition,
                        dwFlagsAndAttributes,
                        pNtStatus,
                        enforceAccess,
                        isCreateDirectory);

                    if (GetRootLength(target.c_str()) > 0)
                    {
                        resolved = target;
                    }
                    else
                    {
                        resolved = resolved.substr(0, resolved.length() - lstrlenW(next));
                        resolved += target;
                    }

                    foundReparsePoint = true;
                }
            }

            next = wcstok_s(nullptr, L"\\/", &context);
            target = L"";
        }

        first = false;

        // If the original path ends with a trailing slash, then file name and extension are both an empty string
        // So make sure we don't append a trailing slash in that case
        if (lstrlenW(file_name.get()) + lstrlenW(extension.get()) > 0)
        {
            resolved += L"\\";
            resolved += file_name.get();
            resolved += extension.get();
        }

        if (foundReparsePoint)
        {
            // Normalize the partially resolved path and repeat the directory resolving, because we could have
            // more reparse points added after each resolution step (e.g. more directory symbolic links or junctions that point to reparse points again)
            HRESULT res = PathCchCanonicalizeEx(normalized.get(), _MAX_EXTENDED_PATH_LENGTH, resolved.c_str(), PATHCCH_ALLOW_LONG_PATHS);
            if (res == S_OK)
            {
                input = normalized.get();
                continue;
            }
            else
            {
                Dbg(L"ResolveAllReparsePointsAndEnforceAccess: PathCchCanonicalizeEx failed for %s", resolved.c_str());
                return false;
            }
        }

        // The path leading to the last path particle has been resolved, now lets take care of the last part - if 'preserveLastReparsePointInPath' is true,
        // we don't resolve the last part of the path because we don't want the potential target value.
        bool result = !preserveLastReparsePointInPath && TryGetReparsePointTarget(resolved, INVALID_HANDLE_VALUE, target, policyResult);
        bool isFilteredPath = !preserveLastReparsePointInPath && (PathContainedInPathTranslations(resolved) || PathContainedInPathTranslations(target, true));
        if (result && !isFilteredPath)
        {
            // The last part is a reparse point, resolve it and repeat the resolving, re-running the outer while loop
            // is ok as each resolving step is cached from previous resolution steps
            order->push_back(resolved);
            resolvedPaths->emplace(resolved, ResolvedPathType::Intermediate);

            success &= EnforceReparsePointAccess(
                resolved,
                dwDesiredAccess,
                dwShareMode,
                dwCreationDisposition,
                dwFlagsAndAttributes,
                pNtStatus,
                enforceAccess,
                isCreateDirectory);

            if (GetRootLength(target.c_str()) > 0)
            {
                resolved = target;
            }
            else
            {
                resolved = resolved.substr(0, resolved.length() - lstrlenW(file_name.get()) - lstrlenW(extension.get()));
                resolved += target;
            }

            HRESULT res = PathCchCanonicalizeEx(normalized.get(), _MAX_EXTENDED_PATH_LENGTH, resolved.c_str(), PATHCCH_ALLOW_LONG_PATHS);
            if (res == S_OK)
            {
                input = normalized.get();
                continue;
            }
            else
            {
                Dbg(L"ResolveAllReparsePointsAndEnforceAccess: PathCchCanonicalizeEx failed for %s", resolved.c_str());
                return false;
            }
        }
        else
        {
            // Now we have a fully resolved path without any reparse points present, normalize it, add it to the cache and enforce access eventually
            HRESULT res = PathCchCanonicalizeEx(normalized.get(), _MAX_EXTENDED_PATH_LENGTH, resolved.c_str(), PATHCCH_ALLOW_LONG_PATHS);
            if (res == S_OK)
            {
                input = normalized.get();

                if (resolvedPath != nullptr)
                {
                    resolvedPath->assign(input);
                }

                order->push_back(input);
                resolvedPaths->emplace(input, ResolvedPathType::FullyResolved);

                if (enforceAccessForResolvedPath)
                {
                    success &= EnforceReparsePointAccess(
                        input,
                        dwDesiredAccess,
                        dwShareMode,
                        dwCreationDisposition,
                        dwFlagsAndAttributes,
                        pNtStatus,
                        enforceAccess,
                        isCreateDirectory,
                        true);
                }
            }
            else
            {
                Dbg(L"ResolveAllReparsePointsAndEnforceAccess: PathCchCanonicalizeEx failed for %s", resolved.c_str());
                return false;
            }
        }

        break;
    }

    PathCache_InsertResolvedPaths(
        path.GetPathStringWithoutTypePrefix(),
        preserveLastReparsePointInPath,
        order,
        resolvedPaths,
        policyResult);
    return success;
}

/// <summary>
/// Enforces allowed accesses for all paths leading to and including the target of a reparse point.
/// </summary>
/// <remarks>
/// This function calls <code>DetourGetFinalPaths</code> to get the sequence of paths leading to and including the target of a reparse point.
/// Having the sequence, this function calls <code>EnforceReparsePointAccess</code> on each path to check that access to that path is allowed.
/// </remarks>
static bool EnforceChainOfReparsePointAccesses(
    const CanonicalizedPath& path,
    HANDLE reparsePointHandle,
    const DWORD dwDesiredAccess,
    const DWORD dwShareMode,
    const DWORD dwCreationDisposition,
    const DWORD dwFlagsAndAttributes,
    const bool isNtCreate,
    const PolicyResult& policyResult,
    NTSTATUS* pNtStatus = nullptr,
    const bool enforceAccess = true,
    const bool isCreateDirectory = false,
    wstring* resolvedPath = nullptr,
    const bool enforceAccessForResolvedPath = true,
    const bool preserveLastReparsePoint = false)
{
    if (IgnoreReparsePoints() || (isNtCreate && !MonitorNtCreateFile()))
    {
        return true;
    }


    bool cached = true;
    const Possible<ResolvedPathCacheEntries> cachedEntries = PathCache_GetResolvedPaths(
        path.GetPathStringWithoutTypePrefix(),
        preserveLastReparsePoint,
        policyResult);

    std::shared_ptr<vector<wstring>> cachedOrder = nullptr;
    std::shared_ptr<map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>> resolvedLookUpTable = nullptr;
    std::shared_ptr <vector<wstring>> order;
    std::shared_ptr <map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>> paths;

    if (!cachedEntries.Found)
    {
        if (IgnoreFullReparsePointResolvingForPath(policyResult))
        {
            cachedOrder = std::make_shared<vector<wstring>>();
            resolvedLookUpTable = std::make_shared <map<wstring, ResolvedPathType, CaseInsensitiveStringLessThan>>();

            DetourGetFinalPaths(path, reparsePointHandle, cachedOrder, resolvedLookUpTable, policyResult);
            cached = false;
        }
        else
        {
            return ResolveAllReparsePointsAndEnforceAccess(
                path,
                dwDesiredAccess,
                dwShareMode,
                dwCreationDisposition,
                dwFlagsAndAttributes,
                policyResult,
                pNtStatus,
                enforceAccess,
                isCreateDirectory,
                resolvedPath,
                enforceAccessForResolvedPath,
                preserveLastReparsePoint);
        }
    }
    else
    {
        cachedOrder = cachedEntries.Value.first;
        resolvedLookUpTable = cachedEntries.Value.second;
    }

#if MEASURE_REPARSEPOINT_RESOLVING_IMPACT
    InterlockedIncrement(&g_resolvedPathsCacheHitCout);
#endif // MEASURE_REPARSEPOINT_RESOLVING_IMPACT

    bool success = true;
    auto contextOperationName = cached ? L"ReparsePointTargetCached" : L"ReparsePointTarget";

    for (auto it = cachedOrder->begin(); it != cachedOrder->end(); ++it)
    {
        const std::wstring& key = *it;
        const ResolvedPathType& type = resolvedLookUpTable->at(key);

        // When fully resolving paths, it is sometimes necessary to either pass back the fully resolved path to the caller, or not report it to BuildXL
        // at all (see <code>ResolveAllReparsePointsAndEnforceAccess</code>). The 'ResolvedPathType' enum is used to flag the resulting parts of resolving a
        // path so we can make the distinction when providing cached results. When IgnoreFullReparsePointResolvingForPath(policyResult) is enabled, all files get flagged with
        // 'ResolvedPathType::Intermediate' in DetourGetFinalPaths when populating the cache, so this check can be skipped too.
        if (!IgnoreFullReparsePointResolvingForPath(policyResult) && type == ResolvedPathType::FullyResolved)
        {
            if (resolvedPath != nullptr)
            {
                resolvedPath->assign(key);
            }

            if (!enforceAccessForResolvedPath)
            {
                continue;
            }
        }

        success &= EnforceReparsePointAccess(
            key,
            dwDesiredAccess,
            dwShareMode,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            pNtStatus,
            enforceAccess,
            isCreateDirectory,
            type == ResolvedPathType::FullyResolved,
            contextOperationName);
    }

    return success;
}

/// <summary>
/// Enforces allowed accesses for all paths leading to and including the target of a reparse point for non CreateFile-like functions.
/// </summary>
static bool EnforceChainOfReparsePointAccessesForNonCreateFile(
    const FileOperationContext& fileOperationContext,
    const PolicyResult& policyResult,
    const bool enforceAccess = true,
    const bool isCreateDirectory = false)
{
    if (!IgnoreNonCreateFileReparsePoints() && !IgnoreReparsePoints())
    {
        CanonicalizedPath canonicalPath = CanonicalizedPath::Canonicalize(fileOperationContext.NoncanonicalPath);

        if (IsReparsePoint(canonicalPath.GetPathString(), INVALID_HANDLE_VALUE))
        {
            bool accessResult = EnforceChainOfReparsePointAccesses(
                canonicalPath,
                INVALID_HANDLE_VALUE,
                fileOperationContext.DesiredAccess,
                fileOperationContext.ShareMode,
                fileOperationContext.CreationDisposition,
                fileOperationContext.FlagsAndAttributes,
                false,
                policyResult,
                nullptr,
                enforceAccess,
                isCreateDirectory);

            if (!accessResult)
            {
                return false;
            }
        }
    }

    return true;
}

/// <summary>
/// Resolves the input policy path and re-adjusts the operation context and policy path with the resolved result.
/// </summary>
/// /// <remarks>
/// If 'preserveLastReparsePoint' is true, and the last part of the policy path is a reparse point, that reparse point does not
/// get resolved. This is important depending on the call site of this function. Some detoured functions work on
/// the reparse point itself e.g. GetFileAttributes*(...) and we don't want to resolve the path fully in those cases.
/// EnforceReparsePointAccess(...) contains several examples for full resolving, here is another one illustrating
/// the behavior of this method:
///
/// C:\path\dir_sym\file.lnk, where dir_sym -> anotherPath, and file.lnk is a symbolic link to some file
///
/// A process calling GetFileAttributesW(L"C:\path\dir_sym\file.lnk") will report the following accesses:
///
/// ReparsePointTarget -> R C:\path\dir_sym (OpenedDirectory: false)
/// Detoured_GetFileAttributesW -> R C:\path\anotherPath\file.lnk (OpenedDirectory: false)
///
/// Note, how the reparse point 'file.lnk' is preserved due to some system calls opening the reparse point instead of
/// the target. This behavior is either implicit or depends on passed flags, e.g. 'FILE_FLAG_OPEN_REPARSE_POINT'
/// </remarks>
static bool AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
    FileOperationContext& opContext,
    PolicyResult& policyResult,
    const bool preserveLastReparsePoint,
    const bool isCreateDirectory = false)
{
    if (IgnoreReparsePoints() || IgnoreFullReparsePointResolvingForPath(policyResult))
    {
        return true;
    }

    const CanonicalizedPath path = policyResult.GetCanonicalizedPath();

    if (ShouldResolveReparsePointsInPath(path, opContext.FlagsAndAttributes, policyResult))
    {
        wstring fullyResolvedPath;
        bool accessResult = EnforceChainOfReparsePointAccesses(
            path,
            INVALID_HANDLE_VALUE,
            opContext.DesiredAccess,
            opContext.ShareMode,
            opContext.CreationDisposition,
            opContext.FlagsAndAttributes,
            false,
            policyResult,
            nullptr,
            true,
            isCreateDirectory,
            &fullyResolvedPath,
            false, // Never enforce access checks and reporting on the fully resolved path - let the caller decide through 'skipAdjustingContextAndPolicy' and subsuquent 'ReportFileAccess(...)' calls.
            preserveLastReparsePoint);

        // Delete from the cache if it is reparse point deletion.
        // Note that in the opContext all options and attributes passed from Nt/ZwCreateFile have been translated into those for CreateFileW.
        bool reparsePointDeletion =
            FlagsAndAttributesContainReparsePointFlag(opContext.FlagsAndAttributes)    // File/directory is opened with reparse point flag.
            && ((opContext.DesiredAccess & DELETE) != 0                                // Nt/ZwCreateFile for making the file eligible for deletion.
                || (opContext.FlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE) != 0);   // Delete when the last handle to the file is closed.

        if (reparsePointDeletion)
        {
            PathCache_Invalidate(path.GetPathStringWithoutTypePrefix(), true, policyResult);
        }

        if (!accessResult)
        {
            Dbg(L"AdjustOperationContextAndPolicyResultWithFullyResolvedPath: Failed resolving and enforcing intermediate accesses for: %s", path.GetPathString());
            return accessResult;
        }

        opContext.AdjustPath(fullyResolvedPath.c_str());

        // Reset policy result because the fully resolved path is likely to be different.
        PolicyResult newPolicyResult;
        if (!newPolicyResult.Initialize(fullyResolvedPath.c_str()))
        {
            newPolicyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
            return false;
        }

        policyResult = newPolicyResult;
    }

    return true;
}

/// <summary>
/// Validates move directory by validating proper deletion for all source files and proper creation for all target files.
/// </summary>
static bool ValidateMoveDirectory(
    _In_      LPCWSTR                  sourceContext,
    _In_      LPCWSTR                  destinationContext,
    _In_      LPCWSTR                  lpExistingFileName,
    _In_opt_  LPCWSTR                  lpNewFileName,
    _Out_     vector<ReportData>&      filesAndDirectoriesToReport)
{
    DWORD error = GetLastError();

    vector<std::pair<wstring, DWORD>> filesAndDirectories;

    DWORD directoryAttributes = GetFileAttributesW(lpExistingFileName);
    bool isDirectory = (directoryAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (directoryAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;

    if (!isDirectory)
    {
        SetLastError(error);
        return true;
    }

    if (!EnumerateDirectory(lpExistingFileName, L"*", true, true, filesAndDirectories))
    {
        SetLastError(error);
        return false;
    }

    wstring sourceDirectory(lpExistingFileName);

    if (sourceDirectory.back() != L'\\')
    {
        sourceDirectory.push_back(L'\\');
    }

    wstring targetDirectory;

    if (lpNewFileName != NULL)
    {
        targetDirectory.assign(lpNewFileName);

        if (targetDirectory.back() != L'\\')
        {
            targetDirectory.push_back(L'\\');
        }
    }

    PolicyResult policyResult;
    policyResult.Initialize(lpExistingFileName);

    for (auto entry : filesAndDirectories)
    {
        const std::pair<wstring, DWORD>& elem = entry;
        wstring file = elem.first;
        const DWORD& fileAttributes = elem.second;

        // Validate deletion of source.
        wstring normalizedSourceFile = NormalizePath(file);
        FileOperationContext sourceOpContext = FileOperationContext(
            sourceContext,
            DELETE,
            0,
            OPEN_EXISTING,
            // We are interested in knowing whether the source path is a directory, so make sure
            // we reflect that in the report
            FILE_ATTRIBUTE_NORMAL | (fileAttributes & FILE_ATTRIBUTE_DIRECTORY),
            normalizedSourceFile.c_str());

        PolicyResult sourcePolicyResult;
        if (!sourcePolicyResult.Initialize(normalizedSourceFile.c_str()))
        {
            sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
            return false;
        }

        AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();

        if (sourceAccessCheck.ShouldDenyAccess())
        {
            DWORD denyError = sourceAccessCheck.DenialError();
            ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, denyError);
            sourceAccessCheck.SetLastErrorToDenialError();
            return false;
        }

        PathCache_Invalidate(sourcePolicyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), fileAttributes & FILE_ATTRIBUTE_DIRECTORY, policyResult);

        filesAndDirectoriesToReport.push_back(ReportData(sourceAccessCheck, sourceOpContext, sourcePolicyResult));

        // Validate creation of target.

        if (lpNewFileName != NULL)
        {
            file.replace(0, sourceDirectory.length(), targetDirectory);

            wstring normalizedTargetFile = NormalizePath(file);

            FileOperationContext destinationOpContext = FileOperationContext(
                destinationContext,
                GENERIC_WRITE,
                0,
                CREATE_ALWAYS,
                // We are interested in knowing whether the source path is a directory, so make sure
                // we reflect that in the report
                FILE_ATTRIBUTE_NORMAL | (fileAttributes & FILE_ATTRIBUTE_DIRECTORY),
                normalizedTargetFile.c_str());
            destinationOpContext.Correlate(sourceOpContext);

            PolicyResult destPolicyResult;

            if (!destPolicyResult.Initialize(normalizedTargetFile.c_str()))
            {
                destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
                return false;
            }

            AccessCheckResult destAccessCheck = (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                ? destPolicyResult.CheckCreateDirectoryAccess()
                : destPolicyResult.CheckWriteAccess();

            if (destAccessCheck.ShouldDenyAccess())
            {
                // We report the destination access here since we are returning early. Otherwise it is deferred until post-read.
                DWORD denyError = destAccessCheck.DenialError();
                ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
                destAccessCheck.SetLastErrorToDenialError();
                return false;
            }

            filesAndDirectoriesToReport.push_back(ReportData(destAccessCheck, destinationOpContext, destPolicyResult));
        }
    }

    SetLastError(error);

    return true;
}

typedef enum _FILE_INFORMATION_CLASS_EXTRA {
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileUnusedInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileRenameInformationBypassAccessCheck,
    FileLinkInformationBypassAccessCheck,
    FileVolumeNameInformation,
    FileIdInformation,
    FileIdExtdDirectoryInformation,
    FileReplaceCompletionInformation,
    FileHardLinkFullIdInformation,
    FileIdExtdBothDirectoryInformation,
    FileDispositionInformationEx,
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation,
    FileStatInformation,
    FileMemoryPartitionInformation,
    FileStatLxInformation,
    FileCaseSensitiveInformation,
    FileLinkInformationEx,
    FileLinkInformationExBypassAccessCheck,
    FileStorageReserveIdInformation,
    FileCaseSensitiveInformationForceAccessCheck,
    FileMaximumInformation
} FILE_INFORMATION_CLASS_EXTRA, *PFILE_INFORMATION_CLASS_EXTRA;

typedef struct _FILE_LINK_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;

// This struct is very similar to _FILE_LINK_INFORMATION. If ULONG is 4 bytes long,
// these two structs even have the same layout:
//   a) BOOLEAN is 1 byte long, but in this struct a compiler, by default, will pad it to 4 bytes
//   b) union is as long as it's biggest member (i.e., ULONG in this case)
// However, there is no guarantee that ULONG is 4 bytes long (in some scenarios, it can be 8 bytes long).
// This structure has been introduced, so we wouldn't depend on the ULONG's length when casting/dereferencing   PVOID.
typedef struct _FILE_LINK_INFORMATION_EX {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    };
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} FILE_LINK_INFORMATION_EX, *PFILE_LINK_INFORMATION_EX;

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
    ULONG Mode;
} FILE_MODE_INFORMATION, *PFILE_MODE_INFORMATION;

static bool TryGetFileNameFromFileInformation(
    _In_  PWCHAR   fileName,
    _In_  ULONG    fileNameLength,
    _In_  HANDLE   rootDirectory,
    _In_  bool     isNtApi,
    _Out_ wstring& result)
{
    size_t length = (size_t)(fileNameLength / sizeof(WCHAR));

    // The rename target is specified in FILE_RENAME_INFORMATION structure, in FileName field. The structure also has the filename length info 
    // in FileNameLength field. However, in some tools, like clang, LLVM, Hermes, the length info does not correspond to the real length of the filename.
    // Thus, on extracting the filename we get incorrect (mostly truncated) filename.
    // 
    // The API implementation of SetFileNameInformationByHandle drops the length info in determining the filename target.
    // SetFileNameInformationByHandle relies on RtlInitUnicodeStringEx to extract the filename target.
    // The latter in turn calls wcslen, which scans the pointer until NULL terminating character
    // 
    // NTFS API (Zw*) would not handle incorrect filename length, the string will be whatever the length says it is.

    if (!isNtApi)
    {
        size_t actualLength = wcslen(fileName);

        // RtlInitUnicodeStringEx limits to 32765 characters.

        if (actualLength > (UNICODE_STRING_MAX_CHARS - 1))
        {
            actualLength = length;
        }

        if (actualLength != length)
        {
            // Prefer calculated length when there is a mismatch.
            length = actualLength;
        }
    }

    result.assign(fileName, length);

    DWORD lastError = GetLastError();

    // See https://msdn.microsoft.com/en-us/library/windows/hardware/ff540344(v=vs.85).aspx
    // See https://msdn.microsoft.com/en-us/library/windows/hardware/ff540324(v=vs.85).aspx
    // RootDirectory:
    //      If the file is not being moved to a different directory, or if the FileName member contains the full pathname, this member is NULL.
    //      Otherwise, it is a handle for the root directory under which the file will reside after it is renamed.
    // FileName:
    //      The first character of a wide - character string containing the new name for the file. This is followed in memory by the remainder of the string.
    //      If the RootDirectory member is NULL, and the file is being moved/linked to a different directory, this member specifies the full pathname
    //      to be assigned to the file. Otherwise, it specifies only the file name or a relative pathname.
    if (rootDirectory != nullptr)
    {
        wstring dirPath;

        if (DetourGetFinalPathByHandle(rootDirectory, dirPath) != ERROR_SUCCESS)
        {
            Dbg(L"TryGetFileNameFromFileInformation: DetourGetFinalPathByHandle: %d", GetLastError());
            SetLastError(lastError);
            return false;
        }

        CanonicalizedPath dirPathCan = CanonicalizedPath::Canonicalize(dirPath.c_str());
        CanonicalizedPath dirPathExtended = dirPathCan.Extend(result.c_str());

        result.assign(dirPathExtended.GetPathString());
    }

    SetLastError(lastError);
    return true;
}

// Forward declaration: the Model W overlay resolvers are defined later in this file
// (near the CreateFile hooks), but the NT-layer link handler below needs to redirect
// the new-link name into the backing store.
static std::wstring ResolveOverlayRenameDest(PolicyResult& policyResult);

NTSTATUS HandleFileRenameInformation(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass)
{
    FILE_INFORMATION_CLASS_EXTRA fiExtra = (FILE_INFORMATION_CLASS_EXTRA)FileInformationClass;

    assert(fiExtra == FILE_INFORMATION_CLASS_EXTRA::FileRenameInformation
        || fiExtra == FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationEx
        || fiExtra == FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationBypassAccessCheck
        || fiExtra == FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationExBypassAccessCheck);

    DetouredScope scope;
    if (scope.Detoured_IsDisabled())
    {
        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD lastError = GetLastError();
    wstring sourcePath;

    DWORD getFinalPathByHandle = DetourGetFinalPathByHandle(FileHandle, sourcePath);
    if ((getFinalPathByHandle != ERROR_SUCCESS) || IsSpecialDeviceName(sourcePath.c_str()) || IsNullOrEmptyW(sourcePath.c_str()))
    {
        if (getFinalPathByHandle != ERROR_SUCCESS)
        {
            Dbg(L"HandleFileRenameInformation: DetourGetFinalPathByHandle: %d", getFinalPathByHandle);
        }

        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    PFILE_RENAME_INFO pRenameInfo = (PFILE_RENAME_INFO)FileInformation;

    wstring targetPath;

    if (!TryGetFileNameFromFileInformation(
        pRenameInfo->FileName,
        pRenameInfo->FileNameLength,
        pRenameInfo->RootDirectory,
        true,
        targetPath)
        || targetPath.empty())
    {
        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD fileOrDirectoryAttribute;
    bool renameDirectory = IsHandleOrPathToDirectory(FileHandle, targetPath.c_str(), /*treatReparsePointAsFile*/ true, /*ref*/ fileOrDirectoryAttribute);
    DWORD flagsAndAttributes = GetAttributesForFileOrDirectory(renameDirectory);

    FileOperationContext sourceOpContext = FileOperationContext(
        L"ZwSetRenameInformationFile_Source",
        DELETE,
        0,
        OPEN_EXISTING,
        flagsAndAttributes,
        sourcePath.c_str());

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(sourcePath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    FileOperationContext destinationOpContext = FileOperationContext(
        L"ZwSetRenameInformationFile_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        flagsAndAttributes,
        targetPath.c_str());
    destinationOpContext.Correlate(sourceOpContext);

    PolicyResult destPolicyResult;

    if (!destPolicyResult.Initialize(targetPath.c_str()))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    // Writes are destructive. Before doing a move we ensure that write access is definitely allowed to the source (delete) and destination (write).
    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();
    sourceOpContext.OpenedFileOrDirectoryAttributes = fileOrDirectoryAttribute;

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, sourceAccessCheck.DenialError());
        sourceAccessCheck.SetLastErrorToDenialError();
        return sourceAccessCheck.DenialNtStatus();
    }

    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();
    destinationOpContext.OpenedFileOrDirectoryAttributes = fileOrDirectoryAttribute;

    if (destAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, destAccessCheck.DenialError());
        destAccessCheck.SetLastErrorToDenialError();
        return destAccessCheck.DenialNtStatus();
    }

    vector<ReportData> filesAndDirectoriesToReport;
    if (renameDirectory)
    {
        if (!ValidateMoveDirectory(
            L"ZwSetRenameInformationFile_Source",
            L"ZwSetRenameInformationFile_Dest",
            sourcePath.c_str(),
            targetPath.c_str(),
            filesAndDirectoriesToReport))
        {
            return FALSE;
        }
    }

    SetLastError(lastError);

    NTSTATUS result = Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass);
    lastError = GetLastError();

    DWORD ntError = RtlNtStatusToDosError(result);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, ntError, lastError);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, ntError, lastError);

    if (renameDirectory)
    {
        for (auto& entry : filesAndDirectoriesToReport)
        {
            ReportIfNeeded(entry.GetAccessCheckResult(), entry.GetFileOperationContext(), entry.GetPolicyResult(), ntError, lastError);
        }
    }

    SetLastError(lastError);

    return result;
}

NTSTATUS HandleFileLinkInformation(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass,
    _In_  BOOL                   IsExtendedFileInformation)
{
    assert((!IsExtendedFileInformation && (FILE_INFORMATION_CLASS_EXTRA)FileInformationClass == FILE_INFORMATION_CLASS_EXTRA::FileLinkInformation)
        || (IsExtendedFileInformation && (FILE_INFORMATION_CLASS_EXTRA)FileInformationClass == FILE_INFORMATION_CLASS_EXTRA::FileLinkInformationEx));

    DetouredScope scope;
    if (scope.Detoured_IsDisabled())
    {
        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD lastError = GetLastError();

    PWCHAR fileName;
    ULONG fileNameLength;
    HANDLE rootDirectory;
    if (!IsExtendedFileInformation) {
        PFILE_LINK_INFORMATION pLinkInfo = (PFILE_LINK_INFORMATION)FileInformation;
        fileName = pLinkInfo->FileName;
        fileNameLength = pLinkInfo->FileNameLength;
        rootDirectory = pLinkInfo->RootDirectory;
    }
    else {
        PFILE_LINK_INFORMATION_EX pLinkInfoEx = (PFILE_LINK_INFORMATION_EX)FileInformation;
        fileName = pLinkInfoEx->FileName;
        fileNameLength = pLinkInfoEx->FileNameLength;
        rootDirectory = pLinkInfoEx->RootDirectory;
    }

    wstring targetPath;

    if (!TryGetFileNameFromFileInformation(
        fileName,
        fileNameLength,
        rootDirectory,
        true,
        targetPath)
        || targetPath.empty())
    {
        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }


    FileOperationContext targetOpContext = FileOperationContext(
        L"ZwSetLinkInformationFile",
        DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        targetPath.c_str());

    PolicyResult targetPolicyResult;

    if (!targetPolicyResult.Initialize(targetPath.c_str()))
    {
        targetPolicyResult.ReportIndeterminatePolicyAndSetLastError(targetOpContext);
        return FALSE;
    }

    AccessCheckResult targetAccessCheck = targetPolicyResult.CheckWriteAccess();
    // Hard links can only be created on files
    targetOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);

    if (targetAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(targetAccessCheck, targetOpContext, targetPolicyResult, targetAccessCheck.DenialError());
        targetAccessCheck.SetLastErrorToDenialError();
        return targetAccessCheck.DenialNtStatus();
    }

    SetLastError(lastError);

    // Model W (write-overlay): redirect the NEW hard-link NAME into the backing store
    // so an in-cone hardlink never lands on the real execroot. This is the path cmd's
    // `mklink /H` (and other tools) actually take - they open the existing file and set
    // FileLinkInformation naming the new link, bypassing the CreateHardLinkW hook. The
    // source is the already-open FileHandle (redirected at open time when it is an
    // overlay file), so only the destination name needs rewriting. We rebuild the info
    // buffer with RootDirectory=NULL and an NT-form backing path (\??\ + backing).
    PVOID effInfo = FileInformation;
    ULONG effLen = Length;
    std::vector<BYTE> redirectedLinkBuf;
    if (ShouldWriteOverlay())
    {
        std::wstring backing = ResolveOverlayRenameDest(targetPolicyResult);
        if (!backing.empty())
        {
            std::wstring nt = (backing.rfind(L"\\\\?\\", 0) == 0)
                ? (L"\\??\\" + backing.substr(4))
                : backing;
            const ULONG nameBytes = (ULONG)(nt.size() * sizeof(wchar_t));
            const size_t hdr = FIELD_OFFSET(FILE_LINK_INFORMATION, FileName);
            redirectedLinkBuf.resize(hdr + nameBytes);
            memcpy(redirectedLinkBuf.data(), FileInformation, hdr);
            auto* ni = (PFILE_LINK_INFORMATION)redirectedLinkBuf.data();
            ni->RootDirectory = NULL;
            ni->FileNameLength = nameBytes;
            memcpy(ni->FileName, nt.c_str(), nameBytes);
            effInfo = redirectedLinkBuf.data();
            effLen = (ULONG)redirectedLinkBuf.size();
        }
    }

    NTSTATUS result = Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        effInfo,
        effLen,
        FileInformationClass);
    lastError = GetLastError();

    ReportIfNeeded(targetAccessCheck, targetOpContext, targetPolicyResult, RtlNtStatusToDosError(result), lastError);

    SetLastError(lastError);

    return result;
}

NTSTATUS HandleFileDispositionInformation(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass)
{
    FILE_INFORMATION_CLASS_EXTRA fiClass = (FILE_INFORMATION_CLASS_EXTRA)FileInformationClass;

    bool isDeleteOperation = false;

    if (fiClass == FILE_INFORMATION_CLASS_EXTRA::FileDispositionInformation)
    {
        PFILE_DISPOSITION_INFO pDispositionInfo = (PFILE_DISPOSITION_INFO)FileInformation;
        isDeleteOperation = pDispositionInfo->DeleteFile;
    }
    else
    {
        assert(fiClass == FILE_INFORMATION_CLASS_EXTRA::FileDispositionInformationEx);

        PFILE_DISPOSITION_INFO_EX pDispositionInfo = (PFILE_DISPOSITION_INFO_EX)FileInformation;
        isDeleteOperation = (pDispositionInfo->Flags & FILE_DISPOSITION_FLAG_DELETE) != 0;
    }

    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || !isDeleteOperation)
    {
        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD lastError = GetLastError();
    wstring sourcePath;

    DWORD getFinalPathByHandle = DetourGetFinalPathByHandle(FileHandle, sourcePath);
    if ((getFinalPathByHandle != ERROR_SUCCESS) || IsSpecialDeviceName(sourcePath.c_str()) || IsNullOrEmptyW(sourcePath.c_str()))
    {
        if (getFinalPathByHandle != ERROR_SUCCESS)
        {
            Dbg(L"HandleFileDispositionInformation: DetourGetFinalPathByHandle: %d", getFinalPathByHandle);
        }

        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    FileOperationContext sourceOpContext = FileOperationContext(
        L"ZwSetDispositionInformationFile",
        DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        sourcePath.c_str());

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(sourcePath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();
    sourceOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, sourceAccessCheck.DenialError());
        sourceAccessCheck.SetLastErrorToDenialError();
        return sourceAccessCheck.DenialNtStatus();
    }

    SetLastError(lastError);

    NTSTATUS result = Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass);
    lastError = GetLastError();

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, RtlNtStatusToDosError(result), lastError);

    SetLastError(lastError);

    return result;
}

NTSTATUS HandleFileModeInformation(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass)
{
    assert((FILE_INFORMATION_CLASS_EXTRA)FileInformationClass == FILE_INFORMATION_CLASS_EXTRA::FileModeInformation);

    PFILE_MODE_INFORMATION pModeInfo = (PFILE_MODE_INFORMATION)FileInformation;

    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || ((pModeInfo->Mode & FILE_DELETE_ON_CLOSE) == 0))
    {
        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD lastError = GetLastError();
    wstring sourcePath;

    DWORD getFinalPathByHandle = DetourGetFinalPathByHandle(FileHandle, sourcePath);
    if ((getFinalPathByHandle != ERROR_SUCCESS) || IsSpecialDeviceName(sourcePath.c_str()) || IsNullOrEmptyW(sourcePath.c_str()))
    {
        if (getFinalPathByHandle != ERROR_SUCCESS)
        {
            Dbg(L"HandleFileModeInformation: DetourGetFinalPathByHandle: %d", getFinalPathByHandle);
        }

        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    FileOperationContext sourceOpContext = FileOperationContext(
        L"ZwSetModeInformationFile",
        DELETE,
        0,
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE,
        sourcePath.c_str());

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(sourcePath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();
    IsHandleOrPathToDirectory(FileHandle, sourcePath.c_str(), /*treatReparsePointAsFile*/ true, /*ref*/ sourceOpContext.OpenedFileOrDirectoryAttributes);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, sourceAccessCheck.DenialError());
        sourceAccessCheck.SetLastErrorToDenialError();
        return sourceAccessCheck.DenialNtStatus();
    }

    SetLastError(lastError);

    NTSTATUS result = Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass);
    lastError = GetLastError();

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, RtlNtStatusToDosError(result), lastError);

    SetLastError(lastError);

    return result;
}

NTSTATUS HandleFileNameInformation(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass)
{
    assert((FILE_INFORMATION_CLASS_EXTRA)FileInformationClass == FILE_INFORMATION_CLASS_EXTRA::FileNameInformation);

    DetouredScope scope;
    if (scope.Detoured_IsDisabled())
    {
        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD lastError = GetLastError();
    wstring sourcePath;

    DWORD getFinalPathByHandle = DetourGetFinalPathByHandle(FileHandle, sourcePath);
    if ((getFinalPathByHandle != ERROR_SUCCESS) || IsSpecialDeviceName(sourcePath.c_str()) || IsNullOrEmptyW(sourcePath.c_str()))
    {
        if (getFinalPathByHandle != ERROR_SUCCESS)
        {
            Dbg(L"HandleFileNameInformation: DetourGetFinalPathByHandle: %d", getFinalPathByHandle);
        }

        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    PFILE_NAME_INFORMATION pNameInfo = (PFILE_NAME_INFORMATION)FileInformation;

    wstring targetPath;

    if (!TryGetFileNameFromFileInformation(
        pNameInfo->FileName,
        pNameInfo->FileNameLength,
        nullptr,
        true,
        targetPath)
        || targetPath.empty())
    {
        SetLastError(lastError);

        return Real_ZwSetInformationFile(
            FileHandle,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass);
    }

    DWORD fileOrDirectoryAttribute;
    bool renameDirectory = IsHandleOrPathToDirectory(FileHandle, sourcePath.c_str(), /*treatReparsePointAsFile*/ true, /*ref*/ fileOrDirectoryAttribute);
    DWORD flagsAndAttributes = GetAttributesForFileOrDirectory(renameDirectory);

    FileOperationContext sourceOpContext = FileOperationContext(
        L"ZwSetFileNameInformationFile_Source",
        DELETE,
        0,
        OPEN_EXISTING,
        flagsAndAttributes,
        sourcePath.c_str());
    sourceOpContext.OpenedFileOrDirectoryAttributes = fileOrDirectoryAttribute;

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(sourcePath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    FileOperationContext destinationOpContext = FileOperationContext(
        L"ZwSetFileNameInformationFile_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        flagsAndAttributes,
        targetPath.c_str());
    destinationOpContext.Correlate(sourceOpContext);
    destinationOpContext.OpenedFileOrDirectoryAttributes = fileOrDirectoryAttribute;

    PolicyResult destPolicyResult;

    if (!destPolicyResult.Initialize(targetPath.c_str()))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    // Writes are destructive. Before doing a move we ensure that write access is definitely allowed to the source (delete) and destination (write).
    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, sourceAccessCheck.DenialError());
        sourceAccessCheck.SetLastErrorToDenialError();
        return sourceAccessCheck.DenialNtStatus();
    }

    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();

    if (destAccessCheck.ShouldDenyAccess())
    {
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, destAccessCheck.DenialError());
        destAccessCheck.SetLastErrorToDenialError();
        return destAccessCheck.DenialNtStatus();
    }

    vector<ReportData> filesAndDirectoriesToReport;
    if (renameDirectory)
    {
        if (!ValidateMoveDirectory(
            L"ZwSetFileNameInformationFile_Source",
            L"ZwSetFileNameInformationFile_Dest",
            sourcePath.c_str(),
            targetPath.c_str(),
            filesAndDirectoriesToReport))
        {
            return FALSE;
        }
    }

    SetLastError(lastError);

    NTSTATUS result = Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass);
    lastError = GetLastError();

    DWORD ntError = RtlNtStatusToDosError(result);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, ntError, lastError);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, ntError, lastError);

    if (renameDirectory)
    {
        for (auto entry : filesAndDirectoriesToReport)
        {
            ReportIfNeeded(entry.GetAccessCheckResult(), entry.GetFileOperationContext(), entry.GetPolicyResult(), ntError, lastError);
        }
    }

    SetLastError(lastError);

    return result;
}

IMPLEMENTED(Detoured_ZwSetInformationFile)
NTSTATUS NTAPI Detoured_ZwSetInformationFile(
    _In_  HANDLE                 FileHandle,
    _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
    _In_  PVOID                  FileInformation,
    _In_  ULONG                  Length,
    _In_  FILE_INFORMATION_CLASS FileInformationClass)
{
    // if this is not an enabled case that we are covering, just call the Real_Function.
    FILE_INFORMATION_CLASS_EXTRA fileInformationClassExtra = (FILE_INFORMATION_CLASS_EXTRA)FileInformationClass;

    switch (fileInformationClassExtra)
    {
    case FILE_INFORMATION_CLASS_EXTRA::FileRenameInformation:
    case FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationEx:
    case FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationBypassAccessCheck:
    case FILE_INFORMATION_CLASS_EXTRA::FileRenameInformationExBypassAccessCheck:
        if (!IgnoreZwRenameFileInformation())
        {
            return HandleFileRenameInformation(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
        }
        break;
    case FILE_INFORMATION_CLASS_EXTRA::FileLinkInformation:
    case FILE_INFORMATION_CLASS_EXTRA::FileLinkInformationEx:
        if (!IgnoreZwOtherFileInformation())
        {
            return HandleFileLinkInformation(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass, fileInformationClassExtra == FILE_INFORMATION_CLASS_EXTRA::FileLinkInformationEx);
        }
        break;
    case FILE_INFORMATION_CLASS_EXTRA::FileDispositionInformation:
    case FILE_INFORMATION_CLASS_EXTRA::FileDispositionInformationEx:
        if (!IgnoreZwOtherFileInformation())
        {
            return HandleFileDispositionInformation(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
        }
        break;
    case FILE_INFORMATION_CLASS_EXTRA::FileModeInformation:
        if (!IgnoreZwOtherFileInformation())
        {
            return HandleFileModeInformation(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
        }
        break;
    case FILE_INFORMATION_CLASS_EXTRA::FileNameInformation:
        if (!IgnoreZwOtherFileInformation())
        {
            return HandleFileNameInformation(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
        }
        break;
    default:
        break;
        // Without the warning suppression below, some compilation flag can produce a warning because the cases aboe are not
        // exhaustive with respect to the FILE_INFORMATION_CLASS_EXTRA enums.
#pragma warning(suppress: 4061)
    }

    return Real_ZwSetInformationFile(
        FileHandle,
        IoStatusBlock,
        FileInformation,
        Length,
        FileInformationClass);
}

static bool ShouldBreakawayFromJob(const CanonicalizedPath& fullApplicationPath, _Inout_opt_ LPWSTR lpCommandLine)
{
    if (g_breakawayChildProcesses->empty() || fullApplicationPath.IsNull())
    {
        return false;
    }

    std::wstring imageName(fullApplicationPath.GetLastComponent());
    for (auto it = g_breakawayChildProcesses->begin(); it != g_breakawayChildProcesses->end(); ++it)
    {
        if (AreEqualCaseInsensitively(it->ProcessName, imageName))
        {
            if (it->RequiredCommandLineArgsSubstring.empty())
            {
#if SUPER_VERBOSE
                Dbg(L"Allowing process to breakaway from job object. Image name: '%s'", imageName.c_str());
#endif
                return true;
            }

            std::wstring command;
            std::wstring commandArgs;
            FindApplicationNameFromCommandLine(lpCommandLine, command, commandArgs);
            if (it->CommandLineArgsSubstringContainmentIgnoreCase)
            {
                if (std::search(commandArgs.begin(), commandArgs.end(), it->RequiredCommandLineArgsSubstring.begin(), it->RequiredCommandLineArgsSubstring.end(), [](wchar_t c1, wchar_t c2) {
                    return std::towlower(c1) == std::towlower(c2);
                    }) != commandArgs.end())
                {
#if SUPER_VERBOSE
                    Dbg(L"Allowing process to breakaway from job object. Image name: '%s' | Command line args: '%s'.", imageName.c_str(), commandArgs.c_str());
#endif
                    return true;
                }
            }
            else if (commandArgs.find(it->RequiredCommandLineArgsSubstring) != std::wstring::npos)
            {
#if SUPER_VERBOSE
                Dbg(L"Allowing process to breakaway from job object. Image name: '%s' | Command line args: '%s'.", imageName.c_str(), commandArgs.c_str());
#endif
                return true;
            }
        }
    }

    return false;
}

BOOL WINAPI Detoured_CreateProcessCommonW(
    _In_opt_      HANDLE                hToken,
    _In_opt_      LPCWSTR               lpApplicationName,
    _Inout_opt_   LPWSTR                lpCommandLine,
    _In_opt_      LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_      LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_          BOOL                  bInheritHandles,
    _In_          DWORD                 dwCreationFlags,
    _In_opt_      LPVOID                lpEnvironment,
    _In_opt_      LPCWSTR               lpCurrentDirectory,
    _In_          LPSTARTUPINFOW        lpStartupInfo,
    _Out_         LPPROCESS_INFORMATION lpProcessInformation)
{
    bool injectedShim = false;
    BOOL ret = MaybeInjectSubstituteProcessShim(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        injectedShim);
    if (injectedShim)
    {
        Dbg(L"Injected shim for lpCommandLine='%s', returning 0x%08X from CreateProcessW", lpCommandLine, ret);
        return ret;
    }

    DetouredScope scope;

    if (!MonitorChildProcesses() || scope.Detoured_IsDisabled())
    {
        return hToken == nullptr
            ? Real_CreateProcessW(
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation)
            : Real_CreateProcessAsUserW(
                hToken,
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                dwCreationFlags,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation);
    }

    CanonicalizedPath imagePath = GetImagePath(lpApplicationName, lpCommandLine);

    if (ShouldBreakawayFromJob(imagePath, lpCommandLine))
    {
        // If the process to be created is configured to breakaway from the current
        // job object, we use the regular process creation, and set the breakaway flag.
        return hToken == nullptr
            ? Real_CreateProcessW(
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                // Since this process will be detached from the job, and could survive the parent, we don't
                // want any handle inheritance to happen
                /*bInheritHandles*/ FALSE,
                dwCreationFlags | CREATE_BREAKAWAY_FROM_JOB,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation)
            : Real_CreateProcessAsUserW(
                hToken,
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                // Since this process will be detached from the job, and could survive the parent, we don't
                // want any handle inheritance to happen
                /*bInheritHandles*/ FALSE,
                dwCreationFlags | CREATE_BREAKAWAY_FROM_JOB,
                lpEnvironment,
                lpCurrentDirectory,
                lpStartupInfo,
                lpProcessInformation);;
    }

    FileOperationContext operationContext = FileOperationContext::CreateForRead(L"CreateProcess", !imagePath.IsNull() ? imagePath.GetPathString() : L"");
    operationContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_NORMAL; // Create process image should be a file
    FileReadContext readContext;
    AccessCheckResult readCheck(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
    PolicyResult policyResult;

    if (!imagePath.IsNull() && !IgnoreCreateProcessReport())
    {
        if (!policyResult.Initialize(imagePath.GetPathString()))
        {
            policyResult.ReportIndeterminatePolicyAndSetLastError(operationContext);
            return FALSE;
        }

        if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(operationContext, policyResult, true))
        {
            return INVALID_FILE_ATTRIBUTES;
        }

        if (ExistsAsFile(imagePath.GetPathString()))
        {
            readContext.Existence = FileExistence::Existent;
        }

        readCheck = policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext);

        if (readCheck.ShouldDenyAccess())
        {
            const bool maskRead = ShouldDeniedReadsAsNotFound();
            DWORD denyError = readCheck.DenialError(maskRead);
            ReportIfNeeded(readCheck, operationContext, policyResult, denyError);
            readCheck.SetLastErrorToDenialError(maskRead);
            return FALSE;
        }

        if (!EnforceChainOfReparsePointAccessesForNonCreateFile(operationContext, policyResult))
        {
            return FALSE;
        }
    }

    bool retryCreateProcess = true;
    unsigned retryCount = 0;

    while (retryCreateProcess)
    {
        retryCreateProcess = false;
        // Make sure we pass the Real_CreateProcessW such that it calls into the prior entry point
        CreateDetouredProcessStatus status = InternalCreateDetouredProcess(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            (HANDLE)0,
            g_pDetouredProcessInjector,
            lpProcessInformation,
            Real_CreateProcessW,
            Real_CreateProcessAsUserW,
            // If enabled in the manifest, hard exit on Detours error on the final retry.
            retryCount == RETRY_DETOURING_PROCESS_COUNT);

        DWORD lastError = GetLastError();

        if (status == CreateDetouredProcessStatus::Succeeded)
        {
            if (!imagePath.IsNull())
            {
                ReportIfNeeded(readCheck, operationContext, policyResult, ERROR_SUCCESS);
            }

            return TRUE;
        }
        else if (status == CreateDetouredProcessStatus::ProcessCreationFailed)
        {
            // Process creation failure is something normally visible to the caller. Preserve last error information.
            if (!imagePath.IsNull())
            {
                ReportIfNeeded(readCheck, operationContext, policyResult, GetLastError());
            }

            return FALSE;
        }
        else
        {
            // Retry process creation a few times in case of transient errors.
            if ((lastError == ERROR_INVALID_FUNCTION || lastError == WAIT_TIMEOUT // Typically due to failed brokered/remote injection.
                || lastError == ERROR_ACCESS_DENIED
                || lastError == ERROR_PARTIAL_COPY) // Copying payload sometimes failed.
                && retryCount < RETRY_DETOURING_PROCESS_COUNT)
            {
                Sleep(RETRY_DETOURING_PROCESS_SLEEP_MS + (retryCount * RETRY_DETOURING_PROCESS_SLEEP_MS));
                retryCount++;
                Dbg(L"Retrying to start process '%s' for %d time due to detouring failure, last error: 0x%08X", lpCommandLine, retryCount, lastError);
                retryCreateProcess = true;

                // Reset last error to avoid confusing the retry logic.
                SetLastError(ERROR_SUCCESS);
                continue;
            }

            Dbg(L"Failure detouring the process '%s' after %d retries, last error: 0x%08X", lpCommandLine, retryCount, lastError);

            if (!imagePath.IsNull())
            {
                ReportIfNeeded(readCheck, operationContext, policyResult, GetLastError());
            }

            // We've invented a failure other than process creation due to our detours; invent a consistent error
            // rather than leaking whatever error might be set due to our failed efforts.
            // This line of code is only reachable if the hard-exit-on-Detours-error feature is disabled.
            SetLastError(ERROR_ACCESS_DENIED);

            return FALSE;
        }
    }

    return TRUE;
}

IMPLEMENTED(Detoured_CreateProcessW)
BOOL WINAPI Detoured_CreateProcessW(
    _In_opt_    LPCWSTR               lpApplicationName,
    _Inout_opt_ LPWSTR                lpCommandLine,
    _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_        BOOL                  bInheritHandles,
    _In_        DWORD                 dwCreationFlags,
    _In_opt_    LPVOID                lpEnvironment,
    _In_opt_    LPCWSTR               lpCurrentDirectory,
    _In_        LPSTARTUPINFOW        lpStartupInfo,
    _Out_       LPPROCESS_INFORMATION lpProcessInformation)
{
    return Detoured_CreateProcessCommonW(
        nullptr,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
}

IMPLEMENTED(Detoured_CreateProcessA)
BOOL WINAPI Detoured_CreateProcessA(
    _In_opt_    LPCSTR                lpApplicationName,
    _Inout_opt_ LPSTR                 lpCommandLine,
    _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_        BOOL                  bInheritHandles,
    _In_        DWORD                 dwCreationFlags,
    _In_opt_    LPVOID                lpEnvironment,
    _In_opt_    LPCSTR                lpCurrentDirectory,
    _In_        LPSTARTUPINFOA        lpStartupInfo,
    _Out_       LPPROCESS_INFORMATION lpProcessInformation)
{
    // Note that we only do Real_CreateProcessA
    // for the case of not doing child processes.
    // Otherwise this converts to CreateProcessW
    if (!MonitorChildProcesses())
    {
        return Real_CreateProcessA(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    UnicodeConverter applicationName(lpApplicationName);
    UnicodeConverter commandLine(lpCommandLine);
    UnicodeConverter currentDirectory(lpCurrentDirectory);

    UnicodeConverter desktop(lpStartupInfo->lpDesktop);
    UnicodeConverter title(lpStartupInfo->lpTitle);

    STARTUPINFOW startupInfo;
    startupInfo.cb = sizeof(STARTUPINFOW);
    startupInfo.lpReserved = NULL;
    startupInfo.lpDesktop = desktop.GetMutableString();
    startupInfo.lpTitle = title.GetMutableString();
    startupInfo.dwX = lpStartupInfo->dwX;
    startupInfo.dwY = lpStartupInfo->dwY;
    startupInfo.dwXSize = lpStartupInfo->dwXSize;
    startupInfo.dwYSize = lpStartupInfo->dwYSize;
    startupInfo.dwXCountChars = lpStartupInfo->dwXCountChars;
    startupInfo.dwYCountChars = lpStartupInfo->dwYCountChars;
    startupInfo.dwFillAttribute = lpStartupInfo->dwFillAttribute;
    startupInfo.dwFlags = lpStartupInfo->dwFlags;
    startupInfo.wShowWindow = lpStartupInfo->wShowWindow;
    startupInfo.cbReserved2 = lpStartupInfo->cbReserved2;
    startupInfo.lpReserved2 = lpStartupInfo->lpReserved2;
    startupInfo.hStdInput = lpStartupInfo->hStdInput;
    startupInfo.hStdOutput = lpStartupInfo->hStdOutput;
    startupInfo.hStdError = lpStartupInfo->hStdError;

    BOOL result = Detoured_CreateProcessW(
        applicationName,
        commandLine.GetMutableString(),
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        currentDirectory,
        &startupInfo,
        lpProcessInformation);

    return result;
}

IMPLEMENTED(Detoured_CreateProcessAsUserW)
BOOL WINAPI Detoured_CreateProcessAsUserW(
    _In_opt_    HANDLE                hToken,
    _In_opt_    LPCWSTR               lpApplicationName,
    _Inout_opt_ LPWSTR                lpCommandLine,
    _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_        BOOL                  bInheritHandles,
    _In_        DWORD                 dwCreationFlags,
    _In_opt_    LPVOID                lpEnvironment,
    _In_opt_    LPCWSTR               lpCurrentDirectory,
    _In_        LPSTARTUPINFOW        lpStartupInfo,
    _Out_       LPPROCESS_INFORMATION lpProcessInformation)
{
    Dbg(L"Detoured_CreateProcessAsUserW called");
    // TODO: Remove this flag once testing is complete.
    if (!MonitorCreateProcessAsUser())
    {
        return Real_CreateProcessAsUserW(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    return Detoured_CreateProcessCommonW(
        hToken,
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
}

IMPLEMENTED(Detoured_CreateProcessAsUserA)
BOOL WINAPI Detoured_CreateProcessAsUserA(
    _In_opt_    HANDLE                hToken,
    _In_opt_    LPCSTR                lpApplicationName,
    _Inout_opt_ LPSTR                 lpCommandLine,
    _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_        BOOL                  bInheritHandles,
    _In_        DWORD                 dwCreationFlags,
    _In_opt_    LPVOID                lpEnvironment,
    _In_opt_    LPCSTR                lpCurrentDirectory,
    _In_        LPSTARTUPINFOA        lpStartupInfo,
    _Out_       LPPROCESS_INFORMATION lpProcessInformation)
{
    UnicodeConverter applicationName(lpApplicationName);
    UnicodeConverter commandLine(lpCommandLine);
    UnicodeConverter currentDirectory(lpCurrentDirectory);

    UnicodeConverter desktop(lpStartupInfo->lpDesktop);
    UnicodeConverter title(lpStartupInfo->lpTitle);

    STARTUPINFOW startupInfo;
    startupInfo.cb = sizeof(STARTUPINFOW);
    startupInfo.lpReserved = NULL;
    startupInfo.lpDesktop = desktop.GetMutableString();
    startupInfo.lpTitle = title.GetMutableString();
    startupInfo.dwX = lpStartupInfo->dwX;
    startupInfo.dwY = lpStartupInfo->dwY;
    startupInfo.dwXSize = lpStartupInfo->dwXSize;
    startupInfo.dwYSize = lpStartupInfo->dwYSize;
    startupInfo.dwXCountChars = lpStartupInfo->dwXCountChars;
    startupInfo.dwYCountChars = lpStartupInfo->dwYCountChars;
    startupInfo.dwFillAttribute = lpStartupInfo->dwFillAttribute;
    startupInfo.dwFlags = lpStartupInfo->dwFlags;
    startupInfo.wShowWindow = lpStartupInfo->wShowWindow;
    startupInfo.cbReserved2 = lpStartupInfo->cbReserved2;
    startupInfo.lpReserved2 = lpStartupInfo->lpReserved2;
    startupInfo.hStdInput = lpStartupInfo->hStdInput;
    startupInfo.hStdOutput = lpStartupInfo->hStdOutput;
    startupInfo.hStdError = lpStartupInfo->hStdError;

    BOOL result = Detoured_CreateProcessAsUserW(
        hToken,
        applicationName,
        commandLine.GetMutableString(),
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        currentDirectory,
        &startupInfo,
        lpProcessInformation);

    return result;
}

static bool TryGetUsn(
    _In_    HANDLE handle,
    _Inout_ USN&   usn,
    _Inout_ DWORD& error)
{
    // TODO: http://msdn.microsoft.com/en-us/library/windows/desktop/aa364993(v=vs.85).aspx says to call GetVolumeInformation to get maximum component length.
    const size_t MaximumComponentLength = 255;
    const size_t MaximumChangeJournalRecordSize =
        (MaximumComponentLength * sizeof(WCHAR)
            + sizeof(USN_RECORD) - sizeof(WCHAR));
    union {
        USN_RECORD_V2 usnRecord;
        BYTE reserved[MaximumChangeJournalRecordSize];
    };
    DWORD bytesReturned;
    if (!DeviceIoControl(handle,
        FSCTL_READ_FILE_USN_DATA,
        NULL,
        0,
        &usnRecord,
        MaximumChangeJournalRecordSize,
        &bytesReturned,
        NULL))
    {
        error = GetLastError();
        return false;
    }

    assert(bytesReturned <= MaximumChangeJournalRecordSize);
    assert(bytesReturned == usnRecord.RecordLength);
    assert(2 == usnRecord.MajorVersion);
    usn = usnRecord.Usn;
    return true;
}

// If we are not attached this is not App use of RAM but the OS proess startup side of the world.
extern bool g_isAttached;

// ---------------------------------------------------------------------------
// Model W write-overlay: write/read redirection to a process-private backing
// store (ShouldWriteOverlay()). Undeclared writes in the execroot-writable cone
// are redirected under g_bazelWriteOverlayRoot (mirroring the virtual path) so
// the real execroot is never mutated and each action's scratch is isolated. The
// virtual path is recorded in the created-set index (reused as the overlay
// index) so reads redirect to the backing copy and enumeration can insert it.
// All policy/reporting still runs on the VIRTUAL path; only the path handed to
// the Real_ call is swapped. Everything here is gated by ShouldWriteOverlay().
// ---------------------------------------------------------------------------

// True if `pr` names an undeclared write target in the execroot-writable cone
// (OverrideAllowWriteForExistingFiles) that should be redirected. That bit is set
// ONLY on the execroot cone under --write-overlay/--execroot-writable; declared -w
// outputs and -d output dirs are granted with Policy_MaskAll (no inheritance) and
// without the override bit, so they are naturally excluded and land in the real
// execroot where Bazel harvests them in place. (Note: IndicateUntracked() is NOT a
// usable discriminator here - the cone's policy equals the DLL's AllowAll mask, so
// both the cone and declared -w outputs report untracked.)
static bool ShouldRedirectToOverlay(const PolicyResult& pr)
{
    return ShouldWriteOverlay()
        && g_bazelWriteOverlayRoot != nullptr
        && g_bazelWriteOverlayRoot[0] != L'\0'
        && pr.OverrideAllowWriteForExistingFiles();
}

// Map a virtual (plain "X:\...") path to its backing-store path by stripping the
// overlay source root (g_bazelOverlaySourceRoot) and appending the remainder under
// the backing root, e.g. with source root C:\ws and backing \\?\<root>,
// C:\ws\a\b.txt -> \\?\<root>\a\b.txt. The \\?\ prefix keeps deep paths under the
// MAX_PATH ceiling. The source-root strip is case-insensitive and tolerant of a
// trailing separator on either side. If the source root is unset or the virtual
// path is not under it (should not happen: the redirect cone == the source root by
// construction), we fall back to a full drive-letter mirror (\\?\<root>\C\ws\...)
// as defensive insurance. Returns "" if the input is not a drive-letter path.
static std::wstring OverlayBackingPath(const std::wstring& virtualPath)
{
    if (virtualPath.size() < 3 || virtualPath[1] != L':')
    {
        return std::wstring();
    }

    // Preferred path: strip the overlay source root prefix (case-insensitive).
    if (g_bazelOverlaySourceRoot != nullptr && g_bazelOverlaySourceRoot[0] != L'\0')
    {
        std::wstring src(g_bazelOverlaySourceRoot);
        while (!src.empty() && src.back() == L'\\') src.pop_back();  // trim trailing sep
        const size_t n = src.size();
        const bool prefixMatch =
            virtualPath.size() >= n &&
            _wcsnicmp(virtualPath.c_str(), src.c_str(), n) == 0 &&
            // Ensure a full path-segment boundary: either an exact match or the
            // next char in the virtual path is a separator (avoids C:\ws matching
            // C:\wsX). At the exact-match boundary the remainder is empty.
            (virtualPath.size() == n || virtualPath[n] == L'\\');
        if (prefixMatch)
        {
            std::wstring rest = virtualPath.substr(n);  // "\a\b.txt" or ""
            std::wstring backing = L"\\\\?\\";
            backing += g_bazelWriteOverlayRoot;
            if (!rest.empty() && rest.front() != L'\\') backing += L'\\';
            backing += rest;
            return backing;
        }
    }

    // Defensive fallback: full drive-letter mirror (\\?\<root>\<drive>\<rest>).
    std::wstring backing = L"\\\\?\\";
    backing += g_bazelWriteOverlayRoot;
    backing += L'\\';
    backing += virtualPath[0];          // drive letter (colon dropped)
    backing += virtualPath.substr(2);   // "\ws\scratch.txt"
    return backing;
}

// Create every ancestor directory of a backing FILE path (incremental prefixes).
// Nested Win32 calls pass through to the real API (DetouredScope disables nested
// Reverse of OverlayBackingPath: map a physical backing-store path back to the
// virtual (real cone) path it stands in for, so a tool that canonicalizes an
// overlay-redirected handle observes the LOGICAL execroot path, not the private
// backing location. Without this the JVM class loader (which canonicalizes each
// classpath entry via GetFinalPathNameByHandle and requires the resource's
// canonical path to stay under the classpath dir's canonical path) rejects every
// class read out of an overlay-redirected file - because the redirect copies the
// file up into the backing store and the handle's final path leaks as
// "\\?\<backingRoot>\...". Handles the primary source-root-strip mapping
// (backingRoot + rest -> sourceRoot + rest); returns false (no rewrite) for any
// path not under the backing root. `finalPath` may carry a \\?\ or \??\ prefix,
// which is preserved on the rewritten result. Kill-switched with the overlay.
static bool ReverseOverlayFinalPath(const std::wstring& finalPath, std::wstring& out)
{
    if (!ShouldWriteOverlay()
        || g_bazelWriteOverlayRoot == nullptr || g_bazelWriteOverlayRoot[0] == L'\0'
        || g_bazelOverlaySourceRoot == nullptr || g_bazelOverlaySourceRoot[0] == L'\0')
    {
        return false;
    }

    std::wstring prefix;
    std::wstring body(finalPath);
    if (body.compare(0, 4, L"\\\\?\\") == 0) { prefix = L"\\\\?\\"; body.erase(0, 4); }
    else if (body.compare(0, 4, L"\\??\\") == 0) { prefix = L"\\??\\"; body.erase(0, 4); }

    std::wstring root(g_bazelWriteOverlayRoot);
    while (!root.empty() && root.back() == L'\\') root.pop_back();
    const size_t n = root.size();
    // The final path must be the backing root itself or a descendant of it, at a
    // full path-segment boundary (so <root> does not match <root>Suffix).
    if (body.size() < n || _wcsnicmp(body.c_str(), root.c_str(), n) != 0) return false;
    if (body.size() != n && body[n] != L'\\') return false;

    std::wstring src(g_bazelOverlaySourceRoot);
    while (!src.empty() && src.back() == L'\\') src.pop_back();
    out = prefix + src + body.substr(n);   // sourceRoot + "\rest" (or "" at exact match)
    return true;
}

// detours on this thread), so no policy is re-applied. Failures are benign
// (ERROR_ALREADY_EXISTS or a parent that a later step recreates).
static void EnsureBackingParentDirs(const std::wstring& backingPath)
{
    size_t start = (backingPath.compare(0, 4, L"\\\\?\\") == 0) ? 4 : 0;
    for (size_t i = start; i < backingPath.size(); ++i)
    {
        if (backingPath[i] == L'\\')
        {
            std::wstring dir = backingPath.substr(0, i);
            if (dir.size() > start)
            {
                CreateDirectoryW(dir.c_str(), nullptr);
            }
        }
    }
}

static bool OverlayPathExists(const std::wstring& p)
{
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// True if `p` exists and is a directory.
static bool OverlayIsDirectory(const std::wstring& p)
{
    DWORD attrs = GetFileAttributesW(p.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// List the immediate child names present in this action's backing store under the
// virtual directory `virtualDir` (plain "X:\..." form). This is the Model W
// "backing store is the source of truth" enumeration source (see design doc
// §6.3): the overlay entries to splice into a directory listing are exactly the
// children of the mirrored backing subdirectory, obtained via one OS directory
// scan - O(children-in-this-dir) - rather than an O(total-created) walk of the
// cross-process created-set index. The backing subdirectory exists only once some
// path under it has been redirected (EnsureBackingParentDirs mirrors ancestors),
// so an absent backing dir simply contributes nothing. "." and ".."
// are skipped. Nested FindFirstFile/FindNextFile pass through to the real API
// (DetouredScope disables nested detours on this thread), so no policy is applied
// to the backing scan itself.
static void ListBackingChildren(const std::wstring& virtualDir, std::vector<std::wstring>& out)
{
    const std::wstring backingDir = OverlayBackingPath(virtualDir);
    if (backingDir.empty() || !OverlayIsDirectory(backingDir))
    {
        return;
    }

    std::wstring pattern = backingDir;
    while (!pattern.empty() && (pattern.back() == L'\\' || pattern.back() == L'/'))
    {
        pattern.pop_back();
    }
    pattern += L"\\*";

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        return;
    }
    do
    {
        const wchar_t* nm = fd.cFileName;
        if (nm[0] == L'.' && (nm[1] == L'\0' || (nm[1] == L'.' && nm[2] == L'\0')))
        {
            continue; // skip "." and ".."
        }
        out.push_back(std::wstring(nm));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// Cross-TU (declared in PolicyResult.h): true if `virtualPathNoPrefix` (plain
// "X:\..." form) has a shadow in THIS action's Model W backing store. This is the
// "backing store is the source of truth" primitive (design doc §6.3): PolicyResult
// treats "exists in the backing store" as "created by this action this run", so the
// rewrite-vs-clobber decision (AllowWrite) and the enumeration/read visibility
// carve-out (WasCreatedInThisProcess) are answered from the filesystem instead of
// the cross-process created-set SHM index. Because the backing store is shared by
// the whole action tree (per-invocation root in the manifest), this is inherently
// cross-process-consistent. Returns false whenever the overlay is inactive (no
// --write-overlay / no root), so the legacy --execroot-writable created-set path is
// unaffected. Callers are always inside an active DetouredScope, so the nested
// GetFileAttributesW passes through to the real API (no policy re-applied).
bool OverlayBackingExists(const std::wstring& virtualPathNoPrefix)
{
    if (!ShouldWriteOverlay() ||
        g_bazelWriteOverlayRoot == nullptr ||
        g_bazelWriteOverlayRoot[0] == L'\0')
    {
        return false;
    }
    const std::wstring backing = OverlayBackingPath(virtualPathNoPrefix);
    return !backing.empty() && OverlayPathExists(backing);
}

// True if an EXISTING real file at this policy's path is HIDDEN from the
// sandboxed process by the Bazel input filter (--filter-inputs): an undeclared
// input that the read/enumeration hooks make appear absent (denied reads masked
// to NOT_FOUND; undeclared children removed from listings).
//
// The predicate must be independent of the per-process created-set: by the time
// this runs the write pre-check (PolicyResult::AllowWrite) has already
// MarkCreated'd a pre-existing undeclared file under --write-overlay, so
// CheckReadAccess / WasCreatedInThisProcess would spuriously report it visible.
// Instead we consult only the STATIC manifest policy, mirroring the enumeration
// filter's visibility rule (IsEnumChildVisible): a path is visible iff its policy
// allows read (a declared input, or under a declared directory-input cone) or it
// is an exact ancestor node leading to a declared input. Everything else is an
// undeclared input the filter hides.
//
// Gated on ShouldDeniedReadsAsNotFound() (set only by --filter-inputs): without
// the filter the execroot cone grants blanket read, nothing is hidden, and this
// returns false - so CREATE_NEW keeps its plain fail-if-exists behavior.
static bool OverlayRealFileHiddenByFilter(const PolicyResult& policyResult)
{
    if (!ShouldDeniedReadsAsNotFound())
    {
        return false;
    }
    return !(policyResult.AllowRead() || policyResult.IsExactManifestNode());
}

// Decide the path to hand to Real_CreateFileW for a Model W redirect, preparing
// the backing store as needed. Returns the backing path (to open instead of the
// virtual path) or "" to leave the open on the real virtual path.
//
//  * Write-intent open of a redirectable path: ensure backing dirs, copy-up the
//    real file first when the disposition preserves existing content, record the
//    virtual path in the overlay index, and return the backing path.
//  * Read-intent open of a path whose backing already exists (this action wrote
//    it): return the backing path so the read sees the overlay copy.
//  * Otherwise: return "" (open the real path unchanged).
static std::wstring ResolveOverlayOpenPath(
    const PolicyResult& policyResult,
    DWORD dwDesiredAccess,
    DWORD dwCreationDisposition)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }

    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return std::wstring();
    }

    // Directory-handle resolution. When the directory exists on the REAL disk we
    // must NOT redirect: enumeration (NtQueryDirectoryFile) has to list the REAL
    // directory so real entries are returned, and the overlay's own children are
    // spliced in separately by InsertOverlayEntries. Redirecting a real directory's
    // open to the backing store would enumerate ONLY the backing dir - dropping real
    // siblings AND double-listing the overlay files that insertion then re-adds.
    //
    // An OVERLAY-ONLY directory (present in the backing store but not on the real
    // disk - e.g. a scratch dir created via CreateDirectoryW, which Model W redirects
    // into the backing store) has no real directory to open, so we DO redirect its
    // handle to the backing directory. The OS then enumerates the backing children
    // directly; InsertOverlayEntries detects the absent real dir and adds nothing, so
    // there is no double-listing. Under --filter-inputs those backing children stay
    // visible via the WasCreatedInThisProcess (backing-existence) enumeration
    // carve-out. The backing dir exists as soon as any file under it is written
    // (EnsureBackingParentDirs), so the real-dir-first ordering here is load-bearing.
    const std::wstring realWidePath = L"\\\\?\\" + virtualPath;
    if (OverlayIsDirectory(realWidePath))
    {
        return std::wstring();
    }
    if (OverlayIsDirectory(backing))
    {
        return backing;
    }

    const bool wantsWrite = WantsWriteAccess(dwDesiredAccess);
    const bool backingExists = OverlayPathExists(backing);

    if (wantsWrite)
    {
        // CREATE_NEW must fail if the file already exists in the MERGED view (real
        // execroot OR this action's overlay) AND that existing file is VISIBLE to
        // the tool. When we have no backing copy yet but the real undeclared file
        // exists and is visible, redirecting to the (absent) backing path would let
        // CREATE_NEW wrongly succeed against an empty backing file. Leave the open
        // on the real path: CREATE_NEW does not open or mutate an existing file, so
        // the OS fails it with ERROR_FILE_EXISTS - the correct merged-view result -
        // without touching the real bytes.
        //
        // Exception (linux-sandbox parity): under --filter-inputs an undeclared
        // pre-existing file is HIDDEN (its reads are masked to NOT_FOUND), so the
        // merged view treats it as ABSENT. CREATE_NEW must then SUCCEED into the
        // backing store, matching linux-sandbox whose throwaway execroot never
        // contains the undeclared file. In that case we fall through to
        // create-in-backing below (the real bytes remain untouched). Without
        // --filter-inputs the file is visible, so we keep the fail-if-exists
        // behavior above.
        //
        // (If the backing copy already exists, we fall through and redirect; Real
        // CREATE_NEW then fails against the existing backing file, which is likewise
        // correct. If neither exists, we create the new file in the backing store.)
        if (dwCreationDisposition == CREATE_NEW && !backingExists)
        {
            const std::wstring realWideNew = L"\\\\?\\" + virtualPath;
            if (OverlayPathExists(realWideNew) && !OverlayRealFileHiddenByFilter(policyResult))
            {
                return std::wstring();
            }
        }

        EnsureBackingParentDirs(backing);

        // Copy-up: if we have not captured this path yet and the real file exists
        // and the disposition keeps existing content, seed the backing copy so the
        // tool observes the current bytes (open-to-modify). TRUNCATE/CREATE_ALWAYS
        // discard content, and CREATE_NEW starts empty, so no copy is needed there.
        if (!backingExists &&
            dwCreationDisposition != CREATE_ALWAYS &&
            dwCreationDisposition != TRUNCATE_EXISTING &&
            dwCreationDisposition != CREATE_NEW)
        {
            const std::wstring realWide = L"\\\\?\\" + virtualPath;
            if (OverlayPathExists(realWide.c_str()))
            {
                CopyFileW(realWide.c_str(), backing.c_str(), TRUE /*failIfExists*/);
            }
        }

        // Record the virtual path so reads redirect here and enumeration inserts it.
        policyResult.MarkCreatedInThisProcess();
        return backing;
    }

    // Read-intent: only redirect when this action already has a backing copy.
    if (backingExists)
    {
        return backing;
    }
    return std::wstring();
}

// Model W (write-overlay) delete/rename-source resolution. Decides how removing
// policyResult's path must be handled so the real execroot is NEVER mutated. See
// docs/design/detours-write-overlay-vfs.md §6.3.1 (backing-store-as-truth, no
// whiteout markers). On RedirectToBacking, backingOut receives the backing-store
// path the unlink/move must operate on instead of the real path.
enum class OverlayDeleteAction { PassThrough, RedirectToBacking, DenyAccess, NotFound };

static OverlayDeleteAction ResolveOverlayDelete(PolicyResult& policyResult, std::wstring& backingOut)
{
    backingOut.clear();
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return OverlayDeleteAction::PassThrough;
    }

    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return OverlayDeleteAction::PassThrough;
    }

    const std::wstring realWide = L"\\\\?\\" + virtualPath;
    const bool backingExists = OverlayPathExists(backing.c_str());
    const bool realExists = OverlayPathExists(realWide.c_str());
    const bool hiddenByFilter = OverlayRealFileHiddenByFilter(policyResult);

    if (backingExists)
    {
        // Written-over lower file with the real original still visible (permissive
        // mode): removing the backing copy would re-expose the real bytes, which we
        // cannot hide without mutating the real execroot. Deny.
        if (realExists && !hiddenByFilter)
        {
            return OverlayDeleteAction::DenyAccess;
        }
        // Backing-only file, or written-over lower whose real original stays hidden
        // by the input filter: remove the backing copy. The tool's merged view then
        // shows the path as gone.
        backingOut = std::move(backing);
        return OverlayDeleteAction::RedirectToBacking;
    }

    // No backing copy exists.
    if (realExists)
    {
        // Pre-existing lower-only file: the real bytes are read-only and must never be
        // deleted. Under the input filter the file is hidden, so the merged view has no
        // such entry -> NOT_FOUND no-op. In permissive mode it is a visible undeclared
        // input -> deny the clobber.
        return hiddenByFilter ? OverlayDeleteAction::NotFound : OverlayDeleteAction::DenyAccess;
    }

    // Neither backing nor real exists: nothing to redirect; let the real call return
    // NOT_FOUND on its own.
    return OverlayDeleteAction::PassThrough;
}

// Model W rename destination resolution. The move's destination half mirrors the
// filter-aware CREATE_NEW of §5.6.2: when policyResult is inside the write-overlay
// redirect cone, the moved file must land in the backing store (creating parent
// dirs), never the real execroot. Returns the backing dest path, or "" to pass the
// destination through to the real path unchanged (e.g. a declared -w output).
static std::wstring ResolveOverlayRenameDest(PolicyResult& policyResult)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }
    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return std::wstring();
    }
    EnsureBackingParentDirs(backing);
    policyResult.MarkCreatedInThisProcess();
    return backing;
}

// Model W (write-overlay) probe/metadata resolution. For a read-only metadata query
// (GetFileAttributes(Ex), GetFileInformationByName, exact FindFirstFile) of a path that
// has a backing copy, return the backing path so the query observes the scratch file
// the action wrote - so stat of a file the process created in the overlay works. Returns
// "" to probe the real path unchanged. Mirrors the read-intent branch of
// ResolveOverlayOpenPath (redirect only when a backing copy already exists).
static std::wstring ResolveOverlayProbePath(PolicyResult& policyResult)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }
    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty() || !OverlayPathExists(backing.c_str()))
    {
        return std::wstring();
    }
    return backing;
}

IMPLEMENTED(Detoured_CreateFileW)
HANDLE WINAPI Detoured_CreateFileW(
    _In_     LPCWSTR               lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwCreationDisposition,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile)
{
    DetouredScope scope;
    // The are potential complication here: How to handle a call to CreateFile with the FILE_FLAG_OPEN_REPARSE_POINT?
    // Is it a real file access. Some code in Windows (urlmon.dll) inspects reparse points when mapping a path to a particular security "Zone".
    if (scope.Detoured_IsDisabled() || IsNullOrEmptyW(lpFileName) || IsSpecialDeviceName(lpFileName))
    {
        return Real_CreateFileW(
            lpFileName,
            dwDesiredAccess,
            dwShareMode,
            lpSecurityAttributes,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            hTemplateFile);
    }

    DWORD error = ERROR_SUCCESS;

    FileOperationContext opContext(
        L"CreateFile",
        dwDesiredAccess,
        dwShareMode,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        lpFileName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpFileName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return INVALID_HANDLE_VALUE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(opContext, policyResult, true))
    {
        return FALSE;
    }

    // We start with allow / ignore (no access requested) and then restrict based on read / write (maybe both, maybe neither!)
    AccessCheckResult accessCheck(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
    bool forceReadOnlyForRequestedRWAccess = false;
    if (WantsWriteAccess(dwDesiredAccess))
    {
        error = GetLastError();
        accessCheck = policyResult.CheckWriteAccess();

        if (ForceReadOnlyForRequestedReadWrite() && accessCheck.Result != ResultAction::Allow)
        {
            // If ForceReadOnlyForRequestedReadWrite() is true, then we allow read for requested read-write access so long as the tool is allowed to read.
            // In such a case, we change the desired access to read only (see the call to Real_CreateFileW below).
            // As a consequence, the tool can fail if it indeed wants to write to the file.
            if (WantsReadAccess(dwDesiredAccess) && policyResult.AllowRead())
            {
                accessCheck = AccessCheckResult(RequestedAccess::Read, ResultAction::Allow, ReportLevel::Ignore);
                FileOperationContext operationContext(
                    L"ChangedReadWriteToReadAccess",
                    dwDesiredAccess,
                    dwShareMode,
                    dwCreationDisposition,
                    dwFlagsAndAttributes,
                    policyResult.GetCanonicalizedPath().GetPathString());

                ReportFileAccess(
                    operationContext,
                    FileAccessStatus::FileAccessStatus_Allowed,
                    policyResult,
                    AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report),
                    0,
                    -1);

                forceReadOnlyForRequestedRWAccess = true;
            }
        }

        if (!forceReadOnlyForRequestedRWAccess && accessCheck.ShouldDenyAccess())
        {
            const bool maskRead = ShouldDeniedReadsAsNotFound();
            DWORD denyError = accessCheck.DenialError(maskRead);
            ReportIfNeeded(accessCheck, opContext, policyResult, denyError); // We won't make it to the post-read-check report below.
            accessCheck.SetLastErrorToDenialError(maskRead);
            return INVALID_HANDLE_VALUE;
        }

        SetLastError(error);
    }

    // At this point and beyond, we know we are either dealing with a write request that has been approved, or a
    // read request which may or may not have been approved (due to special exceptions for directories and non-existent files).
    // It is safe to go ahead and perform the real CreateFile() call, and then to reason about the results after the fact.

    // Note that we need to add FILE_SHARE_DELETE to dwShareMode to leverage NTFS hardlinks to avoid copying cache
    // content, i.e., we need to be able to delete one of many links to a file. Unfortunately, share-mode is aggregated only per file
    // rather than per-link, so in order to keep unused links delete-able, we should ensure in-use links are delete-able as well.
    // However, adding FILE_SHARE_DELETE may be unexpected, for example, some unit tests may test for sharing violation. Thus,
    // we only add FILE_SHARE_DELETE if the file is tracked.

    // We also add FILE_SHARE_READ when it is safe to do so, since some tools accidentally ask for exclusive access on their inputs.

    DWORD desiredAccess = dwDesiredAccess;
    DWORD sharedAccess = dwShareMode;

    if (!policyResult.IndicateUntracked())
    {
        DWORD readSharingIfNeeded = policyResult.ShouldForceReadSharing(accessCheck) ? FILE_SHARE_READ : 0UL;
        desiredAccess = !forceReadOnlyForRequestedRWAccess ? desiredAccess : (desiredAccess & FILE_GENERIC_READ);
        sharedAccess = sharedAccess | readSharingIfNeeded;

        if (!PreserveFileSharingBehaviour())
        {
            sharedAccess |= FILE_SHARE_DELETE;
        }
    }

    // Model W write-overlay: redirect the actual open to the process-private
    // backing store when appropriate. Policy/reporting above ran on the virtual
    // path; only the path handed to the OS is swapped. Empty => open unchanged.
    const std::wstring overlayOpenPath =
        ResolveOverlayOpenPath(policyResult, dwDesiredAccess, dwCreationDisposition);
    LPCWSTR realOpenPath = overlayOpenPath.empty() ? lpFileName : overlayOpenPath.c_str();

    HANDLE handle = Real_CreateFileW(
        realOpenPath,
        desiredAccess,
        sharedAccess,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    error = GetLastError();
    DWORD reportedError = GetReportedError(handle != INVALID_HANDLE_VALUE, error);
    FileReadContext readContext;
    readContext.InferExistenceFromError(reportedError);
    readContext.OpenedDirectory = IsHandleOrPathToDirectory(
        handle,
        lpFileName,
        dwDesiredAccess,
        dwFlagsAndAttributes,
        policyResult,
        /*ref*/ opContext.OpenedFileOrDirectoryAttributes);

    if (WantsReadAccess(dwDesiredAccess))
    {
        // We've now established all of the read context, which can further inform the access decision.
        // (e.g. maybe we we allow read only if the file doesn't exist).
        accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext));
    }
    else if (WantsProbeOnlyAccess(dwDesiredAccess))
    {
        accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Probe, readContext));
    }

    // Additionally, for files (not directories) we can enforce a USN match (or report).
    bool unexpectedUsn = false;
    bool reportUsn = false;
    USN usn = -1; // -1, or 0xFFFFFFFFFFFFFFFF indicates that USN could/was not obtained
    if (!readContext.OpenedDirectory) // We do not want to report accesses to directories.
    {
        reportUsn = handle != INVALID_HANDLE_VALUE && policyResult.ReportUsnAfterOpen();
        bool checkUsn = handle != INVALID_HANDLE_VALUE && policyResult.GetExpectedUsn() != -1;

        DWORD getUsnError = ERROR_SUCCESS;
        if ((reportUsn || checkUsn) && !TryGetUsn(handle, /* inout */ usn, /* inout */ getUsnError))
        {
            WriteWarningOrErrorF(L"Could not obtain USN for file path '%s'. Error: %d",
                policyResult.GetCanonicalizedPath().GetPathString(), getUsnError);
            MaybeBreakOnAccessDenied();

            ReportFileAccess(
                opContext,
                FileAccessStatus::FileAccessStatus_CannotDeterminePolicy,
                policyResult,
                AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report),
                getUsnError,
                usn);

            if (handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle);
            }

            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }

        if (checkUsn && usn != policyResult.GetExpectedUsn())
        {
            WriteWarningOrErrorF(L"USN mismatch.  Actual USN: 0x%08x, expected USN: 0x%08x.",
                policyResult.GetCanonicalizedPath().GetPathString(), usn, policyResult.GetExpectedUsn());
            unexpectedUsn = true;
        }
    }

    // ReportUsnAfterOpen implies reporting.
    // TODO: Would be cleaner to just use the normal Report flags (per file / scope) and a global 'look at USNs' flag.
    // Additionally, we report (but do never deny) if a USN did not match an expectation. We must be tolerant to USN changes
    // (which the consumer of these reports may interpret) due to e.g. hard link changes (when a link is added or removed to a file).
    if (reportUsn || unexpectedUsn)
    {
        accessCheck.Level = ReportLevel::ReportExplicit;
        accessCheck = AccessCheckResult::Combine(accessCheck, accessCheck.With(ReportLevel::ReportExplicit));
    }

    bool isHandleToReparsePoint = (dwFlagsAndAttributes & FILE_FLAG_OPEN_REPARSE_POINT) != 0;
    bool shouldReportAccessCheck = true;
    bool shouldResolveReparsePointsInPath = ShouldResolveReparsePointsInPath(policyResult.GetCanonicalizedPath(), opContext.FlagsAndAttributes, policyResult);

    if (shouldResolveReparsePointsInPath)
    {
        bool accessResult = EnforceChainOfReparsePointAccesses(
            policyResult.GetCanonicalizedPath(),
            isHandleToReparsePoint ? handle : INVALID_HANDLE_VALUE,
            desiredAccess,
            sharedAccess,
            dwCreationDisposition,
            dwFlagsAndAttributes,
            false,
            policyResult,
            nullptr,
            true,
            false,
            nullptr,
            true,
            isHandleToReparsePoint);

        if (!accessResult)
        {
            // If we don't have access to the target, close the handle to the reparse point.
            // This way we don't have a leaking handle.
            // (See below we do the same when a normal file access is not allowed and close the file.)
            CloseHandle(handle);
            return INVALID_HANDLE_VALUE;
        }

        if (!IgnoreFullReparsePointResolvingForPath(policyResult))
        {
            shouldReportAccessCheck = false;
        }
    }

    InvalidateReparsePointCacheIfNeeded(
        shouldResolveReparsePointsInPath,
        dwDesiredAccess,
        dwFlagsAndAttributes,
        readContext.OpenedDirectory,
        policyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(),
        policyResult);

    // Handle-resolution read fallback (bazel-sandbox-windows).
    //
    // The bazel windows-sandbox runs in place in the execroot, which is denied by default; declared
    // inputs are re-granted read. But rulesets wire inputs together with symlinks/junctions (runfiles
    // forests, the aspect_rules_js pnpm node_modules store), and a tool frequently opens the file
    // through a link path that is NOT itself a declared input - only the link's real target is. The
    // literal-path policy check above then denies, even though the real file being read is a granted
    // input. (linux-sandbox never hits this: it makes the whole filesystem readable and enforces
    // hermeticity via a curated symlink-forest execroot, so any symlink to a readable target works.)
    //
    // Since Real_CreateFileW already followed the reparse chain and handed us a handle to the *real*
    // file, resolve that handle to its final path and re-check policy there. If the resolved real path
    // is allowed to read, honor the resolved-path policy instead of denying the literal path. This is
    // name-agnostic (no node_modules/.runfiles heuristics) and strictly no less hermetic than the
    // literal check: a link whose real target is undeclared still resolves to a non-granted path and
    // stays denied. Reads only - write/create opens are never rescued.
    if (accessCheck.ShouldDenyAccess()
        && handle != INVALID_HANDLE_VALUE
        && !WantsWriteAccess(dwDesiredAccess)
        && (WantsReadAccess(dwDesiredAccess) || WantsProbeOnlyAccess(dwDesiredAccess))
        && !isHandleToReparsePoint)
    {
        wstring resolvedPath;
        if (DetourGetFinalPathByHandle(handle, resolvedPath) == ERROR_SUCCESS && !resolvedPath.empty())
        {
            PolicyResult resolvedPolicy;
            if (resolvedPolicy.Initialize(resolvedPath.c_str()))
            {
                RequestedReadAccess requested =
                    WantsReadAccess(dwDesiredAccess) ? RequestedReadAccess::Read : RequestedReadAccess::Probe;
                AccessCheckResult resolvedCheck = resolvedPolicy.CheckReadAccess(requested, readContext);
                // Only rescue when the resolved real target is a DECLARED input (carries the
                // FileAccessPolicy_DeclaredInput marker set on -r/-w/-d/tool grants and
                // inherited by granted-directory descendants), not merely readable via the
                // whole-filesystem root scope. The bazel execroot itself is a symlink to the real
                // source tree (execroot/_main -> the workspace), so an undeclared in-execroot path
                // like _main/package.json resolves to a source-tree file that the root AllowRead
                // baseline would otherwise permit - leaking undeclared inputs and breaking
                // hermetic/RBE parity.
                if (!resolvedCheck.ShouldDenyAccess() && resolvedPolicy.IsDeclaredInput())
                {
                    Dbg(L"Handle-resolution read fallback: allowing '%s' via resolved target '%s'.",
                        policyResult.GetCanonicalizedPath().GetPathString(),
                        resolvedPolicy.GetCanonicalizedPath().GetPathString());
                    accessCheck = resolvedCheck;
                }
            }
        }
    }

    // It is possible that we only reached a deny action under some access check combinations above (rather than a direct check),
    // so log and maybe break here as well now that it is final.
    if (accessCheck.Result != ResultAction::Allow)
    {
        WriteWarningOrErrorF(L"Access to file path '%s' is denied.  Requested access: 0x%08x, policy allows: 0x%08x.",
            policyResult.GetCanonicalizedPath().GetPathString(), dwDesiredAccess, policyResult.GetPolicy());
        MaybeBreakOnAccessDenied();
    }

    if (accessCheck.ShouldDenyAccess())
    {
        error = accessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        reportedError = error;

        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }

        handle = INVALID_HANDLE_VALUE;
    }
    else if (handle != INVALID_HANDLE_VALUE)
    {
        HandleType handleType = readContext.OpenedDirectory ? HandleType::Directory : HandleType::File;
        RegisterHandleOverlay(handle, accessCheck, policyResult, handleType);
    }

    if (shouldReportAccessCheck)
    {
        ReportIfNeeded(accessCheck, opContext, policyResult, reportedError, error, usn);
    }

    // Propagate the correct error code to the caller.
    SetLastError(error);
    return handle;
}

IMPLEMENTED(Detoured_CloseHandle)
BOOL WINAPI Detoured_CloseHandle(_In_ HANDLE handle)
{
    DetouredScope scope;

    if (scope.Detoured_IsDisabled() || IsNullOrInvalidHandle(handle))
    {
        return Real_CloseHandle(handle);
    }

    // Make sure the handle is closed after the object is removed from the map.
    // This way the handle will never be assigned to a another object before removed from the table.
    CloseHandleOverlay(handle, true);

    return Real_CloseHandle(handle);
}

IMPLEMENTED(Detoured_CreateFileA)
HANDLE WINAPI Detoured_CreateFileA(
    _In_     LPCSTR                lpFileName,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwCreationDisposition,
    _In_     DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_CreateFileA(
                lpFileName,
                dwDesiredAccess,
                dwShareMode,
                lpSecurityAttributes,
                dwCreationDisposition,
                dwFlagsAndAttributes,
                hTemplateFile);
        }
    }

    UnicodeConverter fileName(lpFileName);
    return Detoured_CreateFileW(
        fileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);
}

// Detoured_GetVolumePathNameW
//
// There's no need to check lpszFileName for null because we are not applying
// any BuildXL policy in this function. There's no reason to check for whether
// lpszFileName is the empty string because although the function fails,
// the last error is set to ERROR_SUCCESS.
//
// Note: There is no need to detour GetVolumePathNameA because there is no policy to apply.
IMPLEMENTED(Detoured_GetVolumePathNameW)
BOOL WINAPI Detoured_GetVolumePathNameW(
    _In_  LPCWSTR lpszFileName,
    _Out_ LPWSTR  lpszVolumePathName,
    _In_  DWORD   cchBufferLength
)
{
    // The reason for this scope check is that GetVolumePathNameW calls many other detoured APIs.
    // We do not need to have any reports for file accesses from these APIs, because thay are not what the application called.
    // (It was purely inserted by us.)

    DetouredScope scope;
    return Real_GetVolumePathNameW(lpszFileName, lpszVolumePathName, cchBufferLength);
}

IMPLEMENTED(Detoured_GetFileAttributesW)
DWORD WINAPI Detoured_GetFileAttributesW(_In_  LPCWSTR lpFileName)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || IsNullOrEmptyW(lpFileName) || IsSpecialDeviceName(lpFileName))
    {
#pragma warning(suppress: 6387)
        return Real_GetFileAttributesW(lpFileName);
    }

    FileOperationContext fileOperationContext = FileOperationContext::CreateForProbe(L"GetFileAttributes", lpFileName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpFileName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(fileOperationContext);
        return INVALID_FILE_ATTRIBUTES;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, policyResult, true))
    {
        return INVALID_FILE_ATTRIBUTES;
    }

    // Model W (write-overlay): a metadata probe of a path the action wrote into the
    // overlay must observe the backing file (the real execroot has no such path).
    std::wstring overlayProbe = ResolveOverlayProbePath(policyResult);
    LPCWSTR attrTarget = overlayProbe.empty() ? lpFileName : overlayProbe.c_str();

    DWORD attributes = Real_GetFileAttributesW(attrTarget);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(attributes != INVALID_FILE_ATTRIBUTES, error);

    // Now we can make decisions based on the file's existence and type.
    FileReadContext fileReadContext;
    fileReadContext.InferExistenceFromError(reportedError);
    fileReadContext.OpenedDirectory = IsDirectoryFromAttributes(
        attributes,
        ShouldTreatDirectoryReparsePointAsFile(fileOperationContext.DesiredAccess, fileOperationContext.FlagsAndAttributes, policyResult));
    fileOperationContext.OpenedFileOrDirectoryAttributes = attributes;

    AccessCheckResult accessCheck = policyResult.CheckReadAccess(RequestedReadAccess::Probe, fileReadContext);

    if (accessCheck.ShouldDenyAccess())
    {
        error = accessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        reportedError = error;
        attributes = INVALID_FILE_ATTRIBUTES;
    }

    ReportIfNeeded(accessCheck, fileOperationContext, policyResult, reportedError, error);

    SetLastError(error);
    return attributes;
}

IMPLEMENTED(Detoured_GetFileAttributesA)
DWORD WINAPI Detoured_GetFileAttributesA(_In_  LPCSTR lpFileName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
#pragma warning(suppress: 6387)
            return Real_GetFileAttributesA(lpFileName);
        }
    }

    UnicodeConverter unicodePath(lpFileName);
    return Detoured_GetFileAttributesW(unicodePath);
}

IMPLEMENTED(Detoured_GetFileAttributesExW)
BOOL WINAPI Detoured_GetFileAttributesExW(
    _In_  LPCWSTR                lpFileName,
    _In_  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    _Out_ LPVOID                 lpFileInformation)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || IsNullOrEmptyW(lpFileName) || IsSpecialDeviceName(lpFileName))
    {
        return Real_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    }

    FileOperationContext fileOperationContext = FileOperationContext::CreateForProbe(L"GetFileAttributesEx", lpFileName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpFileName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(fileOperationContext);

        lpFileInformation = nullptr;
        return FALSE;
    }

    // We could be clever and avoid calling this when already doomed to failure. However:
    // - Unlike CreateFile, this query can't interfere with other processes
    // - We want lpFileInformation to be zeroed according to whatever policy GetFileAttributesEx has.
    BOOL querySucceeded = Real_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(querySucceeded, error);

    WIN32_FILE_ATTRIBUTE_DATA* fileStandardInfo = (fInfoLevelId == GetFileExInfoStandard && lpFileInformation != nullptr)
        ? (WIN32_FILE_ATTRIBUTE_DATA*)lpFileInformation
        : nullptr;

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, policyResult, true))
    {
        lpFileInformation = nullptr;
        return FALSE;
    }

    // Model W (write-overlay): a metadata probe of a path the action wrote into the
    // overlay must observe the backing file. Re-issue the query against the backing
    // path so the returned attributes/size/timestamps reflect the scratch file.
    std::wstring overlayProbe = ResolveOverlayProbePath(policyResult);
    if (!overlayProbe.empty())
    {
        querySucceeded = Real_GetFileAttributesExW(overlayProbe.c_str(), fInfoLevelId, lpFileInformation);
        error = GetLastError();
        reportedError = GetReportedError(querySucceeded, error);
    }

    // Now we can make decisions based on existence and type.
    FileReadContext fileReadContext;
    fileReadContext.InferExistenceFromError(reportedError);
    fileReadContext.OpenedDirectory =
        querySucceeded
        && fileStandardInfo != nullptr
        && IsDirectoryFromAttributes(
            fileStandardInfo->dwFileAttributes,
            ShouldTreatDirectoryReparsePointAsFile(fileOperationContext.DesiredAccess, fileOperationContext.FlagsAndAttributes, policyResult));
    fileOperationContext.OpenedFileOrDirectoryAttributes = querySucceeded && fileStandardInfo != nullptr
        ? fileStandardInfo->dwFileAttributes
        : INVALID_FILE_ATTRIBUTES;

    AccessCheckResult accessCheck = policyResult.CheckReadAccess(RequestedReadAccess::Probe, fileReadContext);

    // No need to enforce chain of reparse point accesess because if the path points to a symbolic link,
    // then GetFileAttributes returns attributes for the symbolic link.
    if (accessCheck.ShouldDenyAccess())
    {
        // Mask denied read/probes as NOT_FOUND under --filter-inputs, matching
        // Detoured_GetFileAttributesW / Detoured_GetFileInformationByName. Without this
        // an undeclared/hidden probe returns ACCESS_DENIED, which breaks tools that
        // treat access-denied (but not not-found) as fatal - e.g. Java's
        // Files.createDirectories -> WindowsFileSystemProvider.checkAccess (which uses
        // GetFileAttributesEx) throws AccessDeniedException instead of catching
        // NoSuchFileException when probing a not-yet-existent scratch dir (_javac/...).
        error = accessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        reportedError = error;
        querySucceeded = FALSE;
    }

    if (querySucceeded && policyResult.ShouldOverrideTimestamps(accessCheck) && fileStandardInfo != nullptr)
    {
#if SUPER_VERBOSE
        Dbg(L"GetFileAttributesExW: Overriding timestamps for %s", policyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
        OverrideTimestampsForInputFile(fileStandardInfo);
    }

    ReportIfNeeded(accessCheck, fileOperationContext, policyResult, reportedError, error);

    SetLastError(error);
    return querySucceeded;
}

IMPLEMENTED(Detoured_GetFileAttributesExA)
BOOL WINAPI Detoured_GetFileAttributesExA(
    _In_  LPCSTR                 lpFileName,
    _In_  GET_FILEEX_INFO_LEVELS fInfoLevelId,
    _Out_ LPVOID                 lpFileInformation)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_GetFileAttributesExA(
                lpFileName,
                fInfoLevelId,
                lpFileInformation);
        }
    }

    UnicodeConverter unicodePath(lpFileName);
    return Detoured_GetFileAttributesExW(
        unicodePath,
        fInfoLevelId,
        lpFileInformation);
}

// Detoured_CopyFileW
//
// lpExistingFileName is the source file. We require read access to this location.
// lpNewFileName is the destination file. We require write access to this location (as we create it).
//
// Don't worry about bFailIfExists, that will all be handled by the actual API and doesn't affect
// our policy.
//
// Note: Does NOT operate on directories.
IMPLEMENTED(Detoured_CopyFileW)
BOOL WINAPI Detoured_CopyFileW(
    _In_ LPCWSTR lpExistingFileName,
    _In_ LPCWSTR lpNewFileName,
    _In_ BOOL bFailIfExists
)
{
    // Don't duplicate complex access-policy logic between CopyFileEx and CopyFile.
    // This forwarder is identical to the internal implementation of CopyFileExW
    // so it should be safe to always forward at our level.
    return Detoured_CopyFileExW(
        lpExistingFileName,
        lpNewFileName,
        (LPPROGRESS_ROUTINE)NULL,
        (LPVOID)NULL,
        (LPBOOL)NULL,
        bFailIfExists ? (DWORD)COPY_FILE_FAIL_IF_EXISTS : 0);
}

IMPLEMENTED(Detoured_CopyFileA)
BOOL WINAPI Detoured_CopyFileA(
    _In_ LPCSTR lpExistingFileName,
    _In_ LPCSTR lpNewFileName,
    _In_ BOOL   bFailIfExists)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName) || IsNullOrEmptyA(lpNewFileName))
        {
            return Real_CopyFileA(
                lpExistingFileName,
                lpNewFileName,
                bFailIfExists);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);
    return Detoured_CopyFileW(
        existingFileName,
        newFileName,
        bFailIfExists);
}

static BOOL WINAPI DetoursCopyFileEx(
    _In_     bool               transacted,
    _In_     LPCWSTR            lpExistingFileName,
    _In_     LPCWSTR            lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_opt_ LPBOOL             pbCancel,
    _In_     DWORD              dwCopyFlags,
    _In_     HANDLE             hTransaction)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpExistingFileName) ||
        IsNullOrEmptyW(lpNewFileName) ||
        IsSpecialDeviceName(lpExistingFileName) ||
        IsSpecialDeviceName(lpNewFileName))
    {
        return transacted
            ? Real_CopyFileTransactedW(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                pbCancel,
                dwCopyFlags,
                hTransaction)
            : Real_CopyFileExW(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                pbCancel,
                dwCopyFlags);
    }

    FileOperationContext sourceOpContext = FileOperationContext::CreateForRead(L"CopyFile_Source", lpExistingFileName);
    PolicyResult sourcePolicyResult;
    if (!sourcePolicyResult.Initialize(lpExistingFileName))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return FALSE;
    }

    bool copySymlink = (dwCopyFlags & COPY_FILE_COPY_SYMLINK) != 0;

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        sourceOpContext,
        sourcePolicyResult,
        true /* EnforceChainOfReparsePointAccessesForNonCreateFile will do the enforcement for the last reparse point */))
    {
        return FALSE;
    }

    FileOperationContext destinationOpContext = FileOperationContext(
        L"CopyFile_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        lpNewFileName);
    destinationOpContext.Correlate(sourceOpContext);

    PolicyResult destPolicyResult;
    if (!destPolicyResult.Initialize(lpNewFileName))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return FALSE;
    }

    // When COPY_FILE_COPY_SYMLINK is specified, then no need to enforce chain of symlink accesses.
    if (!copySymlink && !EnforceChainOfReparsePointAccessesForNonCreateFile(sourceOpContext, sourcePolicyResult))
    {
        return FALSE;
    }

    if (copySymlink)
    {
        // Invalidate cache entries because we are about to replace the destination with a symbolic link
        PathCache_Invalidate(destPolicyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), false, sourcePolicyResult);
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        destinationOpContext,
        destPolicyResult,
        true /* EnforceChainOfReparsePointAccessesForNonCreateFile will do the enforcement for the last reparse point */))
    {
        return FALSE;
    }

    // Writes are destructive, before doing a copy we ensure that write access is definitely allowed.

    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();
    if (destAccessCheck.ShouldDenyAccess())
    {
        DWORD denyError = destAccessCheck.DenialError();
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
        destAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    if ((!copySymlink || !IsReparsePoint(lpExistingFileName, INVALID_HANDLE_VALUE)) && IsReparsePoint(lpNewFileName, INVALID_HANDLE_VALUE))
    {
        // If not copying symlink or the source of copy is not a symlink
        // but the destination of the copy is a symlink, then enforce chain of reparse point.
        // For example, if we copy a concrete file f to an existing symlink s pointing to g, then
        // if g exists, then g will be modified, but if g doesn't exist, then g will be created.
        if (!EnforceChainOfReparsePointAccessesForNonCreateFile(destinationOpContext, sourcePolicyResult))
        {
            return FALSE;
        }
    }

    // Now we can safely try to copy, but note that the corresponding read of the source file may end up disallowed
    // (maybe the source file exists, as CopyFileW requires, but we only allow non-existence probes for this path).

    // Model W (write-overlay): CopyFile(Ex) is a self-contained kernel copy - it
    // opens the source and destination itself, so unlike the CreateFile paths the
    // overlay redirect never gets a chance to fire on those inner opens. Left alone
    // it would (a) fail to find a source that lives only in the backing store (a
    // file this action wrote via the overlay - Rust std::fs::copy / uutils cp hit
    // this), and (b) write the DESTINATION straight to the real execroot, leaking a
    // scratch output onto disk. Swap in the overlay paths before the real call:
    //   source -> backing copy when one exists (ResolveOverlayProbePath: overlay-only
    //             or overlay-written source; a real in-cone source stays as-is);
    //   dest   -> backing store when inside the redirect cone (ResolveOverlayRenameDest
    //             ensures parent dirs + marks the virtual path created; a declared -w
    //             output stays on the real path).
    LPCWSTR effExistingFileName = lpExistingFileName;
    LPCWSTR effNewFileName = lpNewFileName;
    std::wstring overlayCopySource;
    std::wstring overlayCopyDest;
    if (ShouldWriteOverlay())
    {
        overlayCopySource = ResolveOverlayProbePath(sourcePolicyResult);
        if (!overlayCopySource.empty())
        {
            effExistingFileName = overlayCopySource.c_str();
        }
        overlayCopyDest = ResolveOverlayRenameDest(destPolicyResult);
        if (!overlayCopyDest.empty())
        {
            effNewFileName = overlayCopyDest.c_str();
        }
    }

    BOOL result = transacted
        ? Real_CopyFileTransactedW(
            effExistingFileName,
            effNewFileName,
            lpProgressRoutine,
            lpData,
            pbCancel,
            dwCopyFlags,
            hTransaction)
        : Real_CopyFileExW(
            effExistingFileName,
            effNewFileName,
            lpProgressRoutine,
            lpData,
            pbCancel,
            dwCopyFlags);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    FileReadContext sourceReadContext;
    sourceReadContext.OpenedDirectory = false; // TODO: Perhaps CopyFile fails with a nice error code in this case.
    sourceReadContext.InferExistenceFromError(reportedError);

    sourceOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);
    destinationOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckReadAccess(RequestedReadAccess::Read, sourceReadContext);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, reportedError, error);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, reportedError, error);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        result = FALSE;
        // Mask a denied source read as NOT_FOUND under --filter-inputs, consistent with
        // the probe hooks (GetFileAttributes[Ex]W etc.): an undeclared/hidden source is
        // absent, not permission-denied. DenialError() only masks read-only Valid denials.
        error = sourceAccessCheck.DenialError(ShouldDeniedReadsAsNotFound());
    }

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_CopyFileExW)
BOOL WINAPI Detoured_CopyFileExW(
    _In_     LPCWSTR            lpExistingFileName,
    _In_     LPCWSTR            lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_opt_ LPBOOL             pbCancel,
    _In_     DWORD              dwCopyFlags)
{
    return DetoursCopyFileEx(
        false,
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
        INVALID_HANDLE_VALUE);
}

IMPLEMENTED(Detoured_CopyFileExA)
BOOL WINAPI Detoured_CopyFileExA(
    _In_     LPCSTR             lpExistingFileName,
    _In_     LPCSTR             lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_opt_ LPBOOL             pbCancel,
    _In_     DWORD              dwCopyFlags)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName) || IsNullOrEmptyA(lpNewFileName))
        {
            return Real_CopyFileExA(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                pbCancel,
                dwCopyFlags);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);
    return Detoured_CopyFileExW(
        existingFileName,
        newFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags);
}

IMPLEMENTED(Detoured_CopyFileTransactedW)
BOOL WINAPI Detoured_CopyFileTransactedW(
    _In_     LPCWSTR            lpExistingFileName,
    _In_     LPCWSTR            lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_opt_ LPBOOL             pbCancel,
    _In_     DWORD              dwCopyFlags,
    _In_     HANDLE             hTransaction)
{
    return DetoursCopyFileEx(
        true,
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
        hTransaction);
}

IMPLEMENTED(Detoured_CopyFileTransactedA)
BOOL WINAPI Detoured_CopyFileTransactedA(
    _In_     LPCSTR             lpExistingFileName,
    _In_     LPCSTR             lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_opt_ LPBOOL             pbCancel,
    _In_     DWORD              dwCopyFlags,
    _In_     HANDLE             hTransaction)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName) || IsNullOrEmptyA(lpNewFileName))
        {
            return Real_CopyFileTransactedA(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                pbCancel,
                dwCopyFlags,
                hTransaction);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);
    return Detoured_CopyFileTransactedW(
        existingFileName,
        newFileName,
        lpProgressRoutine,
        lpData,
        pbCancel,
        dwCopyFlags,
        hTransaction);
}

// CopyFile2 (Win8+) is a self-contained kernel copy like CopyFileEx, but unlike
// CreateFile2 it is NOT backstopped by the NtCreateFile hook (its inner opens do not
// route through our detours). Without an explicit hook a Model W action's CopyFile2
// would leak the destination onto the real execroot and fail to find an overlay-only
// source. Hook it and apply the same overlay redirect + read/write policy as
// DetoursCopyFileEx. Returns HRESULT (S_OK on success).
IMPLEMENTED(Detoured_CopyFile2)
HRESULT WINAPI Detoured_CopyFile2(
    _In_     PCWSTR                        pwszExistingFileName,
    _In_     PCWSTR                        pwszNewFileName,
    _In_opt_ COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(pwszExistingFileName) ||
        IsNullOrEmptyW(pwszNewFileName) ||
        IsSpecialDeviceName(pwszExistingFileName) ||
        IsSpecialDeviceName(pwszNewFileName))
    {
        return Real_CopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
    }

    FileOperationContext sourceOpContext = FileOperationContext::CreateForRead(L"CopyFile2_Source", pwszExistingFileName);
    PolicyResult sourcePolicyResult;
    if (!sourcePolicyResult.Initialize(pwszExistingFileName))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(sourceOpContext, sourcePolicyResult, true))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    FileOperationContext destinationOpContext = FileOperationContext(
        L"CopyFile2_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        pwszNewFileName);
    destinationOpContext.Correlate(sourceOpContext);

    PolicyResult destPolicyResult;
    if (!destPolicyResult.Initialize(pwszNewFileName))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return HRESULT_FROM_WIN32(GetLastError());
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(destinationOpContext, destPolicyResult, true))
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();
    if (destAccessCheck.ShouldDenyAccess())
    {
        DWORD denyError = destAccessCheck.DenialError();
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
        destAccessCheck.SetLastErrorToDenialError();
        return HRESULT_FROM_WIN32(denyError);
    }

    // Overlay redirect (see DetoursCopyFileEx / FIX #4 for the rationale).
    PCWSTR effExistingFileName = pwszExistingFileName;
    PCWSTR effNewFileName = pwszNewFileName;
    std::wstring overlayCopySource;
    std::wstring overlayCopyDest;
    if (ShouldWriteOverlay())
    {
        overlayCopySource = ResolveOverlayProbePath(sourcePolicyResult);
        if (!overlayCopySource.empty())
        {
            effExistingFileName = overlayCopySource.c_str();
        }
        overlayCopyDest = ResolveOverlayRenameDest(destPolicyResult);
        if (!overlayCopyDest.empty())
        {
            effNewFileName = overlayCopyDest.c_str();
        }
    }

    HRESULT hr = Real_CopyFile2(effExistingFileName, effNewFileName, pExtendedParameters);
    DWORD error = SUCCEEDED(hr) ? ERROR_SUCCESS : (HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (DWORD)hr);
    DWORD reportedError = GetReportedError(SUCCEEDED(hr), error);

    FileReadContext sourceReadContext;
    sourceReadContext.OpenedDirectory = false;
    sourceReadContext.InferExistenceFromError(reportedError);

    sourceOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);
    destinationOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckReadAccess(RequestedReadAccess::Read, sourceReadContext);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, reportedError, error);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, reportedError, error);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        DWORD denied = sourceAccessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        return HRESULT_FROM_WIN32(denied);
    }

    return hr;
}

// Below are detours of various Move functions. Looking up the actual
// implementation of these functions, one finds that they are all wrappers
// around the MoveFileWithProgress.
//
// MoveFile(a, b) => MoveFileWithProgress(a, b, NULL, NULL, MOVEFILE_COPY_ALLOWED)
// MoveFileEx(a, b, flags) => MoveFileWithProgress(a, b, NULL, NULL, flags)
//
IMPLEMENTED(Detoured_MoveFileW)
BOOL WINAPI Detoured_MoveFileW(
    _In_ LPCWSTR lpExistingFileName,
    _In_ LPCWSTR lpNewFileName)
{
    return Detoured_MoveFileWithProgressW(
        lpExistingFileName,
        lpNewFileName,
        (LPPROGRESS_ROUTINE)NULL,
        NULL,
        MOVEFILE_COPY_ALLOWED);
}

IMPLEMENTED(Detoured_MoveFileA)
BOOL WINAPI Detoured_MoveFileA(
    _In_ LPCSTR lpExistingFileName,
    _In_ LPCSTR lpNewFileName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName) || IsNullOrEmptyA(lpNewFileName))
        {
            return Real_MoveFileA(
                lpExistingFileName,
                lpNewFileName);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);

    return Detoured_MoveFileWithProgressW(
        existingFileName,
        newFileName,
        (LPPROGRESS_ROUTINE)NULL,
        NULL,
        MOVEFILE_COPY_ALLOWED);
}

IMPLEMENTED(Detoured_MoveFileExW)
BOOL WINAPI Detoured_MoveFileExW(
    _In_     LPCWSTR lpExistingFileName,
    _In_opt_ LPCWSTR lpNewFileName,
    _In_     DWORD   dwFlags)
{
    return Detoured_MoveFileWithProgressW(
        lpExistingFileName,
        lpNewFileName,
        (LPPROGRESS_ROUTINE)NULL,
        NULL,
        dwFlags);
}

IMPLEMENTED(Detoured_MoveFileExA)
BOOL WINAPI Detoured_MoveFileExA(
    _In_      LPCSTR lpExistingFileName,
    _In_opt_  LPCSTR lpNewFileName,
    _In_      DWORD  dwFlags)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName) || IsNullOrEmptyA(lpNewFileName))
        {
            return Real_MoveFileExA(
                lpExistingFileName,
                lpNewFileName,
                dwFlags);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);

    return Detoured_MoveFileWithProgressW(
        existingFileName,
        newFileName,
        (LPPROGRESS_ROUTINE)NULL,
        NULL,
        dwFlags);
}

BOOL WINAPI DetoursMoveFileWithProgress(
    _In_      bool               transacted,
    _In_      LPCWSTR            lpExistingFileName,
    _In_opt_  LPCWSTR            lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID             lpData,
    _In_      DWORD              dwFlags,
    _In_      HANDLE             hTransaction)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()
        || IsNullOrEmptyW(lpExistingFileName)
        || IsNullOrEmptyW(lpNewFileName)
        || IsSpecialDeviceName(lpExistingFileName)
        || IsSpecialDeviceName(lpNewFileName))
    {
        return transacted
            ? Real_MoveFileTransactedW(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                dwFlags,
                hTransaction)
            : Real_MoveFileWithProgressW(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                dwFlags);
    }

    bool moveDirectory = false;
    DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    DWORD existingFileOrDirectoryAttribute;

    if (IsHandleOrPathToDirectory(INVALID_HANDLE_VALUE, lpExistingFileName, /*treatReparsePointAsFile*/ true, /*ref*/ existingFileOrDirectoryAttribute))
    {
        moveDirectory = true;
        flagsAndAttributes |= FILE_ATTRIBUTE_DIRECTORY;
    }

    FileOperationContext sourceOpContext = FileOperationContext(
        L"MoveFileWithProgress_Source",
        GENERIC_READ | DELETE,
        0,
        OPEN_EXISTING,
        flagsAndAttributes,
        lpExistingFileName);
    sourceOpContext.OpenedFileOrDirectoryAttributes = existingFileOrDirectoryAttribute;

    PolicyResult sourcePolicyResult;
    if (!sourcePolicyResult.Initialize(lpExistingFileName))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return FALSE;
    }

    PathCache_Invalidate(sourcePolicyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), moveDirectory, sourcePolicyResult);

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(sourceOpContext, sourcePolicyResult, !moveDirectory))
    {
        return FALSE;
    }

    // When MOVEFILE_COPY_ALLOWED is set, If the file is to be moved to a different volume, then the function simulates
    // the move by using the CopyFile and DeleteFile functions. In moving symlink using MOVEFILE_COPY_ALLOWED flag,
    // the call to CopyFile function passes COPY_FILE_SYMLINK, which makes the CopyFile function copies the symlink itself
    // instead of the (final) target of the symlink.

    FileOperationContext destinationOpContext = FileOperationContext(
        L"MoveFileWithProgress_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        flagsAndAttributes,
        lpNewFileName);
    destinationOpContext.Correlate(sourceOpContext);
    destinationOpContext.OpenedFileOrDirectoryAttributes = existingFileOrDirectoryAttribute;

    PolicyResult destPolicyResult;

    if (!destPolicyResult.Initialize(lpNewFileName))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return FALSE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(destinationOpContext, destPolicyResult, !moveDirectory))
    {
        return FALSE;
    }

    // Writes are destructive. Before doing a move we ensure that write access is definitely allowed to the source (read and delete) and destination (write).

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        // We report the source access here since we are returning early. Otherwise it is deferred until post-read.
        DWORD denyError = sourceAccessCheck.DenialError();
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, denyError);
        sourceAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    AccessCheckResult destAccessCheck(RequestedAccess::Write, ResultAction::Allow, ReportLevel::Ignore);

    if (!destPolicyResult.IsIndeterminate())
    {
        // PolicyResult::CheckWriteAccess gives the same result for writing a file or creating a directory.
        // Thus, we don't need to call PolicyResult::CheckCreateDirectoryAccess.
        destAccessCheck = destPolicyResult.CheckWriteAccess();

        if (destAccessCheck.ShouldDenyAccess())
        {
            // We report the destination access here since we are returning early. Otherwise it is deferred until post-read.
            DWORD denyError = destAccessCheck.DenialError();
            ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
            destAccessCheck.SetLastErrorToDenialError();
            return FALSE;
        }
    }

    vector<ReportData> filesAndDirectoriesToReport;
    if (moveDirectory)
    {
        // Verify move directory.
        // The destination of move directory must be on the same drive.
        if (!ValidateMoveDirectory(
            L"MoveFileWithProgress_Source",
            L"MoveFileWithProgress_Dest",
            sourcePolicyResult.GetCanonicalizedPath().GetPathString(),
            destPolicyResult.GetCanonicalizedPath().GetPathString(),
            filesAndDirectoriesToReport))
        {
            return FALSE;
        }
    }
    else if ((dwFlags & MOVEFILE_COPY_ALLOWED) != 0)
    {
        // Copy can be performed, and thus file will be read, but copy cannot be moving directory.
        sourceAccessCheck = AccessCheckResult::Combine(
            sourceAccessCheck,
            sourcePolicyResult.CheckReadAccess(RequestedReadAccess::Read, FileReadContext(FileExistence::Existent, false)));

        if (sourceAccessCheck.ShouldDenyAccess())
        {
            DWORD denyError = sourceAccessCheck.DenialError();
            ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, denyError);
            sourceAccessCheck.SetLastErrorToDenialError();
            return FALSE;
        }
    }

    // Model W (write-overlay): keep the move inside the backing store so the real
    // execroot is never mutated. Resolve the source (delete-half, §6.3.1) and the
    // destination (filter-aware create-half, §5.6.2) to their backing paths. Directory
    // moves are deferred to the enum-classes phase and pass through unchanged.
    LPCWSTR moveSource = lpExistingFileName;
    LPCWSTR moveDest = lpNewFileName;
    std::wstring overlaySourceBacking;
    std::wstring overlayDestBacking;
    if (!moveDirectory && ShouldRedirectToOverlay(sourcePolicyResult))
    {
        switch (ResolveOverlayDelete(sourcePolicyResult, overlaySourceBacking))
        {
        case OverlayDeleteAction::DenyAccess:
            ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, ERROR_ACCESS_DENIED);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        case OverlayDeleteAction::NotFound:
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        case OverlayDeleteAction::RedirectToBacking:
            moveSource = overlaySourceBacking.c_str();
            break;
        case OverlayDeleteAction::PassThrough:
            break;
        }
    }
    if (!moveDirectory && lpNewFileName != nullptr)
    {
        overlayDestBacking = ResolveOverlayRenameDest(destPolicyResult);
        if (!overlayDestBacking.empty())
        {
            moveDest = overlayDestBacking.c_str();
        }
    }

    // It's now safe to perform the move, which should tell us the existence of the source side (and so, if it may be read or not).

    BOOL result = transacted
        ? Real_MoveFileTransactedW(
            moveSource,
            moveDest,
            lpProgressRoutine,
            lpData,
            dwFlags,
            hTransaction)
        : Real_MoveFileWithProgressW(
            moveSource,
            moveDest,
            lpProgressRoutine,
            lpData,
            dwFlags);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, reportedError, error);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, reportedError, error);

    if (moveDirectory)
    {
        for (auto& entry : filesAndDirectoriesToReport)
        {
            ReportIfNeeded(entry.GetAccessCheckResult(), entry.GetFileOperationContext(), entry.GetPolicyResult(), reportedError, error);
        }
    }

    SetLastError(error);

    return result;
}

// Detoured_MoveFileWithProgressW
//
// lpExistingFileName is the source file. We require write access to this location (as we effectively delete it).
// lpNewFileName is the destination file. We require write access to this location (as we create it).
//
// lpNewFileName is optional in this API but if is NULL then this API allows the file to be deleted
// (following a reboot). See the excerpt from the documentation below:
//
// "If dwFlags specifies MOVEFILE_DELAY_UNTIL_REBOOT and lpNewFileName is NULL,
// MoveFileEx registers the lpExistingFileName file to be deleted when the
// system restarts."
IMPLEMENTED(Detoured_MoveFileWithProgressW)
BOOL WINAPI Detoured_MoveFileWithProgressW(
    _In_      LPCWSTR            lpExistingFileName,
    _In_opt_  LPCWSTR            lpNewFileName,
    _In_opt_  LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_  LPVOID             lpData,
    _In_      DWORD              dwFlags)
{
    return DetoursMoveFileWithProgress(
        false,
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        dwFlags,
        INVALID_HANDLE_VALUE);
}

IMPLEMENTED(Detoured_MoveFileWithProgressA)
BOOL WINAPI Detoured_MoveFileWithProgressA(
    _In_     LPCSTR             lpExistingFileName,
    _In_opt_ LPCSTR             lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_     DWORD              dwFlags)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName))
        {
            return Real_MoveFileWithProgressA(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                dwFlags);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);
    return Detoured_MoveFileWithProgressW(
        existingFileName,
        newFileName,
        lpProgressRoutine,
        lpData,
        dwFlags);
}

IMPLEMENTED(Detoured_MoveFileTransactedW)
BOOL WINAPI Detoured_MoveFileTransactedW(
    _In_     LPCWSTR            lpExistingFileName,
    _In_opt_ LPCWSTR            lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_     DWORD              dwFlags,
    _In_     HANDLE             hTransaction)
{
    return DetoursMoveFileWithProgress(
        true,
        lpExistingFileName,
        lpNewFileName,
        lpProgressRoutine,
        lpData,
        dwFlags,
        hTransaction);
}

IMPLEMENTED(Detoured_MoveFileTransactedA)
BOOL WINAPI Detoured_MoveFileTransactedA(
    _In_     LPCSTR             lpExistingFileName,
    _In_opt_ LPCSTR             lpNewFileName,
    _In_opt_ LPPROGRESS_ROUTINE lpProgressRoutine,
    _In_opt_ LPVOID             lpData,
    _In_     DWORD              dwFlags,
    _In_     HANDLE             hTransaction)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpExistingFileName))
        {
            return Real_MoveFileTransactedA(
                lpExistingFileName,
                lpNewFileName,
                lpProgressRoutine,
                lpData,
                dwFlags,
                hTransaction);
        }
    }

    UnicodeConverter existingFileName(lpExistingFileName);
    UnicodeConverter newFileName(lpNewFileName);
    return Detoured_MoveFileTransactedW(
        existingFileName,
        newFileName,
        lpProgressRoutine,
        lpData,
        dwFlags,
        hTransaction);
}

BOOL WINAPI Detoured_ReplaceFileW(
    _In_       LPCWSTR lpReplacedFileName,
    _In_       LPCWSTR lpReplacementFileName,
    _In_opt_   LPCWSTR lpBackupFileName,
    _In_       DWORD   dwReplaceFlags,
    __reserved LPVOID  lpExclude,
    __reserved LPVOID  lpReserved)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled()
            || IsNullOrEmptyW(lpReplacedFileName)
            || IsNullOrEmptyW(lpReplacementFileName)
            || IsSpecialDeviceName(lpReplacedFileName)
            || IsSpecialDeviceName(lpReplacementFileName))
        {
            return Real_ReplaceFileW(
                lpReplacedFileName,
                lpReplacementFileName,
                lpBackupFileName,
                dwReplaceFlags,
                lpExclude,
                lpReserved);
        }
    }

    // ReplaceFile atomically overwrites lpReplacedFileName with the contents of
    // lpReplacementFileName (preserving the replaced file's metadata), optionally
    // saving the old contents to lpBackupFileName. It is the canonical atomic-save
    // primitive, so getting it right matters for many editors/tools.
    FileOperationContext replacedOpContext = FileOperationContext(
        L"ReplaceFile_Replaced",
        GENERIC_WRITE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        lpReplacedFileName);
    PolicyResult replacedPolicy;
    if (!replacedPolicy.Initialize(lpReplacedFileName))
    {
        replacedPolicy.ReportIndeterminatePolicyAndSetLastError(replacedOpContext);
        return FALSE;
    }

    FileOperationContext replacementOpContext = FileOperationContext::CreateForRead(L"ReplaceFile_Replacement", lpReplacementFileName);
    PolicyResult replacementPolicy;
    if (!replacementPolicy.Initialize(lpReplacementFileName))
    {
        replacementPolicy.ReportIndeterminatePolicyAndSetLastError(replacementOpContext);
        return FALSE;
    }

    const bool hasBackup = !IsNullOrEmptyW(lpBackupFileName);
    PolicyResult backupPolicy;
    if (hasBackup && !backupPolicy.Initialize(lpBackupFileName))
    {
        backupPolicy.ReportIndeterminatePolicyAndSetLastError(replacedOpContext);
        return FALSE;
    }

    PathCache_Invalidate(replacedPolicy.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), false, replacedPolicy);

    // The replaced target is the destructive write - ensure it is allowed before acting.
    AccessCheckResult replacedAccess = replacedPolicy.CheckWriteAccess();
    if (replacedAccess.ShouldDenyAccess())
    {
        DWORD denyError = replacedAccess.DenialError();
        ReportIfNeeded(replacedAccess, replacedOpContext, replacedPolicy, denyError);
        replacedAccess.SetLastErrorToDenialError();
        return FALSE;
    }

    // Model W (write-overlay): ReplaceFile is a self-contained kernel op (opens its
    // own handles), so the per-open overlay redirect never fires. Left alone it would
    // mutate/leak the real execroot. Redirect every path into the backing store:
    //   replacement (source, consumed) -> backing copy when one exists;
    //   replaced (dest)                -> backing store; since ReplaceFile requires the
    //                                     target to already exist, copy-up the real
    //                                     original when we have no backing copy yet;
    //   backup (dest)                  -> backing store.
    LPCWSTR effReplaced = lpReplacedFileName;
    LPCWSTR effReplacement = lpReplacementFileName;
    LPCWSTR effBackup = lpBackupFileName;
    std::wstring ovReplaced, ovReplacement, ovBackup;
    if (ShouldWriteOverlay())
    {
        ovReplacement = ResolveOverlayProbePath(replacementPolicy);
        if (!ovReplacement.empty())
        {
            effReplacement = ovReplacement.c_str();
        }

        if (ShouldRedirectToOverlay(replacedPolicy))
        {
            ovReplaced = ResolveOverlayRenameDest(replacedPolicy);
            if (!ovReplaced.empty())
            {
                if (!OverlayPathExists(ovReplaced.c_str()))
                {
                    const std::wstring realWide = L"\\\\?\\" + std::wstring(replacedPolicy.GetTranslatedPathWithoutTypePrefix());
                    if (OverlayPathExists(realWide.c_str()))
                    {
                        Real_CopyFileW(realWide.c_str(), ovReplaced.c_str(), FALSE);
                    }
                }
                effReplaced = ovReplaced.c_str();
            }
        }

        if (hasBackup && ShouldRedirectToOverlay(backupPolicy))
        {
            ovBackup = ResolveOverlayRenameDest(backupPolicy);
            if (!ovBackup.empty())
            {
                effBackup = ovBackup.c_str();
            }
        }
    }

    BOOL result = Real_ReplaceFileW(
        effReplaced,
        effReplacement,
        effBackup,
        dwReplaceFlags,
        lpExclude,
        lpReserved);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    ReportIfNeeded(replacedAccess, replacedOpContext, replacedPolicy, reportedError, error);

    SetLastError(error);
    return result;
}

BOOL WINAPI Detoured_ReplaceFileA(
    _In_        LPCSTR lpReplacedFileName,
    _In_        LPCSTR lpReplacementFileName,
    _In_opt_    LPCSTR lpBackupFileName,
    _In_        DWORD dwReplaceFlags,
    __reserved  LPVOID lpExclude,
    __reserved  LPVOID lpReserved)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled()
            || IsNullOrEmptyA(lpReplacedFileName)
            || IsNullOrEmptyA(lpReplacementFileName))
        {
            return Real_ReplaceFileA(
                lpReplacedFileName,
                lpReplacementFileName,
                lpBackupFileName,
                dwReplaceFlags,
                lpExclude,
                lpReserved);
        }
    }

    UnicodeConverter replacedFileName(lpReplacedFileName);
    UnicodeConverter replacementFileName(lpReplacementFileName);
    UnicodeConverter backupFileName(lpBackupFileName);

    return Detoured_ReplaceFileW(
        replacedFileName,
        replacementFileName,
        backupFileName,
        dwReplaceFlags,
        lpExclude,
        lpReserved);
}


/// <summary>
/// Treats DeleteFile as a probe if the target path does not exist as a file.
/// </summary>
/// <remarks>
/// If the probe indicates that DeleteFile would have attempted to write, then a write access is returned. This can happen
/// if the target path of DeleteFile is an existing file. Otherwise, a probe access check is returned. This probe access may or may not be
/// permitted based on the policy.
/// 
/// Note that this function is only called when DeleteFile is not allowed by the policy.
///
/// In other words, the treatment of DeleteFile can be written in the following pseudocode:
/// <code>
/// atomic
/// {
///   if (Probe(path) == Exists) { Write() } else { fail }
/// }
/// </code>
/// However, only one access is reported, i.e., the Write if it happens otherwise the probe.
/// </remarks>
static AccessCheckResult DeleteFileAsSafeProbe(FileOperationContext& opContext, const PolicyResult& policyResult, const AccessCheckResult& writeAccessCheck)
{
    DWORD attributes = GetFileAttributesW(opContext.NoncanonicalPath);
    DWORD probeError = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;

    FileReadContext probeContext;
    probeContext.OpenedDirectory = IsDirectoryFromAttributes(
        attributes,
        ShouldTreatDirectoryReparsePointAsFile(opContext.DesiredAccess, opContext.FlagsAndAttributes, policyResult));
    probeContext.InferExistenceFromError(probeError);

    opContext.OpenedFileOrDirectoryAttributes = attributes;

    AccessCheckResult probeAccessCheck = policyResult.CheckReadAccess(RequestedReadAccess::Probe, probeContext);

    if (probeContext.Existence == FileExistence::Existent)
    {
        // The path exists, but this can be a directory or a file. Anyway, preserve the deletion's error code.
        if (!probeContext.OpenedDirectory)
        {
            // This would be the deleted file or the file to be deleted, so we fail it.
            probeAccessCheck = AccessCheckResult::Combine(writeAccessCheck, AccessCheckResult::DenyOrWarn(RequestedAccess::Write));
        }
    }

    return probeAccessCheck;
}

/// <summary>
/// Detours the DeleteFileW API.
/// </summary>
/// <param name="lpFileName">The file to be deleted.</param>
/// <returns>TRUE if the file is successfully deleted; otherwise, FALSE.</returns>
/// <remarks>
/// The DeleteFile API will return ERROR_ACCESS_DENIED when lpFileName is a directory or a directory symlink.
/// The DeleteFile API does not follow symlinks, so when lpFileName is a file symlink, only the symlink is deleted, and the target file is not deleted.
///
/// In conjunction with <see cref="DeleteFileAsSafeProbe"/>, this function exhibits the following weird behavior regarding reported access:
///
///             ExistAsFile    ExistsAsDirectory/DirSymlink    DoesNotExist
///   Allow       Write               Write                       Write
///   Deny        Write               Probe                       Probe
///   Warn        Write               Probe                       Probe
///
/// This behavior is inconsistent with CreateFileW in particular when the path exists as a directory (or a directory symlink) or non-existent. For those
/// cases, CreateFileW will report Write access.
/// 
/// TODO: Revisit this behavior and make it consistent with CreateFileW.
/// </remarks>
IMPLEMENTED(Detoured_DeleteFileW)
BOOL WINAPI Detoured_DeleteFileW(_In_ LPCWSTR lpFileName)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpFileName) ||
        IsSpecialDeviceName(lpFileName))
    {
        return Real_DeleteFileW(lpFileName);
    }

    FileOperationContext opContext = FileOperationContext(
        L"DeleteFile",
        DELETE,
        FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
        TRUNCATE_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
        lpFileName);

    // On failure, opContext can be modified by DeleteFileAsSafeProbe.
    opContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpFileName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return FALSE;
    }

    PathCache_Invalidate(policyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), false, policyResult);

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        opContext,
        policyResult,
        /*preserveLastReparsePoint:*/ true)) // DeleteFile does not follow symlinks, so we preserve the last reparse point.
    {
        return FALSE;
    }

    DWORD error = ERROR_SUCCESS;
    AccessCheckResult accessCheck = policyResult.CheckWriteAccess();

    if (accessCheck.ShouldDenyAccess())
    {
        error = accessCheck.DenialError();
        accessCheck = DeleteFileAsSafeProbe(opContext, policyResult, accessCheck);
        ReportIfNeeded(accessCheck, opContext, policyResult, error);
        SetLastError(error);
        return FALSE;
    }

    // Model W (write-overlay): redirect the unlink so the real execroot is never
    // mutated. The access check above allowed the write (a pre-existing lower file
    // MarkCreated's + returns Allow expecting redirection), so without this block the
    // Real_DeleteFileW below would delete the real undeclared file. See §6.3.1.
    LPCWSTR deleteTarget = lpFileName;
    std::wstring overlayBacking;
    if (ShouldRedirectToOverlay(policyResult))
    {
        switch (ResolveOverlayDelete(policyResult, overlayBacking))
        {
        case OverlayDeleteAction::DenyAccess:
            error = ERROR_ACCESS_DENIED;
            accessCheck = DeleteFileAsSafeProbe(opContext, policyResult, accessCheck);
            ReportIfNeeded(accessCheck, opContext, policyResult, error);
            SetLastError(error);
            return FALSE;
        case OverlayDeleteAction::NotFound:
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        case OverlayDeleteAction::RedirectToBacking:
            deleteTarget = overlayBacking.c_str();
            break;
        case OverlayDeleteAction::PassThrough:
            break;
        }
    }

    BOOL result = Real_DeleteFileW(deleteTarget);
    error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    if (!result && accessCheck.Result != ResultAction::Allow)
    {
        // There was no deletion, but we need to ensure ResultAction::Warn acts like ResultAction::Deny.
        accessCheck = DeleteFileAsSafeProbe(opContext, policyResult, accessCheck);
    }

    ReportIfNeeded(accessCheck, opContext, policyResult, reportedError, error);
    SetLastError(error);

    return result;
}

IMPLEMENTED(Detoured_DeleteFileA)
BOOL WINAPI Detoured_DeleteFileA(_In_ LPCSTR lpFileName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_DeleteFileA(lpFileName);
        }
    }

    UnicodeConverter fileName(lpFileName);
    return Detoured_DeleteFileW(fileName);
}

IMPLEMENTED(Detoured_CreateHardLinkW)
BOOL WINAPI Detoured_CreateHardLinkW(
    _In_       LPCWSTR               lpFileName,
    _In_       LPCWSTR               lpExistingFileName,
    __reserved LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpFileName) ||
        IsNullOrEmptyW(lpExistingFileName) ||
        IsSpecialDeviceName(lpFileName) ||
        IsSpecialDeviceName(lpExistingFileName))
    {
        return Real_CreateHardLinkW(
            lpFileName,
            lpExistingFileName,
            lpSecurityAttributes);
    }

    FileOperationContext sourceOpContext = FileOperationContext::CreateForRead(L"CreateHardLink_Source", lpExistingFileName);
    PolicyResult sourcePolicyResult;
    if (!sourcePolicyResult.Initialize(lpExistingFileName))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return FALSE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        sourceOpContext,
        sourcePolicyResult,
        true /* If the path lpExistingFileName points to a symbolic link, CreateHardLinkW creates a hard link to the symbolic link. */))
    {
        return FALSE;
    }

    FileOperationContext destinationOpContext = FileOperationContext(
        L"CreateHardLink_Dest",
        GENERIC_WRITE,
        0,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        lpFileName);
    destinationOpContext.Correlate(sourceOpContext);

    PolicyResult destPolicyResult;
    if (!destPolicyResult.Initialize(lpFileName))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return FALSE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(destinationOpContext, destPolicyResult, true))
    {
        return FALSE;
    }

    sourceOpContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(false);
    destinationOpContext.OpenedFileOrDirectoryAttributes = sourceOpContext.OpenedFileOrDirectoryAttributes;

    // Only attempt the call if the write is allowed (prevent sneaky side effects).
    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();
    if (destAccessCheck.ShouldDenyAccess())
    {
        DWORD denyError = destAccessCheck.DenialError();
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
        destAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    // Now we can safely try to hardlink, but note that the corresponding read of the source file may end up disallowed
    // (maybe the source file exists, as CreateHardLink requires, but we only allow non-existence probes).
    // Recall that failure of CreateHardLink is orthogonal to access-check failure.

    // Model W (write-overlay): CreateHardLink is a self-contained kernel op, so the
    // per-open overlay redirect never fires on its inner opens. Left alone the new
    // link (dest) would be created on the REAL execroot (confirmed leak) and a source
    // that lives only in the backing store would not be found. Swap in overlay paths:
    //   source -> backing copy when one exists (ResolveOverlayProbePath);
    //   dest   -> backing store inside the redirect cone (ResolveOverlayRenameDest).
    LPCWSTR effExistingFileName = lpExistingFileName;
    LPCWSTR effFileName = lpFileName;
    std::wstring overlayLinkSource;
    std::wstring overlayLinkDest;
    if (ShouldWriteOverlay())
    {
        overlayLinkSource = ResolveOverlayProbePath(sourcePolicyResult);
        if (!overlayLinkSource.empty())
        {
            effExistingFileName = overlayLinkSource.c_str();
        }
        overlayLinkDest = ResolveOverlayRenameDest(destPolicyResult);
        if (!overlayLinkDest.empty())
        {
            effFileName = overlayLinkDest.c_str();
        }
    }

    BOOL result = Real_CreateHardLinkW(
        effFileName,
        effExistingFileName,
        lpSecurityAttributes);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    FileReadContext sourceReadContext;
    sourceReadContext.OpenedDirectory = false; // TODO: Perhaps CreateHardLink fails with a nice error code in this case.
    sourceReadContext.InferExistenceFromError(result ? ERROR_SUCCESS : error);

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckReadAccess(RequestedReadAccess::Read, sourceReadContext);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        result = FALSE;
        // Mask a denied source read as NOT_FOUND under --filter-inputs, consistent with
        // the probe hooks: an undeclared/hidden hardlink source is absent, not
        // permission-denied. DenialError() only masks read-only Valid denials.
        error = sourceAccessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        reportedError = error;
    }

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, reportedError, error);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, reportedError, error);

    SetLastError(error);

    return result;
}

IMPLEMENTED(Detoured_CreateHardLinkA)
BOOL WINAPI Detoured_CreateHardLinkA(
    _In_       LPCSTR                lpFileName,
    _In_       LPCSTR                lpExistingFileName,
    __reserved LPSECURITY_ATTRIBUTES lpSecurityAttributes
)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName) || IsNullOrEmptyA(lpExistingFileName))
        {
            return Real_CreateHardLinkA(
                lpFileName,
                lpExistingFileName,
                lpSecurityAttributes);
        }
    }

    UnicodeConverter fileName(lpFileName);
    UnicodeConverter existingFileName(lpExistingFileName);
    return Detoured_CreateHardLinkW(
        fileName,
        existingFileName,
        lpSecurityAttributes);
}

IMPLEMENTED(Detoured_CreateSymbolicLinkW)
BOOLEAN WINAPI Detoured_CreateSymbolicLinkW(
    _In_ LPCWSTR lpSymlinkFileName,
    _In_ LPCWSTR lpTargetFileName,
    _In_ DWORD   dwFlags)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpSymlinkFileName) ||
        IsNullOrEmptyW(lpTargetFileName) ||
        IsSpecialDeviceName(lpSymlinkFileName) ||
        IsSpecialDeviceName(lpTargetFileName))
    {
        return Real_CreateSymbolicLinkW(
            lpSymlinkFileName,
            lpTargetFileName,
            dwFlags);
    }

    if (IgnoreReparsePoints())
    {
        // Reparse-point policy is disabled (our default in-place config), so the full
        // policy path below is skipped. Model W must STILL keep an in-cone symlink off
        // the real execroot: redirect the link LOCATION into the backing store. The
        // link TARGET string is stored verbatim in the reparse point (never opened
        // here), so it is left unchanged. Note: a symlink whose target is itself an
        // overlay-only path cannot be transparently read back - the kernel resolves the
        // reparse target internally, bypassing the detours - but the essential
        // guarantee (no real-execroot leak) holds.
        std::wstring ovDest;
        if (ShouldWriteOverlay())
        {
            PolicyResult pr;
            if (pr.Initialize(lpSymlinkFileName))
            {
                ovDest = ResolveOverlayRenameDest(pr);
            }
        }
        return Real_CreateSymbolicLinkW(
            ovDest.empty() ? lpSymlinkFileName : ovDest.c_str(),
            lpTargetFileName,
            dwFlags);
    }

    // Check to see if we can write at the symlink location.
    FileOperationContext opContextSrc = FileOperationContext(
        L"CreateSymbolicLink_Source",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        lpSymlinkFileName);

    PolicyResult policyResultSrc;
    if (!policyResultSrc.Initialize(lpSymlinkFileName))
    {
        policyResultSrc.ReportIndeterminatePolicyAndSetLastError(opContextSrc);
        return FALSE;
    }

    PathCache_Invalidate(policyResultSrc.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), false, policyResultSrc);

    // When creating symbolic links, only resolve and report the intermediates on the symbolic link path, the target is never accessed
    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        opContextSrc,
        policyResultSrc,
        true,
        (dwFlags & SYMBOLIC_LINK_FLAG_DIRECTORY) != 0))
    {
        return FALSE;
    }

    // Check for write access on the symlink.
    AccessCheckResult accessCheckSrc = policyResultSrc.CheckWriteAccess();
    accessCheckSrc = AccessCheckResult::Combine(accessCheckSrc, policyResultSrc.CheckSymlinkCreationAccess());

    opContextSrc.OpenedFileOrDirectoryAttributes =
        FILE_ATTRIBUTE_NORMAL
        | FILE_ATTRIBUTE_REPARSE_POINT
        | ((dwFlags & SYMBOLIC_LINK_FLAG_DIRECTORY) != 0 ? FILE_ATTRIBUTE_DIRECTORY : 0UL);

    DWORD error = ERROR_SUCCESS;

    if (accessCheckSrc.ShouldDenyAccess())
    {
        error = accessCheckSrc.DenialError();
        ReportIfNeeded(accessCheckSrc, opContextSrc, policyResultSrc, error);
        accessCheckSrc.SetLastErrorToDenialError();
        return FALSE;
    }

    // Model W (write-overlay): redirect the symlink LOCATION (dest) into the backing
    // store so creating an in-cone symlink never lands on the real execroot. The link
    // TARGET string is stored verbatim in the reparse point (never opened here), so it
    // is left unchanged. Mirrors the CreateHardLink dest redirect.
    std::wstring overlaySymlinkDest;
    if (ShouldWriteOverlay())
    {
        overlaySymlinkDest = ResolveOverlayRenameDest(policyResultSrc);
    }

    BOOLEAN result = Real_CreateSymbolicLinkW(
        overlaySymlinkDest.empty() ? lpSymlinkFileName : overlaySymlinkDest.c_str(),
        lpTargetFileName,
        dwFlags);
    error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    // We do not report directory only for ReadAccess. So there is no need to enforce report level to ReportLevel::Report.

    ReportIfNeeded(accessCheckSrc, opContextSrc, policyResultSrc, reportedError, error);
    PathCache_Invalidate(policyResultSrc.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), false, policyResultSrc);

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_CreateSymbolicLinkA)
BOOLEAN WINAPI Detoured_CreateSymbolicLinkA(
    _In_ LPCSTR lpSymlinkFileName,
    _In_ LPCSTR lpTargetFileName,
    _In_ DWORD  dwFlags)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpSymlinkFileName) || IsNullOrEmptyA(lpTargetFileName))
        {
            return Real_CreateSymbolicLinkA(
                lpSymlinkFileName,
                lpTargetFileName,
                dwFlags);
        }
    }

    UnicodeConverter symlinkFileName(lpSymlinkFileName);
    UnicodeConverter targetFileName(lpTargetFileName);
    return Detoured_CreateSymbolicLinkW(
        symlinkFileName,
        targetFileName,
        dwFlags);
}

IMPLEMENTED(Detoured_FindFirstFileW)
HANDLE WINAPI Detoured_FindFirstFileW(
    _In_  LPCWSTR            lpFileName,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData)
{
    // FindFirstFileExW is a strict superset. This line is essentially the same as the FindFirstFileW thunk in \minkernel\kernelbase\filefind.c
    return Detoured_FindFirstFileExW(lpFileName, FindExInfoStandard, lpFindFileData, FindExSearchNameMatch, NULL, 0);
}

IMPLEMENTED(Detoured_FindFirstFileA)
HANDLE WINAPI Detoured_FindFirstFileA(
    _In_   LPCSTR             lpFileName,
    _Out_  LPWIN32_FIND_DATAA lpFindFileData)
{
    // TODO:replace with Detoured_FindFirstFileW below
    return Real_FindFirstFileA(
        lpFileName,
        lpFindFileData);

    // TODO: Note that we can't simply forward to FindFirstFileW here after a unicode conversion.
    // The output value differs too - WIN32_FIND_DATA{A, W}
}

// ---------------------------------------------------------------------------
// Bazel directory-enumeration input filtering (see docs/design/detours-input-filtering.md).
//
// When ShouldFilterDirectoryEnumeration() is set, directory listings hide
// entries that are not declared inputs so that undeclared files are invisible to
// the sandboxed process, matching linux-sandbox / processwrapper-sandbox (which
// enumerate a constructed symlink forest rather than the real execroot).
//
// An entry is visible iff:
//   - it is "." or ".." (always kept), or
//   - its resolved policy allows read (a declared input, or anything under a
//     declared directory-input cone), or
//   - it is an exact node in the manifest policy tree, i.e. an ancestor
//     directory that leads to a declared input. Such directories carry an
//     inherited Deny policy but must remain visible so the input can be reached.
// ---------------------------------------------------------------------------


static bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name, size_t nameChars)
{
    // Always keep the "." and ".." pseudo-entries.
    if ((nameChars == 1 && name[0] == L'.') ||
        (nameChars == 2 && name[0] == L'.' && name[1] == L'.'))
    {
        return true;
    }

    std::wstring childName(name, nameChars);
    PolicyResult childPolicy = directoryPolicyResult.GetPolicyForSubpath(childName.c_str());

    // Be conservative: if we somehow can't determine a policy, don't hide.
    if (childPolicy.IsIndeterminate())
    {
        return true;
    }

    return childPolicy.AllowRead() || childPolicy.IsExactManifestNode()
#if _WIN32
        // Reveal entries this process created in an execroot-writable scratch scope
        // (OverrideAllowWriteForExistingFiles), matching linux-sandbox's readable+
        // writable throwaway execroot. Without this a tool cannot see (jar, clean,
        // or re-open) the outputs it just wrote under an undeclared scratch subtree:
        // e.g. JavaBuilder writes .class files into _javac/<lib>_classes then walks
        // that tree to build the class jar and to clean it up - if the enumeration
        // hides the process's own files the jar comes out empty and the recursive
        // delete leaves a non-empty directory (RemoveDirectory -> ACCESS_DENIED).
        // Undeclared PRE-EXISTING inputs are not created by this process and stay
        // hidden, preserving hermeticity. Mirrors the CheckReadAccess carve-out.
        || (childPolicy.OverrideAllowWriteForExistingFiles() && childPolicy.WasCreatedInThisProcess())
#endif
        ;
}

// Convenience overload for null-terminated Win32 names (WIN32_FIND_DATAW.cFileName).
static bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name)
{
    return IsEnumChildVisible(directoryPolicyResult, name, wcslen(name));
}

// Returns the byte offsets of the FileNameLength field and the FileName field
// within a FILE_*_INFORMATION record for the given NtQueryDirectoryFile info
// class. Returns false for classes we do not know how to filter (the caller must
// then leave the buffer untouched). Offsets assume the natural x64 layout of the
// documented structures.
static bool TryGetDirInfoLayout(ULONG infoClass, ULONG& fileNameLengthOffset, ULONG& fileNameOffset)
{
    switch (infoClass)
    {
    case 1:  fileNameLengthOffset = 60; fileNameOffset = 64;  return true; // FileDirectoryInformation
    case 2:  fileNameLengthOffset = 60; fileNameOffset = 68;  return true; // FileFullDirectoryInformation
    case 3:  fileNameLengthOffset = 60; fileNameOffset = 94;  return true; // FileBothDirectoryInformation
    case 12: fileNameLengthOffset = 8;  fileNameOffset = 12;  return true; // FileNamesInformation
    case 37: fileNameLengthOffset = 60; fileNameOffset = 104; return true; // FileIdBothDirectoryInformation
    case 38: fileNameLengthOffset = 60; fileNameOffset = 80;  return true; // FileIdFullDirectoryInformation
    default: return false;
    }
}

// Maps a GetFileInformationByHandleEx directory-enumeration info class to the
// equivalent NtQueryDirectoryFile info class understood by TryGetDirInfoLayout
// (the underlying FILE_*_DIR_INFO structures are byte-for-byte identical). Also
// returns the "continue" variant of the class to use when re-querying for the
// next batch (Restart variants would otherwise rewind and loop forever).
// Returns false for classes we do not know how to filter.
static bool TryMapHandleDirInfoClass(
    FILE_INFO_BY_HANDLE_CLASS handleClass,
    ULONG& ntInfoClass,
    FILE_INFO_BY_HANDLE_CLASS& continueClass)
{
    switch ((int)handleClass)
    {
    case 10: // FileIdBothDirectoryInfo
    case 11: // FileIdBothDirectoryRestartInfo
        ntInfoClass = 37; continueClass = (FILE_INFO_BY_HANDLE_CLASS)10; return true;
    case 14: // FileFullDirectoryInfo
    case 15: // FileFullDirectoryRestartInfo
        ntInfoClass = 2;  continueClass = (FILE_INFO_BY_HANDLE_CLASS)14; return true;
    default:
        return false;
    }
}

// Filters a packed chain of FILE_*_INFORMATION records in-place, dropping entries
// whose names are not visible under directoryPolicyResult and re-linking the
// surviving records via NextEntryOffset. Surviving records stay at their original
// byte offsets; hidden records are simply left unreferenced. Returns the number of
// visible records kept, or SIZE_MAX if the info class is not one we know how to
// filter (in which case the buffer is left untouched).
//
// bufferLen is the number of valid bytes in `buffer` (the caller's buffer). The
// walk is bounded against it: a record whose fixed header would extend past the
// buffer stops the scan rather than over-reading, and a final record's name is
// clamped to what actually fits. This guards the case where an upstream re-query
// copies back only a truncated prefix of the OS-produced chain, leaving a record's
// NextEntryOffset pointing past the caller's buffer.
static size_t FilterDirectoryInformation(
    PVOID buffer,
    ULONG infoClass,
    ULONG bufferLen,
    const PolicyResult& directoryPolicyResult)
{
    ULONG nameLenOff, nameOff;
    if (!TryGetDirInfoLayout(infoClass, nameLenOff, nameOff))
    {
        return SIZE_MAX;
    }

    // Minimum bytes we must be able to read at a record before touching its fixed
    // header: NextEntryOffset (4 bytes at 0), the name-length field, and the start
    // of the name at nameOff.
    ULONG headerMin = static_cast<ULONG>(sizeof(ULONG));
    if (nameLenOff + static_cast<ULONG>(sizeof(ULONG)) > headerMin) headerMin = nameLenOff + static_cast<ULONG>(sizeof(ULONG));
    if (nameOff > headerMin) headerMin = nameOff;

    BYTE* base = reinterpret_cast<BYTE*>(buffer);
    ULONG offset = 0;
    BYTE* lastKept = nullptr;
    size_t kept = 0;

    for (;;)
    {
        // Bound the fixed-header read against the caller's buffer. A malformed or
        // truncated chain that points past the buffer stops the walk here.
        if (offset > bufferLen || bufferLen - offset < headerMin)
        {
            break;
        }

        BYTE* rec = base + offset;
        ULONG next = *reinterpret_cast<ULONG*>(rec);
        ULONG nameLen = *reinterpret_cast<ULONG*>(rec + nameLenOff);
        const wchar_t* name = reinterpret_cast<const wchar_t*>(rec + nameOff);

        // Clamp the name to what actually fits so IsEnumChildVisible never
        // reads past the end of the buffer on a truncated final record.
        ULONG availNameBytes = bufferLen - offset - nameOff;
        if (nameLen > availNameBytes)
        {
            nameLen = availNameBytes;
        }
        size_t nameChars = nameLen / sizeof(wchar_t);

        if (IsEnumChildVisible(directoryPolicyResult, name, nameChars))
        {
            if (lastKept != nullptr)
            {
                *reinterpret_cast<ULONG*>(lastKept) = static_cast<ULONG>(rec - lastKept);
            }
            lastKept = rec;
            kept++;
        }

        if (next == 0)
        {
            break;
        }
        offset += next;
    }

    if (lastKept != nullptr)
    {
        *reinterpret_cast<ULONG*>(lastKept) = 0; // terminate the surviving chain
    }

    return kept;
}

typedef NTSTATUS(NTAPI* QueryDirectoryFileFn)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

// Applies the Bazel enumeration filter to the result of an Nt/Zw QueryDirectoryFile
// call, re-querying the underlying handle (continuing the scan) as needed so that
// we never hand back a batch that contains only hidden entries. Updates result /
// reportedError / lastError to reflect the filtered output. `buffer`/`bufferSize`
// is the (possibly larger) working buffer actually passed to the Real API;
// FileInformation/Length is the caller's buffer that ultimately receives the data.
static void ApplyEnumerationFilterNt(
    QueryDirectoryFileFn realFn,
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult,
    NTSTATUS& result, DWORD& reportedError, DWORD& lastError)
{
    for (;;)
    {
        if (!NT_SUCCESS(result))
        {
            break;
        }

        size_t kept = FilterDirectoryInformation(FileInformation, (ULONG)FileInformationClass, Length, directoryPolicyResult);
        if (kept == SIZE_MAX || kept > 0)
        {
            // Either an info class we don't filter (leave as-is), or we kept at
            // least one visible entry.
            break;
        }

        // All entries in this batch were hidden. Continue the scan to fetch the
        // next batch and filter again, until we find a visible entry or run out.
        result = realFn(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            buffer, bufferSize, FileInformationClass, ReturnSingleEntry, FileName,
            FALSE /* RestartScan: continue from where we left off */);
        reportedError = RtlNtStatusToDosError(result);
        lastError = GetLastError();

        if (buffer != FileInformation && NT_SUCCESS(result))
        {
            memcpy_s(FileInformation, Length, buffer, Length);
        }
    }
}

// SL_* query flags for NtQueryDirectoryFileEx (from ntifs.h).
#ifndef SL_RESTART_SCAN
#define SL_RESTART_SCAN 0x00000001
#endif
#ifndef SL_RETURN_SINGLE_ENTRY
#define SL_RETURN_SINGLE_ENTRY 0x00000002
#endif

typedef NTSTATUS(NTAPI* QueryDirectoryFileExFn)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);

// Ex-form analogue of ApplyEnumerationFilterNt for NtQueryDirectoryFileEx,
// whose ReturnSingleEntry/RestartScan booleans are folded into a QueryFlags mask.
// Re-queries clear SL_RESTART_SCAN so the scan advances instead of restarting.
static void ApplyEnumerationFilterNtEx(
    QueryDirectoryFileExFn realFn,
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags,
    PUNICODE_STRING FileName,
    PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult,
    NTSTATUS& result, DWORD& reportedError, DWORD& lastError)
{
    for (;;)
    {
        if (!NT_SUCCESS(result))
        {
            break;
        }

        size_t kept = FilterDirectoryInformation(FileInformation, (ULONG)FileInformationClass, Length, directoryPolicyResult);
        if (kept == SIZE_MAX || kept > 0)
        {
            break;
        }

        ULONG continueFlags = QueryFlags & ~static_cast<ULONG>(SL_RESTART_SCAN);
        result = realFn(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            buffer, bufferSize, FileInformationClass, continueFlags, FileName);
        reportedError = RtlNtStatusToDosError(result);
        lastError = GetLastError();

        if (buffer != FileInformation && NT_SUCCESS(result))
        {
            memcpy_s(FileInformation, Length, buffer, Length);
        }
    }
}

// ---------------------------------------------------------------------------
// Model W write-overlay: enumeration INSERTION (experimental, ShouldWriteOverlay).
//
// The subtractive filter above removes undeclared children so a tool cannot see
// files it is not entitled to. The Model W write-overlay needs the opposite move
// on top of it: a file that a tool created but that was REDIRECTED off the real
// execroot into a process-private overlay must still APPEAR when the tool lists
// the directory it "wrote" the file into. Since that file is not present in the
// real directory the OS enumerated, its record has to be constructed and spliced
// into the returned FILE_*_INFORMATION chain.
//
// This is the counterpart to the subtractive filter and reuses the same layout
// table (TryGetDirInfoLayout). It is gated entirely behind ShouldWriteOverlay(),
// so with the flag off the shipped enumeration path is byte-for-byte unchanged.
//
// The names to insert are sourced from the real per-process overlay index (see
// GetOverlayTestSyntheticNames / ListOverlayChildren below). Remaining full-feature scope
// (tracked as mw-enum-classes): only the primary Detoured_NtQueryDirectoryFile
// call site is wired here - the Ex/Zw siblings, the Win32 FindFirstFile layer, and
// GetFileInformationByHandleEx are still filter-only.
// ---------------------------------------------------------------------------

// Supplemental TEST-ONLY source of names to inject into every enumerated directory.
// Parsed once from the BAZEL_SANDBOX_OVERLAY_TEST_NAMES environment variable (empty by
// default => contributes nothing). This is NOT part of the real feature: it lets
// the enforce suite exercise the record-construction / chain-relinking / emit-once
// mechanics in isolation, without first performing a redirected write. In normal
// operation the overlay entries come from the per-process index (ListOverlayChildren
// in InsertOverlayEntries); this env var is merely unioned in when present.
static const std::vector<std::wstring>& GetOverlayTestSyntheticNames()
{
    static const std::vector<std::wstring> names = []() {
        std::vector<std::wstring> v;
        wchar_t buf[2048];
        DWORD n = GetEnvironmentVariableW(L"BAZEL_SANDBOX_OVERLAY_TEST_NAMES", buf, ARRAYSIZE(buf));
        if (n > 0 && n < ARRAYSIZE(buf))
        {
            std::wstring s(buf, n);
            size_t start = 0;
            while (start <= s.size())
            {
                size_t sep = s.find(L';', start);
                size_t len = (sep == std::wstring::npos) ? std::wstring::npos : sep - start;
                std::wstring tok = s.substr(start, len);
                if (!tok.empty()) v.push_back(tok);
                if (sep == std::wstring::npos) break;
                start = sep + 1;
            }
        }
        return v;
    }();
    return names;
}

static inline ULONG AlignUp8(ULONG v) { return (v + 7u) & ~7u; }

// Wildcard match for a synthetic overlay entry name against the caller's
// enumeration expression (e.g. "*.txt"), using ntdll!RtlIsNameInExpression - the
// SAME matcher the filesystem itself applies to real entries. This gives exact NT
// semantics (case-insensitive, and native handling of the DOS wildcard
// metacharacters DOS_STAR '<', DOS_QM '>', DOS_DOT '"' that the I/O manager may
// substitute for '*'/'?'/'.'), so overlay entries are filtered identically to the
// real ones - unlike usvfs, which hand-converts '"'->'.' and runs its own glob.
// An empty or "*" expression matches everything (the common Bazel case).
typedef BOOLEAN (NTAPI* RtlIsNameInExpression_t)(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN, PWCH);
typedef WCHAR (NTAPI* RtlUpcaseUnicodeChar_t)(WCHAR);

static bool OverlayNameMatchesFilter(const std::wstring& name, const std::wstring& expr)
{
    if (expr.empty() || expr == L"*" || expr == L"*.*")
    {
        return true;
    }

    static RtlIsNameInExpression_t s_pRtlIsNameInExpression = []() -> RtlIsNameInExpression_t {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlIsNameInExpression_t>(
                           GetProcAddress(ntdll, "RtlIsNameInExpression"))
                     : nullptr;
    }();
    static RtlUpcaseUnicodeChar_t s_pRtlUpcaseUnicodeChar = []() -> RtlUpcaseUnicodeChar_t {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlUpcaseUnicodeChar_t>(
                           GetProcAddress(ntdll, "RtlUpcaseUnicodeChar"))
                     : nullptr;
    }();

    if (s_pRtlIsNameInExpression == nullptr)
    {
        return true; // fail-open: can't match, so don't hide the entry.
    }

    // With IgnoreCase==TRUE and no UpcaseTable, RtlIsNameInExpression upcases the
    // Name itself but requires the Expression to ALREADY be uppercase. Upcase with
    // the SAME system table the matcher uses (ntdll!RtlUpcaseUnicodeChar) so non-ASCII
    // patterns fold identically; fall back to an ASCII-only fold if unavailable.
    std::wstring up = expr;
    for (wchar_t& c : up)
    {
        if (s_pRtlUpcaseUnicodeChar != nullptr)
        {
            c = s_pRtlUpcaseUnicodeChar(c);
        }
        else if (c >= L'a' && c <= L'z')
        {
            c = (wchar_t)(c - 32);
        }
    }

    UNICODE_STRING uExpr;
    uExpr.Buffer = const_cast<wchar_t*>(up.c_str());
    uExpr.Length = (USHORT)(up.size() * sizeof(wchar_t));
    uExpr.MaximumLength = (USHORT)((up.size() + 1) * sizeof(wchar_t));

    UNICODE_STRING uName;
    uName.Buffer = const_cast<wchar_t*>(name.c_str());
    uName.Length = (USHORT)(name.size() * sizeof(wchar_t));
    uName.MaximumLength = (USHORT)((name.size() + 1) * sizeof(wchar_t));

    return s_pRtlIsNameInExpression(&uExpr, &uName, TRUE, nullptr) != FALSE;
}

// Join a directory (plain "X:\..." form) and a child name with a single separator.
static std::wstring JoinDirAndName(const std::wstring& dir, const std::wstring& name)
{
    std::wstring d = dir;
    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    return d + L'\\' + name;
}

// Build (once) this handle's point-in-time overlay entry snapshot for `enumDir`
// (plain "X:\..." form): the immediate backing-store children of enumDir that are
// ABSENT from the real directory, unioned with the test-only synthetic names, and
// sorted case-insensitively so the emit-once cursor indexes a STABLE ordering
// across the multi-call enumeration protocol. Captured exactly once per scan
// (OverlayEnumStarted gate) so a concurrent write by another process/thread in the
// action tree cannot re-order/resize this in-flight enumeration (which would make
// the cursor skip or duplicate an entry). Shared by every enumeration hook (NT
// packed-buffer + Win32 FindNextFile), so all APIs see the same overlay tail.
//
// The primary source is this action's BACKING STORE (design doc §6.3, "backing
// store is the source of truth"): the children of the mirrored backing subdirectory
// are exactly the files this process (or a peer in the tree, via the shared backing
// root) "wrote" that were redirected off the real execroot and are therefore absent
// from the real listing the OS just produced. This is one OS directory scan
// (O(children)), not an O(total-created) walk of a cross-process index.
static void EnsureOverlayEnumSnapshot(const std::wstring& enumDir, HandleOverlayRef& overlay)
{
    if (overlay->OverlayEnumStarted)
    {
        return;
    }
    std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;
    names.clear();
    // Overlay-only directory: when the enumerated dir is ABSENT from the real disk,
    // the handle was redirected to (and the OS just enumerated) the backing dir
    // itself, so its children are already present in the OS result. Splicing them
    // would double-list every entry. Mirrors the InsertOverlayEntries guard for the
    // NT path; also covers the Win32 Find handle synthesized for an overlay-only
    // directory search. (The gap #2 synthesize path always enumerates a REAL dir, so
    // this guard never suppresses it.)
    if (!enumDir.empty() && !OverlayIsDirectory(L"\\\\?\\" + enumDir))
    {
        overlay->OverlayEnumStarted = true;
        return;
    }
    if (!enumDir.empty())
    {
        ListBackingChildren(enumDir, names);
    }
    for (const std::wstring& e : GetOverlayTestSyntheticNames())
    {
        bool dup = false;
        for (const std::wstring& n : names)
        {
            if (_wcsicmp(n.c_str(), e.c_str()) == 0) { dup = true; break; }
        }
        if (!dup) names.push_back(e);
    }
    // Drop any name that already exists on the real disk in this directory: the OS
    // enumeration returns it in some call, so inserting it would duplicate the entry.
    // (Copy-ups of pre-existing files land here.) Purely new overlay files remain.
    if (!enumDir.empty())
    {
        std::wstring base = enumDir;
        while (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
        std::vector<std::wstring> kept;
        kept.reserve(names.size());
        for (std::wstring& nm : names)
        {
            std::wstring full = base + L"\\" + nm;
            if (GetFileAttributesW(full.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                kept.push_back(std::move(nm));
            }
        }
        names.swap(kept);
    }
    std::sort(names.begin(), names.end(),
        [](const std::wstring& a, const std::wstring& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
    overlay->OverlayEnumStarted = true;
}

// Deterministic 64-bit id synthesized from a (case-insensitive) path, used to fill
// the FileId field of the *Id* directory-info classes so repeated enumerations of
// the same overlay entry return a STABLE id and distinct names get distinct ids.
// FNV-1a over the lower-cased UTF-16 code units; the top bit is cleared so the id
// stays positive and cannot collide with the "no id" sentinel some tools test for.
static LONGLONG SynthOverlayFileId(const std::wstring& path)
{
    unsigned long long h = 1469598103934665603ULL;
    for (wchar_t c : path)
    {
        wchar_t lc = (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
        h ^= (unsigned long long)(unsigned short)lc;
        h *= 1099511628211ULL;
    }
    return (LONGLONG)(h & 0x7fffffffffffffffULL);
}

// Populate the fixed-header metadata of a synthetic directory-info record from the
// backing file's real attributes/size/timestamps, so a tool that reads size, times,
// or FILE_ATTRIBUTE_DIRECTORY off an enumerated overlay entry sees correct values
// (critical for overlay-only SUBDIRECTORIES, which must report the directory bit so
// tools recurse into them). Classes 1/2/3/37/38 share the FILE_*_DIRECTORY_INFORMATION
// header layout through FileAttributes (offset 56); FileNamesInformation (class 12)
// carries no metadata and is left as-is. `rec` must already be zeroed through nameOff.
// Failures to stat the backing file are benign (fields stay zeroed).
static void FillOverlayDirRecordMetadata(BYTE* rec, ULONG infoClass, const std::wstring& backingFullPath)
{
    if (infoClass == 12)
    {
        return; // FileNamesInformation: name only.
    }
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(backingFullPath.c_str(), GetFileExInfoStandard, &fad))
    {
        return;
    }
    auto putTime = [&](ULONG off, const FILETIME& ft) {
        LARGE_INTEGER li; li.LowPart = ft.dwLowDateTime; li.HighPart = (LONG)ft.dwHighDateTime;
        *reinterpret_cast<LONGLONG*>(rec + off) = li.QuadPart;
    };
    putTime(8,  fad.ftCreationTime);
    putTime(16, fad.ftLastAccessTime);
    putTime(24, fad.ftLastWriteTime);
    putTime(32, fad.ftLastWriteTime); // ChangeTime ~ LastWriteTime (best effort)
    LARGE_INTEGER size; size.LowPart = fad.nFileSizeLow; size.HighPart = (LONG)fad.nFileSizeHigh;
    *reinterpret_cast<LONGLONG*>(rec + 40) = size.QuadPart;                    // EndOfFile
    LONGLONG alloc = (size.QuadPart + 4095) & ~((LONGLONG)4095);
    *reinterpret_cast<LONGLONG*>(rec + 48) = alloc;                            // AllocationSize
    *reinterpret_cast<ULONG*>(rec + 56) = fad.dwFileAttributes;                // FileAttributes
    // FileId for the Id classes (offset differs by class; see TryGetDirInfoLayout).
    if (infoClass == 37)      *reinterpret_cast<LONGLONG*>(rec + 96) = SynthOverlayFileId(backingFullPath);
    else if (infoClass == 38) *reinterpret_cast<LONGLONG*>(rec + 72) = SynthOverlayFileId(backingFullPath);
}

// Win32 analogue of the NT record emit: fill `data` with the next un-emitted overlay
// entry for this handle's snapshot (advancing OverlayEnumCursor), sourced from the
// backing store, or return false when the snapshot is exhausted. Used by the Win32
// FindNextFileW hook to append overlay files after the real enumeration ends.
static bool NextOverlayFindDataW(const std::wstring& enumDir, HandleOverlayRef& overlay, LPWIN32_FIND_DATAW data)
{
    EnsureOverlayEnumSnapshot(enumDir, overlay);
    const std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;

    // Advance past any snapshot entries that don't match the caller's wildcard
    // (they'll never match on a later call either - same filter), emitting the
    // first match. Cursor advances permanently so each entry is considered once.
    while (overlay->OverlayEnumCursor < names.size() &&
           !OverlayNameMatchesFilter(names[overlay->OverlayEnumCursor], overlay->OverlayEnumFilter))
    {
        overlay->OverlayEnumCursor++;
    }
    if (overlay->OverlayEnumCursor >= names.size())
    {
        return false;
    }
    const std::wstring& nm = names[overlay->OverlayEnumCursor];
    const std::wstring backing = OverlayBackingPath(JoinDirAndName(enumDir, nm));

    memset(data, 0, sizeof(*data));
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(backing.c_str(), GetFileExInfoStandard, &fad))
    {
        data->dwFileAttributes = fad.dwFileAttributes;
        data->ftCreationTime   = fad.ftCreationTime;
        data->ftLastAccessTime = fad.ftLastAccessTime;
        data->ftLastWriteTime  = fad.ftLastWriteTime;
        data->nFileSizeHigh    = fad.nFileSizeHigh;
        data->nFileSizeLow     = fad.nFileSizeLow;
    }
    else
    {
        data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    size_t n = nm.size();
    if (n > MAX_PATH - 1) n = MAX_PATH - 1;
    memcpy(data->cFileName, nm.c_str(), n * sizeof(wchar_t));
    data->cFileName[n] = L'\0';
    data->cAlternateFileName[0] = L'\0';
    overlay->OverlayEnumCursor++;
    return true;
}

// Capture the caller's enumeration wildcard onto the handle, ONCE per scan (like
// usvfs's Searches::Info::searchPattern). The pattern is only supplied on the first
// NtQueryDirectoryFile(Ex)/Zw call and is NULL on continuation calls, so remembering
// it here lets the deferred exhaustion splice honor it. Reset (and re-captured) on a
// RestartScan so a re-scan can use a different pattern.
static void CaptureOverlayEnumFilter(HandleOverlayRef& overlay, PUNICODE_STRING FileName, bool restartScan)
{
    if (overlay == nullptr)
    {
        return;
    }
    if (restartScan)
    {
        overlay->OverlayEnumFilterSet = false;
        overlay->OverlayEnumFilter.clear();
    }
    if (!overlay->OverlayEnumFilterSet && FileName != nullptr && FileName->Length > 0)
    {
        overlay->OverlayEnumFilter.assign(FileName->Buffer, FileName->Length / sizeof(wchar_t));
        overlay->OverlayEnumFilterSet = true;
    }
}

// Splices synthetic overlay entries into a directory-enumeration result produced
// by Nt/Zw QueryDirectoryFile. Runs AFTER the subtractive filter, so it never
// re-hides what it inserts. Only the info classes understood by TryGetDirInfoLayout
// are handled; any other class is passed through untouched (fail-open).
//
// Two cases are handled, matching how enumeration APIs drive the OS:
//   - result == STATUS_SUCCESS: real entries are present. Synthetic records are
//     appended after the surviving chain (unless ReturnSingleEntry, in which case
//     the caller's single slot is already filled and synthetics wait for the
//     exhaustion call below).
//   - result == STATUS_NO_MORE_FILES / STATUS_NO_SUCH_FILE: the real scan is done.
//     If synthetics remain unemitted they are written into the fresh buffer and
//     the status is rewritten to STATUS_SUCCESS so the caller keeps reading.
//
// overlay->OverlayEnumCursor tracks how many synthetic entries have already been
// emitted for this handle, so each is returned exactly once across the multi-call
// enumeration protocol. RestartScan resets the cursor.
static void InsertOverlayEntries(
    PVOID FileInformation,
    ULONG Length,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG infoClass,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    const std::wstring& enumDir,
    HandleOverlayRef& overlay,
    NTSTATUS& result)
{
    if (overlay == nullptr)
    {
        return;
    }

    ULONG nameLenOff, nameOff;
    if (!TryGetDirInfoLayout(infoClass, nameLenOff, nameOff))
    {
        return; // class we cannot construct: leave the OS result untouched.
    }

    // Overlay-only directory: if the enumerated directory does NOT exist on the real
    // disk, this handle was redirected to (and the OS just enumerated) the backing
    // store itself (see ResolveOverlayOpenPath's directory branch). The backing
    // children are therefore already present in the OS result; sourcing them again
    // from ListBackingChildren and splicing would double-list every entry. Leave the
    // buffer untouched. (A directory present on real disk enumerates the real dir and
    // DOES get its overlay-only children spliced below.)
    if (!enumDir.empty())
    {
        const std::wstring realWideDir = L"\\\\?\\" + enumDir;
        if (!OverlayIsDirectory(realWideDir))
        {
            return;
        }
    }

    // A new scan (first call, or an explicit RestartScan) invalidates any snapshot.
    if (RestartScan)
    {
        overlay->OverlayEnumStarted = false;
        overlay->OverlayEnumCursor = 0;
        overlay->OverlayEnumSnapshot.clear();
    }

    // Capture (once) this handle's overlay entry snapshot; reused for every call.
    EnsureOverlayEnumSnapshot(enumDir, overlay);

    const std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;

    if (names.empty())
    {
        return;
    }

    if (overlay->OverlayEnumCursor >= names.size())
    {
        return; // every synthetic entry has already been emitted for this handle.
    }

    const NTSTATUS kStatusSuccess     = (NTSTATUS)0x00000000;
    const NTSTATUS kStatusNoMoreFiles = (NTSTATUS)0x80000006;
    const NTSTATUS kStatusNoSuchFile  = (NTSTATUS)0xC000000F;

    const bool realSuccess = NT_SUCCESS(result);
    const bool realExhausted = (result == kStatusNoMoreFiles || result == kStatusNoSuchFile);

    // Emit synthetic entries ONLY after the real enumeration has reported exhaustion,
    // never interleaved into a call that still carried real records. This mirrors
    // usvfs (hook_NtQueryDirectoryFile): all "regular" results are returned first
    // across as many calls as the caller needs, and virtual entries are appended only
    // once regularComplete. Interleaving synthetics into a real-SUCCESS buffer is
    // fragile under a small caller buffer that spans many calls - the OS keeps its
    // own scan position while we advance ours, and getting the two cursors to agree
    // per-call invites skipped or duplicated entries. Deferring to exhaustion makes
    // each synthetic depend only on our own emit-once cursor, so it appears exactly
    // once regardless of how the real portion was chunked. Standard enumeration loops
    // (FindNextFile, libuv, NtQueryDirectoryFile callers) always call until they get
    // a non-success status, so the exhaustion call is guaranteed to be made.
    if (realSuccess)
    {
        return; // real records still flowing: leave this buffer untouched.
    }
    if (!realExhausted)
    {
        return; // a genuine error: don't fabricate a result on top of it.
    }

    // Exhaustion: append synthetic records from offset 0. Each record: zeroed fixed
    // header, FileNameLength set, NextEntryOffset relinked, name copied in.
    BYTE* base = reinterpret_cast<BYTE*>(FileInformation);
    ULONG usedEnd = 0;
    BYTE* prevRec = nullptr;
    ULONG prevOff = 0;
    ULONG writeOff = AlignUp8(usedEnd);
    ULONG lastWrittenEnd = usedEnd;
    bool emittedAny = false;

    while (overlay->OverlayEnumCursor < names.size())
    {
        const std::wstring& nm = names[overlay->OverlayEnumCursor];
        // Skip entries that don't match the caller's wildcard (see gap #1); advance
        // the cursor permanently so each snapshot entry is considered exactly once.
        if (!OverlayNameMatchesFilter(nm, overlay->OverlayEnumFilter))
        {
            overlay->OverlayEnumCursor++;
            continue;
        }
        ULONG nameBytes = static_cast<ULONG>(nm.size() * sizeof(wchar_t));
        ULONG recSize = nameOff + nameBytes;
        if (static_cast<size_t>(writeOff) + recSize > Length)
        {
            break; // no room in the caller's buffer for another record.
        }

        BYTE* rec = base + writeOff;
        memset(rec, 0, nameOff);                                   // fixed header
        *reinterpret_cast<ULONG*>(rec) = 0;                        // NextEntryOffset (last)
        *reinterpret_cast<ULONG*>(rec + nameLenOff) = nameBytes;   // FileNameLength
        memcpy(rec + nameOff, nm.c_str(), nameBytes);              // FileName[]
        // Fill attributes/size/timestamps/FileId from the backing file so the entry
        // is indistinguishable from a real one (esp. the directory bit for subdirs).
        FillOverlayDirRecordMetadata(rec, infoClass, OverlayBackingPath(JoinDirAndName(enumDir, nm)));

        if (prevRec != nullptr)
        {
            *reinterpret_cast<ULONG*>(prevRec) = writeOff - prevOff; // link prior -> this
        }

        prevRec = rec;
        prevOff = writeOff;
        lastWrittenEnd = writeOff + recSize;
        emittedAny = true;
        overlay->OverlayEnumCursor++;

        writeOff = AlignUp8(writeOff + recSize);

        // Honor the single-entry contract in the exhaustion case (one record/call).
        if (ReturnSingleEntry)
        {
            break;
        }
    }

    if (emittedAny)
    {
        result = kStatusSuccess;
        if (IoStatusBlock != nullptr)
        {
            IoStatusBlock->Status = kStatusSuccess;
            IoStatusBlock->Information = lastWrittenEnd;
        }
    }
}

// Model W write-overlay, narrow-filter FindFirstFile gap fix. A Win32
// FindFirstFileExW whose wildcard matches ONLY overlay-only files (so the real
// directory returns ERROR_FILE_NOT_FOUND and no Find handle is opened) would never
// surface those files, because the overlay tail is normally appended on FindNextFile
// exhaustion of an existing real handle. Here we synthesize that handle: if the real
// directory exists and has at least one overlay-only child matching `filterExpr`, we
// (re)open the directory enumeration with a match-all "*" pattern to obtain a real
// Find handle, register it, CONSUME all the (non-matching) real entries up front, and
// return the first matching overlay entry as the FindFirstFile result. Subsequent
// FindNextFileW calls then hit real exhaustion immediately and continue emitting the
// (pattern-filtered) overlay tail via the normal TryAppendOverlayFindDataW path.
// Returns a valid Find handle (with lpFindFileData filled) or INVALID_HANDLE_VALUE if
// there is nothing to synthesize (caller keeps the original not-found result).
static HANDLE TrySynthesizeOverlayFindFirstW(
    const std::wstring& dirPath,
    const std::wstring& filterExpr,
    AccessCheckResult const& dirAccessCheck,
    PolicyResult const& dirPolicy,
    LPWIN32_FIND_DATAW lpFindFileData,
    FINDEX_INFO_LEVELS fInfoLevelId,
    FINDEX_SEARCH_OPS fSearchOp,
    DWORD dwAdditionalFlags)
{
    std::wstring base = dirPath;
    while (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
    if (base.empty())
    {
        return INVALID_HANDLE_VALUE;
    }

    // Cheap pre-check: is there at least one overlay-only child matching the filter?
    std::vector<std::wstring> children;
    ListBackingChildren(base, children);
    bool anyMatch = false;
    for (const std::wstring& nm : children)
    {
        std::wstring realFull = base + L"\\" + nm;
        if (GetFileAttributesW(realFull.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            continue; // exists on the real disk; the OS listing already covers it.
        }
        if (OverlayNameMatchesFilter(nm, filterExpr))
        {
            anyMatch = true;
            break;
        }
    }
    if (!anyMatch)
    {
        return INVALID_HANDLE_VALUE;
    }

    // Open the enumeration with match-all to obtain a real handle we can return.
    std::wstring wildAll = base + L"\\*";
    WIN32_FIND_DATAW scratch;
    memset(&scratch, 0, sizeof(scratch));
    HANDLE h = Real_FindFirstFileExW(
        wildAll.c_str(), fInfoLevelId, &scratch, fSearchOp, nullptr, dwAdditionalFlags);
    if (h == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE; // directory vanished; keep the not-found result.
    }

    RegisterHandleOverlay(h, dirAccessCheck, dirPolicy, HandleType::Find);
    HandleOverlayRef ov = TryLookupHandleOverlay(h);
    if (ov == nullptr)
    {
        FindClose(h);
        return INVALID_HANDLE_VALUE;
    }
    ov->OverlayEnumFilter = filterExpr;
    ov->OverlayEnumFilterSet = true;

    // Consume the real entries up front. By precondition none match the narrow filter
    // (the narrow FindFirstFile returned not-found), so we skip them all; a defensive
    // match short-circuits and returns the real entry.
    bool haveReal = true; // scratch currently holds the first real entry (".").
    while (haveReal && !OverlayNameMatchesFilter(scratch.cFileName, filterExpr))
    {
        haveReal = (Real_FindNextFileW(h, &scratch) != FALSE);
    }
    if (haveReal)
    {
        *lpFindFileData = scratch;
        ScrubShortFileName(lpFindFileData);
        return h;
    }

    // Reals exhausted with no match: emit the first (filtered) overlay entry.
    if (NextOverlayFindDataW(base, ov, lpFindFileData))
    {
        return h;
    }
    FindClose(h);
    return INVALID_HANDLE_VALUE;
}

/// <summary>
/// Enforces allowed access for a path that leads to the target of a reparse point.
/// </summary>
static HANDLE WINAPI ReportFindFirstFileExWAccesses(
    _In_       LPCWSTR            lpFileName,
    _In_       FINDEX_INFO_LEVELS fInfoLevelId,
    _Out_      LPVOID             lpFindFileData,
    _In_       FINDEX_SEARCH_OPS  fSearchOp,
    __reserved LPVOID             lpSearchFilter,
    _In_       DWORD              dwAdditionalFlags)
{
    // Both of the currently understood info levels return WIN32_FIND_DATAW.
    LPWIN32_FIND_DATAW findFileDataAtLevel = (LPWIN32_FIND_DATAW)lpFindFileData;
    FileOperationContext fileOperationContext = FileOperationContext::CreateForProbe(L"FindFirstFileEx", lpFileName);

    // There are two categories of FindFirstFile invocation that we can model differently:
    // - Probe: FindFirstFile("C:\componentA\componentB") where componentB is a normal path component.
    //          We model this as a normal probe to the full path. If FindFirstFile returns ERROR_FILE_NOT_FOUND, this is a normal anti-dependency.
    // - Enumeration: FindFirstFile("C:\componentA\wildcard") where the last component is a wildcard, e.g. "*cpp" or "*".
    //          We model this as (filtered) directory enumeration. This access is to C:\componentA, with imaginary anti-dependencies on everything
    //          that _could_ match the filter. This call starts enumerating, but also might return the first match to the wildcard (which requires its own access check).
    //          TODO: We currently cannot report or model invalidation of enumeration 'anti-dependencies', but can report what files are actually found.
    CanonicalizedPath canonicalizedPathIncludingFilter = CanonicalizedPath::Canonicalize(lpFileName);
    if (canonicalizedPathIncludingFilter.IsNull())
    {
        // TODO: This really shouldn't have failure cases. Maybe just failfast on allocation failure, etc.
        Dbg(L"FindFirstFileEx: Failed to canonicalize the search path; passing through.");
        return Real_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    }

    // First, get the policy for the directory itself; this entails removing the last component.
    CanonicalizedPath canonicalizedPathExcludingFilter = canonicalizedPathIncludingFilter.RemoveLastComponent();
    FileOperationContext directoryOperationContext = FileOperationContext::CreateForProbe(L"FindFirstFileEx", canonicalizedPathExcludingFilter.GetPathString());
    PolicyResult directoryPolicyResult;
    directoryPolicyResult.Initialize(canonicalizedPathExcludingFilter);

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(
        directoryOperationContext,
        directoryPolicyResult,
        false /* Need to fully resolve the directory */))
    {
        lpFindFileData = NULL;
        return INVALID_HANDLE_VALUE;
    }

    DWORD error = ERROR_SUCCESS;

    // Model W (write-overlay): an exact (non-wildcard) FindFirstFile is a stat-style
    // probe of a single path. When that path was written into the overlay, probe the
    // backing file so tools whose stat() rides on FindFirstFile observe the scratch
    // file. Wildcard enumeration is not redirected here (that is the mw-enum-classes
    // phase); only a concrete last component with an existing backing copy is.
    LPCWSTR findTarget = lpFileName;
    std::wstring overlayFindProbe;
    {
        wchar_t const* lastComp = canonicalizedPathIncludingFilter.GetLastComponent();
        if (lastComp != nullptr && !PathContainsWildcard(lastComp))
        {
            PolicyResult probePolicy = directoryPolicyResult.GetPolicyForSubpath(lastComp);
            overlayFindProbe = ResolveOverlayProbePath(probePolicy);
            if (!overlayFindProbe.empty())
            {
                findTarget = overlayFindProbe.c_str();
            }
        }
    }

    // Model W (write-overlay): the enumerated DIRECTORY itself may be overlay-only -
    // created via CreateDirectoryW into the backing store and absent from the real
    // disk (e.g. a tool that mkdir's a scratch subdir then lists it, or a recursive
    // walk such as `dir /s` descending into it). Real_FindFirstFileExW on the
    // original path fails with PATH_NOT_FOUND, and the nested Nt open that would
    // redirect (ResolveOverlayOpenPath's directory branch) is shielded by the
    // DetouredScope of this Win32 wrapper. Redirect the whole search into the backing
    // directory so its children enumerate directly. All children of an overlay-only
    // dir live in the backing store, so no separate splice is needed - the
    // EnsureOverlayEnumSnapshot guard suppresses the FindNextFile append for this
    // handle to avoid double-listing. Only when we did not already redirect to an
    // exact backing probe above.
    std::wstring overlayDirSearch;
    if (ShouldWriteOverlay() && findTarget == lpFileName)
    {
        const std::wstring dirVirtual(directoryPolicyResult.GetTranslatedPathWithoutTypePrefix());
        if (!dirVirtual.empty())
        {
            const std::wstring realWideDir = L"\\\\?\\" + dirVirtual;
            const std::wstring backingDir = OverlayBackingPath(dirVirtual);
            if (!backingDir.empty() && !OverlayIsDirectory(realWideDir) && OverlayIsDirectory(backingDir))
            {
                wchar_t const* lastComp = canonicalizedPathIncludingFilter.GetLastComponent();
                overlayDirSearch = JoinDirAndName(backingDir, (lastComp != nullptr && *lastComp) ? lastComp : L"*");
                findTarget = overlayDirSearch.c_str();
            }
        }
    }

    HANDLE searchHandle = Real_FindFirstFileExW(findTarget, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    error = GetLastError();

    // Note that we check success via the returned handle. This function does not call SetLastError(ERROR_SUCCESS) on success. We stash
    // and restore the error code anyway so as to not perturb things.
    bool success = searchHandle != INVALID_HANDLE_VALUE;

    // Model W (write-overlay): when we redirected an exact (non-wildcard) probe to a
    // backing-store path, Real_FindFirstFileExW filled cFileName with the BACKING
    // entry's name, which differs from the virtual name wherever the mapping is not
    // 1:1 - most importantly for the cone ROOT itself, whose virtual last component
    // (e.g. the working-dir name) maps to the backing root's last component ("overlay").
    // A tool that uses FindFirstFile to recover a path component's canonical CASE (the
    // JVM class loader canonicalizes every classpath entry this way) would otherwise
    // substitute the backing name and resolve in-cone paths to the backing location,
    // breaking its "resource under classpath dir" check. Restore the caller's requested
    // last component so the returned name reflects the VIRTUAL path. (For a normal
    // overlay file the names already coincide, so this is a no-op there.)
    if (success && !overlayFindProbe.empty() && findFileDataAtLevel != nullptr)
    {
        wchar_t const* virtualLast = canonicalizedPathIncludingFilter.GetLastComponent();
        if (virtualLast != nullptr && *virtualLast)
        {
            wcsncpy_s(findFileDataAtLevel->cFileName,
                      _countof(findFileDataAtLevel->cFileName),
                      virtualLast, _TRUNCATE);
            findFileDataAtLevel->cAlternateFileName[0] = L'\0';
        }
    }

    // ERROR_DIRECTORY means we had an lpFileName like X:\a\b where X:\a is a file rather than a directory.
    // In other words, this access is equivalent to a non-enumerating probe on a file X:\a.
    bool searchPathIsFile = error == ERROR_DIRECTORY;
    wchar_t const* filter = canonicalizedPathIncludingFilter.GetLastComponent();
    bool isEnumeration = !searchPathIsFile && PathContainsWildcard(filter);
    bool isProbeOfLastComponent = !isEnumeration && !searchPathIsFile;

    // Bazel input filtering: advance past undeclared entries so that the first
    // result we report and return is a visible (declared) one. "." and ".." always
    // match a wildcard filter, so enumerating an existing directory keeps at least
    // those entries; a narrower filter matching only hidden entries collapses to
    // "no matches" (ERROR_FILE_NOT_FOUND), just like an empty directory.
    if (ShouldFilterDirectoryEnumeration() && success && isEnumeration)
    {
        while (!IsEnumChildVisible(directoryPolicyResult, findFileDataAtLevel->cFileName))
        {
            if (!Real_FindNextFileW(searchHandle, findFileDataAtLevel))
            {
                FindClose(searchHandle);
                searchHandle = INVALID_HANDLE_VALUE;
                success = false;
                error = ERROR_FILE_NOT_FOUND;
                break;
            }
        }
    }

    // Read context used for access-checking a probe to the search-directory.
    // This is only used if searchPathIsFile, i.e., we got ERROR_DIRECTORY.
    FileReadContext directoryProbeContext;
    directoryProbeContext.Existence = FileExistence::Existent;
    directoryProbeContext.OpenedDirectory = !searchPathIsFile;

    fileOperationContext.OpenedFileOrDirectoryAttributes = GetAttributesForFileOrDirectory(!searchPathIsFile);

    // Only report the enumeration if specified by the policy
    bool reportDirectoryEnumeration = directoryPolicyResult.ReportDirectoryEnumeration();
    bool explicitlyReportDirectoryEnumeration = isEnumeration && reportDirectoryEnumeration;

    // TODO: Perhaps should have a specific access check for enumeration.
    //       For now, we always allow enumeration and report it.
    //       Since enumeration has historically not been understood or reported at all, this is a fine incremental move -
    //       given a policy flag for allowing enumeration, we'd apply it globally anyway.
    // TODO: Should include the wildcard in enumeration reports, so that directory enumeration assertions can be more precise.

    AccessCheckResult directoryAccessCheck = searchPathIsFile
        ? directoryPolicyResult.CheckReadAccess(RequestedReadAccess::Probe, directoryProbeContext) // Given X:\d\* we're probing X:\d (a file)
        : AccessCheckResult( // Given X:\d\* we're enumerating X:\d (may or may not exist).
            isEnumeration ? RequestedAccess::Enumerate : RequestedAccess::Probe,
            ResultAction::Allow,
            explicitlyReportDirectoryEnumeration ? ReportLevel::ReportExplicit : ReportLevel::Ignore);

    if (!searchPathIsFile && !explicitlyReportDirectoryEnumeration && ReportAnyAccess(false))
    {
        // Ensure access is reported (not explicit) when report all accesses is specified
        directoryAccessCheck.Level = ReportLevel::Report;
    }

    // Now, we can establish a policy for the file actually found.
    // - If enumerating, we can only do this on success (some file actually found) - if the wildcard matches nothing, we can't invent a name for which to report an antidependency.
    //   TODO: This is okay, but we need to complement this behavior with reporting the enumeration on the directory.
    // - If probing, we can do this even on failure. If nothing is found, we have a simple anti-dependency on the fully-canonicalized path.
    PolicyResult filePolicyResult;
    bool canReportPreciseFileAccess;
    if (success && isEnumeration)
    {
        assert(!searchPathIsFile);
        // Start enumeration: append the found name to get a sub-policy for the first file found.
        wchar_t const* enumeratedComponent = &findFileDataAtLevel->cFileName[0];
        filePolicyResult = directoryPolicyResult.GetPolicyForSubpath(enumeratedComponent);
        canReportPreciseFileAccess = true;
    }
    else if (isProbeOfLastComponent)
    {
        assert(!searchPathIsFile);
        // Probe: success doesn't matter; append the last component to get a sub-policy (we excluded it before to get the directory policy).
        filePolicyResult = directoryPolicyResult.GetPolicyForSubpath(canonicalizedPathIncludingFilter.GetLastComponent());
        canReportPreciseFileAccess = true;
    }
    else
    {
        // One of:
        // a) Enumerated an empty directory with a wildcard (!success)
        // b) Search-path is actually a file (searchPathIsFile)
        // In either case we don't have a concrete path for the final component and so can only report the directory access.
        canReportPreciseFileAccess = false;
    }

    // For the enumeration itself, we report ERROR_SUCCESS in the case that no matches were found (the directory itself exists).
    // FindFirstFileEx indicates no matches with ERROR_FILE_NOT_FOUND.
    DWORD enumerationError = (success || error == ERROR_FILE_NOT_FOUND) ? ERROR_SUCCESS : error;
    ReportIfNeeded(directoryAccessCheck, fileOperationContext, directoryPolicyResult, GetReportedError(success, enumerationError), error, -1, filter);

    // TODO: Respect ShouldDenyAccess for directoryAccessCheck.

    if (canReportPreciseFileAccess)
    {
        assert(!filePolicyResult.IsIndeterminate());

        FileReadContext readContext;
        DWORD reportedError = GetReportedError(success, error);
        readContext.InferExistenceFromError(reportedError);
        readContext.OpenedDirectory =
            success
            && findFileDataAtLevel != nullptr
            && IsDirectoryFromAttributes(
                findFileDataAtLevel->dwFileAttributes,
                ShouldTreatDirectoryReparsePointAsFile(fileOperationContext.DesiredAccess, fileOperationContext.FlagsAndAttributes, filePolicyResult));

        fileOperationContext.OpenedFileOrDirectoryAttributes = success && findFileDataAtLevel != nullptr
            ? findFileDataAtLevel->dwFileAttributes
            : INVALID_FILE_ATTRIBUTES;

        AccessCheckResult fileAccessCheck = filePolicyResult.CheckReadAccess(
            isEnumeration ? RequestedReadAccess::EnumerationProbe : RequestedReadAccess::Probe,
            readContext);

        if (fileAccessCheck.ShouldDenyAccess())
        {
            // Note that we won't hard-deny enumeration probes (isEnumeration == true, requested EnumerationProbe). See CheckReadAccess.
            // So this branch is a probe of a concrete file path (e.g. FindFirstFileEx("dir\\file")), which tools such as
            // cmd.exe's `type` and many CRT stat() implementations use as an existence check. Under Bazel input filtering,
            // an undeclared-but-existing file must look ABSENT (ERROR_FILE_NOT_FOUND), not ACCESS_DENIED, to match
            // linux-sandbox's symlink forest (where the path simply is not there) - otherwise these probes diverge.
            error = fileAccessCheck.DenialError(ShouldDeniedReadsAsNotFound());
            reportedError = error;

            if (searchHandle != INVALID_HANDLE_VALUE)
            {
                FindClose(searchHandle);
                searchHandle = INVALID_HANDLE_VALUE;
            }
        }
        else if (success && isEnumeration)
        {
            // We are returning a find handle that might return more results; mark it so that we can respond to FindNextFile on it.
            RegisterHandleOverlay(searchHandle, directoryAccessCheck, directoryPolicyResult, HandleType::Find);

            // Model W write-overlay (gap #1): remember the caller's wildcard on the Find
            // handle so the overlay tail appended at FindNextFile exhaustion is filtered
            // by the same pattern the OS applied to the real entries.
            if (ShouldWriteOverlay())
            {
                HandleOverlayRef ov = TryLookupHandleOverlay(searchHandle);
                if (ov != nullptr && filter != nullptr)
                {
                    ov->OverlayEnumFilter = filter;
                    ov->OverlayEnumFilterSet = true;
                }
            }
        }

        if (success && filePolicyResult.ShouldOverrideTimestamps(fileAccessCheck))
        {
#if SUPER_VERBOSE
            Dbg(L"FindFirstFileExW: Overriding timestamps for %s", filePolicyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
            OverrideTimestampsForInputFile(findFileDataAtLevel);
        }

        // FindFirstFile is the most common way to determine short-names for files and directories (observed to be called by even GetShortPathName).
        // We want to hide short file names, since they are not deterministic, not always present, and we don't canonicalize them for enforcement.
        if (success)
        {
            ScrubShortFileName(findFileDataAtLevel);
        }

        ReportIfNeeded(fileAccessCheck, fileOperationContext, filePolicyResult, reportedError, error);
    }

    // Model W write-overlay (gap #2): a narrow wildcard that matches ONLY overlay-only
    // files leaves the OS with no matches and no Find handle. Synthesize one so those
    // files are still returned. Guarded so it only fires for a genuine enumeration that
    // came up empty on the real disk.
    if (searchHandle == INVALID_HANDLE_VALUE && isEnumeration && !searchPathIsFile &&
        error == ERROR_FILE_NOT_FOUND && ShouldWriteOverlay())
    {
        HANDLE synth = TrySynthesizeOverlayFindFirstW(
            canonicalizedPathExcludingFilter.GetPathString(),
            filter != nullptr ? filter : L"",
            directoryAccessCheck, directoryPolicyResult,
            findFileDataAtLevel, fInfoLevelId, fSearchOp, dwAdditionalFlags);
        if (synth != INVALID_HANDLE_VALUE)
        {
            searchHandle = synth;
            error = ERROR_SUCCESS;
        }
    }

    SetLastError(error);
    return searchHandle;
}

IMPLEMENTED(Detoured_FindFirstFileExW)
HANDLE WINAPI Detoured_FindFirstFileExW(
    _In_       LPCWSTR            lpFileName,
    _In_       FINDEX_INFO_LEVELS fInfoLevelId,
    _Out_      LPVOID             lpFindFileData,
    _In_       FINDEX_SEARCH_OPS  fSearchOp,
    __reserved LPVOID             lpSearchFilter,
    _In_       DWORD              dwAdditionalFlags)
{
    if (ShouldUseLargeEnumerationBuffer())
    {
        dwAdditionalFlags |= FIND_FIRST_EX_LARGE_FETCH;
    }

    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpFileName) ||
        lpFindFileData == NULL ||
        lpSearchFilter != NULL ||
        (fInfoLevelId != FindExInfoStandard && fInfoLevelId != FindExInfoBasic) ||
        IsSpecialDeviceName(lpFileName))
    {
        return Real_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    }

    return ReportFindFirstFileExWAccesses(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
}

IMPLEMENTED(Detoured_FindFirstFileExA)
HANDLE WINAPI Detoured_FindFirstFileExA(
    _In_       LPCSTR             lpFileName,
    _In_       FINDEX_INFO_LEVELS fInfoLevelId,
    _Out_      LPVOID             lpFindFileData,
    _In_       FINDEX_SEARCH_OPS  fSearchOp,
    __reserved LPVOID             lpSearchFilter,
    _In_       DWORD              dwAdditionalFlags)
{
    // TODO: Note that we can't simply forward to FindFirstFileW here after a unicode conversion.
    // The output value differs too - WIN32_FIND_DATA{A, W}

    if (ShouldUseLargeEnumerationBuffer())
    {
        dwAdditionalFlags |= FIND_FIRST_EX_LARGE_FETCH;
    }

    return Real_FindFirstFileExA(
        lpFileName,
        fInfoLevelId,
        lpFindFileData,
        fSearchOp,
        lpSearchFilter,
        dwAdditionalFlags);
}

// Model W write-overlay: emit the next process-private overlay entry (a backing-
// store file absent from the real directory) into a WIN32_FIND_DATAW, one per call,
// tracked by the per-handle emit-once cursor. Returns TRUE and sets last error to
// ERROR_SUCCESS if an entry was produced; FALSE (leaving the caller's exhaustion
// state intact) otherwise. Kill-switched by ShouldWriteOverlay(). Shared by both
// FindNextFileW exhaustion points: the outer real-exhaustion branch and the inner
// --filter-inputs filter loop (which would otherwise return FALSE and skip the
// overlay tail).
static bool TryAppendOverlayFindDataW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    if (!ShouldWriteOverlay())
    {
        return false;
    }

    // Building this handle's overlay snapshot below calls Win32 APIs that clobber
    // the thread's last error: ListBackingChildren (FindFirstFile), OverlayBackingPath
    // (GetEnvironmentVariableW -> ERROR_ENVVAR_NOT_FOUND/203 when the overlay-dir var
    // is absent), and GetFileAttributesW on not-yet-existing paths. Our callers invoke
    // us only after the real enumeration ended with ERROR_NO_MORE_FILES and rely on
    // that error SURVIVING when we produce no entry - a stat/scandir loop (e.g. CPython
    // importlib's os.scandir) treats any error other than ERROR_NO_MORE_FILES as a hard
    // failure and raised OSError [WinError 203] on every overlay-enabled run. Preserve
    // and restore the incoming last error on the no-entry path so the caller's
    // end-of-enumeration contract holds; only the produced-entry path sets SUCCESS.
    const DWORD savedError = GetLastError();

    HandleOverlayRef ov = TryLookupHandleOverlay(hFindFile);
    if (ov == nullptr || ov->Type != HandleType::Find)
    {
        SetLastError(savedError);
        return false;
    }

    std::wstring enumDir(ov->Policy.GetTranslatedPathWithoutTypePrefix());
    if (NextOverlayFindDataW(enumDir, ov, lpFindFileData))
    {
        SetLastError(ERROR_SUCCESS);
        return true;
    }

    SetLastError(savedError);
    return false;
}

IMPLEMENTED(Detoured_FindNextFileW)
BOOL WINAPI Detoured_FindNextFileW(
    _In_  HANDLE             hFindFile,
    _Out_ LPWIN32_FIND_DATAW lpFindFileData)
{
    DetouredScope scope;
    DWORD error = ERROR_SUCCESS;
    BOOL result = Real_FindNextFileW(hFindFile, lpFindFileData);
    error = GetLastError();

    if (scope.Detoured_IsDisabled() || IsNullOrInvalidHandle(hFindFile) || lpFindFileData == nullptr)
    {
        return result;
    }

    if (!result)
    {
        // Real enumeration ended. Model W write-overlay: append process-private
        // overlay entries (backing-store files absent from the real directory) after
        // the real tail, one per FindNextFile call, tracked by the per-handle
        // emit-once cursor so each appears exactly once. Kill-switched by
        // ShouldWriteOverlay(); with the flag off this is the shipped early return.
        if (ShouldWriteOverlay() && error == ERROR_NO_MORE_FILES)
        {
            if (TryAppendOverlayFindDataW(hFindFile, lpFindFileData))
            {
                return TRUE;
            }
        }
        // TODO: This is likely ERROR_NO_MORE_FILES; is there anything more to check or report when enumeration ends?
        return result;
    }

    HandleOverlayRef overlay = TryLookupHandleOverlay(hFindFile);
    if (overlay != nullptr)
    {
        // Bazel input filtering: skip undeclared entries so they are invisible.
        if (ShouldFilterDirectoryEnumeration())
        {
            while (!IsEnumChildVisible(overlay->Policy, lpFindFileData->cFileName))
            {
                if (!Real_FindNextFileW(hFindFile, lpFindFileData))
                {
                    // Real enumeration exhausted after filtering out every remaining
                    // undeclared child. Before reporting end-of-enumeration, append
                    // the Model W overlay tail (backing-store-only files); without
                    // this the overlay entries would be lost whenever the last real
                    // entries are all hidden by --filter-inputs.
                    if (GetLastError() == ERROR_NO_MORE_FILES &&
                        TryAppendOverlayFindDataW(hFindFile, lpFindFileData))
                    {
                        return TRUE;
                    }
                    return FALSE; // ERROR_NO_MORE_FILES set by Real_FindNextFileW
                }
            }
            error = ERROR_SUCCESS;
        }

        FileOperationContext fileOperationContext = FileOperationContext::CreateForProbe(L"FindNextFile", overlay->Policy.GetCanonicalizedPath().GetPathString());

        wchar_t const* enumeratedComponent = &lpFindFileData->cFileName[0];
        PolicyResult filePolicyResult = overlay->Policy.GetPolicyForSubpath(enumeratedComponent);

        if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, overlay->Policy, true))
        {
            return FALSE;
        }

        FileReadContext readContext;
        readContext.Existence = FileExistence::Existent;
        readContext.OpenedDirectory = IsDirectoryFromAttributes(
            lpFindFileData->dwFileAttributes,
            ShouldTreatDirectoryReparsePointAsFile(fileOperationContext.DesiredAccess, fileOperationContext.FlagsAndAttributes, filePolicyResult));
        fileOperationContext.OpenedFileOrDirectoryAttributes = lpFindFileData->dwFileAttributes;

        AccessCheckResult accessCheck = filePolicyResult.CheckReadAccess(RequestedReadAccess::EnumerationProbe, readContext);
        ReportIfNeeded(accessCheck, fileOperationContext, filePolicyResult, GetReportedError(result, error), error);

        if (filePolicyResult.ShouldOverrideTimestamps(accessCheck))
        {
#if SUPER_VERBOSE
            Dbg(L"FindNextFile: Overriding timestamps for %s", filePolicyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
            OverrideTimestampsForInputFile(lpFindFileData);
        }

        // See usage in FindFirstFileExW
        ScrubShortFileName(lpFindFileData);

        // N.B. We do not check ShouldDenyAccess here. It is unusual for FindNextFile to fail. Would the caller clean up the find handle? Etc.
        //      Conveniently, for historical reasons, enumeration-based probes (RequestedReadAccess::EnumerationProbe) always have !ShouldDenyAccess() anyway - see CheckReadAccess.
    }
    else
    {
#if SUPER_VERBOSE
        Dbg(L"FindNextFile: Failed to find a handle overlay for policy information; conservatively not overriding timestamps");
#endif // SUPER_VERBOSE
    }

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_FindNextFileA)
BOOL WINAPI Detoured_FindNextFileA(
    _In_  HANDLE             hFindFile,
    _Out_ LPWIN32_FIND_DATAA lpFindFileData)
{
    // TODO:replace with the same logic as Detoured_FindNextFileW
    // Note that we can't simply forward to FindFirstFileW here after a unicode conversion.
    // The output value differs too - WIN32_FIND_DATA{A, W}
    return Real_FindNextFileA(
        hFindFile,
        lpFindFileData);
}

IMPLEMENTED(Detoured_GetFileInformationByHandleEx)
BOOL WINAPI Detoured_GetFileInformationByHandleEx(
    _In_  HANDLE                    hFile,
    _In_  FILE_INFO_BY_HANDLE_CLASS fileInformationClass,
    _Out_ LPVOID                    lpFileInformation,
    _In_  DWORD                     dwBufferSize)
{
    DetouredScope scope;

    DWORD error = ERROR_SUCCESS;
    BOOL result = Real_GetFileInformationByHandleEx(
        hFile,
        fileInformationClass,
        lpFileInformation,
        dwBufferSize);
    error = GetLastError();

    if (scope.Detoured_IsDisabled() || IsNullOrInvalidHandle(hFile) || lpFileInformation == nullptr)
    {
        return result;
    }

    // Bazel input filtering: hide undeclared entries from directory enumerations
    // performed via GetFileInformationByHandleEx (e.g. the .NET Directory APIs and
    // some CRTs). This wrapper establishes its own DetouredScope before calling the
    // real API, which shields the inner NtQueryDirectoryFile call from our Nt-level
    // enumeration filter AND overlay insertion (they observe a disabled/nested
    // scope). So we apply both directly here for the directory-enumeration info
    // classes, operating on the identical packed NT record buffer.
    {
        const bool doFilter = result && ShouldFilterDirectoryEnumeration();
        const bool doOverlay = ShouldWriteOverlay();
        ULONG ntInfoClass = 0;
        FILE_INFO_BY_HANDLE_CLASS continueClass = fileInformationClass;
        if ((doFilter || doOverlay) &&
            TryMapHandleDirInfoClass(fileInformationClass, ntInfoClass, continueClass))
        {
            HandleOverlayRef dirOverlay = TryLookupHandleOverlay(hFile);
            if (dirOverlay != nullptr && dirOverlay->Type == HandleType::Directory)
            {
                PolicyResult directoryPolicyResult = dirOverlay->Policy;

                // Bazel input filtering: drop undeclared entries, advancing across a
                // fully-hidden batch so the caller never sees success-with-zero-visible.
                if (doFilter)
                {
                    for (;;)
                    {
                        size_t kept = FilterDirectoryInformation(
                            lpFileInformation, ntInfoClass, dwBufferSize, directoryPolicyResult);
                        if (kept == SIZE_MAX || kept > 0)
                        {
                            break;
                        }
                        result = Real_GetFileInformationByHandleEx(
                            hFile, continueClass, lpFileInformation, dwBufferSize);
                        error = GetLastError();
                        if (!result)
                        {
                            break;
                        }
                    }
                }

                // Model W write-overlay: splice process-private overlay entries into
                // the packed buffer on exhaustion. The Win32 BOOL/last-error protocol
                // is translated to the NTSTATUS InsertOverlayEntries expects: a failed
                // call with ERROR_NO_MORE_FILES is the exhaustion signal, and a
                // fabricated success is translated back to TRUE. RestartScan is true
                // only for the *Restart* info classes (11/15).
                if (doOverlay)
                {
                    const NTSTATUS kSuccess     = (NTSTATUS)0x00000000;
                    const NTSTATUS kNoMoreFiles = (NTSTATUS)0x80000006;
                    NTSTATUS st = result
                        ? kSuccess
                        : (error == ERROR_NO_MORE_FILES ? kNoMoreFiles
                                                        : (NTSTATUS)0xC0000001 /* generic */);
                    const bool restart =
                        (int)fileInformationClass == 11 || (int)fileInformationClass == 15;
                    IO_STATUS_BLOCK iosb; iosb.Status = st; iosb.Information = 0;
                    InsertOverlayEntries(
                        lpFileInformation, dwBufferSize, &iosb, ntInfoClass,
                        /*ReturnSingleEntry*/ FALSE, (BOOLEAN)restart,
                        std::wstring(directoryPolicyResult.GetTranslatedPathWithoutTypePrefix()),
                        dirOverlay, st);
                    if (NT_SUCCESS(st) && !result)
                    {
                        result = TRUE;   // synthetic entries were emitted into the buffer
                        error = ERROR_SUCCESS;
                    }
                }

                SetLastError(error);
                return result;
            }
        }
    }

    if (fileInformationClass != FileBasicInfo || lpFileInformation == nullptr)
    {
        return result;
    }

    assert(fileInformationClass == FileBasicInfo);
    FILE_BASIC_INFO* fileBasicInfo = (FILE_BASIC_INFO*)lpFileInformation;

    HandleOverlayRef overlay = TryLookupHandleOverlay(hFile);
    if (overlay != nullptr)
    {
        if (overlay->Policy.ShouldOverrideTimestamps(overlay->AccessCheck))
        {
#if SUPER_VERBOSE
            Dbg(L"GetFileInformationByHandleEx: Overriding timestamps for %s", overlay->Policy.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
            OverrideTimestampsForInputFile(fileBasicInfo);
        }
    }
    else
    {
#if SUPER_VERBOSE
        Dbg(L"GetFileInformationByHandleEx: Failed to find a handle overlay for policy information; conservatively not overriding timestamps");
#endif // SUPER_VERBOSE
    }

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_FindClose)
BOOL WINAPI Detoured_FindClose(_In_ HANDLE handle)
{
    DetouredScope scope;

    DWORD error = ERROR_SUCCESS;

    // Make sure the handle is closed after the object is removed from the map.
    // This way the handle will never be assigned to a another object before removed from the table.
    CloseHandleOverlay(handle, true);

    BOOL result = Real_FindClose(handle);
    error = GetLastError();

    if (scope.Detoured_IsDisabled() || IsNullOrInvalidHandle(handle))
    {
        return result;
    }

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_GetFileInformationByHandle)
BOOL WINAPI Detoured_GetFileInformationByHandle(
    _In_  HANDLE                       hFile,
    _Out_ LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    DetouredScope scope;

    BOOL result = Real_GetFileInformationByHandle(hFile, lpFileInformation);
    DWORD error = GetLastError();

    if (scope.Detoured_IsDisabled() || IsNullOrInvalidHandle(hFile) || lpFileInformation == nullptr)
    {
        return result;
    }

    HandleOverlayRef overlay = TryLookupHandleOverlay(hFile);
    if (overlay != nullptr)
    {
        if (overlay->Policy.ShouldOverrideTimestamps(overlay->AccessCheck))
        {
#if SUPER_VERBOSE
            Dbg(L"GetFileInformationByHandle: Overriding timestamps for %s", overlay->Policy.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
            OverrideTimestampsForInputFile(lpFileInformation);
        }
    }
    else
    {
#if SUPER_VERBOSE
        Dbg(L"GetFileInformationByHandle: Failed to find a handle overlay for policy information; conservatively not overriding timestamps");
#endif // SUPER_VERBOSE
    }

    SetLastError(error);
    return result;
}

static BOOL DeleteUsingSetFileInformationByHandle(
    _In_ HANDLE                    hFile,
    _In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    _In_ LPVOID                    lpFileInformation,
    _In_ DWORD                     dwBufferSize,
    _In_ const wstring&            fullPath)
{
    FileOperationContext sourceOpContext = FileOperationContext(
        L"SetFileInformationByHandle_Source",
        DELETE,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        fullPath.c_str());

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(fullPath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return FALSE;
    }

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();
    IsHandleOrPathToDirectory(hFile, fullPath.c_str(), /*treatReparsePointAsFile*/ true, /*ref*/ sourceOpContext.OpenedFileOrDirectoryAttributes);

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        DWORD denyError = sourceAccessCheck.DenialError();
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, denyError);
        sourceAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    BOOL result = Real_SetFileInformationByHandle(
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize);
    DWORD error = GetLastError();

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, GetReportedError(result, error), error);

    SetLastError(error);

    return result;
}

static BOOL RenameUsingSetFileInformationByHandle(
    _In_ HANDLE                    hFile,
    _In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    _In_ LPVOID                    lpFileInformation,
    _In_ DWORD                     dwBufferSize,
    _In_ const wstring&            fullPath)
{
    DWORD openedFileOrDirectoryAttribute;
    bool renameDirectory = IsHandleOrPathToDirectory(hFile, fullPath.c_str(), /*treatReparsePointAsFile*/  true, /*ref*/ openedFileOrDirectoryAttribute);
    DWORD flagsAndAttributes = GetAttributesForFileOrDirectory(renameDirectory);

    FileOperationContext sourceOpContext = FileOperationContext(
        L"SetFileInformationByHandle_Source",
        DELETE,
        0,
        OPEN_EXISTING,
        flagsAndAttributes,
        fullPath.c_str());
    sourceOpContext.OpenedFileOrDirectoryAttributes = openedFileOrDirectoryAttribute;

    PolicyResult sourcePolicyResult;

    if (!sourcePolicyResult.Initialize(fullPath.c_str()))
    {
        sourcePolicyResult.ReportIndeterminatePolicyAndSetLastError(sourceOpContext);
        return FALSE;
    }

    AccessCheckResult sourceAccessCheck = sourcePolicyResult.CheckWriteAccess();

    if (sourceAccessCheck.ShouldDenyAccess())
    {
        DWORD denyError = sourceAccessCheck.DenialError();
        ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, denyError);
        sourceAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    wstring targetFileName;

    DWORD lastError = GetLastError();

    PFILE_RENAME_INFO pRenameInfo = (PFILE_RENAME_INFO)lpFileInformation;

    if (!TryGetFileNameFromFileInformation(
        pRenameInfo->FileName,
        pRenameInfo->FileNameLength,
        pRenameInfo->RootDirectory,
        false,
        targetFileName)
        || targetFileName.empty())
    {
        SetLastError(lastError);

        return Real_SetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize);
    }

    // Contrary to the documentation, pRenameInfo->RootDirectory for renaming using SetFileInformationByHandle
    // should always be NULL.

    FileOperationContext destinationOpContext = FileOperationContext(
        L"SetFileInformationByHandle_Dest",
        GENERIC_WRITE,
        0,
        CREATE_ALWAYS,
        flagsAndAttributes,
        targetFileName.c_str());
    destinationOpContext.Correlate(sourceOpContext);
    destinationOpContext.OpenedFileOrDirectoryAttributes = openedFileOrDirectoryAttribute;

    PolicyResult destPolicyResult;

    if (!destPolicyResult.Initialize(targetFileName.c_str()))
    {
        destPolicyResult.ReportIndeterminatePolicyAndSetLastError(destinationOpContext);
        return FALSE;
    }

    AccessCheckResult destAccessCheck = destPolicyResult.CheckWriteAccess();

    if (destAccessCheck.ShouldDenyAccess())
    {
        // We report the destination access here since we are returning early. Otherwise it is deferred until post-read.
        DWORD denyError = destAccessCheck.DenialError();
        ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, denyError);
        destAccessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    vector<ReportData> filesAndDirectoriesToReport;
    if (renameDirectory)
    {
        if (!ValidateMoveDirectory(
            L"SetFileInformationByHandle_Source",
            L"SetFileInformationByHandle_Dest",
            fullPath.c_str(),
            targetFileName.c_str(),
            filesAndDirectoriesToReport))
        {
            return FALSE;
        }
    }

    BOOL result = Real_SetFileInformationByHandle(
        hFile,
        FileInformationClass,
        lpFileInformation,
        dwBufferSize);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    ReportIfNeeded(sourceAccessCheck, sourceOpContext, sourcePolicyResult, reportedError, error);
    ReportIfNeeded(destAccessCheck, destinationOpContext, destPolicyResult, reportedError, error);

    if (renameDirectory)
    {
        for (auto& entry : filesAndDirectoriesToReport)
        {
            ReportIfNeeded(entry.GetAccessCheckResult(), entry.GetFileOperationContext(), entry.GetPolicyResult(), reportedError, error);
        }
    }

    SetLastError(error);

    return result;
}

IMPLEMENTED(Detoured_SetFileInformationByHandle)
BOOL WINAPI Detoured_SetFileInformationByHandle(
    _In_ HANDLE                    hFile,
    _In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
    _In_ LPVOID                    lpFileInformation,
    _In_ DWORD                     dwBufferSize)
{
    bool isDisposition =
        FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo
        || FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfoEx;

    bool isRename =
        FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileRenameInfo
        || FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileRenameInfoEx;

    if ((!isDisposition && !isRename) || IgnoreSetFileInformationByHandle())
    {

        // We ignore the use of SetFileInformationByHandle when it is not file renaming or file deletion.
        // However, since SetInformationByHandle may call other APIs, and those APIs may be detoured,
        // we don't check for DetouredScope yet.
        return Real_SetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize);
    }

    DetouredScope scope;
    if (scope.Detoured_IsDisabled())
    {
        return Real_SetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize);
    }

    if (isDisposition)
    {
        bool isDeletion = false;
        if (FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo)
        {
            PFILE_DISPOSITION_INFO pDispStruct = (PFILE_DISPOSITION_INFO)lpFileInformation;
            if (pDispStruct->DeleteFile)
            {
                isDeletion = true;
            }
        }
        else if (FileInformationClass == FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfoEx)
        {
            PFILE_DISPOSITION_INFO_EX pDispStructEx = (PFILE_DISPOSITION_INFO_EX)lpFileInformation;
            if ((pDispStructEx->Flags & FILE_DISPOSITION_FLAG_DELETE) != 0)
            {
                isDeletion = true;
            }
        }

        if (!isDeletion)
        {
            // Not a deletion, don't detour.
            return Real_SetFileInformationByHandle(
                hFile,
                FileInformationClass,
                lpFileInformation,
                dwBufferSize);
        }
    }

    DWORD lastError = GetLastError();

    wstring srcPath;

    DWORD getFinalPathByHandle = DetourGetFinalPathByHandle(hFile, srcPath);
    if ((getFinalPathByHandle != ERROR_SUCCESS) || IsSpecialDeviceName(srcPath.c_str()) || IsNullOrEmptyW(srcPath.c_str()))
    {
        if (getFinalPathByHandle != ERROR_SUCCESS)
        {
            Dbg(L"Detoured_SetFileInformationByHandle: DetourGetFinalPathByHandle: %d", getFinalPathByHandle);
        }

        SetLastError(lastError);

        return Real_SetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize);
    }

    return isDisposition
        ? DeleteUsingSetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize,
            srcPath)
        : RenameUsingSetFileInformationByHandle(
            hFile,
            FileInformationClass,
            lpFileInformation,
            dwBufferSize,
            srcPath);
}

HANDLE WINAPI Detoured_OpenFileMappingW(
    _In_ DWORD   dwDesiredAccess,
    _In_ BOOL    bInheritHandle,
    _In_ LPCWSTR lpName)
{
    // TODO:implement detours logic
    return Real_OpenFileMappingW(
        dwDesiredAccess,
        bInheritHandle,
        lpName);
}

HANDLE WINAPI Detoured_OpenFileMappingA(
    _In_  DWORD  dwDesiredAccess,
    _In_  BOOL   bInheritHandle,
    _In_  LPCSTR lpName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpName))
        {
            return Real_OpenFileMappingA(
                dwDesiredAccess,
                bInheritHandle,
                lpName);
        }
    }

    UnicodeConverter name(lpName);
    return Detoured_OpenFileMappingW(
        dwDesiredAccess,
        bInheritHandle,
        name);
}

// Detoured_GetTempFileNameW
//
// lpPathName is typically "." or result of GetTempPath (which doesn't need to be detoured, itself)
// lpPrefixString is allowed to be empty.
UINT WINAPI Detoured_GetTempFileNameW(
    _In_  LPCWSTR lpPathName,
    _In_  LPCWSTR lpPrefixString,
    _In_  UINT    uUnique,
    _Out_ LPTSTR  lpTempFileName)
{
    // TODO:implement detours logic
    return Real_GetTempFileNameW(
        lpPathName,
        lpPrefixString,
        uUnique,
        lpTempFileName);
}

UINT WINAPI Detoured_GetTempFileNameA(
    _In_  LPCSTR lpPathName,
    _In_  LPCSTR lpPrefixString,
    _In_  UINT   uUnique,
    _Out_ LPSTR  lpTempFileName)
{
    // TODO:implement detours logic
    return Real_GetTempFileNameA(
        lpPathName,
        lpPrefixString,
        uUnique,
        lpTempFileName);
}

/// <summary>
/// Treats CreateDirectory as a probe if the target name exists already.
/// </summary>
/// <remarks>
/// If the probe indicates that CreateDirectory would have attempted to write, then a write access is returned. Otherwise,
/// a probe access check is returned. This probe access may or may not be permitted based on the policy.
/// 
/// Note that this function is only called when CreateDirectory is not allowed by the policy.
///
/// In other words, the treatment of CreateDirectory can be written in the following pseudocode:
/// <code>
/// <code>
/// atomic
/// {
///   if (Probe(path) == FinalComponentDoesNotExist) { Write() } else { fail }
/// }
/// </code>
/// However, only one access is reported, i.e., the Write if it happens otherwise the probe.
/// </remarks>
static AccessCheckResult CreateDirectoryAsSafeProbe(FileOperationContext& opContext, const PolicyResult& policyResult, const AccessCheckResult& writeAccessCheck)
{
    DWORD attributes = GetFileAttributesW(opContext.NoncanonicalPath);
    DWORD probeError = attributes == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;

    opContext.OpenedFileOrDirectoryAttributes = attributes;

    FileReadContext probeContext;
    probeContext.InferExistenceFromError(probeError);
    probeContext.OpenedDirectory = IsDirectoryFromAttributes(
        attributes,
        ShouldTreatDirectoryReparsePointAsFile(opContext.DesiredAccess, opContext.FlagsAndAttributes, policyResult));

    // If we are checking all CreateDirectory calls, just reuse the writeAccessCheck we already have.
    // This will result in blocking CreateDirectory (i.e., returning ERROR_ACCESS_DENIED) if a directory already exists
    // and writeAccessCheck.ResultAction == ResultAction::Deny.
    AccessCheckResult probeAccessCheck = DirectoryCreationAccessEnforcement()
        ? writeAccessCheck
        // otherwise, create a read-only probe
        : policyResult.CheckReadAccess(RequestedReadAccess::Probe, probeContext);

    if (probeContext.Existence != FileExistence::Existent && probeError == ERROR_FILE_NOT_FOUND)
    {
        probeAccessCheck = AccessCheckResult::Combine(writeAccessCheck, AccessCheckResult::DenyOrWarn(RequestedAccess::Write));
    }

    return probeAccessCheck;
}

/// <summary>
/// CreateDirectoryW detour.
/// </summary>
/// <remarks>
/// CODESYNC: keep this weird logic in sync with
//   - IOHandler::HandleCreate in IOHandler.cpp, and
//   - TrustedBsdHandler::HandleVNodeCreateEvent in TrustedBsdHandler.cpp
/// </remarks>
IMPLEMENTED(Detoured_CreateDirectoryW)
BOOL WINAPI Detoured_CreateDirectoryW(
    _In_     LPCWSTR               lpPathName,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled()
        || IsNullOrEmptyW(lpPathName)
        || IsSpecialDeviceName(lpPathName))
    {
        return Real_CreateDirectoryW(lpPathName, lpSecurityAttributes);
    }

    FileOperationContext opContext(
        L"CreateDirectory",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        CREATE_NEW,
        FILE_ATTRIBUTE_DIRECTORY,
        lpPathName);

    // On failure, opContext can be modified by CreateDirectoryAsSafeProbe.
    opContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_DIRECTORY;

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpPathName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return FALSE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(opContext, policyResult, true, true))
    {
        return FALSE;
    }

    DWORD error = ERROR_SUCCESS;
    AccessCheckResult accessCheck = policyResult.CheckCreateDirectoryAccess();

    if (accessCheck.ShouldDenyAccess())
    {
        // We can't create the directory. It turns out that there are tons of calls to CreateDirectory just to 'ensure' all path components exist,
        // and many times those directories already do exist (C:\users for example, or even an output directory for a tool). So, one last chance, perhaps we
        // can rephrase this as a probe.
        error = accessCheck.DenialError();
        AccessCheckResult asProbeAccessCheck = CreateDirectoryAsSafeProbe(
            opContext,
            policyResult,
            accessCheck);
        ReportIfNeeded(asProbeAccessCheck, opContext, policyResult, error);
        accessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    // Model W write-overlay: redirect the creation into the backing store (see the
    // note below). Falls back to the real path when the overlay is inactive/out-of-cone.
    std::wstring overlayDirBacking;
    if (ShouldRedirectToOverlay(policyResult))
    {
        overlayDirBacking = OverlayBackingPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    }
    BOOL result;
    if (!overlayDirBacking.empty())
    {
        EnsureBackingParentDirs(overlayDirBacking);  // create backing ancestors first
        result = Real_CreateDirectoryW(overlayDirBacking.c_str(), lpSecurityAttributes);
    }
    else
    {
        result = Real_CreateDirectoryW(lpPathName, lpSecurityAttributes);
    }
    error = GetLastError();
    // Track directories this process freshly creates in an execroot-writable scratch
    // scope so the process's own later enumerations (IsEnumChildVisible) can see them.
    // AllowWrite only tracks file writes; without this, the intermediate scratch
    // directories (e.g. JavaBuilder's _javac/<lib>_classes/<pkg> tree) stay hidden and
    // the tool cannot walk into them to jar or clean up its outputs. Only mark on a
    // real creation (result == TRUE); a pre-existing undeclared directory returns
    // ERROR_ALREADY_EXISTS and must stay hidden to preserve hermeticity.
    //
    // Model W: when the overlay is active, an explicitly-created directory in the
    // redirect cone is created in the BACKING STORE (not the real execroot), mirroring
    // how redirected file writes work. The backing-only directory then splices into a
    // parent enumeration through every enum layer (Nt/Zw/Ex, GetFileInformationByHandleEx,
    // and the Win32 FindFirstFile family - all now insertion-capable, see
    // InsertOverlayEntries / NextOverlayFindDataW), and is itself openable/enumerable
    // via the overlay-only-directory branch of ResolveOverlayOpenPath. This keeps the
    // real execroot untouched for scratch directory trees, matching the file path.
    if (result && policyResult.OverrideAllowWriteForExistingFiles())
    {
        policyResult.MarkCreatedInThisProcess();
    }

    if (!result && accessCheck.Result != ResultAction::Allow)
    {
        // On error, no directory creation happened, but we need to ensure that ResultAction::Warn acts like ResultAction::Deny.
        accessCheck = CreateDirectoryAsSafeProbe(
            opContext,
            policyResult,
            accessCheck);
    }

    ReportIfNeeded(accessCheck, opContext, policyResult, GetReportedError(result, error), error);
    SetLastError(error);

    return result;
}

BOOL WINAPI Detoured_CreateDirectoryA(
    _In_     LPCSTR                lpPathName,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpPathName))
        {
            return Real_CreateDirectoryA(
                lpPathName,
                lpSecurityAttributes);
        }
    }

    UnicodeConverter pathName(lpPathName);
    return Detoured_CreateDirectoryW(
        pathName,
        lpSecurityAttributes);
}

BOOL WINAPI Detoured_CreateDirectoryExW(
    _In_     LPCWSTR               lpTemplateDirectory,
    _In_     LPCWSTR               lpNewDirectory,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    // TODO:implement detours logic
    return Real_CreateDirectoryExW(
        lpTemplateDirectory,
        lpNewDirectory,
        lpSecurityAttributes);
}

BOOL WINAPI Detoured_CreateDirectoryExA(
    _In_     LPCSTR                lpTemplateDirectory,
    _In_     LPCSTR                lpNewDirectory,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() ||
            IsNullOrEmptyA(lpTemplateDirectory))
        {
            return Real_CreateDirectoryExA(
                lpTemplateDirectory,
                lpNewDirectory,
                lpSecurityAttributes);
        }
    }

    UnicodeConverter templateDir(lpTemplateDirectory);
    UnicodeConverter newDir(lpNewDirectory);
    return Detoured_CreateDirectoryExW(
        templateDir,
        newDir,
        lpSecurityAttributes);
}

IMPLEMENTED(Detoured_RemoveDirectoryW)
BOOL WINAPI Detoured_RemoveDirectoryW(_In_ LPCWSTR lpPathName)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() ||
        IsNullOrEmptyW(lpPathName) ||
        IsSpecialDeviceName(lpPathName))
    {
        return Real_RemoveDirectoryW(lpPathName);
    }

    FileOperationContext opContext(
        L"RemoveDirectory",
        DELETE,
        0,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_DIRECTORY,
        lpPathName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(lpPathName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return FALSE;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(opContext, policyResult, true))
    {
        return FALSE;
    }

    AccessCheckResult accessCheck = policyResult.CheckWriteAccess();
    opContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_DIRECTORY;

    if (accessCheck.ShouldDenyAccess())
    {
        DWORD denyError = accessCheck.DenialError();
        ReportIfNeeded(accessCheck, opContext, policyResult, denyError);
        accessCheck.SetLastErrorToDenialError();
        return FALSE;
    }

    vector<ReportData> filesAndDirectoriesToReport;

    if (!ValidateMoveDirectory(
        L"RemoveDirectory_Source",
        nullptr,
        policyResult.GetCanonicalizedPath().GetPathString(),
        nullptr,
        filesAndDirectoriesToReport))
    {
        return FALSE;
    }

    PathCache_Invalidate(policyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(), true, policyResult);

    // Model W (write-overlay): mirror DeleteFileW. Without this the real execroot
    // would be mutated - an overlay-only scratch dir (created via CreateDirectoryW,
    // which Model W redirects into the backing store) has no real directory, so
    // Real_RemoveDirectoryW on the virtual path would fail NOT_FOUND; and a real
    // in-cone directory would be deleted from disk. Redirect the removal to the
    // backing store (overlay-only dir) or deny/no-op it (real in-cone dir) so the
    // real tree is never touched. See §6.3.1 (symmetric with CreateDirectoryW).
    LPCWSTR removeTarget = lpPathName;
    std::wstring overlayBacking;
    if (ShouldRedirectToOverlay(policyResult))
    {
        switch (ResolveOverlayDelete(policyResult, overlayBacking))
        {
        case OverlayDeleteAction::DenyAccess:
            ReportIfNeeded(accessCheck, opContext, policyResult, ERROR_ACCESS_DENIED);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        case OverlayDeleteAction::NotFound:
            SetLastError(ERROR_FILE_NOT_FOUND);
            return FALSE;
        case OverlayDeleteAction::RedirectToBacking:
            removeTarget = overlayBacking.c_str();
            break;
        case OverlayDeleteAction::PassThrough:
            break;
        }
    }

    BOOL result = Real_RemoveDirectoryW(removeTarget);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(result, error);

    ReportIfNeeded(accessCheck, opContext, policyResult, reportedError, error);

    for (auto& entry : filesAndDirectoriesToReport)
    {
        ReportIfNeeded(entry.GetAccessCheckResult(), entry.GetFileOperationContext(), entry.GetPolicyResult(), reportedError, error);
    }

    return result;
}

IMPLEMENTED(Detoured_RemoveDirectoryA)
BOOL WINAPI Detoured_RemoveDirectoryA(_In_ LPCSTR lpPathName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpPathName))
        {
            return Real_RemoveDirectoryA(lpPathName);
        }
    }

    UnicodeConverter pathName(lpPathName);
    return Detoured_RemoveDirectoryW(pathName);
}

BOOL WINAPI Detoured_DecryptFileW(
    _In_       LPCWSTR lpFileName,
    __reserved DWORD dwReserved)
{
    // TODO:implement detours logic
    return Real_DecryptFileW(
        lpFileName,
        dwReserved);
}

BOOL WINAPI Detoured_DecryptFileA(
    _In_       LPCSTR lpFileName,
    __reserved DWORD dwReserved)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_DecryptFileA(
                lpFileName,
                dwReserved);
        }
    }

    UnicodeConverter fileName(lpFileName);
    return Detoured_DecryptFileW(
        fileName,
        dwReserved);
}

BOOL WINAPI Detoured_EncryptFileW(_In_ LPCWSTR lpFileName)
{
    // TODO:implement detours logic
    return Real_EncryptFileW(lpFileName);
}

BOOL WINAPI Detoured_EncryptFileA(_In_ LPCSTR lpFileName)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_EncryptFileA(lpFileName);
        }
    }

    UnicodeConverter fileName(lpFileName);
    return Detoured_EncryptFileW(fileName);
}

DWORD WINAPI Detoured_OpenEncryptedFileRawW(
    _In_  LPCWSTR lpFileName,
    _In_  ULONG   ulFlags,
    _Out_ PVOID*  pvContext)
{
    // TODO:implement detours logic
    return Real_OpenEncryptedFileRawW(
        lpFileName,
        ulFlags,
        pvContext);
}

DWORD WINAPI Detoured_OpenEncryptedFileRawA(
    _In_  LPCSTR lpFileName,
    _In_  ULONG  ulFlags,
    _Out_ PVOID* pvContext)
{
    {
        DetouredScope scope;
        if (scope.Detoured_IsDisabled() || IsNullOrEmptyA(lpFileName))
        {
            return Real_OpenEncryptedFileRawA(
                lpFileName,
                ulFlags,
                pvContext);
        }
    }

    UnicodeConverter fileName(lpFileName);
    return Detoured_OpenEncryptedFileRawW(
        fileName,
        ulFlags,
        pvContext);
}

// Detoured_OpenFileById
//
// hFile is needed to get access to the drive or volume. It doesn't matter what
//      file is requested, but it cannot be NULL or INVALID.
// lpFileID must not be null because it contains the ID of the file to open.
HANDLE WINAPI Detoured_OpenFileById(
    _In_     HANDLE                hFile,
    _In_     LPFILE_ID_DESCRIPTOR  lpFileID,
    _In_     DWORD                 dwDesiredAccess,
    _In_     DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_     DWORD                 dwFlags)
{
    // TODO:implement detours logic
    return Real_OpenFileById(
        hFile,
        lpFileID,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwFlags);
}

IMPLEMENTED(Detoured_GetFinalPathNameByHandleA)
DWORD WINAPI Detoured_GetFinalPathNameByHandleA(
    _In_  HANDLE hFile,
    _Out_ LPSTR lpszFilePath,
    _In_  DWORD cchFilePath,
    _In_  DWORD dwFlags)
{
    {
        DetouredScope scope;

        if (scope.Detoured_IsDisabled() || IgnoreGetFinalPathNameByHandle())
        {
            return Real_GetFinalPathNameByHandleA(hFile, lpszFilePath, cchFilePath, dwFlags);
        }
    }

    if (g_pManifestTranslatePathTuples->empty())
    {
        // No translation tuples, no need to do anything.
        return Real_GetFinalPathNameByHandleA(hFile, lpszFilePath, cchFilePath, dwFlags);
    }

    unique_ptr<wchar_t[]> wideFilePathBuffer(new wchar_t[cchFilePath]);
    DWORD length = Detoured_GetFinalPathNameByHandleW(hFile, wideFilePathBuffer.get(), cchFilePath, dwFlags);

    if (length == 0 || length > cchFilePath)
    {
        return length;
    }

    int numCharsRequiredIncTerminatingNull = WideCharToMultiByte(
        CP_ACP,
        0,
        wideFilePathBuffer.get(),
        // Processes the entire input string, including the terminating null character.
        // The resulting character string has a terminating null character, and the length returned by the function includes this character.
        -1,
        // Only check for required buffer size.
        NULL,
        0,
        NULL,
        NULL);

    if ((unsigned)numCharsRequiredIncTerminatingNull <= cchFilePath)
    {
        int numCharsWritten = WideCharToMultiByte(
            CP_ACP,
            0,
            wideFilePathBuffer.get(),
            -1,
            lpszFilePath,
            (int)cchFilePath,
            NULL,
            NULL);

        if (numCharsWritten == 0)
        {
            return (DWORD)numCharsWritten;
        }
    }

    // Substract -1 since the \0 char is included.
    return (DWORD)(numCharsRequiredIncTerminatingNull - 1);
}

IMPLEMENTED(Detoured_GetFinalPathNameByHandleW)
DWORD WINAPI Detoured_GetFinalPathNameByHandleW(
    _In_  HANDLE hFile,
    _Out_ LPTSTR lpszFilePath,
    _In_  DWORD  cchFilePath,
    _In_  DWORD  dwFlags)
{
    DetouredScope scope;

    if (scope.Detoured_IsDisabled() || IgnoreGetFinalPathNameByHandle())
    {
        return Real_GetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);
    }

    DWORD length = Real_GetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags);

    if (length == 0)
    {
        // If the function fails for reason other than buffer size, the return value is zero. To get extended error information, call GetLastError.
        return length;
    }

    // Materialize the full final path (handling the buffer-too-small case where
    // lpszFilePath was not filled and `length` is the required size).
    wstring nonNormalizedPath;
    if (length < cchFilePath)
    {
        // Buffer is large enough to hold the final path
        nonNormalizedPath.assign(lpszFilePath);
    }
    else
    {
        // Buffer is too small to hold the final path, but length contains the required buffer size including the terminating null character.
        unique_ptr<wchar_t[]> buffer(new wchar_t[length]);
        DWORD newLength = Real_GetFinalPathNameByHandleW(hFile, buffer.get(), length, dwFlags);

        if (newLength == 0)
        {
            // If the function fails for reason other than buffer size, the return value is zero. To get extended error information, call GetLastError.
            return newLength;
        }

        nonNormalizedPath.assign(buffer.get());
    }

    // Model W (write-overlay): if this handle was redirected into the backing store,
    // GetFinalPathNameByHandle honestly reports the physical backing path. Map it back
    // to the virtual (real cone) path so canonicalization-based tools (e.g. the JVM's
    // class loader) see the logical execroot location. Done before path-translation
    // tuples and independent of them.
    wstring overlayVirtual;
    if (ReverseOverlayFinalPath(nonNormalizedPath, overlayVirtual))
    {
        nonNormalizedPath.swap(overlayVirtual);
    }
    else if (g_pManifestTranslatePathTuples->empty() && length < cchFilePath)
    {
        // No overlay rewrite and no translation tuples: the caller's buffer already
        // holds the correct result, so return it unchanged (shipped fast path).
        return length;
    }

    wstring normalizedPath;
    TranslateFilePath(nonNormalizedPath, normalizedPath);

    DWORD copyPathLength = (DWORD)normalizedPath.length() + 1; // wcscpy_s expects the destination buffer to account for the null terminator
    if (copyPathLength <= cchFilePath)
    {
        wcscpy_s(lpszFilePath, cchFilePath, normalizedPath.c_str());
        // When GetFinalPathNameByHandleW succeeds the return value does not include the terminating null character
        return (DWORD)normalizedPath.length();
    }

    SetLastError(ERROR_INSUFFICIENT_BUFFER);

    // This value includes the size of the terminating null character.
    return copyPathLength;
}

// Detoured_NtQueryDirectoryFile
//
// FileHandle            - a handle for the file object that represents the directory for which information is being requested.
// Event                 - an optional handle for a caller-created event.
// ApcRoutine            - an address of an optional, caller-supplied APC routine to be called when the requested operation completes.
// ApcContext            - an optional pointer to a caller-determined context area to be passed to APC routine, if one was specified,
//                         or to be posted to the associated I / O completion object.
// IoStatusBlock         - A pointer to an IO_STATUS_BLOCK structure that receives the final completion status and information about the operation.
// FileInformation       - A pointer to a buffer that receives the desired information about the file
//                         The structure of the information returned in the buffer is defined by the FileInformationClass parameter.
// Length                - The size, in bytes, of the buffer pointed to by FileInformation.
// FileInformationClass  - The type of information to be returned about files in the directory.One of the following.
//                             FileBothDirectoryInformation     - FILE_BOTH_DIR_INFORMATION is returned
//                             FileDirectoryInformation         - FILE_DIRECTORY_INFORMATION is returned
//                             FileFullDirectoryInformation     - FILE_FULL_DIR_INFORMATION is returned
//                             FileIdBothDirectoryInformation   - FILE_ID_BOTH_DIR_INFORMATION is returned
//                             FileIdFullDirectoryInformation   - FILE_ID_FULL_DIR_INFORMATION is returned
//                             FileNamesInformation             - FILE_NAMES_INFORMATION is returned
//                             FileObjectIdInformation          - FILE_OBJECTID_INFORMATION is returned
//                             FileReparsePointInformation      - FILE_REPARSE_POINT_INFORMATION is returned
// ReturnSingleEntry     - Set to TRUE if only a single entry should be returned, FALSE otherwise.
// FileName              - An optional pointer to a caller-allocated Unicode string containing the name of a file (or multiple files, if wildcards are used)
//                         within the directory specified by FileHandle.This parameter is optional and can be NULL, in which case all files in the directory
//                         are returned.
// RestartScan           - Set to TRUE if the scan is to start at the first entry in the directory.Set to FALSE if resuming the scan from a previous call.
IMPLEMENTED(Detoured_NtQueryDirectoryFile)
NTSTATUS NTAPI Detoured_NtQueryDirectoryFile(
    _In_     HANDLE                 FileHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _Out_    PIO_STATUS_BLOCK       IoStatusBlock,
    _Out_    PVOID                  FileInformation,
    _In_     ULONG                  Length,
    _In_     FILE_INFORMATION_CLASS FileInformationClass,
    _In_     BOOLEAN                ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING        FileName,
    _In_     BOOLEAN                RestartScan)
{
    DetouredScope scope;
    LPCWSTR directoryName = nullptr;
    wstring filter;
    bool isEnumeration = true;
    CanonicalizedPath canonicalizedDirectoryPath;
    HandleOverlayRef overlay = nullptr;

    bool noDetour = scope.Detoured_IsDisabled();

    if (!noDetour)
    {
        // Check for enumeration. The default for us is true,
        // but if the FileName parameter is present and is not
        // a wild card, we'll set it to false.
        if (FileName != nullptr)
        {
            filter.assign(FileName->Buffer, (size_t)(FileName->Length / sizeof(wchar_t)));
            isEnumeration = PathContainsWildcard(filter.c_str());
        }

        // See if the handle is known
        overlay = TryLookupHandleOverlay(FileHandle);

        if (overlay == nullptr || overlay->EnumerationHasBeenReported)
        {
            noDetour = true;
        }
        else
        {
            canonicalizedDirectoryPath = overlay->Policy.GetCanonicalizedPath();
            directoryName = canonicalizedDirectoryPath.GetPathString();

            if (_wcsicmp(directoryName, L"\\\\.\\MountPointManager") == 0 ||
                IsSpecialDeviceName(directoryName))
            {
                noDetour = true;
            }
        }
    }

    PVOID buffer = FileInformation;
    ULONG bufferSize = Length;
    std::unique_ptr<char[]> largerBuffer;

    if (ShouldUseLargeEnumerationBuffer() && Length < NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE)
    {
        largerBuffer = std::make_unique<char[]>(NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE);
        buffer = largerBuffer.get();
        bufferSize = NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE;
    }

    NTSTATUS result = Real_NtQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        buffer,
        bufferSize,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan);
    DWORD reportedError = RtlNtStatusToDosError(result);
    DWORD lastError = GetLastError();

    if (buffer != FileInformation)
    {
        memcpy_s(FileInformation, Length, buffer, Length);
    }

    if (noDetour)
    {
        return result;
    }

    // We should avoid doing anything interesting for non-directory handles.
    // What happens in practice is this:
    //   HANDLE h = NtCreateFile("\\?\C:\someDir\file")
    //   <access checked in NtCreateFile; maybe reported>
    //   NtQueryDirectoryFile(h)
    //   <fails somehow; h is not a directory handle>
    // If we instead went ahead and tried to report an enumeration in that case, we run into problems in report processing;
    // statically declared file dependencies have {Read} policy with {Report} actually masked out, and report
    // processing in fact assumes that the set of explicit reports do *not* contain such dependencies (i.e.
    // an access check is not repeated, so it is not discovered that read/probe is actually allowed).
    //
    // FindFirstFileEx handles this too, and performs a read-level access check if one tries to enumerate a file.
    // We don't have to worry about that at all here, since any necessary access check / report already happened
    // in CreateFile or NtCreateFile in order to get the (non)directory handle.
    if (overlay->Type == HandleType::Directory)
    {
        // TODO: Perhaps should have a specific access check for enumeration.
        //       For now, we always allow enumeration and report it.
        //       Since enumeration has historically not been understood or reported at all, this is a fine incremental move -
        //       given a policy flag for allowing enumeration, we'd apply it globally anyway.
        // TODO: Should include the wildcard in enumeration reports, so that directory enumeration assertions can be more precise.

        PolicyResult directoryPolicyResult = overlay->Policy;
        FileOperationContext fileOperationContext = isEnumeration
            ? FileOperationContext::CreateForRead(L"NtQueryDirectoryFile", directoryName)
            : FileOperationContext::CreateForProbe(L"NtQueryDirectoryFile", directoryName);
        fileOperationContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_DIRECTORY;

        if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, directoryPolicyResult, false))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return DETOURS_STATUS_ACCESS_DENIED;
        }

        // Bazel input filtering: hide undeclared entries from the returned buffer.
        if (ShouldFilterDirectoryEnumeration())
        {
            ApplyEnumerationFilterNt(
                Real_NtQueryDirectoryFile,
                FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName,
                buffer, bufferSize, directoryPolicyResult,
                result, reportedError, lastError);
        }

        // Model W write-overlay (experimental): splice in process-private overlay
        // entries after the subtractive filter. Kill-switched by ShouldWriteOverlay().
        if (ShouldWriteOverlay())
        {
            CaptureOverlayEnumFilter(overlay, FileName, RestartScan != FALSE);
            InsertOverlayEntries(
                FileInformation, Length, IoStatusBlock,
                (ULONG)FileInformationClass, ReturnSingleEntry, RestartScan,
                std::wstring(directoryPolicyResult.GetTranslatedPathWithoutTypePrefix()),
                overlay, result);
            reportedError = RtlNtStatusToDosError(result);
            lastError = GetLastError();
        }

        // Only report the enumeration if specified by the policy
        bool reportDirectoryEnumeration = directoryPolicyResult.ReportDirectoryEnumeration();
        bool explicitlyReportDirectoryEnumeration = isEnumeration && reportDirectoryEnumeration;

        AccessCheckResult directoryAccessCheck(
            isEnumeration ? RequestedAccess::Enumerate : RequestedAccess::Probe,
            ResultAction::Allow,
            explicitlyReportDirectoryEnumeration ? ReportLevel::ReportExplicit : ReportLevel::Ignore);

        if (!explicitlyReportDirectoryEnumeration && ReportAnyAccess(false))
        {
            // Ensure access is reported (not explicit) when report all accesses is specified
            directoryAccessCheck.Level = ReportLevel::Report;
        }

        // Remember that we already enumerated this directory if successful
        overlay->EnumerationHasBeenReported = NT_SUCCESS(result) && directoryAccessCheck.ShouldReport();

        // We can report the status for directory now.
        ReportIfNeeded(directoryAccessCheck, fileOperationContext, directoryPolicyResult, reportedError, lastError, -1, filter.c_str());
    }

    return result;
}

// Detoured_ZwQueryDirectoryFile
// See comments for Detoured_NtQueryDirectoryFile
IMPLEMENTED(Detoured_ZwQueryDirectoryFile)
NTSTATUS NTAPI Detoured_ZwQueryDirectoryFile(
    _In_     HANDLE                 FileHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _Out_    PIO_STATUS_BLOCK       IoStatusBlock,
    _Out_    PVOID                  FileInformation,
    _In_     ULONG                  Length,
    _In_     FILE_INFORMATION_CLASS FileInformationClass,
    _In_     BOOLEAN                ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING        FileName,
    _In_     BOOLEAN                RestartScan)
{
    DetouredScope scope;
    LPCWSTR directoryName = nullptr;
    wstring filter;
    bool isEnumeration = true;
    CanonicalizedPath canonicalizedDirectoryPath;
    HandleOverlayRef overlay = nullptr;

    // MonitorZwCreateOpenQueryFile allows disabling of ZwCreateFile, ZwOpenFile and ZwQueryDirectoryFile functions.
    bool noDetour = scope.Detoured_IsDisabled() || MonitorZwCreateOpenQueryFile();

    if (!noDetour)
    {
        // Check for enumeration. The default for us is true,
        // but if the FileName parameter is present and is not
        // a wild card, we'll set it to false.
        if (FileName != nullptr)
        {
            filter.assign(FileName->Buffer, (size_t)(FileName->Length / sizeof(wchar_t)));
            isEnumeration = PathContainsWildcard(filter.c_str());
        }

        // See if the handle is known
        overlay = TryLookupHandleOverlay(FileHandle);
        if (overlay == nullptr || overlay->EnumerationHasBeenReported)
        {
            noDetour = true;
        }
        else
        {
            canonicalizedDirectoryPath = overlay->Policy.GetCanonicalizedPath();
            directoryName = canonicalizedDirectoryPath.GetPathString();

            if (_wcsicmp(directoryName, L"\\\\.\\MountPointManager") == 0 ||
                IsSpecialDeviceName(directoryName))
            {
                noDetour = true;
            }
        }
    }

    PVOID buffer = FileInformation;
    ULONG bufferSize = Length;
    std::unique_ptr<char[]> largerBuffer;

    if (ShouldUseLargeEnumerationBuffer() && Length < NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE)
    {
        largerBuffer = std::make_unique<char[]>(NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE);
        buffer = largerBuffer.get();
        bufferSize = NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE;
    }

    NTSTATUS result = Real_ZwQueryDirectoryFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        buffer,
        bufferSize,
        FileInformationClass,
        ReturnSingleEntry,
        FileName,
        RestartScan
    );
    DWORD reportedError = RtlNtStatusToDosError(result);
    DWORD lastError = GetLastError();

    if (buffer != FileInformation)
    {
        memcpy_s(FileInformation, Length, buffer, Length);
    }

    // If we should not or cannot get info on the directory, we are done
    if (!noDetour)
    {
        // We should avoid doing anything interesting for non-directory handles.
        // What happens in practice is this:
        //   HANDLE h = ZwCreateFile("\\?\C:\someDir\file")
        //   <access checked in NtCreateFile; maybe reported>
        //   ZwQueryDirectoryFile(h)
        //   <fails somehow; h is not a directory handle>
        // If we instead went ahead and tried to report an enumeration in that case, we run into problems in report processing;
        // statically declared file dependencies have {Read} policy with {Report} actually masked out, and report
        // processing in fact assumes that the set of explicit reports do *not* contain such dependencies (i.e.
        // an access check is not repeated, so it is not discovered that read/probe is actually allowed).
        //
        // FindFirstFileEx handles this too, and performs a read-level access check if one tries to enumerate a file.
        // We don't have to worry about that at all here, since any necessary access check / report already happened
        // in CreateFile or ZtCreateFile in order to get the (non)directory handle.
        if (overlay->Type == HandleType::Directory)
        {
            // TODO: Perhaps should have a specific access check for enumeration.
            //       For now, we always allow enumeration and report it.
            //       Since enumeration has historically not been understood or reported at all, this is a fine incremental move -
            //       given a policy flag for allowing enumeration, we'd apply it globally anyway.
            // TODO: Should include the wildcard in enumeration reports, so that directory enumeration assertions can be more precise.
            PolicyResult directoryPolicyResult = overlay->Policy;
            FileOperationContext fileOperationContext = isEnumeration
                ? FileOperationContext::CreateForRead(L"ZwQueryDirectoryFile", directoryName)
                : FileOperationContext::CreateForProbe(L"ZwQueryDirectoryFile", directoryName);
            fileOperationContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_DIRECTORY;

            if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, directoryPolicyResult, false))
            {
                SetLastError(ERROR_ACCESS_DENIED);
                return DETOURS_STATUS_ACCESS_DENIED;
            }

            // Bazel input filtering: hide undeclared entries from the returned buffer.
            if (ShouldFilterDirectoryEnumeration())
            {
                ApplyEnumerationFilterNt(
                    Real_ZwQueryDirectoryFile,
                    FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                    FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName,
                    buffer, bufferSize, directoryPolicyResult,
                    result, reportedError, lastError);
            }

            // Model W write-overlay (experimental): splice in process-private overlay
            // entries after the subtractive filter. Kill-switched by ShouldWriteOverlay().
            if (ShouldWriteOverlay())
            {
                CaptureOverlayEnumFilter(overlay, FileName, RestartScan != FALSE);
                InsertOverlayEntries(
                    FileInformation, Length, IoStatusBlock,
                    (ULONG)FileInformationClass, ReturnSingleEntry, RestartScan,
                    std::wstring(directoryPolicyResult.GetTranslatedPathWithoutTypePrefix()),
                    overlay, result);
                reportedError = RtlNtStatusToDosError(result);
                lastError = GetLastError();
            }

            // Only report the enumeration if specified by the policy
            bool reportDirectoryEnumeration = directoryPolicyResult.ReportDirectoryEnumeration();
            bool explicitlyReportDirectoryEnumeration = isEnumeration && reportDirectoryEnumeration;

            AccessCheckResult directoryAccessCheck(
                isEnumeration ? RequestedAccess::Enumerate : RequestedAccess::Probe,
                ResultAction::Allow,
                explicitlyReportDirectoryEnumeration ? ReportLevel::ReportExplicit : ReportLevel::Ignore);

            if (!explicitlyReportDirectoryEnumeration && ReportAnyAccess(false))
            {
                // Ensure access is reported (not explicit) when report all accesses is specified
                directoryAccessCheck.Level = ReportLevel::Report;
            }

            // Remember that we already enumerated this directory if successful
            overlay->EnumerationHasBeenReported = NT_SUCCESS(result) && directoryAccessCheck.ShouldReport();

            // We can report the status for directory now.
            ReportIfNeeded(directoryAccessCheck, fileOperationContext, overlay->Policy, reportedError, lastError);
        }
    }

    return result;
}

// Detoured_NtQueryDirectoryFileEx
//
// The modern successor to NtQueryDirectoryFile: FindFirstFileEx and
// GetFileInformationByHandleEx are serviced by this on Windows 8+. It differs from
// NtQueryDirectoryFile only in that the ReturnSingleEntry and RestartScan booleans
// are folded into a single QueryFlags mask (SL_RETURN_SINGLE_ENTRY / SL_RESTART_SCAN).
// We hook it so the Bazel enumeration filter applies to tools that call it directly,
// bypassing both the Win32 FindFirstFileEx hook and the legacy NtQueryDirectoryFile.
IMPLEMENTED(Detoured_NtQueryDirectoryFileEx)
NTSTATUS NTAPI Detoured_NtQueryDirectoryFileEx(
    _In_     HANDLE                 FileHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _Out_    PIO_STATUS_BLOCK       IoStatusBlock,
    _Out_    PVOID                  FileInformation,
    _In_     ULONG                  Length,
    _In_     FILE_INFORMATION_CLASS FileInformationClass,
    _In_     ULONG                  QueryFlags,
    _In_opt_ PUNICODE_STRING        FileName)
{
    DetouredScope scope;
    LPCWSTR directoryName = nullptr;
    wstring filter;
    bool isEnumeration = true;
    CanonicalizedPath canonicalizedDirectoryPath;
    HandleOverlayRef overlay = nullptr;

    bool noDetour = scope.Detoured_IsDisabled();

    if (!noDetour)
    {
        // Check for enumeration. The default for us is true, but if the FileName
        // parameter is present and is not a wild card, we'll set it to false.
        if (FileName != nullptr)
        {
            filter.assign(FileName->Buffer, (size_t)(FileName->Length / sizeof(wchar_t)));
            isEnumeration = PathContainsWildcard(filter.c_str());
        }

        overlay = TryLookupHandleOverlay(FileHandle);

        if (overlay == nullptr || overlay->EnumerationHasBeenReported)
        {
            noDetour = true;
        }
        else
        {
            canonicalizedDirectoryPath = overlay->Policy.GetCanonicalizedPath();
            directoryName = canonicalizedDirectoryPath.GetPathString();

            if (_wcsicmp(directoryName, L"\\\\.\\MountPointManager") == 0 ||
                IsSpecialDeviceName(directoryName))
            {
                noDetour = true;
            }
        }
    }

    PVOID buffer = FileInformation;
    ULONG bufferSize = Length;
    std::unique_ptr<char[]> largerBuffer;

    if (ShouldUseLargeEnumerationBuffer() && Length < NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE)
    {
        largerBuffer = std::make_unique<char[]>(NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE);
        buffer = largerBuffer.get();
        bufferSize = NTQUERYDIRECTORYFILE_MIN_BUFFER_SIZE;
    }

    NTSTATUS result = Real_NtQueryDirectoryFileEx(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        buffer,
        bufferSize,
        FileInformationClass,
        QueryFlags,
        FileName);
    DWORD reportedError = RtlNtStatusToDosError(result);
    DWORD lastError = GetLastError();

    if (buffer != FileInformation)
    {
        memcpy_s(FileInformation, Length, buffer, Length);
    }

    if (noDetour)
    {
        return result;
    }

    if (overlay->Type == HandleType::Directory)
    {
        PolicyResult directoryPolicyResult = overlay->Policy;
        FileOperationContext fileOperationContext = isEnumeration
            ? FileOperationContext::CreateForRead(L"NtQueryDirectoryFileEx", directoryName)
            : FileOperationContext::CreateForProbe(L"NtQueryDirectoryFileEx", directoryName);
        fileOperationContext.OpenedFileOrDirectoryAttributes = FILE_ATTRIBUTE_DIRECTORY;

        if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, directoryPolicyResult, false))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return DETOURS_STATUS_ACCESS_DENIED;
        }

        // Bazel input filtering: hide undeclared entries from the returned buffer.
        if (ShouldFilterDirectoryEnumeration())
        {
            ApplyEnumerationFilterNtEx(
                Real_NtQueryDirectoryFileEx,
                FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                FileInformation, Length, FileInformationClass, QueryFlags, FileName,
                buffer, bufferSize, directoryPolicyResult,
                result, reportedError, lastError);
        }

        // Model W write-overlay (experimental): splice in process-private overlay
        // entries after the subtractive filter. Kill-switched by ShouldWriteOverlay().
        // The Ex signature folds RestartScan/ReturnSingleEntry into QueryFlags
        // (SL_RESTART_SCAN=0x01, SL_RETURN_SINGLE_ENTRY=0x02).
        if (ShouldWriteOverlay())
        {
            CaptureOverlayEnumFilter(overlay, FileName, (QueryFlags & 0x01) != 0);
            InsertOverlayEntries(
                FileInformation, Length, IoStatusBlock,
                (ULONG)FileInformationClass,
                (BOOLEAN)((QueryFlags & 0x02) != 0),
                (BOOLEAN)((QueryFlags & 0x01) != 0),
                std::wstring(directoryPolicyResult.GetTranslatedPathWithoutTypePrefix()),
                overlay, result);
            reportedError = RtlNtStatusToDosError(result);
            lastError = GetLastError();
        }

        // Only report the enumeration if specified by the policy
        bool reportDirectoryEnumeration = directoryPolicyResult.ReportDirectoryEnumeration();
        bool explicitlyReportDirectoryEnumeration = isEnumeration && reportDirectoryEnumeration;

        AccessCheckResult directoryAccessCheck(
            isEnumeration ? RequestedAccess::Enumerate : RequestedAccess::Probe,
            ResultAction::Allow,
            explicitlyReportDirectoryEnumeration ? ReportLevel::ReportExplicit : ReportLevel::Ignore);

        if (!explicitlyReportDirectoryEnumeration && ReportAnyAccess(false))
        {
            directoryAccessCheck.Level = ReportLevel::Report;
        }

        overlay->EnumerationHasBeenReported = NT_SUCCESS(result) && directoryAccessCheck.ShouldReport();

        ReportIfNeeded(directoryAccessCheck, fileOperationContext, directoryPolicyResult, reportedError, lastError, -1, filter.c_str());
    }

    return result;
}

static bool PathFromObjectAttributesViaId(POBJECT_ATTRIBUTES objectAttributes, ULONG fileAttributes, CanonicalizedPath& path)
{
    DetouredScope scope;

    // Ensure Detours is disabled at this point.
    assert(scope.Detoured_IsDisabled());

    DWORD lastError = GetLastError();

    // Tool wants to open file by id, then that file is assumed to exist.
    // Unfortunately, we need to open a handle to get the file path.
    // Try open a handle with Read access.
    HANDLE hFile;
    IO_STATUS_BLOCK ioStatusBlock;

    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        objectAttributes,
        &ioStatusBlock,
        nullptr,
        fileAttributes,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_BY_FILE_ID,
        nullptr,
        0);

    if (!NT_SUCCESS(status))
    {
        SetLastError(lastError);
        return false;
    }

    wstring fullPath;

    if (DetourGetFinalPathByHandle(hFile, fullPath) != ERROR_SUCCESS)
    {
        SetLastError(lastError);
        return false;
    }

    NtClose(hFile);
    path = CanonicalizedPath::Canonicalize(fullPath.c_str());

    SetLastError(lastError);

    return true;
}

// Helper function converts OBJECT_ATTRIBUTES into CanonicalizedPath
static bool PathFromObjectAttributes(POBJECT_ATTRIBUTES objectAttributes, ULONG fileAttributes, ULONG createOptions, CanonicalizedPath& path)
{
    if ((createOptions & FILE_OPEN_BY_FILE_ID) != 0)
    {
        return PathFromObjectAttributesViaId(objectAttributes, fileAttributes, path);
    }

    if (objectAttributes->ObjectName == nullptr)
    {
        return false;
    }

    HandleOverlayRef overlay;

    // Check for the root directory
    if (objectAttributes->RootDirectory != nullptr)
    {
        overlay = TryLookupHandleOverlay(objectAttributes->RootDirectory);
        // If root directory is specified, we better know about it by know -- ignore unknown relative paths
        if (overlay == nullptr || overlay->Policy.GetCanonicalizedPath().IsNull())
        {
            return false;
        }
    }

    // Convert the ObjectName (buffer with a size) to be null-terminated.
    wstring name(objectAttributes->ObjectName->Buffer, (size_t)(objectAttributes->ObjectName->Length / sizeof(wchar_t)));

    if (overlay != nullptr)
    {
        // If there is no 'name' set (name is empty), just use the canonicalized path. Otherwise need to extend,
        // so '\' is appended to the canonicalized path and then the name is appended.
        path = name.empty() ? overlay->Policy.GetCanonicalizedPath() : overlay->Policy.GetCanonicalizedPath().Extend(name.c_str());
    }
    else
    {
        path = CanonicalizedPath::Canonicalize(name.c_str());
    }

    // Nt* functions require an NT-style path syntax. Opening 'C:\foo' will fail with STATUS_OBJECT_PATH_SYNTAX_BAD;
    // instead something like '\??\C:\foo' or '\Device\HarddiskVolume1\foo' would work. If the caller provides a path
    // that couldn't be canonicalized or looks doomed to fail (not NT-style), we give up.
    // TODO: CanonicalizedPath may deserve an NT-specific Canonicalize equivalent (e.g. PathType::Win32Nt also matches \\?\, but that doesn't make sense here).
    return !path.IsNull() && (overlay != nullptr || path.Type == PathType::Win32Nt);
}

static DWORD MapNtCreateOptionsToWin32FileFlags(ULONG createOptions)
{
    DWORD flags = 0;

    // We ignore most create options here, emphasizing just those that significantly affect semantics.
    flags |= (((createOptions & FILE_OPEN_FOR_BACKUP_INTENT) && !(createOptions & FILE_NON_DIRECTORY_FILE)) ? FILE_FLAG_BACKUP_SEMANTICS : 0);
    flags |= (createOptions & FILE_DELETE_ON_CLOSE ? FILE_FLAG_DELETE_ON_CLOSE : 0);
    flags |= (createOptions & FILE_OPEN_REPARSE_POINT ? FILE_FLAG_OPEN_REPARSE_POINT : 0);

    return flags;
}

static DWORD MapNtCreateDispositionToWin32Disposition(ULONG ntDisposition)
{
    switch (ntDisposition)
    {
    case FILE_CREATE:
        return CREATE_NEW;
    case FILE_OVERWRITE_IF:
        return CREATE_ALWAYS;
    case FILE_OPEN:
        return OPEN_EXISTING;
    case FILE_OPEN_IF:
        return OPEN_ALWAYS;
    case FILE_OVERWRITE: // For some reason, CreateFile(TRUNCATE_EXISTING) doesn't actually map to this (but something else may use it).
    case FILE_SUPERSEDE: // Technically this creates a new file rather than truncating.
        return TRUNCATE_EXISTING;
    default:
        return 0;
    }
}

static bool CheckIfNtCreateMayDeleteFile(ULONG createOptions, ULONG access)
{
    return (createOptions & FILE_DELETE_ON_CLOSE) != 0 || (access & DELETE) != 0;
}

// Some dispositions implicitly perform a write (truncate) or delete (supersede) inline;
// the write or delete is not required as part of the DesiredAccess mask though the filesystem will still (conditionally?) perform an access check anyway.
static bool CheckIfNtCreateDispositionImpliesWriteOrDelete(ULONG ntDisposition)
{
    switch (ntDisposition)
    {
    case FILE_OVERWRITE_IF:
    case FILE_OVERWRITE:
    case FILE_SUPERSEDE:
        return true;
    default:
        return false;
    }
}

// If FILE_DIRECTORY_FILE is specified, then only a directory will be opened / created (not a file).
static bool CheckIfNtCreateFileOptionsExcludeOpeningFiles(ULONG createOptions)
{
    return (createOptions & FILE_DIRECTORY_FILE) != 0;
}

IMPLEMENTED(Detoured_ZwCreateFile)
NTSTATUS NTAPI Detoured_ZwCreateFile(
    _Out_    PHANDLE            FileHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_    PIO_STATUS_BLOCK   IoStatusBlock,
    _In_opt_ PLARGE_INTEGER     AllocationSize,
    _In_     ULONG              FileAttributes,
    _In_     ULONG              ShareAccess,
    _In_     ULONG              CreateDisposition,
    _In_     ULONG              CreateOptions,
    _In_opt_ PVOID              EaBuffer,
    _In_     ULONG              EaLength)
{
    DetouredScope scope;

    // As a performance workaround, neuter the FILE_RANDOM_ACCESS hint (even if Detoured_IsDisabled() and there's another detoured API higher on the stack).
    // Prior investigations have shown that some tools do mention this hint, and as a result the cache manager holds on to pages more aggressively than
    // expected, even in very low memory conditions.
    CreateOptions &= ~FILE_RANDOM_ACCESS;

    CanonicalizedPath path;

    if (scope.Detoured_IsDisabled() ||
        !MonitorZwCreateOpenQueryFile() ||
        ObjectAttributes == nullptr ||
        !PathFromObjectAttributes(ObjectAttributes, FileAttributes, CreateOptions, path) ||
        IsSpecialDeviceName(path.GetPathString()))
    {
        return Real_ZwCreateFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength);
    }

    DWORD win32Disposition = MapNtCreateDispositionToWin32Disposition(CreateDisposition);
    DWORD win32Options = MapNtCreateOptionsToWin32FileFlags(CreateOptions);

    FileOperationContext opContext(
        L"ZwCreateFile",
        DesiredAccess,
        ShareAccess,
        win32Disposition,
        win32Options,
        path.GetPathString());

    // BazelSandbox: under -n (all network blocked) deny socket creation via the
    // AFD device (see the matching check in Detoured_NtCreateFile).
    if (bazelsandbox::IsAllNetworkBlocked() && bazelsandbox::IsAfdDeviceName(path.GetPathString()))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    PolicyResult policyResult;
    if (!policyResult.Initialize(path.GetPathString()))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(opContext, policyResult, true))
    {
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    bool isDirectoryCreation = CheckIfNtCreateFileOptionsExcludeOpeningFiles(CreateOptions);

    // We start with allow / ignore (no access requested) and then restrict based on read / write (maybe both, maybe neither!)
    AccessCheckResult accessCheck(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
    bool forceReadOnlyForRequestedRWAccess = false;
    DWORD error = ERROR_SUCCESS;

    // Note that write operations are quite sneaky, and can perhaps be implied by any of options, dispositions, or desired access.
    // (consider FILE_DELETE_ON_CLOSE and FILE_OVERWRITE).
    // If we are operating on a directory, allow access - BuildXL allows accesses to directories (creation/deletion/etc.) always, as long as they are on a readable mount (at lease).
    if ((WantsWriteAccess(opContext.DesiredAccess) ||
        CheckIfNtCreateDispositionImpliesWriteOrDelete(CreateDisposition) ||
        CheckIfNtCreateMayDeleteFile(CreateOptions, DesiredAccess)) &&
        // Force directory checking using path, instead of handle, because the value of *FileHandle is still undefined, i.e., neither valid nor not valid.
        !IsHandleOrPathToDirectory(INVALID_HANDLE_VALUE, path.GetPathString(), opContext.DesiredAccess, win32Options, policyResult, /*ref*/opContext.OpenedFileOrDirectoryAttributes))
    {
        error = GetLastError();
        accessCheck = policyResult.CheckWriteAccess();

        // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
        if (accessCheck.Result != ResultAction::Allow && !MonitorNtCreateFile())
        {
            // TODO: As part of gradually turning on NtCreateFile detour reports, we currently only enforce deletes (some cmd builtins delete this way),
            //       and we ignore potential deletes on *directories* (specifically, robocopy likes to open target directories with delete access, without actually deleting them).
            if (!CheckIfNtCreateMayDeleteFile(CreateOptions, DesiredAccess))
            {
#if SUPER_VERBOSE
                Dbg(L"NtCreateFile: Ignoring a write-level access since it is not a delete: %s", policyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
                accessCheck = AccessCheckResult(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
            }
            else if (isDirectoryCreation)
            {
#if SUPER_VERBOSE
                Dbg(L"NtCreateFile: Ignoring a delete-level access since it will only apply to directories: %s", policyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
                accessCheck = AccessCheckResult(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
            }
        }

        if (ForceReadOnlyForRequestedReadWrite() && accessCheck.Result != ResultAction::Allow)
        {
            // If ForceReadOnlyForRequestedReadWrite() is true, then we allow read for requested read-write access so long as the tool is allowed to read.
            // In such a case, we change the desired access to read only (see the call to Real_CreateFileW below).
            // As a consequence, the tool can fail if it indeed wants to write to the file.
            if (WantsReadAccess(DesiredAccess) && policyResult.AllowRead())
            {
                accessCheck = AccessCheckResult(RequestedAccess::Read, ResultAction::Allow, ReportLevel::Ignore);
                FileOperationContext operationContext(
                    L"ChangedReadWriteToReadAccess",
                    DesiredAccess,
                    ShareAccess,
                    win32Disposition,
                    win32Options,
                    policyResult.GetCanonicalizedPath().GetPathString());

                ReportFileAccess(
                    operationContext,
                    FileAccessStatus::FileAccessStatus_Allowed,
                    policyResult,
                    AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report),
                    0,
                    -1);

                forceReadOnlyForRequestedRWAccess = true;
            }
        }

        if (!forceReadOnlyForRequestedRWAccess && accessCheck.ShouldDenyAccess())
        {
            const bool maskRead = ShouldDeniedReadsAsNotFound();
            ReportIfNeeded(accessCheck, opContext, policyResult, accessCheck.DenialError(maskRead));
            accessCheck.SetLastErrorToDenialError(maskRead);
            return accessCheck.DenialNtStatus(maskRead);
        }

        SetLastError(error);
    }

    // At this point and beyond, we know we are either dealing with a write request that has been approved, or a
    // read request which may or may not have been approved (due to special exceptions for directories and non-existent files).
    // It is safe to go ahead and perform the real NtCreateFile() call, and then to reason about the results after the fact.

    // Note that we need to add FILE_SHARE_DELETE to dwShareMode to leverage NTFS hardlinks to avoid copying cache
    // content, i.e., we need to be able to delete one of many links to a file. Unfortunately, share-mode is aggregated only per file
    // rather than per-link, so in order to keep unused links delete-able, we should ensure in-use links are delete-able as well.
    // However, adding FILE_SHARE_DELETE may be unexpected, for example, some unit tests may test for sharing violation. Thus,
    // we only add FILE_SHARE_DELETE if the file is tracked.

    // We also add FILE_SHARE_READ when it is safe to do so, since some tools accidentally ask for exclusive access on their inputs.

    DWORD desiredAccess = DesiredAccess;
    DWORD sharedAccess = ShareAccess;

    if (!policyResult.IndicateUntracked())
    {
        DWORD readSharingIfNeeded = policyResult.ShouldForceReadSharing(accessCheck) ? FILE_SHARE_READ : 0UL;
        desiredAccess = !forceReadOnlyForRequestedRWAccess ? desiredAccess : (desiredAccess & FILE_GENERIC_READ);
        sharedAccess = sharedAccess | readSharingIfNeeded | FILE_SHARE_DELETE;
    }

    // Model W (write-overlay): redirect the open to the process-private backing store
    // by rewriting ObjectAttributes to an absolute NT-form backing path (\??\...), as
    // in Detoured_NtCreateFile. Only reached for direct ZwCreateFile callers; Win32
    // opens are redirected one layer up and suppressed here by the DetouredScope.
    POBJECT_ATTRIBUTES effectiveObjectAttributes = ObjectAttributes;
    UNICODE_STRING overlayNtName;
    OBJECT_ATTRIBUTES overlayObjectAttributes;
    std::wstring overlayBackingNt = ResolveOverlayOpenPath(policyResult, DesiredAccess, win32Disposition);
    if (!overlayBackingNt.empty())
    {
        if (overlayBackingNt.compare(0, 4, L"\\\\?\\") == 0)
        {
            overlayBackingNt.replace(0, 4, L"\\??\\");
        }
        overlayNtName.Buffer = (PWSTR)overlayBackingNt.c_str();
        overlayNtName.Length = (USHORT)(overlayBackingNt.size() * sizeof(wchar_t));
        overlayNtName.MaximumLength = (USHORT)((overlayBackingNt.size() + 1) * sizeof(wchar_t));
        overlayObjectAttributes = *ObjectAttributes;
        overlayObjectAttributes.RootDirectory = nullptr; // backing path is absolute
        overlayObjectAttributes.ObjectName = &overlayNtName;
        effectiveObjectAttributes = &overlayObjectAttributes;
    }

    NTSTATUS result = Real_ZwCreateFile(
        FileHandle,
        desiredAccess,
        effectiveObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        sharedAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength);

    error = GetLastError();

    if (!NT_SUCCESS(result))
    {
        // If we failed, just report. No need to execute anything below.
        FileReadContext readContext;
        readContext.InferExistenceFromNtStatus(result);
        readContext.OpenedDirectory = IsHandleOrPathToDirectory(
            INVALID_HANDLE_VALUE, // Do not use *FileHandle because even though it is not NT_SUCCESS, *FileHandle can be different from INVALID_HANDLE_VALUE
            path.GetPathString(),
            opContext.DesiredAccess,
            win32Options,
            policyResult,
            /*ref*/ opContext.OpenedFileOrDirectoryAttributes);

        // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
        if (MonitorNtCreateFile())
        {
            if (WantsReadAccess(opContext.DesiredAccess))
            {
                // We've now established all of the read context, which can further inform the access decision.
                // (e.g. maybe we we allow read only if the file doesn't exist).
                accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext));
            }
            else if (WantsProbeOnlyAccess(opContext.DesiredAccess))
            {
                accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Probe, readContext));
            }
        }

        ReportIfNeeded(accessCheck, opContext, policyResult, RtlNtStatusToDosError(result), error);

        SetLastError(error);
        return result;
    }

    FileReadContext readContext;
    readContext.InferExistenceFromNtStatus(result);
    readContext.OpenedDirectory = IsHandleOrPathToDirectory(*FileHandle, path.GetPathString(), opContext.DesiredAccess, win32Options, policyResult, /*ref*/ opContext.OpenedFileOrDirectoryAttributes);

    // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
    if (MonitorNtCreateFile())
    {
        if (WantsReadAccess(opContext.DesiredAccess))
        {
            // We've now established all of the read context, which can further inform the access decision.
            // (e.g. maybe we we allow read only if the file doesn't exist).
            accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext));
        }
        else if (WantsProbeOnlyAccess(opContext.DesiredAccess))
        {
            accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Probe, readContext));
        }
    }

    bool isHandleToReparsePoint = (CreateOptions & FILE_OPEN_REPARSE_POINT) != 0;
    bool shouldReportAccessCheck = true;
    bool shouldResolveReparsePointsInPath = ShouldResolveReparsePointsInPath(policyResult.GetCanonicalizedPath(), opContext.FlagsAndAttributes, policyResult);

    if (shouldResolveReparsePointsInPath)
    {
        // Note that handle can be invalid because users can CreateFileW of a symlink whose target is non-existent.
        NTSTATUS ntStatus;

        bool accessResult = EnforceChainOfReparsePointAccesses(
            policyResult.GetCanonicalizedPath(),
            isHandleToReparsePoint ? *FileHandle : INVALID_HANDLE_VALUE,
            desiredAccess,
            sharedAccess,
            win32Disposition,
            FileAttributes,
            true,
            policyResult,
            &ntStatus,
            true,
            isDirectoryCreation,
            nullptr,
            true,
            isHandleToReparsePoint);

        if (!accessResult)
        {
            // If we don't have access to the target, close the handle to the reparse point.
            // This way we don't have a leaking handle.
            // (See below we do the same when a normal file access is not allowed and close the file.)
            NtClose(*FileHandle);
            *FileHandle = INVALID_HANDLE_VALUE;
            ntStatus = DETOURS_STATUS_ACCESS_DENIED;

            return ntStatus;
        }

        if (!IgnoreFullReparsePointResolvingForPath(policyResult))
        {
            shouldReportAccessCheck = false;
        }
    }

    InvalidateReparsePointCacheIfNeeded(
        shouldResolveReparsePointsInPath,
        opContext.DesiredAccess,
        opContext.FlagsAndAttributes,
        readContext.OpenedDirectory,
        policyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(),
        policyResult);

    bool hasValidHandle = NT_SUCCESS(result) && !IsNullOrInvalidHandle(*FileHandle);

    // Handle-resolution read fallback (bazel-sandbox-windows). See Detoured_CreateFileW for the full
    // rationale: honor the resolved-target policy for a denied read when the real file behind the
    // reparse chain is a granted input. Reads only; name-agnostic; no less hermetic than the literal
    // check. Only DECLARED inputs (carrying the DeclaredInput marker) are rescued.
    if (accessCheck.ShouldDenyAccess()
        && hasValidHandle
        && !WantsWriteAccess(opContext.DesiredAccess)
        && (WantsReadAccess(opContext.DesiredAccess) || WantsProbeOnlyAccess(opContext.DesiredAccess))
        && !isHandleToReparsePoint)
    {
        wstring resolvedPath;
        if (DetourGetFinalPathByHandle(*FileHandle, resolvedPath) == ERROR_SUCCESS && !resolvedPath.empty())
        {
            PolicyResult resolvedPolicy;
            if (resolvedPolicy.Initialize(resolvedPath.c_str()))
            {
                RequestedReadAccess requested =
                    WantsReadAccess(opContext.DesiredAccess) ? RequestedReadAccess::Read : RequestedReadAccess::Probe;
                AccessCheckResult resolvedCheck = resolvedPolicy.CheckReadAccess(requested, readContext);
                if (!resolvedCheck.ShouldDenyAccess() && resolvedPolicy.IsDeclaredInput())
                {
                    Dbg(L"Handle-resolution read fallback: allowing '%s' via resolved target '%s'.",
                        policyResult.GetCanonicalizedPath().GetPathString(),
                        resolvedPolicy.GetCanonicalizedPath().GetPathString());
                    accessCheck = resolvedCheck;
                }
            }
        }
    }

    if (accessCheck.ShouldDenyAccess())
    {
        const bool maskRead = ShouldDeniedReadsAsNotFound();
        error = accessCheck.DenialError(maskRead);

        if (hasValidHandle)
        {
            NtClose(*FileHandle);
        }

        *FileHandle = INVALID_HANDLE_VALUE;
        result = accessCheck.DenialNtStatus(maskRead);
    }
    else if (hasValidHandle)
    {
        HandleType handleType = readContext.OpenedDirectory ? HandleType::Directory : HandleType::File;
        RegisterHandleOverlay(*FileHandle, accessCheck, policyResult, handleType);
    }

    if (shouldReportAccessCheck)
    {
        ReportIfNeeded(accessCheck, opContext, policyResult, RtlNtStatusToDosError(result), error);
    }

    SetLastError(error);
    return result;
}

IMPLEMENTED(Detoured_NtCreateFile)
NTSTATUS NTAPI Detoured_NtCreateFile(
    _Out_    PHANDLE            FileHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_     POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_    PIO_STATUS_BLOCK   IoStatusBlock,
    _In_opt_ PLARGE_INTEGER     AllocationSize,
    _In_     ULONG              FileAttributes,
    _In_     ULONG              ShareAccess,
    _In_     ULONG              CreateDisposition,
    _In_     ULONG              CreateOptions,
    _In_opt_ PVOID              EaBuffer,
    _In_     ULONG              EaLength)
{
    DetouredScope scope;

    // As a performance workaround, neuter the FILE_RANDOM_ACCESS hint (even if Detoured_IsDisabled() and there's another detoured API higher on the stack).
    // Prior investigations have shown that some tools do mention this hint, and as a result the cache manager holds on to pages more aggressively than
    // expected, even in very low memory conditions.
    CreateOptions &= ~FILE_RANDOM_ACCESS;

    CanonicalizedPath path;

    if (scope.Detoured_IsDisabled() ||
        ObjectAttributes == nullptr ||
        !PathFromObjectAttributes(ObjectAttributes, FileAttributes, CreateOptions, path) ||
        IsSpecialDeviceName(path.GetPathString()))
    {
        return Real_NtCreateFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength);
    }

    DWORD error = ERROR_SUCCESS;

    // BazelSandbox: under -n (all network blocked) deny socket creation at the
    // syscall layer. Winsock opens the AFD device to create a socket, so
    // blocking \Device\Afd here stops even code that bypasses ws2_32 and talks
    // to AFD directly. Under -N sockets must still be creatable (loopback), so
    // this hard block is limited to the all-blocked policy.
    if (bazelsandbox::IsAllNetworkBlocked() && bazelsandbox::IsAfdDeviceName(path.GetPathString()))
    {
        SetLastError(ERROR_ACCESS_DENIED);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    DWORD win32Disposition = MapNtCreateDispositionToWin32Disposition(CreateDisposition);
    DWORD win32Options = MapNtCreateOptionsToWin32FileFlags(CreateOptions);

    FileOperationContext opContext(
        L"NtCreateFile",
        DesiredAccess,
        ShareAccess,
        win32Disposition,
        win32Options,
        path.GetPathString());

    PolicyResult policyResult;
    if (!policyResult.Initialize(path.GetPathString()))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(opContext);
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(opContext, policyResult, true))
    {
        return DETOURS_STATUS_ACCESS_DENIED;
    }

    bool isDirectoryCreation = CheckIfNtCreateFileOptionsExcludeOpeningFiles(CreateOptions);

    // We start with allow / ignore (no access requested) and then restrict based on read / write (maybe both, maybe neither!)
    AccessCheckResult accessCheck(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
    bool forceReadOnlyForRequestedRWAccess = false;

    // Note that write operations are quite sneaky, and can perhaps be implied by any of options, dispositions, or desired access.
    // (consider FILE_DELETE_ON_CLOSE and FILE_OVERWRITE).
    // If we are operating on a directory, allow access - BuildXL allows accesses to directories (creation/deletion/etc.) always, as long as they are on a readable mount (at least).
    // TODO: Directory operation through NtCreateFile needs to be reviewed based on olkonone's work.
    //  - Users can call NtCreateFile directly to create directory.
    //  - Commit 86e8274b by olkonone changes the way Detours validates directory creation. But the new validation is only applied to CreateDirectoryW.
    //  - Perhaps the validation should be done in NtCreateFile instead of in CreateDirectoryW.
    if ((WantsWriteAccess(opContext.DesiredAccess) ||
        CheckIfNtCreateDispositionImpliesWriteOrDelete(CreateDisposition) ||
        CheckIfNtCreateMayDeleteFile(CreateOptions, DesiredAccess)) &&
        // Force directory checking using path, instead of handle, because the value of *FileHandle is still undefined, i.e., neither valid nor not valid.
        !IsHandleOrPathToDirectory(INVALID_HANDLE_VALUE, path.GetPathString(), opContext.DesiredAccess, win32Options, policyResult, /*ref*/opContext.OpenedFileOrDirectoryAttributes))
    {
        error = GetLastError();
        accessCheck = policyResult.CheckWriteAccess();

        // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
        if (accessCheck.Result != ResultAction::Allow && !MonitorNtCreateFile())
        {
            // TODO: As part of gradually turning on NtCreateFile detour reports, we currently only enforce deletes (some cmd builtins delete this way),
            //       and we ignore potential deletes on *directories* (specifically, robocopy likes to open target directories with delete access, without actually deleting them).
            if (!CheckIfNtCreateMayDeleteFile(CreateOptions, DesiredAccess))
            {
#if SUPER_VERBOSE
                Dbg(L"NtCreateFile: Ignoring a write-level access since it is not a delete: %s", policyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
                accessCheck = AccessCheckResult(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
            }
            else if (isDirectoryCreation)
            {
#if SUPER_VERBOSE
                Dbg(L"NtCreateFile: Ignoring a delete-level access since it will only apply to directories: %s", policyResult.GetCanonicalizedPath().GetPathString());
#endif // SUPER_VERBOSE
                accessCheck = AccessCheckResult(RequestedAccess::None, ResultAction::Allow, ReportLevel::Ignore);
            }
        }

        if (ForceReadOnlyForRequestedReadWrite() && accessCheck.Result != ResultAction::Allow)
        {
            // If ForceReadOnlyForRequestedReadWrite() is true, then we allow read for requested read-write access so long as the tool is allowed to read.
            // In such a case, we change the desired access to read only (see the call to Real_CreateFileW below).
            // As a consequence, the tool can fail if it indeed wants to write to the file.
            if (WantsReadAccess(DesiredAccess) && policyResult.AllowRead())
            {
                accessCheck = AccessCheckResult(RequestedAccess::Read, ResultAction::Allow, ReportLevel::Ignore);
                FileOperationContext operationContext(
                    L"ChangedReadWriteToReadAccess",
                    DesiredAccess,
                    ShareAccess,
                    win32Disposition,
                    win32Options,
                    path.GetPathString());

                ReportFileAccess(
                    operationContext,
                    FileAccessStatus::FileAccessStatus_Allowed,
                    policyResult,
                    AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report),
                    0,
                    -1);

                forceReadOnlyForRequestedRWAccess = true;
            }
        }

        if (!forceReadOnlyForRequestedRWAccess && accessCheck.ShouldDenyAccess())
        {
            const bool maskRead = ShouldDeniedReadsAsNotFound();
            ReportIfNeeded(accessCheck, opContext, policyResult, accessCheck.DenialError(maskRead));
            accessCheck.SetLastErrorToDenialError(maskRead);
            return accessCheck.DenialNtStatus(maskRead);
        }

        SetLastError(error);
    }

    // At this point and beyond, we know we are either dealing with a write request that has been approved, or a
    // read request which may or may not have been approved (due to special exceptions for directories and non-existent files).
    // It is safe to go ahead and perform the real NtCreateFile() call, and then to reason about the results after the fact.

    // Note that we need to add FILE_SHARE_DELETE to dwShareMode to leverage NTFS hardlinks to avoid copying cache
    // content, i.e., we need to be able to delete one of many links to a file. Unfortunately, share-mode is aggregated only per file
    // rather than per-link, so in order to keep unused links delete-able, we should ensure in-use links are delete-able as well.
    // However, adding FILE_SHARE_DELETE may be unexpected, for example, some unit tests may test for sharing violation. Thus,
    // we only add FILE_SHARE_DELETE if the file is tracked.

    // We also add FILE_SHARE_READ when it is safe to do so, since some tools accidentally ask for exclusive access on their inputs.

    DWORD desiredAccess = DesiredAccess;
    DWORD sharedAccess = ShareAccess;

    if (!policyResult.IndicateUntracked())
    {
        DWORD readSharingIfNeeded = policyResult.ShouldForceReadSharing(accessCheck) ? FILE_SHARE_READ : 0UL;
        desiredAccess = !forceReadOnlyForRequestedRWAccess ? desiredAccess : (desiredAccess & FILE_GENERIC_READ);
        sharedAccess = sharedAccess | readSharingIfNeeded;

        if (!PreserveFileSharingBehaviour())
        {
            sharedAccess |= FILE_SHARE_DELETE;
        }
    }

    // Model W (write-overlay): redirect the open to the process-private backing store
    // when this path is in the redirect cone, by rewriting ObjectAttributes to an
    // absolute NT-form backing path (\??\...). Policy/reporting above ran on the
    // virtual path; only the path handed to the OS is swapped, mirroring the Win32
    // CreateFileW redirect. This layer is only reached for tools that call NtCreateFile
    // directly - Win32 opens are redirected one layer up and suppressed here by the
    // DetouredScope. Empty => open unchanged.
    POBJECT_ATTRIBUTES effectiveObjectAttributes = ObjectAttributes;
    UNICODE_STRING overlayNtName;
    OBJECT_ATTRIBUTES overlayObjectAttributes;
    std::wstring overlayBackingNt = ResolveOverlayOpenPath(policyResult, DesiredAccess, win32Disposition);
    if (!overlayBackingNt.empty())
    {
        if (overlayBackingNt.compare(0, 4, L"\\\\?\\") == 0)
        {
            overlayBackingNt.replace(0, 4, L"\\??\\");
        }
        overlayNtName.Buffer = (PWSTR)overlayBackingNt.c_str();
        overlayNtName.Length = (USHORT)(overlayBackingNt.size() * sizeof(wchar_t));
        overlayNtName.MaximumLength = (USHORT)((overlayBackingNt.size() + 1) * sizeof(wchar_t));
        overlayObjectAttributes = *ObjectAttributes;
        overlayObjectAttributes.RootDirectory = nullptr; // backing path is absolute
        overlayObjectAttributes.ObjectName = &overlayNtName;
        effectiveObjectAttributes = &overlayObjectAttributes;
    }

    NTSTATUS result = Real_NtCreateFile(
        FileHandle,
        desiredAccess,
        effectiveObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        sharedAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength);

    error = GetLastError();

    if (!NT_SUCCESS(result))
    {
        // If we failed, just report. No need to execute anything below.
        FileReadContext readContext;
        readContext.InferExistenceFromNtStatus(result);
        readContext.OpenedDirectory = IsHandleOrPathToDirectory(
            INVALID_HANDLE_VALUE, // Do not use *FileHandle because even though it is not NT_SUCCESS, *FileHandle can be different from INVALID_HANDLE_VALUE
            path.GetPathString(),
            opContext.DesiredAccess,
            win32Options,
            policyResult,
            /*ref*/ opContext.OpenedFileOrDirectoryAttributes);

        // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
        if (MonitorNtCreateFile())
        {
            if (WantsReadAccess(opContext.DesiredAccess))
            {
                // We've now established all of the read context, which can further inform the access decision.
                // (e.g. maybe we we allow read only if the file doesn't exist).
                accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext));
            }
            else if (WantsProbeOnlyAccess(opContext.DesiredAccess))
            {
                accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Probe, readContext));
            }
        }

        ReportIfNeeded(accessCheck, opContext, policyResult, RtlNtStatusToDosError(result));

        SetLastError(error);

        return result;
    }

    FileReadContext readContext;
    readContext.InferExistenceFromNtStatus(result);
    readContext.OpenedDirectory = IsHandleOrPathToDirectory(*FileHandle, path.GetPathString(), opContext.DesiredAccess, win32Options, policyResult, /*ref*/ opContext.OpenedFileOrDirectoryAttributes);

    // Note: The MonitorNtCreateFile() flag is temporary until OSG (we too) fixes all newly discovered dependencies.
    if (MonitorNtCreateFile())
    {
        if (WantsReadAccess(opContext.DesiredAccess))
        {
            // We've now established all of the read context, which can further inform the access decision.
            // (e.g. maybe we we allow read only if the file doesn't exist).
            accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Read, readContext));
        }
        else if (WantsProbeOnlyAccess(opContext.DesiredAccess))
        {
            accessCheck = AccessCheckResult::Combine(accessCheck, policyResult.CheckReadAccess(RequestedReadAccess::Probe, readContext));
        }
    }

    bool isHandleToReparsePoint = (CreateOptions & FILE_OPEN_REPARSE_POINT) != 0;
    bool shouldReportAccessCheck = true;

    bool shouldResolveReparsePointsInPath = ShouldResolveReparsePointsInPath(policyResult.GetCanonicalizedPath(), opContext.FlagsAndAttributes, policyResult);
    if (shouldResolveReparsePointsInPath)
    {
        NTSTATUS ntStatus;

        bool accessResult = EnforceChainOfReparsePointAccesses(
            policyResult.GetCanonicalizedPath(),
            isHandleToReparsePoint ? *FileHandle : INVALID_HANDLE_VALUE,
            desiredAccess,
            sharedAccess,
            win32Disposition,
            FileAttributes,
            true,
            policyResult,
            &ntStatus,
            true,
            isDirectoryCreation,
            nullptr,
            true,
            isHandleToReparsePoint);

        if (!accessResult)
        {
            // If we don't have access to the target, close the handle to the reparse point.
            // This way we don't have a leaking handle.
            // (See below we do the same when a normal file access is not allowed and close the file.)
            NtClose(*FileHandle);

            *FileHandle = INVALID_HANDLE_VALUE;
            ntStatus = DETOURS_STATUS_ACCESS_DENIED;

            return ntStatus;
        }

        if (!IgnoreFullReparsePointResolvingForPath(policyResult))
        {
            shouldReportAccessCheck = false;
        }
    }

    InvalidateReparsePointCacheIfNeeded(
        shouldResolveReparsePointsInPath,
        opContext.DesiredAccess,
        opContext.FlagsAndAttributes,
        readContext.OpenedDirectory,
        policyResult.GetCanonicalizedPath().GetPathStringWithoutTypePrefix(),
        policyResult);

    bool hasValidHandle = NT_SUCCESS(result) && !IsNullOrInvalidHandle(*FileHandle);

    // Handle-resolution read fallback (bazel-sandbox-windows). See the detailed rationale in
    // Detoured_CreateFileW: a denied literal path may be a symlink/junction (or reached through one)
    // whose real target IS a granted input. NtCreateFile already followed the reparse chain, so
    // resolve the handle to its final path and re-check policy there; honor the resolved-path policy
    // if it allows the read. Reads only; name-agnostic; no less hermetic than the literal check.
    // Only DECLARED inputs (carrying the DeclaredInput marker) are rescued.
    if (accessCheck.ShouldDenyAccess()
        && hasValidHandle
        && !WantsWriteAccess(opContext.DesiredAccess)
        && (WantsReadAccess(opContext.DesiredAccess) || WantsProbeOnlyAccess(opContext.DesiredAccess))
        && !isHandleToReparsePoint)
    {
        wstring resolvedPath;
        if (DetourGetFinalPathByHandle(*FileHandle, resolvedPath) == ERROR_SUCCESS && !resolvedPath.empty())
        {
            PolicyResult resolvedPolicy;
            if (resolvedPolicy.Initialize(resolvedPath.c_str()))
            {
                RequestedReadAccess requested =
                    WantsReadAccess(opContext.DesiredAccess) ? RequestedReadAccess::Read : RequestedReadAccess::Probe;
                AccessCheckResult resolvedCheck = resolvedPolicy.CheckReadAccess(requested, readContext);
                if (!resolvedCheck.ShouldDenyAccess() && resolvedPolicy.IsDeclaredInput())
                {
                    Dbg(L"Handle-resolution read fallback: allowing '%s' via resolved target '%s'.",
                        policyResult.GetCanonicalizedPath().GetPathString(),
                        resolvedPolicy.GetCanonicalizedPath().GetPathString());
                    accessCheck = resolvedCheck;
                }
            }
        }
    }

    if (accessCheck.ShouldDenyAccess())
    {
        const bool maskRead = ShouldDeniedReadsAsNotFound();
        error = accessCheck.DenialError(maskRead);

        if (hasValidHandle)
        {
            NtClose(*FileHandle);
        }

        *FileHandle = INVALID_HANDLE_VALUE;
        result = accessCheck.DenialNtStatus(maskRead);
    }
    else if (hasValidHandle)
    {
        HandleType handleType = readContext.OpenedDirectory ? HandleType::Directory : HandleType::File;
        RegisterHandleOverlay(*FileHandle, accessCheck, policyResult, handleType);
    }

    if (shouldReportAccessCheck)
    {
        ReportIfNeeded(accessCheck, opContext, policyResult, RtlNtStatusToDosError(result), error);
    }

    SetLastError(error);

    return result;
}

IMPLEMENTED(Detoured_ZwOpenFile)
NTSTATUS NTAPI Detoured_ZwOpenFile(
    _Out_ PHANDLE            FileHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
    _In_  ULONG              ShareAccess,
    _In_  ULONG              OpenOptions)
{
    return Detoured_ZwCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        (PLARGE_INTEGER)NULL, // AllocationSize
        0L, // Attributes
        ShareAccess,
        FILE_OPEN,
        OpenOptions,
        (PVOID)NULL, // EaBuffer,
        0L // EaLength
    );
}

IMPLEMENTED(Detoured_NtOpenFile)
NTSTATUS NTAPI Detoured_NtOpenFile(
    _Out_ PHANDLE            FileHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
    _In_  ULONG              ShareAccess,
    _In_  ULONG              OpenOptions)
{
    // We don't EnterLoggingScope for NtOpenFile or NtCreateFile for two reasons:
    // - Of course these get called.
    // - It's hard to predict library loads (e.g. even by a statically linked CRT), which complicates testing of other call logging.

    // NtOpenFile is just a handy shortcut for NtCreateFile (with creation-specific parameters omitted).
    // We forward to the NtCreateFile detour here in order to have a single implementation.

    return Detoured_NtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        (PLARGE_INTEGER)NULL, // AllocationSize
        0L, // Attributes
        ShareAccess,
        FILE_OPEN,
        OpenOptions,
        (PVOID)NULL, // EaBuffer,
        0L // EaLength
    );
}

// FileAttributes offset within FILE_STAT_BASIC_INFORMATION (the record returned for
// FileStatBasicByNameInfo): FileId + 6 timestamp/size LARGE_INTEGERs precede it. We only read
// FileAttributes (to detect directories) and avoid pulling in the full SDK struct definition.
typedef struct _BXL_FILE_STAT_BASIC_INFORMATION {
    LARGE_INTEGER FileId;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
    // ... trailing fields (ReparseTag, NumberOfLinks, DeviceType, ...) intentionally omitted.
} BXL_FILE_STAT_BASIC_INFORMATION;

// Detoured_GetFileInformationByName: mask undeclared-input probes for modern libuv's fast
// fs.stat path (GetFileInformationByName + FileStatBasicByNameInfo). Without this, an
// undeclared existing file would remain visible to stat() even though CreateFile/read of the
// same file are masked to NOT_FOUND, breaking parity with linux-sandbox (where an undeclared
// input is simply absent from the symlink forest, so BOTH stat and read observe ENOENT).
// Mirrors the Detoured_GetFileAttributesExW probe-masking logic.
IMPLEMENTED(Detoured_GetFileInformationByName)
BOOL WINAPI Detoured_GetFileInformationByName(
    _In_  PCWSTR FileName,
    _In_  BXL_FILE_INFO_BY_NAME_CLASS FileInformationClass,
    _Out_ PVOID  FileInfoBuffer,
    _In_  ULONG  FileInfoBufferSize)
{
    DetouredScope scope;
    if (scope.Detoured_IsDisabled() || IsNullOrEmptyW(FileName) || IsSpecialDeviceName(FileName))
    {
        return Real_GetFileInformationByName(FileName, FileInformationClass, FileInfoBuffer, FileInfoBufferSize);
    }

    FileOperationContext fileOperationContext = FileOperationContext::CreateForProbe(L"GetFileInformationByName", FileName);

    PolicyResult policyResult;
    if (!policyResult.Initialize(FileName))
    {
        policyResult.ReportIndeterminatePolicyAndSetLastError(fileOperationContext);
        return FALSE;
    }

    BOOL querySucceeded = Real_GetFileInformationByName(FileName, FileInformationClass, FileInfoBuffer, FileInfoBufferSize);
    DWORD error = GetLastError();
    DWORD reportedError = GetReportedError(querySucceeded, error);

    if (!AdjustOperationContextAndPolicyResultWithFullyResolvedPath(fileOperationContext, policyResult, true))
    {
        return FALSE;
    }

    // Model W (write-overlay): a metadata probe of a path the action wrote into the
    // overlay must observe the backing file. Re-issue the query against the backing path.
    std::wstring overlayProbe = ResolveOverlayProbePath(policyResult);
    if (!overlayProbe.empty())
    {
        querySucceeded = Real_GetFileInformationByName(overlayProbe.c_str(), FileInformationClass, FileInfoBuffer, FileInfoBufferSize);
        error = GetLastError();
        reportedError = GetReportedError(querySucceeded, error);
    }

    // We can extract file attributes (to detect directories) only for the layout we understand
    // (FileStatBasicByNameInfo). For other classes we conservatively treat the type as unknown;
    // that only matters for directories, whose accesses BuildXL always allows via policy anyway.
    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    if (querySucceeded
        && FileInformationClass == BxlFileStatBasicByNameInfo
        && FileInfoBuffer != nullptr
        && FileInfoBufferSize >= sizeof(BXL_FILE_STAT_BASIC_INFORMATION))
    {
        attributes = ((BXL_FILE_STAT_BASIC_INFORMATION*)FileInfoBuffer)->FileAttributes;
    }

    FileReadContext fileReadContext;
    fileReadContext.InferExistenceFromError(reportedError);
    fileReadContext.OpenedDirectory =
        attributes != INVALID_FILE_ATTRIBUTES
        && IsDirectoryFromAttributes(
            attributes,
            ShouldTreatDirectoryReparsePointAsFile(fileOperationContext.DesiredAccess, fileOperationContext.FlagsAndAttributes, policyResult));
    fileOperationContext.OpenedFileOrDirectoryAttributes = attributes;

    AccessCheckResult accessCheck = policyResult.CheckReadAccess(RequestedReadAccess::Probe, fileReadContext);

    // Handle-resolution probe fallback (bazel-sandbox-windows).
    //
    // GetFileInformationByName is handle-less: it queries by path. When the queried path traverses
    // an UNDECLARED reparse point mid-path (e.g. the aspect_rules_js pnpm store's intra-store package
    // junctions, @a+cli@v/node_modules/@scope/b -> @scope+b@v/...), the literal-path policy check
    // above denies even though the junction's real target IS a granted input. The CreateFile read
    // fallback (see Detoured_CreateFileW) cannot apply here because there is no handle to resolve, and
    // BuildXL's fast path only resolves a reparse point when it is the LAST path component - not a
    // middle-of-path junction. Node/libuv stat the target before opening it, so a masked stat here
    // yields ERR_MODULE_NOT_FOUND before the (rescuable) CreateFile read is ever attempted, breaking
    // parity with linux-sandbox (whose symlink forest lets stat follow the link to the readable
    // target). Mirror the read fallback: open a transient read handle that FOLLOWS the reparse chain
    // (no FILE_FLAG_OPEN_REPARSE_POINT), resolve its final path, and honor that path's read policy.
    // Reads/probes only; a link whose real target is undeclared still resolves to a non-granted path
    // and stays denied, so hermeticity is preserved.
    if (accessCheck.ShouldDenyAccess() && querySucceeded)
    {
        HANDLE probeHandle = Real_CreateFileW(
            FileName,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            nullptr);
        if (probeHandle != INVALID_HANDLE_VALUE)
        {
            wstring resolvedPath;
            if (DetourGetFinalPathByHandle(probeHandle, resolvedPath) == ERROR_SUCCESS && !resolvedPath.empty())
            {
                PolicyResult resolvedPolicy;
                if (resolvedPolicy.Initialize(resolvedPath.c_str()))
                {
                    AccessCheckResult resolvedCheck = resolvedPolicy.CheckReadAccess(RequestedReadAccess::Probe, fileReadContext);
                    // Only rescue links to DECLARED inputs (carrying the DeclaredInput marker) - not files merely
                    // readable via the whole-filesystem root scope. See Detoured_CreateFileW for the
                    // execroot-symlink leak this guards against (_main -> real source tree).
                    if (!resolvedCheck.ShouldDenyAccess() && resolvedPolicy.IsDeclaredInput())
                    {
                        Dbg(L"Handle-resolution probe fallback: allowing '%s' via resolved target '%s'.",
                            policyResult.GetCanonicalizedPath().GetPathString(),
                            resolvedPolicy.GetCanonicalizedPath().GetPathString());
                        accessCheck = resolvedCheck;
                    }
                }
            }
            CloseHandle(probeHandle);
        }
    }

    if (accessCheck.ShouldDenyAccess())
    {
        error = accessCheck.DenialError(ShouldDeniedReadsAsNotFound());
        reportedError = error;
        querySucceeded = FALSE;
    }

    ReportIfNeeded(accessCheck, fileOperationContext, policyResult, reportedError, error);

    SetLastError(error);
    return querySucceeded;
}

IMPLEMENTED(Detoured_NtClose)
NTSTATUS NTAPI Detoured_NtClose(_In_ HANDLE handle)
{
#if MEASURE_DETOURED_NT_CLOSE_IMPACT
    InterlockedIncrement(&g_ntCloseHandeCount);
#endif // MEASURE_DETOURED_NT_CLOSE_IMPACT

    // NtClose can be called in some surprising circumstances.
    // One that has arisen is in some particular exception handling stacks,
    // where KiUserExceptionDispatch is at the bottom; for some reason, the
    // TEB may have a null pointer for TLS, in which case querying Detoured_IsDisabled()
    // would AV. As a workaround, we just don't check it here (there's no harm in
    // dropping a handle overlay when trying to close the handle, anyway).
    //
    // Make sure the handle is closed after the object is marked for removal from the map.
    // This way the handle will never be assigned to a another object before removed from the map
    // (whenever the map is accessed, the closed handle list is drained).

    if (!IsNullOrInvalidHandle(handle))
    {
        if (MonitorNtCreateFile())
        {
            // The map is cleared only if the MonitorNtCreateFile is on.
            // This is to make sure the behaviour for Windows builds is not altered.
            // Also if the NtCreateFile is no monitored, the map should not grow significantly. The other cases where it is updated -
            // for example CreateFileW, the map is updated by the CloseFile detoured API.
            if (UseExtraThreadToDrainNtClose())
            {
                AddClosedHandle(handle);
            }
            else
            {
                // Just remove the handle from the table directly.
                // Pass true for recursiveCall, since we don't have anything in the handle drain list and call to drain it is not needed.
                CloseHandleOverlay(handle, true);
            }
        }
    }

    return Real_NtClose(handle);
}

IMPLEMENTED(Detoured_CreatePipe)
BOOL WINAPI Detoured_CreatePipe(
    _Out_          PHANDLE               hReadPipe,
    _Out_          PHANDLE               hWritePipe,
    _In_opt_       LPSECURITY_ATTRIBUTES lpPipeAttributes,
    _In_           DWORD                 nSize)
{
    // The reason for this scope check is that CreatePipe calls many other detoured APIs, e.g., NtOpenFile, and we do not want to have any reports
    // for file accesses from those APIs (they are not what the application calls).
    DetouredScope scope;
    return Real_CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
}

/// <summary>
/// We are only detouring the FSCTL_GET_REPARSE_POINT control code in order to apply a proper translation if needed. This is in sync
/// with the treatment we give to GetFinalPathNameByHandle, where translations (if defined) are applied to the result.
/// Observe it is not necessary to enforce policies/report accesses for the FSCTL_GET_REPARSE_POINT case: a handle to the reparse point
/// source needs to be provided (which we presumably already detoured and reported) and the call returns a string with the target file path
/// without actually implying a file operation on it.
/// </summary>
IMPLEMENTED(Detoured_DeviceIoControl)
BOOL WINAPI Detoured_DeviceIoControl(
    _In_                HANDLE       hDevice,
    _In_                DWORD        dwIoControlCode,
    _In_opt_            LPVOID       lpInBuffer,
    _In_                DWORD        nInBufferSize,
    _Out_               LPVOID       lpOutBuffer,
    _In_                DWORD        nOutBufferSize,
    _Out_               LPDWORD      lpBytesReturned,
    _Out_               LPOVERLAPPED lpOverlapped
)
{
    DetouredScope scope;

    BOOL result = Real_DeviceIoControl(
        hDevice,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize,
        lpBytesReturned,
        lpOverlapped);

    if (scope.Detoured_IsDisabled()
        || IgnoreDeviceIoControlGetReparsePoint()
        // We are only interested in the FSCTL_GET_REPARSE_POINT control code.
        || dwIoControlCode != FSCTL_GET_REPARSE_POINT
        // If the call fails, no need to translate anything
        || !result)
    {
        return result;
    }

    PREPARSE_DATA_BUFFER pReparseDataBuffer = (PREPARSE_DATA_BUFFER)lpOutBuffer;
    DWORD reparsePointType = pReparseDataBuffer->ReparseTag;

    // Only interested in symlinks/mountpoints reparse point types
    if (!IsActionableReparsePointType(reparsePointType))
    {
        return result;
    }

    DWORD lastError = GetLastError();

    // Retrieve the target name from the reparse data buffer and translate it
    std::wstring target;
    GetTargetNameFromReparseData(pReparseDataBuffer, reparsePointType, target);

    std::wstring translation;
    TranslateFilePath(target, translation);

    // If the translation returned back the same path, nothing to do.
    if (target == translation)
    {
        SetLastError(lastError);
        return result;
    }

    // Check that the translation will fit in the provided buffer.
    // The translation will be used for both print and substitute name, so we need a buffer that can hold both
    // The paths are stored without the null terminating char, so no need to account for it
    if (translation.length() * 2 * sizeof(WCHAR) > nOutBufferSize)
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        *lpBytesReturned = 0;
        return 0;
    }

    // Update the returned structure with the translated path
    SetTargetNameFromReparseData(pReparseDataBuffer, reparsePointType, translation);
    *lpBytesReturned = (USHORT)translation.length() * 2 * sizeof(WCHAR);

    SetLastError(lastError);
    return result;
}

#undef IMPLEMENTED
