// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"

#include <algorithm>
#include <memory>

#include "DataTypes.h"
#include "DebuggingHelpers.h"
#include "DetoursHelpers.h"
#include "FileAccessHelpers.h"
#include "SendReport.h"
#include "PolicyResult.h"
#include "buildXL_mem.h"
#include "ReportType.h"

using std::unique_ptr;

extern volatile LONG g_detoursAllocatedNoLockConcurentPoolEntries;
extern volatile LONG64 g_detoursMaxHandleHeapEntries;
extern volatile LONG64 g_detoursHandleHeapEntries;

// ----------------------------------------------------------------------------
// HELPER FUNCTION DEFINITIONS
// ----------------------------------------------------------------------------

void SendReportString(_In_z_ wchar_t const* dataString)
{
    if (g_reportFileHandle == NULL || g_reportFileHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    OVERLAPPED overlapped;
    ZeroMemory(&overlapped, sizeof(OVERLAPPED));
    // This offset specifies "append".
    overlapped.Offset = 0xFFFFFFFF;
    overlapped.OffsetHigh = 0xFFFFFFFF;

    size_t length = wcslen(dataString);
    size_t reportLineLength = sizeof(wchar_t) * length;

    DWORD bytesWritten;
    DWORD lastError = GetLastError();
    if (!WriteFile(g_reportFileHandle, dataString, (DWORD)reportLineLength, &bytesWritten, &overlapped))
    {
        DWORD error = GetLastError();
        std::wstring errorMsg = DebugStringFormat(L"SendReportString: Failed to write file access report line '%s' (error code: 0x%08X)", dataString, (int)error);
        Dbg(errorMsg.c_str());
        HandleDetoursInjectionAndCommunicationErrors(DETOURS_PIPE_WRITE_ERROR_4, errorMsg.c_str(), DETOURS_WINDOWS_LOG_MESSAGE_4);
    }

    SetLastError(lastError);
}

/**
 ** Escapes new line characters from filenames by replacing the \ with \\
 ** Returns true if the filename needed to be escaped, with the escaped name set in escapedFileName.
 **
 ** CODESYNC: Public/Src/Engine/Processes/SandboxedProcessReports.cs
 */
bool EscapeFileName(PCWSTR fileName, size_t fileNameLength, std::wstring &escapedFileName)
{
    size_t escapeCharIndex = wcscspn(fileName, L"\r\n"); // Returns the length of fileName if \r or \n not found.
    if (escapeCharIndex < fileNameLength)
    {
        size_t startIndex = 0;

        while (startIndex < fileNameLength)
        {
            // Append the part of the string from the starting index up to the character to be escaped.
            escapedFileName.append(fileName, startIndex, escapeCharIndex);

            // Escape \r or \n
            switch (fileName[startIndex + escapeCharIndex])
            {
                case L'\r':
                    escapedFileName.append(L"/\\r");
                    break;
                case L'\n':
                    escapedFileName.append(L"/\\n");
                    break;
            }

            startIndex += escapeCharIndex + 1;
            escapeCharIndex = startIndex < fileNameLength ? wcscspn(&fileName[startIndex], L"\r\n") : 0;
        }

        return true;
    }

    return false;
}

// ----------------------------------------------------------------------------
// FUNCTION DEFINITIONS
// ----------------------------------------------------------------------------
void ReportFileAccess(
    FileOperationContext const& fileOperationContext,
    FileAccessStatus status,
    PolicyResult const& policyResult,
    AccessCheckResult const& accessCheckResult,
    DWORD error,
    wchar_t const* filter)
{
    ReportFileAccess(fileOperationContext, status, policyResult, accessCheckResult, error, error, filter);
}

void ReportFileAccess(
    FileOperationContext const& fileOperationContext,
    FileAccessStatus status,
    PolicyResult const& policyResult,
    AccessCheckResult const& accessCheckResult,
    DWORD error,
    DWORD rawError,
    wchar_t const* filter)
{
    if (g_reportFileHandle == NULL || g_reportFileHandle == INVALID_HANDLE_VALUE) {
        return;
    }

    PCWSTR fileName, filterStr;
    std::wstring escapedFileName;

    if (policyResult.IsIndeterminate()) {
        fileName = fileOperationContext.NoncanonicalPath;
    }
    else {
        fileName = policyResult.GetCanonicalizedPath().GetPathString();
    }

    if (fileName == nullptr) {
        fileName = L"";
    }

    size_t fileNameLength = wcslen(fileName); // in characters

    if (EscapeFileName(fileName, fileNameLength, escapedFileName))
    {
        fileName = escapedFileName.c_str();
        fileNameLength = wcslen(fileName);
    }

    if (filter == nullptr || accessCheckResult.Access != RequestedAccess::Enumerate) {
        filterStr = L"";
    }
    else {
        filterStr = filter;
    }

    if (g_currentProcessCommandLine == nullptr) {
        g_currentProcessCommandLine = L"";
    }

    size_t filterLength = wcslen(filterStr); // in characters
    size_t fileProcessCommandLineLength = wcslen(g_currentProcessCommandLine); // in characters
    size_t operationLen = wcslen(fileOperationContext.Operation); // in characters
    size_t reportBufferSize = fileNameLength + filterLength + fileProcessCommandLineLength + operationLen + 124; // in characters

    // Adding 124 should be enough for now since the max values for the members of the message are:
    // buildxl::common::ReportType::kFileAccess - 1 char
    // g_currentProcessId - 8 chars
    // FileOperationContext.Id - 8 chars
    // FileOperationContext.CorrelationId - 8 chars
    // accessCheckResult.RequestedAccess - 1 char
    // status - 1 char
    // (int)(accessCheckResult.ReportLevel == ReportLevel::ReportExplicit) - 1 char(0 or 1)
    // Error - 8 chars
    // RawError - 8 chars
    // fileOperationContext.DesiredAccess - 8 chars
    // fileOperationContext.ShareMode - 8 chars
    // fileOperationContext.CreationDisposition - 8 chars,
    // fileOperationContext.FlagsAndAttributes - 8 chars
    // policyResult.IsIndeterminate() ? 0 : policyResult.GetPathId() - 8 chars
    // filename separately added
    // filterStr separately added
    // fileOrDirectoryAttribute - 8 chars
    // g_currentProcessCommandLine - separately added
    // 15 chars for | chars
    // 5 chars for ',', ':', '\r', '\n', '\0' chars
    // Total : 128 characters.

    unique_ptr<wchar_t[]> report(new wchar_t[reportBufferSize]);
    assert(report.get());

    // Only report the process command line args when the C# code has requested it and when the file operation context is "Process"
    // This way we only transmit the command line arguments once
    int constructReportResult = -1;
    if (ReportProcessArgs() && !_wcsicmp(fileOperationContext.Operation, L"Process")) {
        // The command line arguments may contain the | (pipe) character - the same character that is used here as a field separator.
        // It is important to keep the command line arguments last in this string because the C# code will 
        // check how many | chars the string contains and if there are more fields than expected, it will assume that  
        // everything after the last expected (13th) field is part of the command line arguments.
        //
        // The command line can contain newline characters. In the C# code our pipe reader performs read line, and thus it can read part of
        // the command line. Thus, the command line needs to be sanitized. This is OK because no further consumer should rely on the exact
        // form of the command line. Here, newline characters are simply replaced with space. Replacing it with space is fine because
        // it won't change the length of the string, and thus no need to resize the report buffer.
        std::wstring commandLine(g_currentProcessCommandLine);
        std::replace(commandLine.begin(), commandLine.end(), L'\r', L' ');
        std::replace(commandLine.begin(), commandLine.end(), L'\n', L' ');

        constructReportResult = swprintf_s(report.get(), reportBufferSize, L"%d,%s:%lx|%lx|%lx|%x|%x|%x|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%s|%s|%s\r\n",
            buildxl::common::ReportType::kFileAccess,
            fileOperationContext.Operation,
            g_currentProcessId,
            fileOperationContext.Id,
            fileOperationContext.CorrelationId,
            accessCheckResult.Access,
            status,
            (int)(accessCheckResult.Level == ReportLevel::ReportExplicit),
            error,
            rawError,
            fileOperationContext.DesiredAccess,
            fileOperationContext.ShareMode,
            fileOperationContext.CreationDisposition,
            fileOperationContext.FlagsAndAttributes,
            fileOperationContext.OpenedFileOrDirectoryAttributes,
            policyResult.IsIndeterminate() ? 0 : policyResult.GetPathId(),
            fileName,
            filterStr,
            commandLine.c_str());
    }
    else
    {
        constructReportResult = swprintf_s(report.get(), reportBufferSize, L"%d,%s:%lx|%lx|%lx|%x|%x|%x|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%s|%s\r\n",
            buildxl::common::ReportType::kFileAccess,
            fileOperationContext.Operation,
            g_currentProcessId,
            fileOperationContext.Id,
            fileOperationContext.CorrelationId,
            accessCheckResult.Access,
            status,
            (int)(accessCheckResult.Level == ReportLevel::ReportExplicit),
            error,
            rawError,
            fileOperationContext.DesiredAccess,
            fileOperationContext.ShareMode,
            fileOperationContext.CreationDisposition,
            fileOperationContext.FlagsAndAttributes,
            fileOperationContext.OpenedFileOrDirectoryAttributes,
            policyResult.IsIndeterminate() ? 0 : policyResult.GetPathId(),
            fileName,
            filterStr);
    }

    if (constructReportResult <= 0)
    {
        Dbg(L"ReportFileAccess:swprintf_s: %d <= 0", constructReportResult);
        assert(!L"ReportFileAccess:swprintf_s: %d <= 0");
    }
    else
    {
        SendReportString(report.get());
    }
}
