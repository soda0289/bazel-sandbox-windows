// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// DetoursServices.cpp : Defines the exported functions for the DLL application.

// Adapted from MidBuild

#pragma warning( disable : 4710 4820 4350 4668)

#include "stdafx.h"

#ifdef _DLL
#error DetoursServices must be statically linked with a native runtime. Linking to DLL native runtime results in it loading into processes we detour, which unsafely assumes that they can find it.
#endif

#include <crtdbg.h>

#include "DataTypes.h"
#include "DebuggingHelpers.h"
#include "DetouredFunctions.h"
#include "DetouredFunctionTypes.h"
#include "DetoursHelpers.h"
#include "DetoursServices.h"
#include "FileAccessHelpers.h"
#include "globals.h"
#include "buildXL_mem.h"
#include "DetouredScope.h"
#include "StringOperations.h"
#include "HandleOverlay.h"
#include "DetouredProcessInjector.h"
#include "SendReport.h"
#include "locale.h"

// BazelSandbox network sandboxing (-N / -n). Winsock-free interface; the actual
// Winsock detours live in a separate stdafx-free translation unit.
#include "network_detours.h"

#define BUILDXL_DETOURS_CREATE_PROCESS_RETRY_COUNT 5
#define BUILDXL_DETOURS_MS_TO_SLEEP 10

extern "C" {
    NTSTATUS NTAPI ZwSetInformationFile(
        _In_  HANDLE                 FileHandle,
        _Out_ PIO_STATUS_BLOCK       IoStatusBlock,
        _In_  PVOID                  FileInformation,
        _In_  ULONG                  Length,
        _In_  FILE_INFORMATION_CLASS FileInformationClass);

    NTSTATUS NTAPI ZwCreateFile(
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
        _In_     ULONG              EaLength);

    NTSTATUS NTAPI ZwOpenFile(
        _Out_ PHANDLE            FileHandle,
        _In_  ACCESS_MASK        DesiredAccess,
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK   IoStatusBlock,
        _In_  ULONG              ShareAccess,
        _In_  ULONG              OpenOptions);
}


extern "C" {
    NTSTATUS NTAPI NtQueryDirectoryFile(
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
        _In_     BOOLEAN                RestartScan);

    NTSTATUS NTAPI NtQueryDirectoryFileEx(
        _In_     HANDLE                 FileHandle,
        _In_opt_ HANDLE                 Event,
        _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
        _In_opt_ PVOID                  ApcContext,
        _Out_    PIO_STATUS_BLOCK       IoStatusBlock,
        _Out_    PVOID                  FileInformation,
        _In_     ULONG                  Length,
        _In_     FILE_INFORMATION_CLASS FileInformationClass,
        _In_     ULONG                  QueryFlags,
        _In_opt_ PUNICODE_STRING        FileName);

    NTSTATUS NTAPI ZwQueryDirectoryFile(
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
        _In_     BOOLEAN                RestartScan);

    // Handle-less metadata probes (used by the image loader / LoadLibrary and other
    // callers). FileInformation is declared PVOID so we don't depend on
    // FILE_BASIC_INFORMATION / FILE_NETWORK_OPEN_INFORMATION from the SDK headers.
    NTSTATUS NTAPI NtQueryAttributesFile(
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PVOID              FileInformation);

    NTSTATUS NTAPI NtQueryFullAttributesFile(
        _In_  POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PVOID              FileInformation);
}

/*

This translation unit is the DLL bootstrap for the sandbox enforcement engine.
Detours injects this library into each sandboxed process; the parent (our
BazelSandbox launcher) hands it a binary File Access Manifest payload via the
Detours payload mechanism.

All setup happens when the DLL is loaded into the target process, inside the
DllMain / DLL_PROCESS_ATTACH handler: DllProcessAttach() locates the payload,
ParseFileAccessManifest() (DetoursHelpers.cpp) parses it into the global
manifest tree + flags, and the DetourAttach() table below installs the Win32 /
Nt hooks (bodies in DetouredFunctions.cpp). After initialization the parsed
manifest globals are read-only, so hook bodies need no synchronization to read
them.

The manifest wire format is a compact little-endian binary blob produced by our
own src/manifest_builder.cpp (NOT the legacy BuildXL text format). Its layout
is documented at the builder and in DataTypes.h (the Manifest*_t structs the
parser casts over). Access reporting, when a report path is present, is written
as UTF-8 lines via SendReport.cpp.

*/

using std::string;
using std::vector;
using std::unordered_set;
using std::unique_ptr;
using std::make_unique;

// ----------------------------------------------------------------------------
// GLOBALS
// ----------------------------------------------------------------------------

_locale_t g_invariantLocale;

DWORD g_currentProcessId;

FileAccessManifestFlag g_fileAccessManifestFlags;

FileAccessManifestExtraFlag g_fileAccessManifestExtraFlags;

PCManifestRecord g_manifestTreeRoot;

HANDLE g_reportFileHandle;

LPCSTR g_lpDllNameX86;
LPCSTR g_lpDllNameX64;

DetouredProcessInjector* g_pDetouredProcessInjector = nullptr;

HANDLE g_hPrivateHeap = nullptr;


// Bazel fork (Model W): overlay backing-store root (see globals.h).
wchar_t* g_bazelWriteOverlayRoot = nullptr;
// Bazel fork (Model W): overlay source root, stripped to map virtual->backing.
wchar_t* g_bazelOverlaySourceRoot = nullptr;

//
// Real Windows API function pointers
//

CreateProcessW_t Real_CreateProcessW;
CreateProcessA_t Real_CreateProcessA;
CreateProcessAsUserW_t Real_CreateProcessAsUserW;
CreateProcessAsUserA_t Real_CreateProcessAsUserA;
CreateFileW_t Real_CreateFileW;

RtlFreeHeap_t Real_RtlFreeHeap;
RtlAllocateHeap_t Real_RtlAllocateHeap;
RtlReAllocateHeap_t Real_RtlReAllocateHeap;
VirtualAlloc_t Real_VirtualAlloc;

CreateFileA_t Real_CreateFileA;
GetVolumePathNameW_t Real_GetVolumePathNameW;
GetFileAttributesA_t Real_GetFileAttributesA;
GetFileAttributesW_t Real_GetFileAttributesW;
GetCurrentDirectoryW_t Real_GetCurrentDirectoryW;
GetCurrentDirectoryA_t Real_GetCurrentDirectoryA;
GetFileAttributesExW_t Real_GetFileAttributesExW;
GetFileAttributesExA_t Real_GetFileAttributesExA;
CloseHandle_t Real_CloseHandle;

CopyFileW_t Real_CopyFileW;
CopyFileA_t Real_CopyFileA;
CopyFileExW_t Real_CopyFileExW;
CopyFileExA_t Real_CopyFileExA;
CopyFile2_t Real_CopyFile2;
CopyFileTransactedW_t Real_CopyFileTransactedW;
CopyFileTransactedA_t Real_CopyFileTransactedA;
MoveFileW_t Real_MoveFileW;
MoveFileA_t Real_MoveFileA;
MoveFileExW_t Real_MoveFileExW;
MoveFileExA_t Real_MoveFileExA;
MoveFileWithProgressW_t Real_MoveFileWithProgressW;
MoveFileWithProgressA_t Real_MoveFileWithProgressA;
MoveFileTransactedW_t Real_MoveFileTransactedW;
MoveFileTransactedA_t Real_MoveFileTransactedA;
ReplaceFileW_t Real_ReplaceFileW;
ReplaceFileA_t Real_ReplaceFileA;
DeleteFileA_t Real_DeleteFileA;
DeleteFileW_t Real_DeleteFileW;

CreateHardLinkW_t Real_CreateHardLinkW;
CreateHardLinkA_t Real_CreateHardLinkA;
CreateSymbolicLinkW_t Real_CreateSymbolicLinkW;
CreateSymbolicLinkA_t Real_CreateSymbolicLinkA;
FindFirstFileW_t Real_FindFirstFileW;
FindFirstFileA_t Real_FindFirstFileA;
FindFirstFileExW_t Real_FindFirstFileExW;
FindFirstFileExA_t Real_FindFirstFileExA;
FindNextFileW_t Real_FindNextFileW;
FindNextFileA_t Real_FindNextFileA;
FindClose_t Real_FindClose;
GetFileInformationByHandleEx_t Real_GetFileInformationByHandleEx;
GetFileInformationByHandle_t Real_GetFileInformationByHandle;
SetFileInformationByHandle_t Real_SetFileInformationByHandle;
OpenFileMappingW_t Real_OpenFileMappingW;
OpenFileMappingA_t Real_OpenFileMappingA;
GetTempFileNameW_t Real_GetTempFileNameW;
GetTempFileNameA_t Real_GetTempFileNameA;
CreateDirectoryW_t Real_CreateDirectoryW;
CreateDirectoryA_t Real_CreateDirectoryA;
CreateDirectoryExW_t Real_CreateDirectoryExW;
CreateDirectoryExA_t Real_CreateDirectoryExA;
RemoveDirectoryW_t Real_RemoveDirectoryW;
RemoveDirectoryA_t Real_RemoveDirectoryA;
DecryptFileW_t Real_DecryptFileW;
DecryptFileA_t Real_DecryptFileA;
EncryptFileW_t Real_EncryptFileW;
EncryptFileA_t Real_EncryptFileA;
OpenEncryptedFileRawW_t Real_OpenEncryptedFileRawW;
OpenEncryptedFileRawA_t Real_OpenEncryptedFileRawA;
OpenFileById_t Real_OpenFileById;
GetFinalPathNameByHandleW_t Real_GetFinalPathNameByHandleW;
GetFinalPathNameByHandleA_t Real_GetFinalPathNameByHandleA;

NtClose_t Real_NtClose;
NtCreateFile_t Real_NtCreateFile;
NtOpenFile_t Real_NtOpenFile;
NtQueryAttributesFile_t Real_NtQueryAttributesFile;
NtQueryFullAttributesFile_t Real_NtQueryFullAttributesFile;
GetFileInformationByName_t Real_GetFileInformationByName;
ZwCreateFile_t Real_ZwCreateFile;
ZwOpenFile_t Real_ZwOpenFile;
NtQueryDirectoryFile_t Real_NtQueryDirectoryFile;
NtQueryDirectoryFileEx_t Real_NtQueryDirectoryFileEx;
ZwQueryDirectoryFile_t Real_ZwQueryDirectoryFile;
ZwSetInformationFile_t Real_ZwSetInformationFile;

CreatePipe_t Real_CreatePipe;
DeviceIoControl_t Real_DeviceIoControl;

// Value used to signal the the exit code of the current process cannot be retrieved
#define PROCESS_EXIT_CODE_CANNOT_BE_RETRIEVED 0xFFFFFF9A

// Value used to as an exit code when terminating the current process because the detouring process has failed.
#define PROCESS_DETOURING_FAILED_EXIT_CODE 0xFFFFFF9B

// ----------------------------------------------------------------------------
// FUNCTION DEFINITIONS
// ----------------------------------------------------------------------------

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

//
// Code to create a detoured process
//
// This code is just to create the initial detoured process,
// and it will also be used to create detoured nested processes.
// The pfCreateProcessW function pointer points at the CreateProcessW
// function we should run.  When called within a detour of CreateProcessW
// it will point at the prior CreateProcessW entry point.  When called
// from outside (not within the detour of CreateProcessW) it will be
// passed the normal public CreateProcessW entry point.
//

CreateDetouredProcessStatus
WINAPI
InternalCreateDetouredProcess(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpcwWorkingDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    HANDLE hJob,
    DetouredProcessInjector *pInjector,
    LPPROCESS_INFORMATION lpProcessInformation,
    CreateProcessW_t pfCreateProcessW,
    CreateProcessAsUserW_t pfCreateProcessAsUserW,
    bool hardExitOnDetoursErrorIfEnabled)
{
    // No detours should be called recursively from here.
    DetouredScope scope;

    DWORD error = ERROR_SUCCESS;
    BOOL fProcCreated = FALSE;
    BOOL fProcDetoured = FALSE;
    CreateDetouredProcessStatus status = CreateDetouredProcessStatus::Succeeded;
    DWORD creationFlags = dwCreationFlags;
    unsigned nRetryCount = 0;

    bool needsInjection = pInjector != nullptr && pInjector->IsValid();

    if (needsInjection || hJob != 0)
    {
        creationFlags |= CREATE_SUSPENDED;
    }

    // It appears the AV might hold exclusive read lock while scaning and this can fail create process.
    // Inject some retries.
    while (true)
    {
        // Create the process as requested, but make sure it's suspended
        fProcCreated = hToken == nullptr
            ? pfCreateProcessW(
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                creationFlags,
                lpEnvironment,
                lpcwWorkingDirectory,
                lpStartupInfo,
                lpProcessInformation)
            : pfCreateProcessAsUserW(
                hToken,
                lpApplicationName,
                lpCommandLine,
                lpProcessAttributes,
                lpThreadAttributes,
                bInheritHandles,
                creationFlags,
                lpEnvironment,
                lpcwWorkingDirectory,
                lpStartupInfo,
                lpProcessInformation);

        if (fProcCreated == 0) // Failed
        {
            if (GetLastError() == ERROR_ACCESS_DENIED)
            {
                if (nRetryCount < BUILDXL_DETOURS_CREATE_PROCESS_RETRY_COUNT)
                {
                    Sleep(BUILDXL_DETOURS_MS_TO_SLEEP + (nRetryCount * BUILDXL_DETOURS_MS_TO_SLEEP));
                    nRetryCount++;
                    continue;
                }
            }
        }

        break;
    }

    if (!fProcCreated)
    {
        error = GetLastError();
    }
    else if (needsInjection)
    {
        // Check if all handles are inherited. While extended attributes are not necessarily about
        // handle inheritance, the structure is undocumented, so we assume that if the extended
        // attributes are preset, we are inheriting specific handles. The flag, when not set
        // will cause the injection function to duplicate required handles. When set, we assume
        // all handles are inherited and there is no need for duplication.
        bool fullInheritHandles = bInheritHandles == TRUE && !(dwCreationFlags & EXTENDED_STARTUPINFO_PRESENT);

        // Do not retry process injection on the same process handle on failure. This is because the target process may
        // have been updated with the Detours dll. Trying to inject the same process again will result in ERROR_INVALID_OPERATION.
        // Instead of retrying process injection, retry the process creation as a whole.
        error = pInjector->InjectProcess(lpProcessInformation->hProcess, fullInheritHandles);
        fProcDetoured = error == ERROR_SUCCESS;
    }

    if ((fProcDetoured || !needsInjection) && fProcCreated)
    {
        status = CreateDetouredProcessStatus::Succeeded;

        if (hJob != 0 && !AssignProcessToJobObject(hJob, lpProcessInformation->hProcess)) {
            status = CreateDetouredProcessStatus::JobAssignmentFailed;
            error = GetLastError();
            Dbg(L"Assigning to job failed, error: %08X", (int)error);
        }
    }
    else if (fProcCreated)
    {
        status = CreateDetouredProcessStatus::DetouringFailed;
    }
    else
    {
        status = CreateDetouredProcessStatus::ProcessCreationFailed;
    }

    if (status == CreateDetouredProcessStatus::Succeeded &&
        !(dwCreationFlags & CREATE_SUSPENDED) &&
        dwCreationFlags != creationFlags &&
        ResumeThread(lpProcessInformation->hThread) == -1)
    {

        status = CreateDetouredProcessStatus::ProcessResumeFailed;
        error = GetLastError();
    }

    if (status != CreateDetouredProcessStatus::Succeeded)
    {
        // Clean-up
        if (fProcCreated)
        {
            Dbg(L"Detouring failed. Application name: '%s' Command line: '%s' Error: 0x%08X",
                lpApplicationName, lpCommandLine, (int)error);
            // The process never ran any code, as the main thread was initially suspended, so let's just kill it again.
            BOOL terminatedProcess = TerminateProcess(lpProcessInformation->hProcess, PROCESS_DETOURING_FAILED_EXIT_CODE);
            if (terminatedProcess)
            {
                CloseHandle(lpProcessInformation->hProcess);
                lpProcessInformation->hProcess = 0;
                CloseHandle(lpProcessInformation->hThread);
                lpProcessInformation->hThread = 0;
                lpProcessInformation->dwProcessId = 0;
            }
            else
            {
                DWORD terminateProcessError = GetLastError();
                Dbg(L"Termination of undetoured process failed. Application name: '%s' Command line: '%s' Error: %08X",
                    lpApplicationName, lpCommandLine, (int)terminateProcessError);
            }
        }
    }

    if (status == CreateDetouredProcessStatus::DetouringFailed ||
        status == CreateDetouredProcessStatus::JobAssignmentFailed ||
        status == CreateDetouredProcessStatus::HandleInheritanceFailed ||
        status == CreateDetouredProcessStatus::ProcessResumeFailed ||
        status == CreateDetouredProcessStatus::PayloadCopyFailed)
    {
        std::wstring errorMsg = DebugStringFormat(L"InternalCreateDetouredProcess: Failed to create process (CreateDetouredProcessStatus: %d, error code: 0x%08X)", (int)status, (int)error);
        // Ensure that the error message is sent to both the Detours error file and to the log file.
        Dbg(errorMsg.c_str());

        if (hardExitOnDetoursErrorIfEnabled)
        {
            // Hard exit is set on the final time this function should be called, meaning this failure is fatal and will not be retried.
            // We only want to log to the detours error file if all retries have been exhausted.
            HandleDetoursInjectionAndCommunicationErrors(DETOURS_CREATE_PROCESS_ERROR_5, errorMsg.c_str(), DETOURS_WINDOWS_LOG_MESSAGE_5, hardExitOnDetoursErrorIfEnabled);
        }
    }

    // HandleDetoursInjectionAndCommunicationErrors may have changed the last error code, so we need to set it again.
    SetLastError(error);

    return status;
}


//
// Code that runs in detoured process
//

#pragma warning( push )
#pragma warning( disable: 4100 ) // Unreferenced parameters

// Debug hook for CRT-sourced failures, e.g. heap corruption detection.
// Versus the default handling, this one triggers a post-mortem debugger,
// if configured, via debugbreak exceptions. This replaces the default behavior
// of showing an Abort / Retry / Ignore dialog.
static int __cdecl CrtDebugHook(int nReportType, wchar_t* szMsg, int* pnRet) {
    RaiseFailFastException(nullptr, nullptr, FAIL_FAST_GENERATE_EXCEPTION_ADDRESS);
    return FALSE;
}
#pragma warning( pop )

static bool DllProcessDetach()
{
    return TRUE;
}

/*

This function runs during DLL process attach, DllMain executing with DLL_PROCESS_ATTACH.
Special restrictions apply when running within this context; please take great care
not to violate these restrictions. For more info, see DllMain in MSDN. Specifically,
all forms of dynamic library binding (LoadLibrary and friends) are forbidden.

The purpose of this function is to use the Detours API, which has been statically linked
into this PE/COFF image, to detour several important Windows file access APIs. "Detour"
here, when used as a verb, refers to intercepting calls to functions, usually functions
exported by DLLs, to invoke a different implementation. The functions which detour
the file access APIs implement the file access monitoring functionality of this library,
including potentially denying access to files, based on the contents of the file access
manifest that was provided by the creator of this process.

This function also handles locating and parsing the file access manifest.
The file access manifest specifies which files and directories this process may access,
and specifies what action to take when the process violates the file access manifest
(by requesting access to files that are outside of the manifest).  The actions taken
(independently) may include:
* printing diagnostic messages on stderr,
* allowing or prohibiting the file access request.

If this function fails in the presence of a payload, it returns false, and the caller,
DllMain, also returns false. This prevents the DLL from attaching to the process,
which usually has the effect of causing the process into which this DLL was injected
to fail to load. This is the desired behavior. If the file access APIs cannot be detoured,
then the process cannot execute with the desired behavior (of enforcing file access).

*/

// Flipped to true when DllProcessAttach has completed for the Detouring case.
bool g_isAttached = false;

static bool DllProcessAttach()
{
    // One-time init for the Detours library.
    DetourInit();

    // Debug hook for CRT-sourced failures, e.g. heap corruption detection.
    // Causes a debugger break (or post-mortem launch) instead of showing a modal dialog.
    _CrtSetReportHookW2(_CRT_RPTHOOK_INSTALL, &CrtDebugHook);

    g_hPrivateHeap = HeapCreate(0, 40960, 0); // Commit initially 40k of memory for the private heap.
    if (g_hPrivateHeap == nullptr)
    {
        Dbg(L"Failure creating private heap. Last Error: %d", (int)GetLastError());
        return false;
    }

    g_pDetouredProcessInjector = new DetouredProcessInjector(g_manifestGuid);

    int error;

    if (!LocateAndParseFileAccessManifest()) {
        // When DetoursServices.dll is loaded, there always must be a valid FileAccess manifest.
        // Otherwise it is an error.
        return false;
    }

    g_invariantLocale = _wcreate_locale(LC_CTYPE, L"");
    InitializeHandleOverlay();

#define ATTACH(Name) \
    Real_##Name = ::Name; \
    error = DetourAttach((PVOID*)&Real_##Name, Detoured_##Name); \
    if (error != ERROR_SUCCESS) { \
        Dbg(L"Failed to attach to function: " L#Name); \
        failed = true; \
    }
    // end #define ATTACH

    bool failed = false;

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        Dbg(L"DetourTransactionBegin() failed.  Cannot detour file access.");
        return false;
    }

    // Next, attach to (detour) each API function of interest.
    {
#pragma warning( push )
#pragma warning( disable : 5039)
        ATTACH(CreateProcessA);
        ATTACH(CreateProcessW);
        ATTACH(CreateProcessAsUserA);
        ATTACH(CreateProcessAsUserW);

        ATTACH(CreateFileW);
            ATTACH(CreateFileA);

            ATTACH(GetVolumePathNameW);
            ATTACH(GetFileAttributesA);
            ATTACH(GetFileAttributesW);
            ATTACH(GetFileAttributesExW);
            ATTACH(GetFileAttributesExA);
            ATTACH(GetCurrentDirectoryW);
            ATTACH(GetCurrentDirectoryA);

            // GetFileInformationByName is a modern (Win8+/Win11) handle-less attribute probe
            // resolved dynamically: it may be absent on older OSes and isn't guaranteed to be
            // in the import lib. When present, hook it so libuv's fast fs.stat path is filtered
            // like the CreateFile/GetFileAttributes read paths. When absent, libuv falls back to
            // CreateFileW (already hooked), so skipping is safe.
            Real_GetFileInformationByName = (GetFileInformationByName_t)::GetProcAddress(
                ::GetModuleHandleW(L"kernelbase.dll"), "GetFileInformationByName");
            if (Real_GetFileInformationByName != nullptr)
            {
                error = DetourAttach((PVOID*)&Real_GetFileInformationByName, Detoured_GetFileInformationByName);
                if (error != ERROR_SUCCESS) {
                    Dbg(L"Failed to attach to function: GetFileInformationByName");
                    failed = true;
                }
            }

            ATTACH(GetFileInformationByHandle);
            ATTACH(GetFileInformationByHandleEx);
            ATTACH(SetFileInformationByHandle);

            ATTACH(CopyFileW);
            ATTACH(CopyFileA);
            ATTACH(CopyFileExW);
            ATTACH(CopyFileExA);
            ATTACH(CopyFileTransactedW);
            ATTACH(CopyFileTransactedA);

            // CopyFile2 (Win8+) is a self-contained kernel copy that is NOT backstopped
            // by the NtCreateFile hook, so a Model W action would leak its destination to
            // the real execroot without an explicit hook. Resolve it dynamically (absent on
            // older OSes; not guaranteed in the import lib). When present, hook it so the
            // overlay redirect + policy apply as they do for CopyFileEx.
            Real_CopyFile2 = (CopyFile2_t)::GetProcAddress(
                ::GetModuleHandleW(L"kernelbase.dll"), "CopyFile2");
            if (Real_CopyFile2 == nullptr)
            {
                Real_CopyFile2 = (CopyFile2_t)::GetProcAddress(
                    ::GetModuleHandleW(L"kernel32.dll"), "CopyFile2");
            }
            if (Real_CopyFile2 != nullptr)
            {
                error = DetourAttach((PVOID*)&Real_CopyFile2, Detoured_CopyFile2);
                if (error != ERROR_SUCCESS) {
                    Dbg(L"Failed to attach to function: CopyFile2");
                    failed = true;
                }
            }
            ATTACH(MoveFileW);
            ATTACH(MoveFileA);
            ATTACH(MoveFileExW);
            ATTACH(MoveFileExA);
            ATTACH(MoveFileWithProgressW);
            ATTACH(MoveFileWithProgressA);
            ATTACH(MoveFileTransactedW);
            ATTACH(MoveFileTransactedA);
            ATTACH(ReplaceFileW);
            ATTACH(ReplaceFileA);
            ATTACH(DeleteFileA);
            ATTACH(DeleteFileW);

            ATTACH(CreateHardLinkW);
            ATTACH(CreateHardLinkA);
            ATTACH(CreateSymbolicLinkW);
            ATTACH(CreateSymbolicLinkA);
            ATTACH(FindFirstFileW);
            ATTACH(FindFirstFileA);
            ATTACH(FindFirstFileExW);
            ATTACH(FindFirstFileExA);
            ATTACH(FindNextFileW);
            ATTACH(FindNextFileA);
            ATTACH(FindClose);
            ATTACH(OpenFileMappingW);
            ATTACH(OpenFileMappingA);
            ATTACH(GetTempFileNameW);
            ATTACH(GetTempFileNameA);
            ATTACH(CreateDirectoryW);
            ATTACH(CreateDirectoryA);
            ATTACH(CreateDirectoryExW);
            ATTACH(CreateDirectoryExA);
            ATTACH(RemoveDirectoryW);
            ATTACH(RemoveDirectoryA);
            ATTACH(DecryptFileW);
            ATTACH(DecryptFileA);
            ATTACH(EncryptFileW);
            ATTACH(EncryptFileA);
            ATTACH(OpenEncryptedFileRawW);
            ATTACH(OpenEncryptedFileRawA);
            ATTACH(OpenFileById);

            ATTACH(NtCreateFile);
            ATTACH(NtOpenFile);
            ATTACH(NtQueryAttributesFile);
            ATTACH(NtQueryFullAttributesFile);
            ATTACH(ZwCreateFile);
            ATTACH(ZwOpenFile);
            ATTACH(NtQueryDirectoryFile);
            ATTACH(NtQueryDirectoryFileEx);
            ATTACH(ZwQueryDirectoryFile);
            // See comments in DetorsFunctions.cpp
            // on the Detoured_NtClose for more information 
            // on this function.
            ATTACH(NtClose);
            ATTACH(ZwSetInformationFile);

            ATTACH(CreatePipe);

            ATTACH(GetFinalPathNameByHandleW);
            ATTACH(GetFinalPathNameByHandleA);

            ATTACH(DeviceIoControl);
#pragma warning( pop )
    }

    if (failed) {
        DetourTransactionAbort();
        Dbg(L"The Detours package could not be initialized.  Failed to attach to one or more functions.");
        return false;
    }

    error = DetourTransactionCommit();

    if (error != ERROR_SUCCESS) {
        DetourTransactionAbort();
        Dbg(L"The Detours package could not be initialized.  The transaction could not be committed.");
        return false;
    }

    //
    // File APIs successfully detoured.
    //

#undef ATTACH

    g_isAttached = true;

    // BazelSandbox: apply the network policy (-N / -n) carried in the
    // BAZEL_SANDBOX_NETWORK environment variable (inherited by every child).
    // This reads the policy and, if the process is network-restricted, attaches
    // the Winsock detours in their own transaction. Must run before the child's
    // entry point, which it does (all of DllProcessAttach completes first).
    bazelsandbox::InitializeAndAttachNetworkDetours();

    return true;
}


#pragma warning( disable : 4100)

BOOL
WINAPI
DllMain(
    _In_ HINSTANCE instance,
    _In_ ULONG reason,
    _In_ PVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        if (DllProcessAttach()) {
            return TRUE;
        }
        DebuggerOutputDebugString(L"DllProcessAttach() failed.\r\n", true);
        return FALSE;

    case DLL_PROCESS_DETACH:
        if (DllProcessDetach()) {
            return TRUE;
        }
        return FALSE;

    default:
        return TRUE;
    }
}
