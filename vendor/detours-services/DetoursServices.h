// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "FileAccessHelpers.h"

// ----------------------------------------------------------------------------
// DEFINES
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// TYPE DEFINITIONS
// ----------------------------------------------------------------------------

typedef unsigned __int64 ulong;

// ----------------------------------------------------------------------------
// CONSTANTS
// ----------------------------------------------------------------------------

const GUID g_manifestGuid = { 0x7CFDBB96, 0xC3D6, 0x47CD, { 0x90, 0x26, 0x8F, 0xA8, 0x63, 0xC5, 0x2F, 0xEC } };

// ----------------------------------------------------------------------------
// INTERFACES
// ----------------------------------------------------------------------------

__interface __declspec(uuid("7CFDBB96-C3D6-47CD-9026-8FA863C52FEC")) IDetourServicesManifest;
interface IDetourServicesManifest
{
};


// ----------------------------------------------------------------------------
// FUNCTION DECLARATIONS
// ----------------------------------------------------------------------------

// Status indication for creating a detoured process; useful for preventing ambiguous error indication when a process fails to start.
// This must be in sync with CreateDetouredProcessStatus.cs
enum class CreateDetouredProcessStatus : int {
    Succeeded = 0,
    ProcessCreationFailed = 1,
    DetouringFailed = 2,
    JobAssignmentFailed = 3,
    HandleInheritanceFailed = 4,
    ProcessResumeFailed = 5,
    PayloadCopyFailed = 6,
	CreateProcessAttributeListFailed = 7,
};

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
    DetouredProcessInjector *injector,
    LPPROCESS_INFORMATION lpProcessInformation,
    CreateProcessW_t pfCreateProcessW,
    CreateProcessAsUserW_t pfCreateProcessAsUserW,
    bool hardExitOnDetoursErrorIfEnabled
);
