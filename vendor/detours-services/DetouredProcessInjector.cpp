// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"
using namespace std;
#include "DetouredProcessInjector.h"
#include "DetoursHelpers.h"
#include <iomanip>
#include "buildXL_mem.h"

// A flag that gets set for 64 bit processes
bool DetouredProcessInjector::s_is64BitProcess = sizeof(void *) == 8;

unsigned long g_injectionTimeoutInMinutes = 0;

// Address of the function that checks if a process is a Wow64 process. Not all
// versions of Windows have this function, so this value could be null. Casting
// from FARPROC causes warning, disable
#pragma warning( push )
#pragma warning( disable: 4191 ) // requiredSize is the result of a function call which may fail, but there is no other way to use that function
typedef BOOL(WINAPI *lp_IsWow64Process) (HANDLE, PBOOL);
static lp_IsWow64Process s_fnIsWow64Process =
    reinterpret_cast<lp_IsWow64Process>(GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process"));
#pragma warning( pop )

// A flag that gets set if the current process is a Wow64 process
bool DetouredProcessInjector::s_isWow64Process =
    !DetouredProcessInjector::s_is64BitProcess && isWow64Process(GetCurrentProcess());

// Check if the given process is a Wow64 process
bool DetouredProcessInjector::isWow64Process(HANDLE processHandle)
{
    BOOL isWow64;
    return s_fnIsWow64Process != nullptr && s_fnIsWow64Process(processHandle, &isWow64) && isWow64;
}

void DetouredProcessInjector::Clear()
{
    _initialized = false;
    _payload.reset(nullptr);
    _payloadSize = 0;
    _otherHandles.clear();
    _dllX64.clear();
    _dllX86.clear();
}

// Initialize object with the payload wrapper that has the following data:
// uint32_t size - the size of the block
// uint32_t handleCount - the number of handles
// uint64_t handles - handles passed from the parent. All of these are
//                    "other" handles now; the fixed device-map / remote-injector
//                    / report pipe handles were removed (hard fork).
// payload
bool DetouredProcessInjector::Init(LPCBYTE payloadWrapper, std::wstring& errorMessage, _Out_ LPCBYTE* payload, _Out_ uint32_t& payloadSize)
{
    errorMessage = L"";
    *payload = nullptr;
    payloadSize = 0;

    if (payloadWrapper == nullptr)
    {
        errorMessage = L"Payload is null";
        return false;
    }

    LockGuard lock(_injectorLock);

    // Each object can be initialized only once.
    if (_initialized)
    {
        return true;
    }

    const uint32_t *data = reinterpret_cast<const uint32_t *>(payloadWrapper);
    uint32_t size = *data;
    data++;

    // The data must at least contain the size, handle count, and the
    // minimum number of handles.
    if (!(size >= 2 * sizeof(uint32_t) + c_minHandleCount * sizeof(uint64_t))) 
    {
        errorMessage = L"Payload has incorrect size: ";
        errorMessage += std::to_wstring(size);

        return false;
    }

    assert(size >= 2 * sizeof(uint32_t) + c_minHandleCount * sizeof(uint64_t));
    size -= 2 * sizeof(uint32_t);

    // Copy known handles
    uint32_t handleCount = *data;
    data++;

    if (!(handleCount >= c_minHandleCount && size >= handleCount * sizeof(uint64_t)))
    {
        errorMessage = L"Payload has incorrect handle count or size: (handleCount: ";
        errorMessage += std::to_wstring(handleCount);
        errorMessage += L", size: ";
        errorMessage += std::to_wstring(size);
        errorMessage += L")";

        return false;
    }

    assert(handleCount >= c_minHandleCount && size >= handleCount * sizeof(uint64_t));
    const uint64_t *handles = reinterpret_cast<const uint64_t *>(data);

    // Compute the size remaining after the handles are copied
    size -= handleCount * sizeof(uint64_t);

    handleCount -= c_minHandleCount;

    // Copy other handles
    if (handleCount == 0)
    {
        _otherHandles.clear();
    }
    else {
        while (handleCount--)
        {
            _otherHandles.push_back(Uint64ToHandle(*handles++));
        }
    }

    // Copy payload immediately only if this process is not WOW64 process.
    if (!s_isWow64Process)
    {
        _payloadSize = size;

        if (size == 0)
        {
            _payload = nullptr;
        }
        else
        {
            _payload = make_unique<unsigned char[]>(size);
            memcpy_s(_payload.get(), size, handles, size);
        }

        *payload = _payload.get();
        payloadSize = _payloadSize;
    }
    else
    {
        *payload = (LPCBYTE)handles;
        payloadSize = size;
    }

    _initialized = true;
    return true;
}

void DetouredProcessInjector::SetPayload(LPCBYTE payload, uint32_t payloadSize)
{
    if (_payload.get() != nullptr)
    {
        // Payload can be set only once.
        return;
    }

    _payloadSize = payloadSize;

    if (payloadSize == 0)
    {
        _payload = nullptr;
    }
    else
    {
        _payload = make_unique<unsigned char[]>(payloadSize);
        memcpy_s(_payload.get(), payloadSize, payload, payloadSize);
    }
}


void DetouredProcessInjector::SetHandles(uint32_t otherHandleCount, PHANDLE otherHandles)
{
    if (otherHandleCount == 0)
    {
        _otherHandles.clear();
    }
    else {
        _otherHandles.assign(otherHandles, otherHandles + otherHandleCount);
    }
}

DWORD DetouredProcessInjector::LocalInjectProcess(HANDLE processHandle, bool inheritedHandles)
{
    LockGuard lock(_injectorLock);

    // Install detours
    LPCSTR dll = isWow64Process(processHandle) ? _dllX86.data() : _dllX64.data();
    if (!DetourUpdateProcessWithDll(processHandle, &dll, 1))
    {
        DWORD err = GetLastError();
        Dbg(L"DetouredProcessInjector::LocalInjectProcess: Failed to inject %S from %s process into %s process (error code: 0x%08x)",
              dll, s_isWow64Process ? L"WOW64" : L"Native", isWow64Process(processHandle) ? L"WOW64" : L"Native", (int)err);
        return err;
    }

    // Allocate space for the payload wrapper.
    uint32_t size = WrapperSize();
    std::unique_ptr<unsigned char[]> payloadWrapper = make_unique<unsigned char[]>(size);

    // Write sizes
    uint32_t *sizes = reinterpret_cast<uint32_t *>(payloadWrapper.get());
    *sizes++ = size;
    *sizes++ = static_cast<uint32_t>(c_minHandleCount + _otherHandles.size());

    // Write handles. Only optional "other" handles remain; the fixed
    // device-map / remote-injector-pipe / report-pipe handles were removed.
    uint64_t *handles = reinterpret_cast<uint64_t *>(sizes);

    if (!_otherHandles.empty())
    {
        for (auto i : _otherHandles)
        {
            *handles++ = inheritedHandles ? HandleToUint64(i) : DuplicateHandleToUint64(processHandle, i);
        }
    }

    // Copy payload
    errno_t memcpyerror = memcpy_s(handles, _payloadSize, _payload.get(), _payloadSize);
    if (memcpyerror != 0)
    {
        Dbg(L"DetouredProcessInjector::LocalInjectProcess: Failed to do memcpy (error code: 0x%08x)", (int)memcpyerror);
        return ERROR_PARTIAL_COPY;
    }

    if (!DetourCopyPayloadToProcess(processHandle, _payloadGuid, payloadWrapper.get(), size))
    {
        DWORD err = GetLastError();
        Dbg(L"DetouredProcessInjector::LocalInjectProcess: Failed to copy payload to process (error code: 0x%08x)", (int)err);
        return err;
    }

    return ERROR_SUCCESS;
}
