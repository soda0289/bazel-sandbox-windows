// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#include "UniqueHandle.h"
#include "DebuggingHelpers.h"

using std::unique_ptr;
using std::vector;
using std::string;

// This class injects the payload and the detours DLL into a process. It may
// do so for the process it just created (local injection). It can be created
// with the data to be used, or it can be initialized from the previously
// injected payload during child process startup so the sandbox propagates
// down the whole process tree.
//
// The NT DOS-device-map feature and the remote (WOW64 -> Native64) injection
// handshake were removed in this hard fork; all injection is now local.
class DetouredProcessInjector
{
private:
    uint32_t _tag;            // this value is a sanity check to make sure that we are looking at a valid object

    // A flag set for wow64 process
    static bool s_isWow64Process;

    // A flag set for 64 bit process
    static bool s_is64BitProcess;

    // Minimum number of handles required. The injector no longer passes any
    // fixed handles (device map / remote-injector pipe / report pipe were all
    // removed); only optional "other" handles remain in the wire format.
    static const uint32_t c_minHandleCount = 0;

    static const uint32_t c_buildxlInjectorTag = 0xD031B09E;      // DOMIno BONE

    unique_ptr<unsigned char[]> _payload = nullptr;
    uint32_t _payloadSize = 0;
    vector<HANDLE> _otherHandles;
    string _dllX86;
    string _dllX64;
    GUID _payloadGuid;
    bool _initialized = false;

    CRITICAL_SECTION _injectorLock;

    class LockGuard
    {
    private:
        CRITICAL_SECTION &_lock;
    public:
        LockGuard(CRITICAL_SECTION &lock) noexcept : _lock(lock) { EnterCriticalSection(&_lock); }
        ~LockGuard() { LeaveCriticalSection(&_lock); }
        LockGuard() = delete;
        LockGuard(const LockGuard&) = delete;
        LockGuard& operator=(LockGuard const &) = delete;
    };

    // Convert uint64 to HANDLE
    static inline HANDLE Uint64ToHandle(uint64_t value)
    {
        if (s_is64BitProcess)
        {
            return reinterpret_cast<HANDLE>(value);
        }
        else {
#pragma warning( push )
#pragma warning( disable: 4312 )
            return reinterpret_cast<HANDLE>(static_cast<uint32_t>(value & UINT32_MAX));
#pragma warning( pop )
        }
    }

    // Duplicate handle for the specified process and convert the new handle to uint64
    static inline uint64_t DuplicateHandleToUint64(HANDLE processHandle, HANDLE value)
    {
        HANDLE targetValue;
        if (value == INVALID_HANDLE_VALUE ||
                !DuplicateHandle(GetCurrentProcess(), value, processHandle, &targetValue, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            targetValue = INVALID_HANDLE_VALUE;
        }

        return HandleToUint64(targetValue);
    }

    // Given all data, compute the size of the wrapped payload
    uint32_t inline WrapperSize() const
    {
        // The data must contain the size, handle count, the handles, and the payload
        return static_cast<uint32_t>(2 * sizeof(uint32_t) + (c_minHandleCount + _otherHandles.size()) * sizeof(uint64_t) + _payloadSize);
    }


    // Clear the object (free memory, etc.)
    void Clear();

public:
    // Check if the process is wow64
    static bool isWow64Process(HANDLE processHandle);
    
    // The only constructor requires the payload GUID
    DetouredProcessInjector(const GUID &payloadGuid) : _tag(c_buildxlInjectorTag), _payloadGuid(payloadGuid)
    {
        InitializeCriticalSection(&_injectorLock);
    }

    ~DetouredProcessInjector()
    {
        DeleteCriticalSection(&_injectorLock);
    }

    // Populate the data from the serialized wrapper.
    bool Init(LPCBYTE payloadWrapper, std::wstring& errorMessage, _Out_ LPCBYTE* payload, _Out_ uint32_t& payloadSize);

    void SetPayload(LPCBYTE payload, uint32_t payloadSize);

    // Set the dll paths to be injected
    void inline SetDlls(LPCSTR dllX86, LPCSTR dllX64)
    {
        _dllX86 = dllX86;
        _dllX64 = dllX64;
    }

    inline bool IsValid() const
    {
#ifdef _DEBUG
        assert(_tag == c_buildxlInjectorTag);
#endif
        return _tag == c_buildxlInjectorTag && _initialized;
    }

    // This method will inject the data stored in the object into the specified process.
    //   processHandle - the process to inject
    //   inheritedHandles - when true, all handles are inherited.
    //                      When false, none or only some handles
    //                      are inherited. The handles stored in
    //                      the object need to be duplicated.
    DWORD LocalInjectProcess(HANDLE processHandle, bool inheritedHandles);

    // Remote injection (WOW64 -> Native64 via a top-of-process-tree server pipe)
    // was removed with the injector handshake; all injection is now local.
    DWORD InjectProcess(HANDLE processHandle, bool inheritedHandles)
    {
        return LocalInjectProcess(processHandle, inheritedHandles);
    }

    // No default constructor, no copies
    DetouredProcessInjector() = delete;
    DetouredProcessInjector(const DetouredProcessInjector &) = delete;
    DetouredProcessInjector& operator=(DetouredProcessInjector const &) = delete;

#pragma warning( push )
#pragma warning( disable: 4302 4310 4311 4826 )
    // Convert a handle to uint64_t
    static inline uint64_t HandleToUint64(HANDLE value)
    {
        if (s_is64BitProcess)
        {
            return static_cast<uint64_t>(reinterpret_cast<int64_t>(value));
        }
        else {
            // Generally we don't want to sign extend the handle, only in case of the INVALID_HANDLE_VALUE. The compiler
            // helpfully provides a warning when sign-extending pointers, therefore disable above warnings
            return value == INVALID_HANDLE_VALUE ? (uint64_t)(int64_t)(int32_t)INVALID_HANDLE_VALUE : (uint64_t)value;
        }
    }
#pragma warning( pop )
};

