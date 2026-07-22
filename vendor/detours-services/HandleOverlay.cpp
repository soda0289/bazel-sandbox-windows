// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"
#include "HandleOverlay.h"
#include <map>

bool g_initialized;
CRITICAL_SECTION g_handleOverlayLock;

class HandleOverlayMap;
HandleOverlayMap* g_handleOverlayMap;

class HandleOverlayMap {
public:
    void MapRegisterHandleOverlay(HANDLE handle, HandleOverlayRef& newRef) {

        // Now, insert (move-assign to empty) or replace (destruct then move-assign). Note that despite perhaps
        // holding g_handleOverlayLock, we require here that shared_ptr is thread safe for refcount changes (as documented).
        // When destructing, we need to atomically decrement the ref-count ; some other routine may still be using another ref to the same overlay.
        m_map[handle] = std::move(newRef);
    }

    HandleOverlayRef TryLookupHandleOverlay(HANDLE handle) {
        auto iter = m_map.find(handle);
        if (iter == m_map.end()) {
            return HandleOverlayRef();
        }
        else {
            // Create a new ref (refcount increases) via copy-construction of the existing one.
            return HandleOverlayRef(iter->second);
        }
    }

    void CloseHandleOverlay(HANDLE handle) {
        m_map.erase(handle);
    }

private:
    std::map<HANDLE, HandleOverlayRef> m_map;
};

// Holds g_handleOverlayLock
struct HandleOverlayLockGuard {
    HandleOverlayLockGuard() {
        assert(g_initialized);
        EnterCriticalSection(&g_handleOverlayLock);
    }

    ~HandleOverlayLockGuard() {
        LeaveCriticalSection(&g_handleOverlayLock);
    }

    // This is a member function to make sure we always get the map inside a lock.
    inline HandleOverlayMap* GetGlobalOverlayMap() {
        assert(g_handleOverlayMap != nullptr);
        return g_handleOverlayMap;
    }
};

void InitializeHandleOverlay() {

    assert(!g_initialized);
    InitializeCriticalSection(&g_handleOverlayLock);
    // Always create the OverlayMap. This is called from DllAttach, so it is inside a lock already.
    // Doing it here, we save a check and creating the map inside GetOverlayMap.
    g_handleOverlayMap = new HandleOverlayMap();

    g_initialized = true;
}

void RegisterHandleOverlay(HANDLE handle, AccessCheckResult const& accessCheck, PolicyResult const& policy, HandleType type) {
    // First we create a shared_ptr for a new HandleOverlay (ref count 1).
    // Note: This must be created outside of the HandleOverlayLockGuard lock below,
    //       because otherwise we will get a deadlock - the HandleMap lock and the RtlAllocHeap in the OS heap allocator lock.
    HandleOverlayRef newRef = std::make_shared<HandleOverlay>(accessCheck, policy, type);

    // Get an extra reference to the handle. This way the shared_ptr is not deleted when removed from the map.
    // (See CloseHandleOverlay for the full deadlock-avoidance rationale.)
    HandleOverlayRef overlay = TryLookupHandleOverlay(handle, false);

    {
        HandleOverlayLockGuard lock;
        HandleOverlayMap* map = lock.GetGlobalOverlayMap();
        map->MapRegisterHandleOverlay(handle, newRef);
    }
}

HandleOverlayRef TryLookupHandleOverlay(HANDLE handle, bool drain) {
    UNREFERENCED_PARAMETER(drain);
    HandleOverlayLockGuard lock;
    HandleOverlayMap* map = lock.GetGlobalOverlayMap();
    return map->TryLookupHandleOverlay(handle);
}

void CloseHandleOverlay(HANDLE handle, bool inRecursion) {
    UNREFERENCED_PARAMETER(inRecursion);

    // Get an extra reference to the handle. This way the shared_ptr is not deleted when removed from the
    // map. The removal from the map happens while holding the HandleOverlayLockGuard lock (see below).
    // If the map holds the last ref to the shared_ptr, when removing it, the destructor of the object will be called,
    // thus triggering deletion of the object from the OS heap - RtlFreeHeap. The freeing of memory happens
    // while a heap lock is held - so if destruction happens, the order of lock aquisition is HandleMapLock--> HeapLock.
    // RtlAllocateHeap also calls NtClose, while holding the heap lock, so it is possible to try to get the locks in
    // order HeapLock-->HandleMapLock. These two clearly point to a deadlock due to inverted lock aquisition.
    HandleOverlayRef overlay = TryLookupHandleOverlay(handle, false);

    {
        // Extra scope here to make sure the lock is destroyed before the overlay above goes out of scope
        // and releases the last ref to the object pointer.
        HandleOverlayLockGuard lock;
        HandleOverlayMap* map = lock.GetGlobalOverlayMap();
        map->CloseHandleOverlay(handle);
    }
}