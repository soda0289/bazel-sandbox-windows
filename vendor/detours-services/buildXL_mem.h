// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "globals.h"

#pragma once

#define BUILDXL_DETOURS_MEMORY_ALLOC_FLAGS HEAP_ZERO_MEMORY

// This file defines a memory interface for BuildXL Detours, using the dd_ prefix.
// The general allocation APIs are stubbed out and one should call only the dd_* methods.
// The memory allocation done from the BuildXL Detours library happens on a private heap.

// malloc and free versions for this DLL.
inline void* dd_malloc(size_t size)
{
    assert(g_hPrivateHeap != nullptr);
    void* ret = HeapAlloc(g_hPrivateHeap, BUILDXL_DETOURS_MEMORY_ALLOC_FLAGS, size);
    return ret;
}

inline void dd_free(void* pMem)
{
    assert(g_hPrivateHeap != nullptr);
    if (pMem == nullptr)
    {
        return;
    }

    HeapFree(g_hPrivateHeap, HEAP_ZERO_MEMORY, pMem);
}

// New news and deletes operators that call the private heap.
inline void* operator new(size_t count)
{
    return dd_malloc(count);
}

inline void* operator new[](size_t count)
{
    return dd_malloc(count);
}

inline void operator delete(void* ptr)
{
    dd_free(ptr);
}

inline void operator delete[](void* ptr)
{
    dd_free(ptr);
}

// Make sure noone calls malloc and free directly.
inline __declspec(restrict) void* malloc(size_t size)
{
    UNREFERENCED_PARAMETER(size);
    assert(!"Use dd_malloc method instead.");
}

inline void free(void* pMem)
{
    UNREFERENCED_PARAMETER(pMem);
    assert(!"Use dd_free method instead.");
}
