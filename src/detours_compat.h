// Compatibility shim for building the vendored BuildXL DetoursServices engine
// against STOCK upstream microsoft/Detours.
//
// BuildXL ships a private *fork* of Detours that adds a one-time initialization
// entry point, DetourInit(), which DetoursServices.cpp's DllProcessAttach calls.
// Upstream Detours has no such function: it performs its own initialization
// lazily and internally (on the first DetourTransactionBegin/DetourAttach), so
// there is nothing for us to do. Providing this no-op lets the unmodified
// vendored sources link against upstream Detours.
#pragma once

inline void DetourInit() noexcept {}
