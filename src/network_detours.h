// Network sandboxing for BazelSandbox: reproduces the effect of Bazel's Linux
// sandbox -N (loopback-only) / -n (no network) flags on Windows by intercepting
// Winsock APIs with Detours.
//
// This header is deliberately winsock-free (only plain integer/enum/wchar_t
// types) so it can be included from the vendored engine translation units
// (DetouredFunctions.cpp, DetoursServices.cpp) which are force-compiled with
// stdafx.h (<windows.h> first). Including <winsock2.h> after <windows.h> is a
// hard error, so all the Winsock machinery lives in network_detours.cpp, which
// is compiled as a separate, stdafx-free translation unit.

#pragma once

namespace bazelsandbox {

// Mirrors Bazel linux-sandbox network semantics.
enum class NetworkPolicy {
    Allow = 0,         // no restriction (env var unset)
    LoopbackOnly = 1,  // -N: only 127.0.0.0/8 and ::1 are reachable
    BlockAll = 2,      // -n: no network at all, not even loopback
};

// Name of the environment variable the launcher uses to hand the policy to the
// injected DLL. It is inherited by every child/grandchild automatically, so the
// policy propagates through the whole process tree without touching the manifest
// blob format. Values: "loopback" (-N), "block" (-n); unset/anything else = Allow.
// CODESYNC: keep in sync with the launcher (src/main.cpp).
constexpr const wchar_t* kNetworkEnvVar = L"BAZEL_SANDBOX_NETWORK";

// Returns the policy in effect for this process (set during DLL attach).
NetworkPolicy GetNetworkPolicy();

// True when any network restriction is in effect.
inline bool IsNetworkRestricted() { return GetNetworkPolicy() != NetworkPolicy::Allow; }

// True only for -n (block everything). Used by the NtCreateFile AFD hardening:
// under -N we must let sockets be created so loopback keeps working, so AFD
// creation is only denied outright when ALL network is blocked.
inline bool IsAllNetworkBlocked() { return GetNetworkPolicy() == NetworkPolicy::BlockAll; }

// Reads kNetworkEnvVar, stores the policy, and (if restricted) attaches the
// Winsock detours in their own Detour transaction. Safe to call once from
// DllProcessAttach; a no-op (beyond reading the env var) when unrestricted.
void InitializeAndAttachNetworkDetours();

// True if the given NT object path names the Ancillary Function Driver (AFD),
// i.e. the kernel device Winsock opens to create a socket. Matches, case
// insensitively, "\Device\Afd..." and "\??\Afd..." (with or without a trailing
// "\Endpoint"). Used by the NtCreateFile/ZwCreateFile hooks to block socket
// creation at the syscall layer under -n.
bool IsAfdDeviceName(const wchar_t* ntPath);

}  // namespace bazelsandbox
