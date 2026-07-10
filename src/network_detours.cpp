// Winsock detours implementing BazelSandbox's -N / -n network sandboxing.
//
// This translation unit is compiled WITHOUT the vendored stdafx.h force-include
// so that <winsock2.h> is included before <windows.h> (the reverse order is a
// hard compile error). Everything Winsock-typed stays local to this file; the
// public interface in network_detours.h uses only plain types.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <windows.h>
#include <detours.h>

#include <cwchar>

#include "network_detours.h"

namespace bazelsandbox {
namespace {

// The policy in effect for this process. Written once during attach (before any
// child code runs) and only read afterwards, so no synchronization is needed.
NetworkPolicy g_policy = NetworkPolicy::Allow;
bool g_attached = false;

// ---- real function pointers -------------------------------------------------
using Connect_t = decltype(&::connect);
using WSAConnect_t = decltype(&::WSAConnect);
using Sendto_t = decltype(&::sendto);
using WSASendTo_t = decltype(&::WSASendTo);
using Bind_t = decltype(&::bind);
using Getaddrinfo_t = decltype(&::getaddrinfo);
using GetAddrInfoW_t = decltype(&::GetAddrInfoW);
using Gethostbyname_t = decltype(&::gethostbyname);

Connect_t Real_connect = ::connect;
WSAConnect_t Real_WSAConnect = ::WSAConnect;
Sendto_t Real_sendto = ::sendto;
WSASendTo_t Real_WSASendTo = ::WSASendTo;
Bind_t Real_bind = ::bind;
Getaddrinfo_t Real_getaddrinfo = ::getaddrinfo;
GetAddrInfoW_t Real_GetAddrInfoW = ::GetAddrInfoW;
Gethostbyname_t Real_gethostbyname = ::gethostbyname;

// ---- policy helpers ---------------------------------------------------------

// A destination address is "loopback" if it is 127.0.0.0/8 (IPv4) or ::1 (IPv6).
// Non-IP families (AF_UNIX and friends) are treated as local and allowed.
bool IsLoopbackAddr(const sockaddr* sa, int len) {
    if (sa == nullptr || len < static_cast<int>(sizeof(sa->sa_family))) {
        // No address to inspect (e.g. connectionless send with null dest).
        return true;
    }
    if (sa->sa_family == AF_INET) {
        if (len < static_cast<int>(sizeof(sockaddr_in))) return false;
        const auto* s4 = reinterpret_cast<const sockaddr_in*>(sa);
        // 127.0.0.0/8 -> high-order octet == 127.
        return (ntohl(s4->sin_addr.s_addr) >> 24) == 127;
    }
    if (sa->sa_family == AF_INET6) {
        if (len < static_cast<int>(sizeof(sockaddr_in6))) return false;
        const auto* s6 = reinterpret_cast<const sockaddr_in6*>(sa);
        return IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) != 0;
    }
    // AF_UNIX / AF_BTH / etc.: local transports, not "the network".
    return true;
}

// Whether an outbound connection/send/bind to the given address is permitted.
bool AddrAllowed(const sockaddr* sa, int len) {
    switch (g_policy) {
        case NetworkPolicy::Allow:
            return true;
        case NetworkPolicy::BlockAll:
            return false;  // even loopback is blocked (-n has no loopback)
        case NetworkPolicy::LoopbackOnly:
        default:
            return IsLoopbackAddr(sa, len);
    }
}

// A host name is "local" if it resolves within the machine: literal loopback
// addresses or the well-known localhost aliases. Used to keep localhost name
// resolution working under -N while blocking outbound DNS.
bool IsLocalNameW(const wchar_t* name) {
    if (name == nullptr || name[0] == L'\0') {
        // Null/empty node (AI_PASSIVE bind lookups) is local.
        return true;
    }
    if (_wcsicmp(name, L"localhost") == 0) return true;
    if (_wcsicmp(name, L"ip6-localhost") == 0) return true;
    if (wcscmp(name, L"127.0.0.1") == 0) return true;
    if (wcscmp(name, L"::1") == 0) return true;
    // Any 127.x.y.z literal.
    if (wcsncmp(name, L"127.", 4) == 0) return true;
    return false;
}

bool IsLocalNameA(const char* name) {
    if (name == nullptr || name[0] == '\0') return true;
    if (_stricmp(name, "localhost") == 0) return true;
    if (_stricmp(name, "ip6-localhost") == 0) return true;
    if (strcmp(name, "127.0.0.1") == 0) return true;
    if (strcmp(name, "::1") == 0) return true;
    if (strncmp(name, "127.", 4) == 0) return true;
    return false;
}

bool NameResolutionAllowed(bool isLocalName) {
    switch (g_policy) {
        case NetworkPolicy::Allow:
            return true;
        case NetworkPolicy::BlockAll:
            return false;  // no DNS, not even localhost
        case NetworkPolicy::LoopbackOnly:
        default:
            return isLocalName;
    }
}

// ---- detour implementations -------------------------------------------------

int WSAAPI Detoured_connect(SOCKET s, const sockaddr* name, int namelen) {
    if (!AddrAllowed(name, namelen)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_connect(s, name, namelen);
}

int WSAAPI Detoured_WSAConnect(SOCKET s, const sockaddr* name, int namelen,
                               LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                               LPQOS lpSQOS, LPQOS lpGQOS) {
    if (!AddrAllowed(name, namelen)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS,
                           lpGQOS);
}

int WSAAPI Detoured_sendto(SOCKET s, const char* buf, int len, int flags,
                           const sockaddr* to, int tolen) {
    if (!AddrAllowed(to, tolen)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI Detoured_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                              LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                              const sockaddr* lpTo, int iTolen,
                              LPWSAOVERLAPPED lpOverlapped,
                              LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (!AddrAllowed(lpTo, iTolen)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
                          dwFlags, lpTo, iTolen, lpOverlapped,
                          lpCompletionRoutine);
}

int WSAAPI Detoured_bind(SOCKET s, const sockaddr* name, int namelen) {
    // Deny binding a listener to a non-loopback interface when restricted, so a
    // sandboxed action can't accept connections from the outside world.
    if (!AddrAllowed(name, namelen)) {
        WSASetLastError(WSAEACCES);
        return SOCKET_ERROR;
    }
    return Real_bind(s, name, namelen);
}

int WSAAPI Detoured_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName,
                                const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    if (!NameResolutionAllowed(IsLocalNameA(pNodeName))) {
        if (ppResult != nullptr) *ppResult = nullptr;
        WSASetLastError(WSAHOST_NOT_FOUND);
        return WSAHOST_NOT_FOUND;
    }
    return Real_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI Detoured_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                                 const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    if (!NameResolutionAllowed(IsLocalNameW(pNodeName))) {
        if (ppResult != nullptr) *ppResult = nullptr;
        WSASetLastError(WSAHOST_NOT_FOUND);
        return WSAHOST_NOT_FOUND;
    }
    return Real_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

hostent* WSAAPI Detoured_gethostbyname(const char* name) {
    if (!NameResolutionAllowed(IsLocalNameA(name))) {
        WSASetLastError(WSAHOST_NOT_FOUND);
        return nullptr;
    }
    return Real_gethostbyname(name);
}

}  // namespace

// ---- public API -------------------------------------------------------------

NetworkPolicy GetNetworkPolicy() { return g_policy; }

bool IsAfdDeviceName(const wchar_t* ntPath) {
    if (ntPath == nullptr) return false;
    // Strip a leading NT prefix: "\Device\" or "\??\".
    const wchar_t* p = ntPath;
    if (_wcsnicmp(p, L"\\Device\\", 8) == 0) {
        p += 8;
    } else if (_wcsnicmp(p, L"\\??\\", 4) == 0) {
        p += 4;
    } else {
        return false;
    }
    // Must name the "Afd" device, either exactly or as "Afd\..." (e.g. Endpoint).
    if (_wcsnicmp(p, L"Afd", 3) != 0) return false;
    return p[3] == L'\0' || p[3] == L'\\';
}

void InitializeAndAttachNetworkDetours() {
    // Read the policy handed down by the launcher (inherited by every child).
    wchar_t value[32];
    DWORD n = GetEnvironmentVariableW(kNetworkEnvVar, value, 32);
    if (n > 0 && n < 32) {
        if (_wcsicmp(value, L"loopback") == 0) {
            g_policy = NetworkPolicy::LoopbackOnly;
        } else if (_wcsicmp(value, L"block") == 0) {
            g_policy = NetworkPolicy::BlockAll;
        }
    }

    // No restriction -> attach nothing (zero overhead in the common case).
    if (g_policy == NetworkPolicy::Allow || g_attached) {
        return;
    }

    // Attach the Winsock detours in their own transaction, independent of the
    // file-access detours. ws2_32.dll is guaranteed present because this DLL
    // imports it (the network_detours target links ws2_32), so the Real_*
    // pointers resolved above are valid at attach time.
    if (DetourTransactionBegin() != NO_ERROR) {
        return;
    }
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&reinterpret_cast<PVOID&>(Real_connect), Detoured_connect);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_WSAConnect), Detoured_WSAConnect);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_sendto), Detoured_sendto);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_WSASendTo), Detoured_WSASendTo);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_bind), Detoured_bind);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_getaddrinfo), Detoured_getaddrinfo);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_GetAddrInfoW), Detoured_GetAddrInfoW);
    DetourAttach(&reinterpret_cast<PVOID&>(Real_gethostbyname), Detoured_gethostbyname);
    if (DetourTransactionCommit() == NO_ERROR) {
        g_attached = true;
    } else {
        DetourTransactionAbort();
    }
}

}  // namespace bazelsandbox
