// Tiny test helper used by the enforcement tests. It performs one file-system
// operation (or spawns a child that does) and maps the result to a stable exit
// code so tests can distinguish "allowed" from "sandbox-denied":
//
//   0  = operation succeeded (access allowed)
//   10 = operation denied (ERROR_ACCESS_DENIED, i.e. the sandbox blocked it)
//   20 = operation failed for some other reason
//   30 = bad usage
//
// Usage:
//   probe read  <path>            open <path> for reading
//   probe write <path>            create/overwrite <path>
//   probe delete <path>           delete <path>
//   probe deleteh <path>          delete <path> via SetFileInformationByHandle
//   probe delonclose <path>       delete <path> via FILE_FLAG_DELETE_ON_CLOSE
//   probe replace <old> <new>     ReplaceFileW(<old>, <new>) atomic replace
//   probe mkdir <path>            create directory <path>
//   probe rename <src> <dst>      move/rename <src> to <dst>
//   probe spawn <exe> [args...]   run a child process, return its exit code
//                                 (used to verify child-process propagation)
//   probe connect <host> <port>   attempt an outbound TCP connect
//                                 (used to verify -N / -n network sandboxing)
//   probe stdio                   verify all three std handles are usable
//   probe exit  <code>            exit with <code> (exit-code fidelity)
//   probe sleep <ms>              sleep <ms> (used to exercise -T timeout)
//   probe cwdis <dir>             0 iff the current directory equals <dir>
//   probe tempfile <dir>          GetTempFileNameW in <dir> (intercepted API)
//   probe ntread <path>           open <path> for read via native NtCreateFile

#include <windows.h>
#include <winternl.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace {

constexpr int kOk = 0;
constexpr int kDenied = 10;
constexpr int kOtherError = 20;
constexpr int kBadUsage = 30;

int MapLastError() {
    DWORD e = GetLastError();
    return (e == ERROR_ACCESS_DENIED) ? kDenied : kOtherError;
}

int DoRead(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    CloseHandle(h);
    return kOk;
}

int DoWrite(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    const char data[] = "probe";
    DWORD written = 0;
    WriteFile(h, data, sizeof(data) - 1, &written, nullptr);
    CloseHandle(h);
    return kOk;
}

int DoDelete(const wchar_t* path) {
    if (DeleteFileW(path)) return kOk;
    return MapLastError();
}

int DoMkdir(const wchar_t* path) {
    if (CreateDirectoryW(path, nullptr)) return kOk;
    return MapLastError();
}

int DoRename(const wchar_t* src, const wchar_t* dst) {
    if (MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING)) return kOk;
    return MapLastError();
}

// Rename via a handle (SetFileInformationByHandle + FILE_RENAME_INFO). This is
// the path modern runtimes (Rust/uutils, .NET, MSVC) use instead of MoveFile,
// and is exactly what fusion's coreutils-based actions exercise.
int DoRenameByHandle(const wchar_t* src, const wchar_t* dst) {
    HANDLE h = CreateFileW(src, DELETE | SYNCHRONIZE, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();

    size_t dstLen = wcslen(dst);
    size_t bufSize = sizeof(FILE_RENAME_INFO) + (dstLen + 1) * sizeof(wchar_t);
    std::vector<uint8_t> buf(bufSize, 0);
    auto* fri = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    fri->ReplaceIfExists = TRUE;
    fri->RootDirectory = nullptr;
    fri->FileNameLength = static_cast<DWORD>(dstLen * sizeof(wchar_t));
    memcpy(fri->FileName, dst, dstLen * sizeof(wchar_t));

    BOOL ok = SetFileInformationByHandle(h, FileRenameInfo, fri,
                                         static_cast<DWORD>(bufSize));
    int rc = ok ? kOk : MapLastError();
    CloseHandle(h);
    return rc;
}

// Delete via a handle (SetFileInformationByHandle + FILE_DISPOSITION_INFO). This
// is how .NET (File.Delete) and other runtimes delete on Windows, distinct from
// the DeleteFileW path. The engine must enforce it identically (the DELETE open
// is the enforced access).
int DoDeleteByHandle(const wchar_t* path) {
    HANDLE h = CreateFileW(path, DELETE | SYNCHRONIZE, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    FILE_DISPOSITION_INFO fdi{};
    fdi.DeleteFile = TRUE;
    BOOL ok = SetFileInformationByHandle(h, FileDispositionInfo, &fdi,
                                         sizeof(fdi));
    int rc = ok ? kOk : MapLastError();
    CloseHandle(h);
    return rc;
}

// Delete via CreateFile with FILE_FLAG_DELETE_ON_CLOSE - a common temp-file
// idiom. The delete intent rides on the open (DELETE access), so a read-only
// scope must reject it up front.
int DoDeleteOnClose(const wchar_t* path) {
    HANDLE h = CreateFileW(path, DELETE, FILE_SHARE_DELETE | FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    CloseHandle(h);
    return kOk;
}

// Atomic replace via ReplaceFileW (used by editors/tools for safe saves). Usage:
// replace <replaced> <replacement>. Enforcement must cover the replaced target.
int DoReplace(const wchar_t* replaced, const wchar_t* replacement) {
    if (ReplaceFileW(replaced, replacement, nullptr, 0, nullptr, nullptr)) {
        return kOk;
    }
    return MapLastError();
}

int DoStat(const wchar_t* path) {
    DWORD attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return MapLastError();
    return kOk;
}
int DoStatA(const wchar_t* path) {
    char pathA[1024];
    WideCharToMultiByte(CP_ACP, 0, path, -1, pathA, sizeof(pathA), nullptr,
                        nullptr);
    DWORD attrs = GetFileAttributesA(pathA);
    if (attrs == INVALID_FILE_ATTRIBUTES) return MapLastError();
    return kOk;
}

int DoReadA(const wchar_t* path) {
    char pathA[1024];
    WideCharToMultiByte(CP_ACP, 0, path, -1, pathA, sizeof(pathA), nullptr,
                        nullptr);
    HANDLE h = CreateFileA(pathA, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    CloseHandle(h);
    return kOk;
}

// Enumerate a directory: FindFirstFileW(dir\*) + FindNextFileW.
int DoEnumerate(const wchar_t* dir) {
    std::wstring pattern = std::wstring(dir) + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    while (FindNextFileW(h, &fd)) {
    }
    FindClose(h);
    return kOk;
}

int DoCopy(const wchar_t* src, const wchar_t* dst) {
    if (CopyFileW(src, dst, FALSE)) return kOk;
    return MapLastError();
}

int DoRmdir(const wchar_t* path) {
    if (RemoveDirectoryW(path)) return kOk;
    return MapLastError();
}

int DoHardlink(const wchar_t* link, const wchar_t* target) {
    if (CreateHardLinkW(link, target, nullptr)) return kOk;
    return MapLastError();
}

// Create a symbolic link. Note: this usually needs SeCreateSymbolicLinkPrivilege
// or Developer Mode; without it the call fails with a privilege error (kOther),
// not a sandbox denial. Tests treat "other error" as inconclusive.
int DoSymlink(const wchar_t* link, const wchar_t* target) {
    if (CreateSymbolicLinkW(link, target, 0)) return kOk;
    return MapLastError();
}

// Attempt an outbound TCP connect. We measure whether the SANDBOX permitted the
// attempt, not whether a server was actually listening:
//   kOk     = the call reached the network stack (connected, or failed with a
//             network error such as connection-refused / timeout)
//   kDenied = the sandbox blocked it (ERROR/WSAEACCES from our hooks, or the
//             socket could not even be created because \Device\Afd was denied)
int DoConnect(const wchar_t* host, const wchar_t* portStr) {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return (WSAGetLastError() == WSAEACCES) ? kDenied : kOtherError;
    }
    char hostA[256];
    WideCharToMultiByte(CP_ACP, 0, host, -1, hostA, sizeof(hostA), nullptr, nullptr);
    unsigned short port = static_cast<unsigned short>(_wtoi(portStr));

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        int e = WSAGetLastError();
        WSACleanup();
        return (e == WSAEACCES) ? kDenied : kOtherError;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (InetPtonA(AF_INET, hostA, &addr.sin_addr) != 1) {
        closesocket(s);
        WSACleanup();
        return kBadUsage;
    }

    int r = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    int e = (r == 0) ? 0 : WSAGetLastError();
    closesocket(s);
    WSACleanup();

    if (r == 0) return kOk;
    return (e == WSAEACCES) ? kDenied : kOk;
}

// Validate that all three standard handles are usable in the child. This
// reproduces the "The handle is invalid" failure seen when Bazel drives the
// launcher: with STARTF_USESTDHANDLES the child must receive valid, inheritable
// std handles for stdin/stdout/stderr (a missing stdin must be substituted with
// NUL). Returns kOk only if every handle is present and writable/queryable.
constexpr int kBadStdHandle = 40;

int DoStdio() {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE handles[] = {in, out, err};
    for (HANDLE h : handles) {
        if (h == nullptr || h == INVALID_HANDLE_VALUE) return kBadStdHandle;
        SetLastError(NO_ERROR);
        DWORD t = GetFileType(h);
        if (t == FILE_TYPE_UNKNOWN && GetLastError() != NO_ERROR) {
            return kBadStdHandle;
        }
    }
    // Actually write to stdout/stderr to confirm they are usable, not just
    // valid handle values.
    DWORD written = 0;
    if (!WriteFile(out, "o", 1, &written, nullptr)) return kBadStdHandle;
    if (!WriteFile(err, "e", 1, &written, nullptr)) return kBadStdHandle;
    return kOk;
}

int DoSpawn(int argc, wchar_t** argv) {
    // argv[2] = exe, argv[3..] = args. Rebuild a command line.
    std::wstring cmd;
    for (int i = 2; i < argc; ++i) {
        if (i > 2) cmd += L' ';
        cmd += L'"';
        cmd += argv[i];
        cmd += L'"';
    }
    std::wstring mutableCmd = cmd;
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE, 0,
                        nullptr, nullptr, &si, &pi)) {
        return kOtherError;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = kOtherError;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

int DoExit(const wchar_t* code) {
    return static_cast<int>(wcstol(code, nullptr, 10));
}

int DoSleep(const wchar_t* ms) {
    Sleep(static_cast<DWORD>(wcstoul(ms, nullptr, 10)));
    return kOk;
}

// Succeeds (0) iff the process's current directory equals <expected>
// (case-insensitively), else kOtherError. Used to verify -W sets the child cwd.
int DoCwdIs(const wchar_t* expected) {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetCurrentDirectoryW(_countof(buf), buf);
    if (n == 0 || n >= _countof(buf)) return kOtherError;
    return (_wcsicmp(buf, expected) == 0) ? kOk : kOtherError;
}

// Creates a temp file in <dir> via GetTempFileNameW (an intercepted API) and
// reports whether the sandbox allowed it.
int DoTempFile(const wchar_t* dir) {
    wchar_t out[MAX_PATH];
    if (GetTempFileNameW(dir, L"prb", 0, out) == 0) return MapLastError();
    return kOk;
}

// Opens <path> for reading via the native NtCreateFile syscall (resolved from
// ntdll at runtime), bypassing the Win32 CreateFileW wrapper. This exercises the
// engine's Nt* hooks directly, which is the layer many runtimes (and the CRT)
// ultimately call. <path> must be an absolute Win32 path; it is converted to the
// NT object path form "\??\<path>".
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
int DoNtRead(const wchar_t* path) {
    using NtCreateFileFn = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto ntCreateFile = reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    if (ntCreateFile == nullptr) return kOtherError;

    std::wstring nt = L"\\??\\";
    nt += path;
    UNICODE_STRING us;
    us.Buffer = const_cast<wchar_t*>(nt.c_str());
    us.Length = static_cast<USHORT>(nt.size() * sizeof(wchar_t));
    us.MaximumLength = static_cast<USHORT>((nt.size() + 1) * sizeof(wchar_t));

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE h = nullptr;
    IO_STATUS_BLOCK iosb{};
    NTSTATUS st = ntCreateFile(
        &h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (st == 0) {
        if (h) CloseHandle(h);
        return kOk;
    }
    // STATUS_ACCESS_DENIED.
    if (st == static_cast<NTSTATUS>(0xC0000022L)) return kDenied;
    return kOtherError;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == L"stdio") return DoStdio();
    if (argc < 3) {
        fwprintf(stderr, L"usage: probe <op> <arg> [args...]  (see header for the op list)\n");
        return kBadUsage;
    }
    std::wstring op = argv[1];
    if (op == L"read") return DoRead(argv[2]);
    if (op == L"write") return DoWrite(argv[2]);
    if (op == L"delete") return DoDelete(argv[2]);
    if (op == L"deleteh") return DoDeleteByHandle(argv[2]);
    if (op == L"delonclose") return DoDeleteOnClose(argv[2]);
    if (op == L"mkdir") return DoMkdir(argv[2]);
    if (op == L"rename") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe rename <src> <dst>\n");
            return kBadUsage;
        }
        return DoRename(argv[2], argv[3]);
    }
    if (op == L"renameh") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe renameh <src> <dst>\n");
            return kBadUsage;
        }
        return DoRenameByHandle(argv[2], argv[3]);
    }
    if (op == L"replace") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe replace <replaced> <replacement>\n");
            return kBadUsage;
        }
        return DoReplace(argv[2], argv[3]);
    }
    if (op == L"stat") return DoStat(argv[2]);
    if (op == L"stata") return DoStatA(argv[2]);
    if (op == L"reada") return DoReadA(argv[2]);
    if (op == L"enumerate") return DoEnumerate(argv[2]);
    if (op == L"rmdir") return DoRmdir(argv[2]);
    if (op == L"copy") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe copy <src> <dst>\n");
            return kBadUsage;
        }
        return DoCopy(argv[2], argv[3]);
    }
    if (op == L"hardlink") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe hardlink <link> <target>\n");
            return kBadUsage;
        }
        return DoHardlink(argv[2], argv[3]);
    }
    if (op == L"symlink") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe symlink <link> <target>\n");
            return kBadUsage;
        }
        return DoSymlink(argv[2], argv[3]);
    }
    if (op == L"connect") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe connect <host> <port>\n");
            return kBadUsage;
        }
        return DoConnect(argv[2], argv[3]);
    }
    if (op == L"spawn") return DoSpawn(argc, argv);
    if (op == L"exit") return DoExit(argv[2]);
    if (op == L"sleep") return DoSleep(argv[2]);
    if (op == L"cwdis") return DoCwdIs(argv[2]);
    if (op == L"tempfile") return DoTempFile(argv[2]);
    if (op == L"ntread") return DoNtRead(argv[2]);
    fwprintf(stderr, L"probe: unknown op '%s'\n", argv[1]);
    return kBadUsage;
}
