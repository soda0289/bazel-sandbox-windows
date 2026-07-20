// Tiny test helper used by the enforcement tests. It performs one file-system
// operation (or spawns a child that does) and maps the result to a stable exit
// code so tests can distinguish "allowed" from "sandbox-denied":
//
//   0  = operation succeeded (access allowed)
//   10 = operation denied (ERROR_ACCESS_DENIED, i.e. the sandbox blocked it)
//   11 = operation reported the path as NOT_FOUND (the sandbox hid it; this is
//        how --filter-inputs masks a denied read - linux-sandbox "absent" parity)
//   20 = operation failed for some other reason
//   30 = bad usage
//
// Usage:
//   probe read  <path>            open <path> for reading
//   probe statbyname <path>       stat <path> via GetFileInformationByName
//                                 (FileStatBasicByNameInfo) -- the handle-less fast path
//                                 modern libuv/Node use for fs.stat; 0 visible, 11 hidden
//   probe write <path>            create/overwrite <path>
//   probe createnew <path>        CreateFileW(CREATE_NEW): 0 if newly created, 20
//                                 if it already exists (merged-view fail-if-exists)
//   probe delete <path>           delete <path>
//   probe deleteh <path>          delete <path> via SetFileInformationByHandle
//   probe delonclose <path>       delete <path> via FILE_FLAG_DELETE_ON_CLOSE
//   probe replace <old> <new>     ReplaceFileW(<old>, <new>) atomic replace
//   probe mkdir <path>            create directory <path>
//   probe rename <src> <dst>      move/rename <src> to <dst>
//   probe spawn <exe> [args...]   run a child process, return its exit code
//                                 (used to verify child-process propagation)
//   probe writespawnread <path> <childExe>
//                                 create <path> in this process, then spawn
//                                 <childExe> read <path>; returns the child's code
//                                 (verifies the created-set is shared cross-process)
//   probe writespawndelete <path> <childExe>
//                                 create <path> in this process, then spawn
//                                 <childExe> delete <path>; returns the child's code
//                                 (JavaBuilder create-here / clean-there parity)
//   probe writespawnenum <dir> <name> <childExe>
//                                 create <dir>\<name> in this process, then spawn
//                                 <childExe> enumfindntdirect <dir> <name>; returns
//                                 the child's code (verifies the overlay index is
//                                 shared cross-process and inserted into enumeration)
//   probe connect <host> <port>   attempt an outbound TCP connect
//                                 (used to verify -N / -n network sandboxing)
//   probe stdio                   verify all three std handles are usable
//   probe exit  <code>            exit with <code> (exit-code fidelity)
//   probe sleep <ms>              sleep <ms> (used to exercise -T timeout)
//   probe cwdis <dir>             0 iff the current directory equals <dir>
//   probe tempfile <dir>          GetTempFileNameW in <dir> (intercepted API)
//   probe ntread <path>           open <path> for read via native NtCreateFile
//   probe ntwriteread <base>      create+write <base>\ntov.txt via native NtCreateFile
//                                 (bypassing Win32), then read it back the same way;
//                                 0 iff both direct-NtCreateFile opens redirect to the
//                                 backing store (real execroot never gets the path)
//   probe findfile <path>         FindFirstFileEx on an EXACT file path (single-file
//                                 existence probe, as cmd `type` does); 0 if visible,
//                                 11 if absent/hidden, 10 if denied
//   probe enumfind <dir> <name>   0 iff <name> is listed when enumerating <dir>
//                                 via Win32 FindFirstFile/FindNextFile, else 11
//   probe enumfindnt <dir> <name> same, via GetFileInformationByHandleEx
//                                 (FileIdBothDirectoryInfo)
//   probe enumfindntdirect <dir> <name>
//                                 same, via a direct ntdll!NtQueryDirectoryFile
//                                 call (the path Node/libuv use)
//   probe writeenum <dir> <name>  create <dir>\<name> in this process, then
//                                 enumerate <dir> via ntdll!NtQueryDirectoryFile;
//                                 0 iff <name> is listed (Model W overlay insertion)
//   probe writeenummulti <dir> <bufBytes> <name1> [name2 ...]
//                                 write each name into the overlay, then enumerate
//                                 <dir> with a SMALL <bufBytes> buffer forcing many
//                                 NtQueryDirectoryFile calls; 0 iff every name is
//                                 listed EXACTLY once (multi-call cursor: 11 if any
//                                 skipped, 20 if any duplicated)
//   probe writeovdirenum <base>   write <base>\ovsub\f.txt (redirected into the
//                                 overlay so <base>\ovsub exists only in the backing
//                                 store), then enumerate the overlay-only directory
//                                 <base>\ovsub via ntdll!NtQueryDirectoryFile; 0 iff
//                                 f.txt is listed (overlay-only-dir open + enum)
//   probe writeovdelete <base>    write <base>\ovdel.txt into the overlay then delete
//                                 it; 0 iff the delete of the process's own overlay
//                                 file succeeds (backing removed, real untouched)
//   probe writeovdeleteh <base>   like writeovdelete but deletes via a HANDLE
//                                 (SetFileInformationByHandle + FILE_DISPOSITION_INFO)
//   probe writeovrename <base>    write <base>\ovr_src.txt into the overlay, rename it
//                                 to <base>\ovr_dst.txt, read the dest back; 0 iff the
//                                 whole move stays inside the backing store
//   probe writeovrenameh <base>   like writeovrename but renames via a HANDLE
//                                 (SetFileInformationByHandle + FILE_RENAME_INFO), the
//                                 path cmd's ren/move take; 0 iff no real-execroot leak
//   probe writeovstat <base>      write <base>\ovstat.txt into the overlay then stat it
//                                 via GetFileAttributes(Ex)/GetFileInformationByName/
//                                 exact FindFirstFileEx; 0 iff every metadata API sees
//                                 the backing file (stat of own scratch works)

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
constexpr int kNotFound = 11;
constexpr int kOtherError = 20;
constexpr int kBadUsage = 30;

int MapLastError() {
    DWORD e = GetLastError();
    if (e == ERROR_ACCESS_DENIED) return kDenied;
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return kNotFound;
    return kOtherError;
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

// Write the same path twice (CREATE_ALWAYS) within a SINGLE process. Exercises the
// execroot-writable per-process "files I created" cache: the first write creates a
// new file (allowed), the second sees it exists but was created by THIS process, so
// it must still be allowed. Returns the mapped result of the SECOND write.
int DoRewrite(const wchar_t* path) {
    int first = DoWrite(path);
    if (first != kOk) return first;
    return DoWrite(path);
}

// Create a NEW file, then read it back within the SAME process. Under execroot-
// writable this must succeed: the file the process just created has to be readable
// even though the execroot read-filter otherwise hides undeclared paths (mirrors
// vite writing then importing a .vite-temp timestamp module). Returns the mapped
// result of the READ.
int DoWriteRead(const wchar_t* path) {
    int w = DoWrite(path);
    if (w != kOk) return w;
    return DoRead(path);
}

int DoDelete(const wchar_t* path) {
    if (DeleteFileW(path)) return kOk;
    return MapLastError();
}

// Open <path> with CREATE_NEW (create-if-absent, fail-if-exists) and report the
// mapped result: kOk if a brand-new file was created; kOtherError if it already
// exists (ERROR_FILE_EXISTS/ERROR_ALREADY_EXISTS - the fail-if-exists contract);
// kDenied/kNotFound per the usual mapping. Under --write-overlay this pins the
// merged-view semantics: CREATE_NEW must fail if the target exists in the real
// execroot OR the action's overlay, and must NOT silently succeed by creating an
// empty backing file over a pre-existing (undeclared) real file.
int DoCreateNew(const wchar_t* path) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) return kOtherError;
        return MapLastError();
    }
    CloseHandle(h);
    return kOk;
}

// Create a NEW file, then delete it within the SAME process. Under execroot-writable
// this must succeed: a file the process just created has to be deletable. This is the
// create-temp-then-rename/delete idiom used by zip/cygwin (and many temp-file tools).
// It is distinct from DoRewrite: the delete resolves the file name via the handle
// (DetourGetFinalPathByHandle -> "\\?\C:\..."), while the create used the literal path
// ("\??\C:\..." / "C:\..."), so it regression-guards the per-process created-files
// tracker against keying on the (differing) path-type prefix.
int DoWriteDelete(const wchar_t* path) {
    int w = DoWrite(path);
    if (w != kOk) return w;
    return DoDelete(path);
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
// and is exactly what coreutils-based build actions exercise.
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
// Stat via GetFileAttributesExW -- the API Java's WindowsFileSystemProvider.checkAccess /
// Files.createDirectories uses. Regression coverage for the probe read-masking fix: the
// ordinary "stat" op uses GetFileAttributesW (a sibling hook), so it could not catch the
// GetFileAttributesExW denial-masking divergence that broke Java compilation.
int DoStatEx(const wchar_t* path) {
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data)) return MapLastError();
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

// Stat via GetFileInformationByName(FileStatBasicByNameInfo) -- the handle-less fast path that
// modern libuv (Node) uses for fs.stat. Resolved dynamically since it only exists on Win8+/Win11
// and may be absent from the SDK import lib. Regression coverage for the stat/read masking fix:
// the ordinary "stat" op above uses GetFileAttributesW, which was already masked, so it could
// not catch a GetFileInformationByName leak.
int DoStatByName(const wchar_t* path) {
    typedef enum {
        pFileStatByNameInfo,
        pFileStatLxByNameInfo,
        pFileCaseSensitiveByNameInfo,
        pFileStatBasicByNameInfo
    } P_FILE_INFO_BY_NAME_CLASS;
    typedef struct {
        LARGE_INTEGER FileId;
        LARGE_INTEGER CreationTime;
        LARGE_INTEGER LastAccessTime;
        LARGE_INTEGER LastWriteTime;
        LARGE_INTEGER ChangeTime;
        LARGE_INTEGER AllocationSize;
        LARGE_INTEGER EndOfFile;
        ULONG FileAttributes;
        ULONG ReparseTag;
        ULONG NumberOfLinks;
        ULONG DeviceType;
        ULONG DeviceCharacteristics;
        ULONG Reserved;
        LARGE_INTEGER VolumeSerialNumber;
        struct { BYTE Id[16]; } FileId128;
    } P_FILE_STAT_BASIC_INFORMATION;
    typedef BOOL(WINAPI * GetFileInformationByName_fn)(
        PCWSTR, P_FILE_INFO_BY_NAME_CLASS, PVOID, ULONG);

    static GetFileInformationByName_fn pGetFileInformationByName =
        (GetFileInformationByName_fn)GetProcAddress(
            GetModuleHandleW(L"kernelbase.dll"), "GetFileInformationByName");
    if (pGetFileInformationByName == nullptr) {
        // API unavailable on this OS: skip (harness treats this op as N/A -> allowed).
        return kOk;
    }

    P_FILE_STAT_BASIC_INFORMATION info{};
    if (!pGetFileInformationByName(path, pFileStatBasicByNameInfo, &info, sizeof(info))) {
        return MapLastError();
    }
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

// Enumerate <dir> via the Win32 FindFirstFile/FindNextFile APIs and report
// whether an entry named <name> is visible: kOk if present, kNotFound if the
// directory lists but <name> is not among the entries (i.e. it was filtered).
int DoEnumFind(const wchar_t* dir, const wchar_t* name) {
    std::wstring pattern = std::wstring(dir) + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    bool found = false;
    do {
        if (_wcsicmp(fd.cFileName, name) == 0) { found = true; break; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found ? kOk : kNotFound;
}

// FindFirstFileEx on an EXACT file path (no wildcard) - this is a single-file
// existence/metadata probe, not a directory enumeration. It is the path cmd.exe's
// `type`, GetShortPathName, and many CRT stat() implementations use. Under input
// filtering an undeclared-but-existing file must look ABSENT (kNotFound), matching
// linux-sandbox, rather than kDenied.
int DoFindFile(const wchar_t* path) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileExW(path, FindExInfoStandard, &fd, FindExSearchNameMatch,
                                nullptr, 0);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    FindClose(h);
    return kOk;
}

// Enumerate <dir> via GetFileInformationByHandleEx(FileIdBothDirectoryInfo) and
// report whether an entry named <name> is visible. This is the path used by the
// .NET Directory APIs and some CRTs; it is filtered inside the sandbox's
// GetFileInformationByHandleEx interception (the wrapper shields the inner
// NtQueryDirectoryFile call from the native filter).
int DoEnumFindNt(const wchar_t* dir, const wchar_t* name) {
    HANDLE h = CreateFileW(
        dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();

    bool found = false;
    std::vector<char> buf(64 * 1024);
    while (!found &&
           GetFileInformationByHandleEx(h, FileIdBothDirectoryInfo, buf.data(), (DWORD)buf.size())) {
        auto* info = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(buf.data());
        for (;;) {
            std::wstring n(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), name) == 0) { found = true; break; }
            if (info->NextEntryOffset == 0) break;
            info = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(
                reinterpret_cast<char*>(info) + info->NextEntryOffset);
        }
    }
    CloseHandle(h);
    return found ? kOk : kNotFound;
}

typedef NTSTATUS (NTAPI* NtQueryDirectoryFile_fn)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

// Enumerate <dir> by calling ntdll!NtQueryDirectoryFile directly (via
// GetProcAddress) with FILE_NAMES_INFORMATION, and report whether an entry named
// <name> is visible. This mirrors how Node/libuv enumerate directories, and
// exercises the native (un-nested) NtQueryDirectoryFile enumeration filter
// directly rather than going through a hooked Win32 wrapper.
int DoEnumFindNtDirect(const wchar_t* dir, const wchar_t* name) {
    HANDLE h = CreateFileW(
        dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();

    auto pNtQuery = reinterpret_cast<NtQueryDirectoryFile_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    if (pNtQuery == nullptr) { CloseHandle(h); return kOtherError; }

    const ULONG FileNamesInformation = 12;
    std::vector<char> buf(64 * 1024);
    bool found = false;
    BOOLEAN restart = TRUE;
    for (;;) {
        IO_STATUS_BLOCK iosb{};
        NTSTATUS st = pNtQuery(
            h, nullptr, nullptr, nullptr, &iosb,
            buf.data(), (ULONG)buf.size(),
            (FILE_INFORMATION_CLASS)FileNamesInformation,
            FALSE, nullptr, restart);
        restart = FALSE;
        if (st != 0) break; // STATUS_NO_MORE_FILES or an error
        char* p = buf.data();
        for (;;) {
            ULONG next = *reinterpret_cast<ULONG*>(p + 0);
            ULONG nameLen = *reinterpret_cast<ULONG*>(p + 8);
            const wchar_t* nm = reinterpret_cast<const wchar_t*>(p + 12);
            std::wstring n(nm, nameLen / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), name) == 0) { found = true; break; }
            if (next == 0) break;
            p += next;
        }
        if (found) break;
    }
    CloseHandle(h);
    return found ? kOk : kNotFound;
}

// Model W write-overlay: create <dir>\<name> in THIS process (redirected into the
// process-private overlay backing store, so it does not appear on the real disk),
// then enumerate <dir> via the direct ntdll!NtQueryDirectoryFile path and report
// whether <name> is listed. Under --write-overlay the DLL must splice the overlay
// entry into the enumeration so the tool sees the file it just "wrote". Returns kOk
// iff the write succeeds AND the name is subsequently enumerated.
int DoWriteEnum(const wchar_t* dir, const wchar_t* name) {
    std::wstring path = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(path.c_str());
    if (w != kOk) return w;
    return DoEnumFindNtDirect(dir, name);
}

// Enumerate <dir> via ntdll!NtQueryDirectoryFile using a CALLER-SPECIFIED buffer
// size (deliberately small) so the multi-call enumeration cursor protocol is
// exercised, and count how many times each name in <names> appears across the
// whole scan. This is the analogue of usvfs's NtQueryDirectoryFileExVirtualFile
// test (small buffer + several varying-length virtual entries), extended to also
// catch DUPLICATES: with a point-in-time snapshot cursor each spliced overlay
// entry must appear EXACTLY once even when the listing spans many calls. Returns
// via outCounts (parallel to names). Result: kOk on a completed scan, else error.
int EnumCountNames(const wchar_t* dir, ULONG bufBytes,
                   const std::vector<std::wstring>& names,
                   std::vector<int>& outCounts) {
    outCounts.assign(names.size(), 0);
    HANDLE h = CreateFileW(
        dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();

    auto pNtQuery = reinterpret_cast<NtQueryDirectoryFile_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    if (pNtQuery == nullptr) { CloseHandle(h); return kOtherError; }

    const ULONG FileNamesInformation = 12;
    if (bufBytes < 64) bufBytes = 64;
    std::vector<char> buf(bufBytes);
    BOOLEAN restart = TRUE;
    for (;;) {
        IO_STATUS_BLOCK iosb{};
        NTSTATUS st = pNtQuery(
            h, nullptr, nullptr, nullptr, &iosb,
            buf.data(), (ULONG)buf.size(),
            (FILE_INFORMATION_CLASS)FileNamesInformation,
            FALSE, nullptr, restart);
        restart = FALSE;
        if (st != 0) break; // STATUS_NO_MORE_FILES or an error terminates the scan
        char* p = buf.data();
        for (;;) {
            ULONG next = *reinterpret_cast<ULONG*>(p + 0);
            ULONG nameLen = *reinterpret_cast<ULONG*>(p + 8);
            const wchar_t* nm = reinterpret_cast<const wchar_t*>(p + 12);
            std::wstring n(nm, nameLen / sizeof(wchar_t));
            for (size_t i = 0; i < names.size(); ++i) {
                if (_wcsicmp(n.c_str(), names[i].c_str()) == 0) outCounts[i]++;
            }
            if (next == 0) break;
            p += next;
        }
    }
    CloseHandle(h);
    return kOk;
}

// Model W write-overlay, multi-call cursor stress: write several files (which are
// redirected into the overlay backing store) into <dir>, then enumerate <dir> with
// a SMALL buffer that forces NtQueryDirectoryFile to return across MANY calls, and
// verify every written name appears EXACTLY once (no skip from a shifting index, no
// duplicate from re-inserting on each call). This is the test the 64KB-buffer
// enumfindntdirect op cannot provide. argv: <dir> <bufBytes> <name1> [name2 ...].
// Returns kOk iff all writes succeed and every name is enumerated exactly once;
// kNotFound if any name is missing; kOtherError if any name is duplicated.
int DoWriteEnumMulti(const wchar_t* dir, ULONG bufBytes,
                     const std::vector<std::wstring>& names) {
    for (const std::wstring& nm : names) {
        std::wstring path = std::wstring(dir) + L"\\" + nm;
        int w = DoWrite(path.c_str());
        if (w != kOk) return w;
    }
    std::vector<int> counts;
    int rc = EnumCountNames(dir, bufBytes, names, counts);
    if (rc != kOk) return rc;
    for (int c : counts) {
        if (c == 0) return kNotFound;   // cursor skipped an entry
        if (c > 1) return kOtherError;  // cursor emitted an entry more than once
    }
    return kOk;
}

// Model W write-overlay, OVERLAY-ONLY directory: write a file into a subdirectory
// that does NOT exist on the real disk. The redirected file write creates the
// subdirectory only in the backing store (EnsureBackingParentDirs), so <base>\<sub>
// exists solely in the overlay. Then enumerate that overlay-only directory via the
// direct ntdll!NtQueryDirectoryFile path: opening it must redirect the handle to the
// backing directory (there is no real directory to open) and the enumeration must
// list the file. Returns kOk iff the write succeeds AND the file is enumerated from
// the overlay-only directory. (This exercises overlay-only-dir open+enum without a
// CreateDirectoryW redirect, which is deferred to the enumeration-class work.)
int DoWriteOvDirEnum(const wchar_t* base) {
    std::wstring sub = std::wstring(base) + L"\\ovsub";
    std::wstring file = sub + L"\\f.txt";
    int w = DoWrite(file.c_str());
    if (w != kOk) return w;
    return DoEnumFindNtDirect(sub.c_str(), L"f.txt");
}

// Model W delete: write a brand-new undeclared file into the overlay, then delete
// it within the same process. The delete must succeed (the backing copy is removed)
// and the real execroot is never touched. Regression-guards the delete redirect: a
// process must be able to delete a file it just created in the overlay.
int DoWriteOvDelete(const wchar_t* base) {
    std::wstring file = std::wstring(base) + L"\\ovdel.txt";
    int w = DoWrite(file.c_str());
    if (w != kOk) return w;
    return DoDelete(file.c_str());
}

// Model W delete via a HANDLE (SetFileInformationByHandle + FILE_DISPOSITION_INFO):
// write a brand-new undeclared file into the overlay, then delete it through the
// handle-based disposition path. The disposition acts on the already-redirected
// backing handle, so the backing copy is removed and the real execroot is never
// touched. Regression-guards the handle-based delete overlay source resolution.
int DoWriteOvDeleteH(const wchar_t* base) {
    std::wstring file = std::wstring(base) + L"\\ovdelh.txt";
    int w = DoWrite(file.c_str());
    if (w != kOk) return w;
    return DoDeleteByHandle(file.c_str());
}

// Model W rename: write a brand-new undeclared file into the overlay, rename it to
// another undeclared execroot path, then read back the destination. The whole move
// stays inside the backing store, so the read-back succeeds and neither real path is
// created. Regression-guards the rename source+dest redirect.
int DoWriteOvRename(const wchar_t* base) {
    std::wstring src = std::wstring(base) + L"\\ovr_src.txt";
    std::wstring dst = std::wstring(base) + L"\\ovr_dst.txt";
    int w = DoWrite(src.c_str());
    if (w != kOk) return w;
    int r = DoRename(src.c_str(), dst.c_str());
    if (r != kOk) return r;
    return DoRead(dst.c_str());
}

// Model W rename via a HANDLE (SetFileInformationByHandle + FILE_RENAME_INFO): the
// path cmd's `ren`/`move` and other tools take instead of MoveFileEx. Write a
// brand-new undeclared file into the overlay, rename it by handle to another
// undeclared execroot path, then read back the destination. The whole move must stay
// inside the backing store (read-back succeeds, neither real path is created).
// Regression-guards the handle-based rename dest redirect: previously the source
// handle pointed at the backing copy but the destination NAME was left as the virtual
// path, so the move leaked the destination onto the real execroot.
int DoWriteOvRenameH(const wchar_t* base) {
    std::wstring src = std::wstring(base) + L"\\ovrh_src.txt";
    std::wstring dst = std::wstring(base) + L"\\ovrh_dst.txt";
    int w = DoWrite(src.c_str());
    if (w != kOk) return w;
    int r = DoRenameByHandle(src.c_str(), dst.c_str());
    if (r != kOk) return r;
    return DoRead(dst.c_str());
}

// Model W metadata: write a brand-new undeclared file into the overlay, then stat it
// through every path-based metadata API (GetFileAttributesW, GetFileAttributesExW,
// GetFileInformationByName, and exact FindFirstFileEx). Each must observe the backing
// file the action just wrote (the real execroot has no such path), so a process can
// stat its own scratch. Returns the first non-kOk result; kOk iff all four succeed.
int DoWriteOvStat(const wchar_t* base) {
    std::wstring file = std::wstring(base) + L"\\ovstat.txt";
    int w = DoWrite(file.c_str());
    if (w != kOk) return w;
    int rc = DoStat(file.c_str());
    if (rc != kOk) return rc;
    rc = DoStatEx(file.c_str());
    if (rc != kOk) return rc;
    rc = DoStatByName(file.c_str());
    if (rc != kOk) return rc;
    return DoFindFile(file.c_str());
}

// Forward declarations: these composite overlay ops call link/rmdir primitives that
// are defined further down the file.
int DoHardlink(const wchar_t* link, const wchar_t* target);
int DoSymlink(const wchar_t* link, const wchar_t* target);
int DoRmdir(const wchar_t* path);

// Model W hardlink: write an overlay-only file, hardlink it to another undeclared
// execroot path, then read back through the link. The whole op stays in the backing
// store: the new link lands in the overlay (never the real execroot) and the
// read-back succeeds. Regression-guards the CreateHardLink overlay redirect, which
// previously leaked the link onto the real disk.
int DoWriteOvHardlink(const wchar_t* base) {
    std::wstring target = std::wstring(base) + L"\\ovhl_tgt.txt";
    std::wstring link = std::wstring(base) + L"\\ovhl_lnk.txt";
    int w = DoWrite(target.c_str());
    if (w != kOk) return w;
    int h = DoHardlink(link.c_str(), target.c_str());
    if (h != kOk) return h;
    return DoRead(link.c_str());
}

// Model W symlink: write an overlay-only target, then create a symlink at another
// undeclared execroot path pointing to it. The link must resolve into the backing
// store (never the real execroot). We do NOT read back through the link: a symlink
// whose target is itself an overlay path cannot be transparently followed (the kernel
// resolves the reparse target internally, bypassing the detours), so we only assert
// creation succeeds; the enforce harness separately asserts no real-execroot leak.
// Symlink creation needs SeCreateSymbolicLinkPrivilege / Developer Mode; when
// unavailable CreateSymbolicLinkW fails with a privilege error (kOtherError), which
// the harness treats as inconclusive (skip), not a failure.
int DoWriteOvSymlink(const wchar_t* base) {
    std::wstring target = std::wstring(base) + L"\\ovsl_tgt.txt";
    std::wstring link = std::wstring(base) + L"\\ovsl_lnk.txt";
    int w = DoWrite(target.c_str());
    if (w != kOk) return w;
    return DoSymlink(link.c_str(), target.c_str());  // kOtherError if unprivileged
}

// Model W ReplaceFile (atomic save): write an overlay-only "replaced" target and a
// "replacement" file, ReplaceFile the target with the replacement, then read back the
// replaced path. The replace resolves entirely inside the backing store, so the
// read-back succeeds and the real execroot is never touched. Regression-guards the
// ReplaceFile overlay redirect (was previously a no-op stub).
int DoWriteOvReplace(const wchar_t* base) {
    std::wstring replaced = std::wstring(base) + L"\\ovrep_dst.txt";
    std::wstring replacement = std::wstring(base) + L"\\ovrep_src.txt";
    int w = DoWrite(replaced.c_str());
    if (w != kOk) return w;
    w = DoWrite(replacement.c_str());
    if (w != kOk) return w;
    int r = DoReplace(replaced.c_str(), replacement.c_str());
    if (r != kOk) return r;
    return DoRead(replaced.c_str());
}

// Model W rmdir: create an overlay-only directory (CreateDirectoryW redirects it into
// the backing store), then remove it. The rmdir must succeed against the backing
// dir; without the RemoveDirectory overlay redirect the virtual path has no real
// directory to remove and the call returns NOT_FOUND. Regression-guards the symmetry
// with CreateDirectoryW.
int DoWriteOvRmdir(const wchar_t* base) {
    std::wstring dir = std::wstring(base) + L"\\ovrmdir";
    if (!CreateDirectoryW(dir.c_str(), nullptr)) return MapLastError();
    return DoRmdir(dir.c_str());
}

// Model W write-overlay, enumeration via GetFileInformationByHandleEx (class
// FileIdBothDirectoryInfo): write a file into the overlay, then enumerate <dir>
// through the GetFileInformationByHandleEx path (the .NET Directory / some-CRT
// path, whose Win32 wrapper shields the inner NtQueryDirectoryFileEx from the
// Nt-level hook) and report whether <name> is spliced in. kOk iff write succeeds
// AND the name is enumerated.
int DoWriteEnumGfibhe(const wchar_t* dir, const wchar_t* name) {
    std::wstring path = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(path.c_str());
    if (w != kOk) return w;
    return DoEnumFindNt(dir, name);
}

// Model W write-overlay, enumeration via the Win32 FindFirstFile/FindNextFile
// family: write a file into the overlay, then enumerate <dir> via FindFirstFileW +
// FindNextFileW (the classic Win32 path) and report whether <name> is spliced in.
// kOk iff write succeeds AND the name is enumerated.
int DoWriteEnumFind(const wchar_t* dir, const wchar_t* name) {
    std::wstring path = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(path.c_str());
    if (w != kOk) return w;
    return DoEnumFind(dir, name);
}

typedef NTSTATUS (NTAPI* NtQueryDirectoryFileEx_fn)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, ULONG, PUNICODE_STRING);

// Enumerate <dir> via a direct ntdll!NtQueryDirectoryFileEx call (the modern
// successor hooked separately from NtQueryDirectoryFile) and report whether <name>
// is visible. Exercises the Ex hook's overlay insertion path directly.
int DoEnumFindNtDirectEx(const wchar_t* dir, const wchar_t* name) {
    HANDLE h = CreateFileW(
        dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    auto pEx = reinterpret_cast<NtQueryDirectoryFileEx_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFileEx"));
    if (pEx == nullptr) { CloseHandle(h); return kOtherError; }

    const ULONG FileNamesInformation = 12;
    const ULONG SL_RESTART_SCAN = 0x01;
    std::vector<char> buf(64 * 1024);
    bool found = false;
    ULONG flags = SL_RESTART_SCAN;
    for (;;) {
        IO_STATUS_BLOCK iosb{};
        NTSTATUS st = pEx(
            h, nullptr, nullptr, nullptr, &iosb,
            buf.data(), (ULONG)buf.size(),
            (FILE_INFORMATION_CLASS)FileNamesInformation, flags, nullptr);
        flags = 0;
        if (st != 0) break;
        char* p = buf.data();
        for (;;) {
            ULONG next = *reinterpret_cast<ULONG*>(p + 0);
            ULONG nameLen = *reinterpret_cast<ULONG*>(p + 8);
            const wchar_t* nm = reinterpret_cast<const wchar_t*>(p + 12);
            std::wstring n(nm, nameLen / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), name) == 0) { found = true; break; }
            if (next == 0) break;
            p += next;
        }
        if (found) break;
    }
    CloseHandle(h);
    return found ? kOk : kNotFound;
}

int DoWriteEnumEx(const wchar_t* dir, const wchar_t* name) {
    std::wstring path = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(path.c_str());
    if (w != kOk) return w;
    return DoEnumFindNtDirectEx(dir, name);
}

// Model W write-overlay, wildcard filtering (gap #1): enumerate <dir>\<wildcard> via
// Win32 FindFirstFileW/FindNextFileW and report whether <match> (should match the
// wildcard) and <nomatch> (should NOT) appear. kOk iff <match> is listed and
// <nomatch> is not; kOtherError if <nomatch> leaked (over-inclusion bug); kNotFound
// if <match> was dropped.
int EnumFilterFind(const wchar_t* dir, const wchar_t* wildcard,
                   const wchar_t* match, const wchar_t* nomatch) {
    std::wstring pattern = std::wstring(dir) + L"\\" + wildcard;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    bool foundMatch = false, foundNomatch = false;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (_wcsicmp(fd.cFileName, match) == 0) foundMatch = true;
            if (_wcsicmp(fd.cFileName, nomatch) == 0) foundNomatch = true;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (foundNomatch) return kOtherError;
    return foundMatch ? kOk : kNotFound;
}

// As EnumFilterFind but via a direct ntdll!NtQueryDirectoryFile call carrying the
// wildcard as the FileName expression on the first (restart) call. Exercises the
// native enumeration filter's overlay-splice wildcard honoring.
int EnumFilterNtDirect(const wchar_t* dir, const wchar_t* wildcard,
                       const wchar_t* match, const wchar_t* nomatch) {
    HANDLE h = CreateFileW(
        dir, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    auto pNtQuery = reinterpret_cast<NtQueryDirectoryFile_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile"));
    if (pNtQuery == nullptr) { CloseHandle(h); return kOtherError; }

    UNICODE_STRING us{};
    us.Buffer = const_cast<PWSTR>(wildcard);
    us.Length = (USHORT)(wcslen(wildcard) * sizeof(wchar_t));
    us.MaximumLength = us.Length;

    const ULONG FileNamesInformation = 12;
    std::vector<char> buf(64 * 1024);
    bool foundMatch = false, foundNomatch = false;
    BOOLEAN restart = TRUE;
    for (;;) {
        IO_STATUS_BLOCK iosb{};
        NTSTATUS st = pNtQuery(
            h, nullptr, nullptr, nullptr, &iosb,
            buf.data(), (ULONG)buf.size(),
            (FILE_INFORMATION_CLASS)FileNamesInformation,
            FALSE, restart ? &us : nullptr, restart);
        restart = FALSE;
        if (st != 0) break;
        char* p = buf.data();
        for (;;) {
            ULONG next = *reinterpret_cast<ULONG*>(p + 0);
            ULONG nameLen = *reinterpret_cast<ULONG*>(p + 8);
            const wchar_t* nm = reinterpret_cast<const wchar_t*>(p + 12);
            std::wstring n(nm, nameLen / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), match) == 0) foundMatch = true;
            if (_wcsicmp(n.c_str(), nomatch) == 0) foundNomatch = true;
            if (next == 0) break;
            p += next;
        }
    }
    CloseHandle(h);
    if (foundNomatch) return kOtherError;
    return foundMatch ? kOk : kNotFound;
}

// Write <match> and <nomatch> into the overlay, then check that a wildcard
// enumeration lists only the matching one (gap #1, Win32 FindFirstFile path).
int DoWriteEnumFilterFind(const wchar_t* dir, const wchar_t* wildcard,
                          const wchar_t* match, const wchar_t* nomatch) {
    std::wstring p1 = std::wstring(dir) + L"\\" + match;
    std::wstring p2 = std::wstring(dir) + L"\\" + nomatch;
    int w = DoWrite(p1.c_str()); if (w != kOk) return w;
    w = DoWrite(p2.c_str()); if (w != kOk) return w;
    return EnumFilterFind(dir, wildcard, match, nomatch);
}

// As DoWriteEnumFilterFind but via the direct NtQueryDirectoryFile path.
int DoWriteEnumFilterNt(const wchar_t* dir, const wchar_t* wildcard,
                        const wchar_t* match, const wchar_t* nomatch) {
    std::wstring p1 = std::wstring(dir) + L"\\" + match;
    std::wstring p2 = std::wstring(dir) + L"\\" + nomatch;
    int w = DoWrite(p1.c_str()); if (w != kOk) return w;
    w = DoWrite(p2.c_str()); if (w != kOk) return w;
    return EnumFilterNtDirect(dir, wildcard, match, nomatch);
}

// Model W write-overlay, narrow-filter synthesis (gap #2): write only <name> into
// the overlay, then FindFirstFileW(<dir>\<wildcard>) where NO real entry matches the
// wildcard. The OS would return not-found; the synthesize path must return our
// overlay-only file as the FIRST result. kOk iff the first result is <name>;
// kOtherError if some other entry came first; otherwise the mapped error.
int DoWriteEnumSynth(const wchar_t* dir, const wchar_t* wildcard, const wchar_t* name) {
    std::wstring p = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(p.c_str()); if (w != kOk) return w;
    std::wstring pattern = std::wstring(dir) + L"\\" + wildcard;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    bool firstIsOurs = (_wcsicmp(fd.cFileName, name) == 0);
    FindClose(h);
    return firstIsOurs ? kOk : kOtherError;
}

// Model W write-overlay, synthetic-record METADATA correctness: write a file of
// KNOWN length and create a subdirectory (both redirected into the overlay), then
// enumerate <base> via GetFileInformationByHandleEx(FileIdBothDirectoryInfo) and
// verify the spliced records carry real metadata: the file's EndOfFile equals the
// bytes written, and the directory entry has FILE_ATTRIBUTE_DIRECTORY set (so tools
// recurse into overlay-only subdirs). kOk iff both hold; kNotFound if the file
// entry is missing/wrong-size; kOtherError if the dir entry lacks the directory bit.
int DoWriteEnumMeta(const wchar_t* base) {
    const char* content = "hello-overlay"; // 13 bytes
    const DWORD clen = 13;
    std::wstring file = std::wstring(base) + L"\\meta.txt";
    HANDLE hf = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return MapLastError();
    DWORD wr = 0;
    if (!WriteFile(hf, content, clen, &wr, nullptr)) { CloseHandle(hf); return kOtherError; }
    CloseHandle(hf);

    std::wstring subdir = std::wstring(base) + L"\\metadir";
    if (!CreateDirectoryW(subdir.c_str(), nullptr)) return MapLastError();

    HANDLE h = CreateFileW(
        base, FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();

    bool fileOk = false, dirOk = false;
    std::vector<char> buf(64 * 1024);
    while (GetFileInformationByHandleEx(h, FileIdBothDirectoryInfo, buf.data(), (DWORD)buf.size())) {
        auto* info = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(buf.data());
        for (;;) {
            std::wstring n(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (_wcsicmp(n.c_str(), L"meta.txt") == 0) {
                fileOk = (info->EndOfFile.QuadPart == (LONGLONG)clen);
            } else if (_wcsicmp(n.c_str(), L"metadir") == 0) {
                dirOk = (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            }
            if (info->NextEntryOffset == 0) break;
            info = reinterpret_cast<FILE_ID_BOTH_DIR_INFO*>(
                reinterpret_cast<char*>(info) + info->NextEntryOffset);
        }
    }
    CloseHandle(h);
    if (!fileOk) return kNotFound;
    if (!dirOk) return kOtherError;
    return kOk;
}

// Model W write-overlay, CreateDirectoryW redirect + Win32 parent splice: create a
// subdirectory that does NOT exist on the real disk (redirected into the backing
// store), then enumerate the PARENT via the Win32 FindFirstFile family and verify
// the overlay-only subdir appears WITH the directory attribute set. kOk iff present
// as a directory; kNotFound if missing; kOtherError if not flagged a directory.
int DoWriteOvSubdirEnum(const wchar_t* base) {
    std::wstring sub = std::wstring(base) + L"\\ovsubdir";
    if (!CreateDirectoryW(sub.c_str(), nullptr)) return MapLastError();
    std::wstring pattern = std::wstring(base) + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return MapLastError();
    bool found = false, isDir = false;
    do {
        if (_wcsicmp(fd.cFileName, L"ovsubdir") == 0) {
            found = true;
            isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    if (!found) return kNotFound;
    if (!isDir) return kOtherError;
    return kOk;
}

// Model W write-overlay: create an overlay-only SUBDIRECTORY (redirected into the
// backing store, absent from the real disk), write a file INTO it, then enumerate
// the CONTENTS OF THE SUBDIR via both the Win32 FindFirstFile family and a direct
// ntdll!NtQueryDirectoryFile call, checking the just-written file is listed. This is
// the recursive-descent case (a tool that mkdir's a scratch dir then lists it, or
// `dir /s`): the parent enum shows the dir, and descending into it must reveal its
// overlay children. kOk iff BOTH enumeration surfaces list the file; otherwise the
// mapped error / kNotFound of the first surface that misses it.
int DoWriteOvSubdirInnerEnum(const wchar_t* base) {
    std::wstring sub = std::wstring(base) + L"\\ovinner";
    if (!CreateDirectoryW(sub.c_str(), nullptr)) return MapLastError();
    std::wstring file = sub + L"\\inside.txt";
    int w = DoWrite(file.c_str());
    if (w != kOk) return w;
    int rc = DoEnumFind(sub.c_str(), L"inside.txt");        // Win32 FindFirstFile path
    if (rc != kOk) return rc;
    return DoEnumFindNtDirect(sub.c_str(), L"inside.txt");   // direct NtQueryDirectoryFile
}

int DoCopy(const wchar_t* src, const wchar_t* dst) {
    if (CopyFileW(src, dst, FALSE)) return kOk;
    return MapLastError();
}

int DoRmdir(const wchar_t* path) {
    if (RemoveDirectoryW(path)) return kOk;
    return MapLastError();
}

// Reproduce JavaBuilder's scratch-tree flow inside a SINGLE process: create a
// nested subdirectory + file under <base>, then walk the tree (enumerate) to find
// the just-written entries, then recursively delete them. Under execroot-writable
// input-filtering the process's OWN created directory and file must be VISIBLE to
// its later enumerations (matching linux-sandbox's readable+writable execroot), and
// the recursive delete must succeed (an enumeration that hid the scratch would
// leave a non-empty directory -> RemoveDirectory ACCESS_DENIED, and would produce an
// empty class jar). Returns kOk only if every step behaves as it must; otherwise the
// mapped error of the first failing step (so a hidden entry surfaces as kNotFound).
int DoScratchTree(const wchar_t* base) {
    std::wstring dir = std::wstring(base) + L"\\d";
    std::wstring file = dir + L"\\f.class";

    int rc = DoMkdir(dir.c_str());
    if (rc != kOk) return rc;
    rc = DoWrite(file.c_str());
    if (rc != kOk) return rc;

    // The process must see the subdirectory it just created when enumerating <base>.
    rc = DoEnumFind(base, L"d");
    if (rc != kOk) return rc;
    // ...and the file it just wrote when enumerating the subdirectory.
    rc = DoEnumFind(dir.c_str(), L"f.class");
    if (rc != kOk) return rc;

    // Recursive cleanup: delete the file, then remove the (now-empty) directory.
    rc = DoDelete(file.c_str());
    if (rc != kOk) return rc;
    return DoRmdir(dir.c_str());
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

// Run "<exe> <op> <path>" as a child process (same sandbox tree) and return the
// child's mapped exit code. Shared by the cross-process created-set ops below.
int RunChildOp(const wchar_t* exe, const wchar_t* op, const wchar_t* path) {
    std::wstring cmd = L"\"";
    cmd += exe;
    cmd += L"\" ";
    cmd += op;
    cmd += L" \"";
    cmd += path;
    cmd += L"\"";
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

// Create a NEW file in THIS (parent) process, then spawn a SEPARATE child process
// that reads it back. Under --execroot-writable this must succeed only if the
// "files created by the tree" set is shared ACROSS processes: the parent records
// the creation, and the child - a distinct process attaching to the same manifest-
// carried shared-memory region - must see it and be allowed to read the otherwise-
// hidden undeclared path. With a per-process-only set the child would be denied
// (10) or see the path as hidden (11). Returns the mapped result of the CHILD read.
// This is the JavaBuilder pattern: one process writes _javac scratch, another reads
// it. argv[2] = path to create, argv[3] = child probe exe.
int DoWriteSpawnRead(const wchar_t* path, const wchar_t* childExe) {
    int w = DoWrite(path);
    if (w != kOk) return w;
    return RunChildOp(childExe, L"read", path);
}

// Same as DoWriteSpawnRead but the child DELETES the parent-created file. This is
// the JavaBuilder cleanup pattern: one process creates _javac/*_tmp scratch and a
// DIFFERENT process removes it. It must succeed only if the created-set propagates
// cross-process; otherwise the child's delete of an undeclared path is denied (10).
// Returns the mapped result of the CHILD delete.
int DoWriteSpawnDelete(const wchar_t* path, const wchar_t* childExe) {
    int w = DoWrite(path);
    if (w != kOk) return w;
    return RunChildOp(childExe, L"delete", path);
}

// Like RunChildOp but forwards a two-argument child op (e.g. "enumfindntdirect
// <dir> <name>"). Returns the child's exit code, or kOtherError if spawn failed.
int RunChildOp2(const wchar_t* exe, const wchar_t* op,
                const wchar_t* arg1, const wchar_t* arg2) {
    std::wstring cmd = L"\"";
    cmd += exe; cmd += L"\" "; cmd += op;
    cmd += L" \""; cmd += arg1; cmd += L"\"";
    cmd += L" \""; cmd += arg2; cmd += L"\"";
    std::wstring mutableCmd = cmd;
    STARTUPINFOW si{}; si.cb = sizeof(si);
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

// Model W write-overlay, CROSS-PROCESS enumeration: create <dir>\<name> in THIS
// (parent) process - redirected into the shared per-action overlay backing store -
// then spawn a SEPARATE child that enumerates <dir> via ntdll!NtQueryDirectoryFile.
// The child must SEE the parent's overlay file spliced into its listing (0), which
// only works if the overlay index propagates cross-process (manifest-carried SHM)
// and each process independently inserts from it. This is the enumeration analogue
// of writespawnread/writespawndelete. Returns the CHILD's exit code.
int DoWriteSpawnEnum(const wchar_t* dir, const wchar_t* name, const wchar_t* childExe) {
    std::wstring path = std::wstring(dir) + L"\\" + name;
    int w = DoWrite(path.c_str());
    if (w != kOk) return w;
    return RunChildOp2(childExe, L"enumfindntdirect", dir, name);
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

// Write each argument after the op (argv[2..]) to stdout, one per line (LF).
// Used by the launcher suite to verify BuildChildCommandLine round-trips the
// child's arguments intact - a space-containing token must arrive as ONE argv
// element (escaped regime) and cmd.exe's tail must arrive VERBATIM (quotes
// preserved). Writes via the stdout HANDLE so the launcher's -l capture sees it.
int DoEchoArgs(int argc, wchar_t** argv) {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    for (int i = 2; i < argc; ++i) {
        int n = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(n > 0 ? n - 1 : 0, '\0');
        if (n > 1) {
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, s.data(), n, nullptr, nullptr);
        }
        s.push_back('\n');
        DWORD written = 0;
        WriteFile(out, s.data(), static_cast<DWORD>(s.size()), &written, nullptr);
    }
    return kOk;
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
    // STATUS_OBJECT_NAME_NOT_FOUND / STATUS_OBJECT_PATH_NOT_FOUND (how
    // --filter-inputs masks a denied native read).
    if (st == static_cast<NTSTATUS>(0xC0000034L) ||
        st == static_cast<NTSTATUS>(0xC000003AL)) return kNotFound;
    return kOtherError;
}

#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif

// Model W NT-layer redirect: create + write <base>\ntov.txt via the native
// NtCreateFile syscall (bypassing Win32 CreateFileW), then read it back the same way.
// Both opens must be redirected to the backing store (the real execroot never gets the
// path), so the read-back succeeds. Exercises the OBJECT_ATTRIBUTES rewrite in
// Detoured_NtCreateFile that Win32-layer redirection alone cannot cover.
int DoNtWriteRead(const wchar_t* base) {
    using NtCreateFileFn = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    auto ntCreateFile = reinterpret_cast<NtCreateFileFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
    if (ntCreateFile == nullptr) return kOtherError;

    std::wstring path = std::wstring(base) + L"\\ntov.txt";
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
        &h, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (st != 0) {
        if (st == static_cast<NTSTATUS>(0xC0000022L)) return kDenied;
        return kOtherError;
    }
    DWORD written = 0;
    WriteFile(h, "x", 1, &written, nullptr);
    CloseHandle(h);

    return DoNtRead(path.c_str());
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
    if (op == L"createnew") return DoCreateNew(argv[2]);
    if (op == L"rewrite") return DoRewrite(argv[2]);
    if (op == L"writeread") return DoWriteRead(argv[2]);
    if (op == L"writedelete") return DoWriteDelete(argv[2]);
    if (op == L"writespawnread") {
        if (argc < 4) return kBadUsage;
        return DoWriteSpawnRead(argv[2], argv[3]);
    }
    if (op == L"writespawndelete") {
        if (argc < 4) return kBadUsage;
        return DoWriteSpawnDelete(argv[2], argv[3]);
    }
    if (op == L"writespawnenum") {
        if (argc < 5) {
            fwprintf(stderr, L"usage: probe writespawnenum <dir> <name> <childExe>\n");
            return kBadUsage;
        }
        return DoWriteSpawnEnum(argv[2], argv[3], argv[4]);
    }
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
    if (op == L"statex") return DoStatEx(argv[2]);
    if (op == L"statbyname") return DoStatByName(argv[2]);
    if (op == L"stata") return DoStatA(argv[2]);
    if (op == L"reada") return DoReadA(argv[2]);
    if (op == L"enumerate") return DoEnumerate(argv[2]);
    if (op == L"findfile") return DoFindFile(argv[2]);
    if (op == L"enumfind") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe enumfind <dir> <name>\n");
            return kBadUsage;
        }
        return DoEnumFind(argv[2], argv[3]);
    }
    if (op == L"enumfindnt") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe enumfindnt <dir> <name>\n");
            return kBadUsage;
        }
        return DoEnumFindNt(argv[2], argv[3]);
    }
    if (op == L"enumfindntdirect") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe enumfindntdirect <dir> <name>\n");
            return kBadUsage;
        }
        return DoEnumFindNtDirect(argv[2], argv[3]);
    }
    if (op == L"writeenum") {
        if (argc < 4) {
            fwprintf(stderr, L"usage: probe writeenum <dir> <name>\n");
            return kBadUsage;
        }
        return DoWriteEnum(argv[2], argv[3]);
    }
    if (op == L"writeenummulti") {
        if (argc < 5) {
            fwprintf(stderr, L"usage: probe writeenummulti <dir> <bufBytes> <name1> [name2 ...]\n");
            return kBadUsage;
        }
        ULONG bufBytes = (ULONG)_wtoi(argv[3]);
        std::vector<std::wstring> names;
        for (int i = 4; i < argc; ++i) names.emplace_back(argv[i]);
        return DoWriteEnumMulti(argv[2], bufBytes, names);
    }
    if (op == L"rmdir") return DoRmdir(argv[2]);
    if (op == L"writeovdirenum") return DoWriteOvDirEnum(argv[2]);
    if (op == L"writeenumgfibhe") {
        if (argc < 4) { fwprintf(stderr, L"usage: probe writeenumgfibhe <dir> <name>\n"); return kBadUsage; }
        return DoWriteEnumGfibhe(argv[2], argv[3]);
    }
    if (op == L"writeenumfind") {
        if (argc < 4) { fwprintf(stderr, L"usage: probe writeenumfind <dir> <name>\n"); return kBadUsage; }
        return DoWriteEnumFind(argv[2], argv[3]);
    }
    if (op == L"writeenumex") {
        if (argc < 4) { fwprintf(stderr, L"usage: probe writeenumex <dir> <name>\n"); return kBadUsage; }
        return DoWriteEnumEx(argv[2], argv[3]);
    }
    if (op == L"writeenumfilterfind") {
        if (argc < 6) { fwprintf(stderr, L"usage: probe writeenumfilterfind <dir> <wildcard> <match> <nomatch>\n"); return kBadUsage; }
        return DoWriteEnumFilterFind(argv[2], argv[3], argv[4], argv[5]);
    }
    if (op == L"writeenumfilternt") {
        if (argc < 6) { fwprintf(stderr, L"usage: probe writeenumfilternt <dir> <wildcard> <match> <nomatch>\n"); return kBadUsage; }
        return DoWriteEnumFilterNt(argv[2], argv[3], argv[4], argv[5]);
    }
    if (op == L"writeenumsynth") {
        if (argc < 5) { fwprintf(stderr, L"usage: probe writeenumsynth <dir> <wildcard> <name>\n"); return kBadUsage; }
        return DoWriteEnumSynth(argv[2], argv[3], argv[4]);
    }
    if (op == L"writeenummeta") return DoWriteEnumMeta(argv[2]);
    if (op == L"writeovsubdirenum") return DoWriteOvSubdirEnum(argv[2]);
    if (op == L"writeovsubdirinnerenum") return DoWriteOvSubdirInnerEnum(argv[2]);
    if (op == L"writeovdelete") return DoWriteOvDelete(argv[2]);
    if (op == L"writeovdeleteh") return DoWriteOvDeleteH(argv[2]);
    if (op == L"writeovrename") return DoWriteOvRename(argv[2]);
    if (op == L"writeovrenameh") return DoWriteOvRenameH(argv[2]);
    if (op == L"writeovstat") return DoWriteOvStat(argv[2]);
    if (op == L"writeovhardlink") return DoWriteOvHardlink(argv[2]);
    if (op == L"writeovsymlink") return DoWriteOvSymlink(argv[2]);
    if (op == L"writeovreplace") return DoWriteOvReplace(argv[2]);
    if (op == L"writeovrmdir") return DoWriteOvRmdir(argv[2]);
    if (op == L"scratchtree") return DoScratchTree(argv[2]);
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
    if (op == L"echoargs") return DoEchoArgs(argc, argv);
    if (op == L"exit") return DoExit(argv[2]);
    if (op == L"sleep") return DoSleep(argv[2]);
    if (op == L"cwdis") return DoCwdIs(argv[2]);
    if (op == L"tempfile") return DoTempFile(argv[2]);
    if (op == L"ntread") return DoNtRead(argv[2]);
    if (op == L"ntwriteread") return DoNtWriteRead(argv[2]);
    fwprintf(stderr, L"probe: unknown op '%s'\n", argv[1]);
    return kBadUsage;
}
