// BazelSandbox.exe: a standalone Windows process sandbox that reproduces
// BuildXL's BazelSandbox using only upstream Detours + the vendored
// DetoursServices enforcement engine. See plan.md and README.md.

#include <windows.h>
#include <detours.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "manifest_builder.h"

// Same GUID as DetoursServices.h g_manifestGuid / IDetourServicesManifest. The
// injected DetoursServices.dll reads the serialized file-access manifest from
// its process payload under this GUID (via DetourFindPayload) in DllMain.
static const GUID kManifestGuid = {
    0x7CFDBB96, 0xC3D6, 0x47CD, {0x90, 0x26, 0x8F, 0xA8, 0x63, 0xC5, 0x2F, 0xEC}};

// ---------------------------------------------------------------------------
// Options (ported from BuildXL SandboxOption.cs).
// ---------------------------------------------------------------------------
namespace {

constexpr uint32_t kInfiniteTime = 0;

struct Options {
    std::wstring workingDir;
    uint32_t timeoutSecs = kInfiniteTime;
    uint32_t killDelaySecs = kInfiniteTime;
    std::wstring stdoutPath;
    std::wstring stderrPath;
    std::vector<std::wstring> readonlyFiles;
    std::vector<std::wstring> writableFiles;
    std::vector<std::wstring> blockedFiles;
    // -d <path>: a declared output's parent DIRECTORY. Applied as a node-only
    // grant (read + create-directory + write on the exact dir) so the tool can
    // stat/enumerate it and its recursive mkdir succeeds (ALREADY_EXISTS), while
    // the dir's subtree stays Deny - undeclared files inside it remain hidden and
    // unwritable. Mirrors linux-sandbox, which pre-creates output parent dirs in
    // the (writable) sandbox execroot. See docs/detours-input-filtering.md.
    std::vector<std::wstring> outputDirs;
    // -D <file>: write launcher diagnostics to this file (linux-sandbox parity).
    std::wstring debugPath;
    // --trace <file>: write a per-access report (from the injected DLL) here.
    std::wstring tracePath;
    // -S <file>: write child resource-usage statistics (ExecutionStatistics
    // protobuf) here, for linux-sandbox parity.
    std::wstring statsPath;
    // Network sandboxing (Bazel linux-sandbox parity): 0 = allow (default),
    // 1 = loopback only (-N), 2 = no network at all (-n).
    int networkPolicy = 0;
    // -H / --hermetic: strict read hermeticity. When false (default) the working
    // directory is READABLE (writes still confined to -w), matching the default
    // linux-sandbox where "the entire filesystem is made read-only" and only the
    // working dir is writable - i.e. reads are never confined to declared inputs.
    // When true, the working directory is denied by default and only -r/-w grants
    // expose it, matching --experimental_use_hermetic_linux_sandbox (Goal 2).
    bool hermetic = false;
    // --filter-inputs: strict "match linux-sandbox reads" mode. Implies hermetic
    // (execroot denied by default; only -r/-w visible) and additionally makes the
    // sandbox SUBTRACTIVE: denied reads of existing-but-undeclared paths report
    // NOT_FOUND instead of ACCESS_DENIED, and undeclared entries are removed from
    // directory enumerations - so undeclared inputs are invisible, as under
    // linux-sandbox's symlink forest. See docs/detours-input-filtering.md.
    bool filterInputs = false;
    // --execroot-writable: allow the sandboxed tool to CREATE new files/directories
    // anywhere in the execroot (working dir) and re-write files it created, while
    // still DENYING overwrites of pre-existing undeclared/input files. This matches
    // linux-sandbox, whose throwaway execroot is fully writable, and covers tools
    // that write undeclared scratch inside the execroot (e.g. vite's node_modules/
    // .vite-temp) without granting a hole to clobber real inputs. Declared -w outputs
    // stay freely overwritable; -r inputs stay read-only. Enforced via the execroot
    // cone's OverrideAllowWriteForExistingFiles policy bit (see PolicyResult::AllowWrite).
    bool execrootWritable = false;
    std::vector<std::wstring> args;  // tool + arguments
};

[[noreturn]] void Die(const std::wstring& msg) {
    fwprintf(stderr, L"BazelSandbox: %s\n", msg.c_str());
    exit(1);
}

std::wstring ToAbsolute(const std::wstring& path) {
    wchar_t buf[MAX_PATH];
    DWORD n = GetFullPathNameW(path.c_str(), MAX_PATH, buf, nullptr);
    if (n == 0) {
        Die(L"cannot resolve path: " + path);
    }
    if (n < MAX_PATH) {
        return std::wstring(buf, n);
    }
    std::vector<wchar_t> big(n);
    DWORD n2 = GetFullPathNameW(path.c_str(), n, big.data(), nullptr);
    return std::wstring(big.data(), n2);
}

void PrintUsage(int exitCode) {
    fwprintf(stderr,
        L"\nUsage: BazelSandbox [option...] -- command [arg...]\n"
        L"\nOptions:\n"
        L"  -W <dir>   working directory (default: current directory)\n"
        L"  -T <secs>  timeout after which the child is terminated\n"
        L"  -t <secs>  grace period before force kill after timeout\n"
        L"  -l <file>  redirect stdout to a file\n"
        L"  -L <file>  redirect stderr to a file\n"
        L"  -w <path>  make a file/directory read/writable in the sandbox\n"
        L"  -r <path>  make a file/directory read-only in the sandbox\n"
        L"  -b <path>  make a file/directory inaccessible in the sandbox\n"
        L"  -d <path>  reveal an output's parent dir (allow mkdir/write on the\n"
        L"             dir itself; its undeclared contents stay hidden)\n"
        L"  -N         allow only loopback network access (block external)\n"
        L"  -n         block all network access (no loopback either)\n"
        L"  -H         hermetic reads: deny the working dir by default so only\n"
        L"             -r/-w inputs are readable (default: reads unconfined, like\n"
        L"             the default linux-sandbox; writes still confined to -w)\n"
        L"  --filter-inputs  strict mode: implies -H and makes undeclared inputs\n"
        L"             invisible - denied reads return NOT_FOUND and directory\n"
        L"             listings hide undeclared entries (matches linux-sandbox)\n"
        L"  --execroot-writable  allow creating NEW files/dirs anywhere in the\n"
        L"             working dir (and re-writing files created this run) while still\n"
        L"             denying overwrites of pre-existing undeclared/input files\n"
        L"  -D <file>  write launcher diagnostics to a file\n"
        L"  --trace <file>  write a per-access report (from the sandbox DLL) to a file\n"
        L"  -S <file>  write child resource-usage statistics (protobuf) to a file\n"
        L"  @FILE      read newline-separated arguments from FILE\n"
        L"  --         command to run in the sandbox, followed by arguments\n");
    exit(exitCode);
}

// Expand @response-files; expansion stops at the first "--".
std::vector<std::wstring> ExpandArguments(const std::vector<std::wstring>& args) {
    std::vector<std::wstring> out;
    for (size_t i = 0; i < args.size(); i++) {
        const std::wstring& a = args[i];
        if (a.size() > 1 && a[0] == L'@') {
            std::wifstream f(a.substr(1));
            if (!f) {
                Die(L"cannot open response file: " + a.substr(1));
            }
            std::wstring line;
            while (std::getline(f, line)) {
                if (!line.empty() && line.back() == L'\r') {
                    line.pop_back();
                }
                out.push_back(line);
            }
        } else if (a == L"--") {
            for (size_t j = i; j < args.size(); j++) {
                out.push_back(args[j]);
            }
            break;
        } else {
            out.push_back(a);
        }
    }
    return out;
}

uint32_t ParseUint(const std::wstring& s) {
    return static_cast<uint32_t>(wcstoul(s.c_str(), nullptr, 10));
}

Options ParseOptions(std::vector<std::wstring> args) {
    args = ExpandArguments(args);
    Options o;
    size_t i = 0;
    for (; i < args.size() && args[i] != L"--"; i++) {
        const std::wstring& arg = args[i];
        if (arg.size() > 1 && (arg[0] == L'/' || arg[0] == L'-')) {
            std::wstring name = arg.substr(1);
            auto next = [&]() -> std::wstring {
                if (i + 1 >= args.size()) Die(L"missing value for " + arg);
                return args[++i];
            };
            if (name == L"h") {
                PrintUsage(0);
            } else if (name == L"W") {
                o.workingDir = ToAbsolute(next());
            } else if (name == L"T") {
                o.timeoutSecs = ParseUint(next());
            } else if (name == L"t") {
                o.killDelaySecs = ParseUint(next());
            } else if (name == L"l") {
                o.stdoutPath = ToAbsolute(next());
            } else if (name == L"L") {
                o.stderrPath = ToAbsolute(next());
            } else if (name == L"w") {
                o.writableFiles.push_back(ToAbsolute(next()));
            } else if (name == L"r") {
                o.readonlyFiles.push_back(ToAbsolute(next()));
            } else if (name == L"b") {
                o.blockedFiles.push_back(ToAbsolute(next()));
            } else if (name == L"d") {
                o.outputDirs.push_back(ToAbsolute(next()));
            } else if (name == L"N") {
                if (o.networkPolicy == 2) Die(L"-N and -n are mutually exclusive");
                o.networkPolicy = 1;
            } else if (name == L"n") {
                if (o.networkPolicy == 1) Die(L"-N and -n are mutually exclusive");
                o.networkPolicy = 2;
            } else if (name == L"H" || name == L"-hermetic") {
                o.hermetic = true;
            } else if (name == L"-filter-inputs") {
                o.filterInputs = true;
                o.hermetic = true;
            } else if (name == L"-execroot-writable") {
                o.execrootWritable = true;
            } else if (name == L"D") {
                o.debugPath = ToAbsolute(next());
            } else if (name == L"-trace") {
                o.tracePath = ToAbsolute(next());
            } else if (name == L"S") {
                o.statsPath = ToAbsolute(next());
            } else {
                Die(L"unknown option: " + arg);
            }
        } else {
            Die(L"unknown argument: " + arg);
        }
    }
    if (i >= args.size() || args[i] != L"--") {
        Die(L"command to sandbox not specified (missing --)");
    }
    for (size_t j = i + 1; j < args.size(); j++) {
        o.args.push_back(args[j]);
    }
    if (o.args.empty()) {
        Die(L"no command specified after --");
    }
    if (o.workingDir.empty()) {
        wchar_t cwd[MAX_PATH];
        GetCurrentDirectoryW(MAX_PATH, cwd);
        o.workingDir = cwd;
    }
    if (o.tracePath.empty()) {
        wchar_t envTrace[1024];
        DWORD n = GetEnvironmentVariableW(L"BAZEL_SANDBOX_TRACE", envTrace, 1024);
        if (n > 0 && n < 1024) {
            o.tracePath = std::wstring(envTrace) + L"." +
                          std::to_wstring(GetCurrentProcessId());
        }
    }
    return o;
}

// Append one Windows-escaped argument (CommandLineToArgvW rules).
void EscapeArg(const std::wstring& s, std::wstring& out) {
    if (s.empty()) {
        out += L"\"\"";
        return;
    }
    bool needEscape = false;
    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t' || c == L'\n' || c == L'\v' || c == L'"') {
            needEscape = true;
            break;
        }
    }
    if (!needEscape) {
        out += s;
        return;
    }
    out += L'"';
    for (size_t i = 0; i < s.size(); i++) {
        size_t backslashes = 0;
        while (i < s.size() && s[i] == L'\\') {
            i++;
            backslashes++;
        }
        if (i == s.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        } else if (s[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out += L'"';
        } else {
            out.append(backslashes, L'\\');
            out += s[i];
        }
    }
    out += L'"';
}

std::wstring BuildCommandLine(const std::vector<std::wstring>& args) {
    std::wstring cmd;
    for (size_t i = 0; i < args.size(); i++) {
        if (i != 0) {
            cmd += L' ';
        }
        EscapeArg(args[i], cmd);
    }
    return cmd;
}

// Case-insensitive test whether a tool path's final component is "cmd.exe".
bool IsCmdExe(const std::wstring& toolPath) {
    size_t slash = toolPath.find_last_of(L"\\/");
    std::wstring base =
        (slash == std::wstring::npos) ? toolPath : toolPath.substr(slash + 1);
    if (base.size() != 7) return false;
    static const wchar_t kCmd[] = L"cmd.exe";
    for (size_t k = 0; k < 7; k++) {
        if (towlower(base[k]) != kCmd[k]) return false;
    }
    return true;
}

// Build the child command line from the parsed argv (o.args).
//
// We deliberately match how Bazel itself launches Windows subprocesses (see
// Bazel's src/main/java/com/google/devtools/build/lib/shell/
// WindowsSubprocessFactory.java, method escapeArgvRest). Doing exactly what
// Bazel's own launcher does means a command behaves identically whether Bazel
// runs it directly (local strategy) or through this sandbox wrapper.
//
// The child's command-line STRING must be quoted for the child's own parser, and
// Windows has two parsing regimes, so Bazel dispatches on argv0 == "cmd.exe":
//
//  - Normal programs parse their command line with the CommandLineToArgvW / CRT
//    convention (inner quotes as \"), so each argument is escaped with EscapeArg
//    (Bazel uses ShellUtils.windowsEscapeArg for this branch).
//  - cmd.exe does NOT use that convention: it strips one outer quote pair (with
//    /S) and otherwise treats the text literally, and does not understand \".
//    So when argv0 is cmd.exe, Bazel (and therefore we) append its arguments
//    VERBATIM (no escaping). The command already carries real, literal quotes:
//    Bazel's transport \" escaping was consumed when THIS process parsed its own
//    argv via CommandLineToArgvW. Re-escaping would corrupt quoted paths such as
//    "external\zlib+\crc32.h" (cmd's copy would then read '+' as its file-
//    concatenation operator).
//
// This is dispatch on the child's command-line grammar (the same key Bazel uses),
// not filename special-casing.
std::wstring BuildChildCommandLine(const std::vector<std::wstring>& args) {
    bool isCmd = !args.empty() && IsCmdExe(args[0]);
    std::wstring out;
    for (size_t k = 0; k < args.size(); k++) {
        if (k != 0) out += L' ';
        // argv0 is always escaped so a path with spaces stays one token; the
        // rest is verbatim for cmd.exe, escaped for every other tool.
        if (k == 0 || !isCmd) {
            EscapeArg(args[k], out);
        } else {
            out += args[k];
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Cross-process created-files set (shared memory).
//
// The whole sandboxed process tree is a single Bazel action. Like linux-sandbox's
// shared writable execroot, a scratch file/dir CREATED by ANY process in the tree
// must be readable/enumerable/deletable by EVERY other process in the tree (e.g.
// JavaBuilder forks javac to create _javac/*_tmp/native_headers in one process and
// cleans it up in another). The DetoursServices DLL keeps that "created this run"
// set here; a per-process set cannot see a sibling/parent's creations, so the set
// is backed by a named shared-memory region created per launcher invocation (i.e.
// per action - no cross-action leakage) and inherited by every injected DLL. The
// region name is carried in the manifest payload (ManifestBuilder::SetCreatedShmName
// -> g_bazelCreatedShmName in the DLL), which is re-copied verbatim to every child
// on injection, so it propagates robustly even to a child spawned with a custom
// environment block. Layout / semantics are mirrored in
// vendor/detours-services/PolicyResult.cpp (CreatedFilesTracker). Only set up when
// --execroot-writable is in effect (the only mode that consults the tracker).
// ---------------------------------------------------------------------------
struct CreatedShmHeader {
    volatile long long usedBytes;  // bytes of records written into the data region
    long long capacity;            // usable data-region size in bytes
};
constexpr long long kCreatedShmDataBytes = 32ll * 1024 * 1024;

struct CreatedShmHandles {
    HANDLE mapping = nullptr;
    HANDLE mutex = nullptr;
    std::wstring name;
};

// Create the shared-memory region + mutex and initialize the header. The region
// name is returned in CreatedShmHandles::name so the caller can carry it in the
// manifest payload (ManifestBuilder::SetCreatedShmName), which propagates it to
// every injected DLL in the process tree via the payload that is re-copied on
// injection - robust even for children spawned with a custom environment block.
// Returns the owning handles; keep them open for the lifetime of the process tree.
CreatedShmHandles SetupCreatedFilesShm() {
    CreatedShmHandles shm;
    std::wstring base = L"Local\\BazelSandboxCreated_" +
                        std::to_wstring(GetCurrentProcessId()) + L"_" +
                        std::to_wstring(GetTickCount64());
    long long total = static_cast<long long>(sizeof(CreatedShmHeader)) + kCreatedShmDataBytes;
    HANDLE mapping = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
        static_cast<DWORD>(total >> 32), static_cast<DWORD>(total & 0xFFFFFFFF),
        base.c_str());
    if (mapping == nullptr) return shm;
    void* view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(CreatedShmHeader));
    if (view == nullptr) {
        CloseHandle(mapping);
        return shm;
    }
    auto* h = static_cast<CreatedShmHeader*>(view);
    h->usedBytes = 0;
    h->capacity = kCreatedShmDataBytes;
    UnmapViewOfFile(view);
    shm.mutex = CreateMutexW(nullptr, FALSE, (base + L".mtx").c_str());
    shm.mapping = mapping;
    shm.name = base;
    return shm;
}

// Discard undeclared scratch after the sandboxed process tree exits, mirroring
// linux-sandbox, which throws away its writable execroot after every action so no
// action ever inherits another's (or a prior attempt's) leftover files. We run
// IN PLACE, so the execroot persists between actions and across Bazel's reduced->
// full classpath re-execution of the same Java action; a first attempt that fails
// mid-way leaves scratch (e.g. _javac/*_tmp/native_headers) that the second
// attempt's JavaBuilder cleanupDirectory cannot remove (hidden by the input
// filter) -> "directory not empty". Deleting our own tracked creations on exit
// gives each attempt/action the clean slate it would get under linux-sandbox.
//
// The SHM created-set records ONLY undeclared creations under the execroot-writable
// (OverrideAllowWriteForExistingFiles) cone; declared -w outputs are AllowAll /
// IndicateUntracked and are never in the set, so they are preserved. Deleting
// deepest-first empties a scratch directory before its own removal; a directory
// that still holds a declared output (e.g. an -d output parent dir) simply fails
// RemoveDirectory and is left in place. Skipped under -D (--sandbox_debug), matching
// linux-sandbox keeping its sandbox dir for inspection.
void CleanupCreatedScratch(HANDLE mapping) {
    if (mapping == nullptr) return;
    BYTE* view = static_cast<BYTE*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
    if (view == nullptr) return;
    auto* h = reinterpret_cast<CreatedShmHeader*>(view);
    long long used = h->usedBytes;
    BYTE* data = view + sizeof(CreatedShmHeader);
    std::vector<std::wstring> paths;
    long long off = 0;
    while (off + static_cast<long long>(sizeof(uint32_t)) <= used) {
        uint32_t nameBytes = *reinterpret_cast<uint32_t*>(data + off);
        long long recEnd = off + static_cast<long long>(sizeof(uint32_t)) + nameBytes;
        if (recEnd > used) break;
        const wchar_t* chars = reinterpret_cast<const wchar_t*>(data + off + sizeof(uint32_t));
        paths.emplace_back(chars, nameBytes / sizeof(wchar_t));
        long long rec = static_cast<long long>(sizeof(uint32_t)) + nameBytes;
        rec = (rec + 3) & ~3ll;  // records are 4-byte aligned
        off += rec;
    }
    UnmapViewOfFile(view);
    // Deepest paths first so children are gone before we remove their parent dir.
    std::sort(paths.begin(), paths.end(),
              [](const std::wstring& a, const std::wstring& b) { return a.size() > b.size(); });
    for (const auto& p : paths) {
        if (!DeleteFileW(p.c_str())) {
            RemoveDirectoryW(p.c_str());
        }
    }
}

// Encode a uint64 as a protobuf base-128 varint.
void PutVarint(std::string& out, uint64_t v) {
    while (v >= 0x80) {
        out.push_back(static_cast<char>((v & 0x7F) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<char>(v));
}

// Append a proto3 int64 field (wire type 0) if the value is non-zero. Only used
// with field numbers <= 15, so the tag always fits in a single byte.
void PutInt64Field(std::string& out, uint32_t fieldNum, uint64_t value) {
    if (value == 0) return;  // proto3 omits default (zero) values
    out.push_back(static_cast<char>((fieldNum << 3) | 0));  // tag: varint field
    PutVarint(out, value);
}

// Write a tools.protos.ExecutionStatistics protobuf describing the child's
// resource usage, mirroring what linux-sandbox writes with -S. The numbers come
// from the job object, which accounts for the whole (possibly multi-process)
// tree and retains the totals after the processes have exited. Bazel parses the
// whole file as a single message (no length framing), so we write raw bytes.
void WriteStats(const std::wstring& statsPath, HANDLE hJob) {
    if (statsPath.empty() || hJob == nullptr) return;

    uint64_t utimeSec = 0, utimeUsec = 0, stimeSec = 0, stimeUsec = 0;
    uint64_t maxrssKb = 0, inBlock = 0, ouBlock = 0;

    JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION acct{};
    if (QueryInformationJobObject(hJob, JobObjectBasicAndIoAccountingInformation,
                                  &acct, sizeof(acct), nullptr)) {
        // Times are in 100-ns units; split into whole seconds + microseconds.
        uint64_t user100ns = static_cast<uint64_t>(acct.BasicInfo.TotalUserTime.QuadPart);
        uint64_t kern100ns = static_cast<uint64_t>(acct.BasicInfo.TotalKernelTime.QuadPart);
        utimeSec = user100ns / 10000000ULL;
        utimeUsec = (user100ns % 10000000ULL) / 10ULL;
        stimeSec = kern100ns / 10000000ULL;
        stimeUsec = (kern100ns % 10000000ULL) / 10ULL;
        inBlock = acct.IoInfo.ReadOperationCount;
        ouBlock = acct.IoInfo.WriteOperationCount;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
    if (QueryInformationJobObject(hJob, JobObjectExtendedLimitInformation,
                                  &ext, sizeof(ext), nullptr)) {
        // Bazel treats maxrss as kilobytes on non-Darwin platforms (matching
        // Linux getrusage); PeakJobMemoryUsed is in bytes.
        maxrssKb = static_cast<uint64_t>(ext.PeakJobMemoryUsed) / 1024ULL;
    }

    // ResourceUsage message (field numbers from execution_statistics.proto).
    std::string ru;
    PutInt64Field(ru, 1, utimeSec);   // utime_sec
    PutInt64Field(ru, 2, utimeUsec);  // utime_usec
    PutInt64Field(ru, 3, stimeSec);   // stime_sec
    PutInt64Field(ru, 4, stimeUsec);  // stime_usec
    PutInt64Field(ru, 5, maxrssKb);   // maxrss (KiB)
    PutInt64Field(ru, 12, inBlock);   // inblock
    PutInt64Field(ru, 13, ouBlock);   // oublock

    // ExecutionStatistics { ResourceUsage resource_usage = 1; }
    // Always emit the length-delimited field so hasResourceUsage() is true.
    std::string msg;
    msg.push_back(static_cast<char>((1 << 3) | 2));  // tag: field 1, wire type 2
    PutVarint(msg, ru.size());
    msg.append(ru);

    HANDLE h = CreateFileW(statsPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, msg.data(), static_cast<DWORD>(msg.size()), &written, nullptr);
    CloseHandle(h);
}

std::string ToAnsi(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), static_cast<int>(w.size()), &s[0],
                        n, nullptr, nullptr);
    return s;
}

std::wstring ExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : path.substr(0, slash);
}

HANDLE OpenOutputFile(const std::wstring& path) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        Die(L"cannot open output file: " + path);
    }
    return h;
}

// Returns a standard handle that is safe to hand to a child via
// STARTF_USESTDHANDLES with bInheritHandles=TRUE. When we are launched as a
// subprocess (e.g. by Bazel), our inherited std handles are valid but may not
// carry the HANDLE_FLAG_INHERIT bit, and stdin may be missing entirely. With
// STARTF_USESTDHANDLES every slot must be an inheritable, valid handle or the
// child receives an invalid handle (manifesting as "The handle is invalid").
// So we mark real handles inheritable and substitute the NUL device for any
// that are absent. If a NUL handle is opened, it is returned via *openedNul so
// the caller can close it afterwards.
HANDLE PrepareStdHandle(HANDLE h, bool forRead, HANDLE* openedNul) {
    *openedNul = nullptr;
    DWORD type;
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        type = FILE_TYPE_UNKNOWN;
        SetLastError(ERROR_INVALID_HANDLE);
    } else {
        SetLastError(NO_ERROR);
        type = GetFileType(h);
    }
    if (type == FILE_TYPE_UNKNOWN && GetLastError() != NO_ERROR) {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        HANDLE nul = CreateFileW(L"NUL", forRead ? GENERIC_READ : GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                                 OPEN_EXISTING, 0, nullptr);
        *openedNul = nul;
        return nul;
    }
    SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    return h;
}

// Reads the machine architecture from a PE file's COFF header (the value in
// IMAGE_FILE_HEADER.Machine, e.g. IMAGE_FILE_MACHINE_AMD64 / _I386 / _ARM64).
// Returns false if the file cannot be opened or is not a PE image (e.g. a .bat
// script), in which case the caller should not treat it as a bitness mismatch.
static bool PeMachine(const std::wstring& path, USHORT* out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    if (ReadFile(h, &dos, sizeof(dos), &read, nullptr) && read == sizeof(dos) &&
        dos.e_magic == IMAGE_DOS_SIGNATURE &&
        SetFilePointer(h, dos.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
        DWORD sig = 0;
        IMAGE_FILE_HEADER fh{};
        if (ReadFile(h, &sig, sizeof(sig), &read, nullptr) && read == sizeof(sig) &&
            sig == IMAGE_NT_SIGNATURE &&
            ReadFile(h, &fh, sizeof(fh), &read, nullptr) && read == sizeof(fh)) {
            *out = fh.Machine;
            ok = true;
        }
    }
    CloseHandle(h);
    return ok;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::vector<std::wstring> rawArgs(argv + 1, argv + argc);
    Options o = ParseOptions(std::move(rawArgs));

    // -D <file>: launcher-side diagnostics (Bazel linux-sandbox parity). This
    // logs what *the sandbox wrapper* did (options, resolved paths, the manifest
    // policy scopes, injection status, exit). It is distinct from --trace, which
    // logs what the *sandboxed process* touched. Buffered writes are flushed by
    // the CRT on any exit()/return-from-main path (incl. Die()).
    FILE* dbgFp = nullptr;
    if (!o.debugPath.empty()) {
        dbgFp = _wfopen(o.debugPath.c_str(), L"w, ccs=UTF-8");
        if (dbgFp == nullptr) Die(L"cannot open debug file: " + o.debugPath);
    }
    auto dline = [&](const std::wstring& s) {
        if (dbgFp) { fputws(s.c_str(), dbgFp); fputwc(L'\n', dbgFp); }
    };
    // Scope-policy line (kind = na/ro/rw); mirrors the manifest we build.
    auto dbg = [&](const wchar_t* kind, const std::wstring& p) {
        if (dbgFp) fwprintf(dbgFp, L"scope %s: %s\n", kind, p.c_str());
    };

    dline(L"BazelSandbox debug log");
    dline(L"working dir: " + o.workingDir);
    if (o.timeoutSecs != kInfiniteTime)
        dline(L"timeout (s): " + std::to_wstring(o.timeoutSecs));
    if (!o.stdoutPath.empty()) dline(L"stdout -> " + o.stdoutPath);
    if (!o.stderrPath.empty()) dline(L"stderr -> " + o.stderrPath);
    dline(L"network policy: " +
          std::wstring(o.networkPolicy == 0   ? L"allow"
                       : o.networkPolicy == 1 ? L"loopback-only"
                                              : L"blocked"));
    if (!o.tracePath.empty()) dline(L"trace -> " + o.tracePath);

    // Bazel passes the executable using its internal forward-slash path style
    // (e.g. "bazel-out/.../validator.bat"). CreateProcessW - and the cmd.exe it
    // auto-invokes for a .bat/.cmd target - only resolve a *relative* executable
    // when it uses Windows '\' separators. Given forward slashes, cmd treats the
    // first component as a bare command ("'bazel-out' is not recognized") and
    // CreateProcessW fails outright (ERROR_FILE_NOT_FOUND). Normalize separators
    // in the executable token only; the remaining arguments are left untouched so
    // tools receive Bazel's forward-slash paths verbatim, exactly as they do under
    // the local strategy.
    std::replace(o.args[0].begin(), o.args[0].end(), L'/', L'\\');

    const std::wstring toolPath = ToAbsolute(o.args[0]);
    dline(L"tool: " + toolPath);

    // Refuse a target we cannot sandbox BEFORE spawning it. The injected hook
    // DLL is x64, so a non-x64 target (32-bit, or native ARM64) could not load
    // it - which raises a blocking hard-error dialog and would leave the child
    // running unsandboxed. We read the target's PE machine type from disk and
    // fail closed with a clear message, so nothing is ever created. A path that
    // is not a PE image (e.g. a .bat) is left alone - its real interpreter is
    // the process that actually runs. (A 32-bit *grandchild* spawned by an x64
    // tool is still a gap; see the README's cross-bitness limitation.)
    USHORT toolMachine = 0;
    if (PeMachine(toolPath, &toolMachine) &&
        toolMachine != IMAGE_FILE_MACHINE_AMD64) {
        dline(L"refused: non-x64 target");
        fwprintf(stderr,
                 L"BazelSandbox: refusing to run non-x64 target '%s' (machine "
                 L"0x%04X). Only x64 children can be sandboxed by the x64 hook "
                 L"DLL; rebuild the tool as x64 or add an x86 DetoursServices.dll.\n",
                 toolPath.c_str(), toolMachine);
        return 3;
    }

    // DLL to inject (same-architecture). We only build x64.
    const std::wstring dllPath = ExeDir() + L"\\DetoursServices.dll";
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Die(L"cannot find DetoursServices.dll next to BazelSandbox.exe");
    }
    const std::string dllAnsi = ToAnsi(dllPath);
    dline(L"dll: " + dllPath);

    // Build the file access manifest (CreateManifest in SandboxedProcess.cs).
    using namespace bazelsandbox;
    // Enforce policy on the literal path opened rather than resolving symlinks/junctions to their
    // targets. Reparse-point resolution cannot help the in-place execution model here: policy is
    // evaluated on the path as opened (DetouredFunctions Detoured_CreateFileW computes accessCheck
    // from the literal path and denies on it unconditionally), and resolution only ADDS enforcement
    // on the target - it never turns a denied literal path into an allowed one. It is a
    // hermeticity-tightening feature (deny symlink escapes), not an allow mechanism. Enabling full
    // resolution (clearing Flag_IgnoreFullReparsePointResolving too) was also unstable in this
    // standalone build (broke plain file copies with ERROR_INVALID_HANDLE). So instead the runner
    // (WindowsSandboxedSpawnRunner) grants the in-place LINK paths directly: each declared input's
    // execroot location is granted readable, which covers runfiles symlink forests name-agnostically.
    // The one residual is the aspect_rules_js pnpm node_modules store, whose package directory
    // junctions are not declared as inputs; the runner grants that store as a readable cone.
    uint32_t flags = Flag_FailUnexpectedFileAccesses | Flag_MonitorNtCreateFile |
                     Flag_MonitorChildProcesses | Flag_MonitorZwCreateOpenQueryFile |
                     Flag_IgnoreReparsePoints | Flag_IgnoreFullReparsePointResolving;

    // --filter-inputs turns on the subtractive behaviors in the DLL: denied reads
    // report NOT_FOUND (not ACCESS_DENIED) and directory enumerations hide
    // undeclared children. See docs/detours-input-filtering.md.
    uint32_t extraFlags = ExtraFlag_None;
    if (o.filterInputs) {
        extraFlags |= ExtraFlag_DeniedReadsAsNotFound |
                      ExtraFlag_FilterDirectoryEnumeration;
    }

    // --trace <file>: turn on the DLL's report channel (otherwise fully inert).
    // We report both expected and unexpected accesses so the trace is a complete
    // record. The DLL opens the report path itself (OPEN_ALWAYS, append) and
    // propagates it to every child, so no pipe or reader thread is needed. We
    // truncate the file up front so each run starts fresh (the DLL only appends).
    if (!o.tracePath.empty()) {
        flags |= Flag_ReportFileAccesses | Flag_ReportUnexpectedFileAccesses;
        HANDLE ht = CreateFileW(o.tracePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (ht == INVALID_HANDLE_VALUE) Die(L"cannot open trace file: " + o.tracePath);
        CloseHandle(ht);
    }

    ManifestBuilder mb(flags, /*extraFlags*/ extraFlags, dllAnsi, dllAnsi);
    mb.SetReportPath(o.tracePath);

    // Whole file system read-only. AllowReadIfNonExistent lets probes of files that do not exist
    // return the real "not found" status instead of a synthesized access-denied error: with plain
    // AllowRead, BuildXL's policy (PolicyResult_common.cpp) only permits reads of files that exist,
    // so a probe of an absent path is denied. Many tools probe optional files at startup - e.g.
    // node.exe opens C:\Program Files\Common Files\SSL\openssl.cnf, which does not exist here, and
    // treats access-denied (but not "not found") as a fatal OpenSSL configuration error. Granting
    // AllowReadIfNonExistent never exposes file contents (it only changes the error for absent
    // paths) and matches how the process behaves outside the sandbox and under linux-sandbox.
    mb.AddRootScope(Policy_MaskAll, Policy_AllowRead | Policy_AllowReadIfNonExistent);
    // Working directory (execroot) policy. In the default (permissive) mode the
    // execroot stays READABLE like the rest of the file system - this mirrors the
    // default linux-sandbox, where the whole FS is read-only and only writes are
    // confined, so undeclared reads inside the execroot (e.g. sibling split-config
    // outputs reached via --preserveSymlinks, or package.json files node walks for
    // module-type resolution) succeed exactly as they do under linux. Writes are
    // still confined because we grant no write bit here (only -w does). In hermetic
    // mode the execroot is denied by default, so only -r/-w declared inputs are
    // visible (Goal 2 / --experimental_use_hermetic_linux_sandbox parity).
    uint32_t workingDirPolicy = o.hermetic
        ? Policy_Deny
        : (Policy_AllowRead | Policy_AllowReadIfNonExistent);
    // --execroot-writable: grant write + create-directory on the execroot cone, with
    // OverrideAllowWriteForExistingFiles so the DLL allows creating NEW files/dirs and
    // re-writing files created this run but denies clobbering pre-existing undeclared
    // files. Read bits are unchanged (still hidden under a hermetic/filter-inputs
    // execroot). Declared -w outputs (AllowAll) and -r inputs are applied as more
    // specific scopes below and are unaffected.
    if (o.execrootWritable) {
        workingDirPolicy |= Policy_AllowWrite | Policy_AllowCreateDirectory |
                            Policy_OverrideAllowWriteForExistingFiles;
    }
    if (!mb.AddScope(o.workingDir, Policy_MaskAll, workingDirPolicy))
        Die(L"bad working dir: " + o.workingDir);
    dbg(o.hermetic ? L"na" : L"ro", o.workingDir);
    // Allow reading the tool itself.
    if (!mb.AddScope(toolPath, Policy_MaskAll,
                     Policy_AllowRead | Policy_AllowReadIfNonExistent | Policy_DeclaredInput))
        Die(L"bad tool path: " + toolPath);
    dbg(L"ro", toolPath);

    for (const auto& p : o.readonlyFiles) {
        if (!mb.AddScope(p, Policy_MaskAll,
                         Policy_AllowRead | Policy_AllowReadIfNonExistent | Policy_DeclaredInput))
            Die(L"bad -r: " + p);
        dbg(L"ro", p);
    }
    for (const auto& p : o.writableFiles) {
        if (!mb.AddScope(p, Policy_MaskAll, Policy_AllowAll | Policy_DeclaredInput)) Die(L"bad -w: " + p);
        dbg(L"rw", p);
    }
    for (const auto& p : o.blockedFiles) {
        if (!mb.AddScope(p, Policy_MaskAll, Policy_Deny)) Die(L"bad -b: " + p);
        dbg(L"na", p);
    }
    // Output parent directories: node-only grant so the exact dir is revealed
    // (readable/enumerable) and mkdir/write on it is allowed, but its subtree
    // policy is left as-is (Deny under a hermetic execroot) so undeclared files
    // inside stay hidden. See Options::outputDirs.
    for (const auto& p : o.outputDirs) {
        if (!mb.AddNodeScope(p, Policy_MaskAll,
                             Policy_AllowRead | Policy_AllowReadIfNonExistent |
                                 Policy_AllowWrite | Policy_AllowCreateDirectory |
                                 Policy_DeclaredInput))
            Die(L"bad -d: " + p);
        dbg(L"od", p);
    }

    // Set up the cross-process created-files shared-memory region BEFORE building
    // the manifest so its name can be embedded in the payload (which is re-copied
    // to every child on injection). Only needed under --execroot-writable, the
    // sole mode that consults the created-files tracker. The handles are kept open
    // until the tree exits (region lifetime == action).
    CreatedShmHandles createdShm;
    if (o.execrootWritable) {
        createdShm = SetupCreatedFilesShm();
        mb.SetCreatedShmName(createdShm.name);
    }

    std::vector<uint8_t> manifest = mb.Build(/*injectionTimeoutMins*/ 10);
    dline(L"manifest bytes: " + std::to_wstring(manifest.size()));

    // DetoursServices.dll does not read the raw manifest directly. It reads a
    // "payload wrapper" (see DetouredProcessInjector::Init) laid out as:
    //   [u32 totalSize][u32 handleCount][u64 handles...][manifest bytes...]
    // handleCount must be >= 3 (c_minHandleCount): mapDirectory, remote
    // injector pipe, and report pipe. We use none of those features.
    //
    // IMPORTANT: these handle slots must be INVALID_HANDLE_VALUE (all 0xFF), NOT
    // zero. The injector's handle wrapper treats INVALID_HANDLE_VALUE as "no
    // handle" (isValid() == false), but a NULL (0) handle is considered *valid*.
    // If mapDirectory reads as valid, the DLL calls ApplyMapping when it injects
    // a child process; that fails and aborts child injection, so grandchildren
    // would not be sandboxed (the first process still works because the launcher
    // copies the payload directly and never calls ApplyMapping).
    const uint32_t kHandleCount = 3;
    const uint64_t kInvalidHandle = ~0ull;  // INVALID_HANDLE_VALUE as u64
    const uint32_t kPrefixSize =
        2 * sizeof(uint32_t) + kHandleCount * sizeof(uint64_t);
    const uint32_t kTotalSize =
        kPrefixSize + static_cast<uint32_t>(manifest.size());
    std::vector<uint8_t> payload(kTotalSize, 0);
    {
        uint8_t* p = payload.data();
        *reinterpret_cast<uint32_t*>(p) = kTotalSize;
        p += sizeof(uint32_t);
        *reinterpret_cast<uint32_t*>(p) = kHandleCount;
        p += sizeof(uint32_t);
        // mapDirectory, remoteInjectorPipe, reportPipe: all "no handle".
        for (uint32_t h = 0; h < kHandleCount; ++h) {
            *reinterpret_cast<uint64_t*>(p) = kInvalidHandle;
            p += sizeof(uint64_t);
        }
        memcpy(p, manifest.data(), manifest.size());
    }

    // Network policy (-N / -n). Set an environment variable that the injected
    // DetoursServices.dll reads at attach time. Because the child inherits the
    // launcher's environment (lpEnvironment is null below), and each grandchild
    // inherits from its parent, the policy propagates through the whole process
    // tree automatically. CODESYNC: kNetworkEnvVar in src/network_detours.h.
    if (o.networkPolicy == 1) {
        SetEnvironmentVariableW(L"BAZEL_SANDBOX_NETWORK", L"loopback");
    } else if (o.networkPolicy == 2) {
        SetEnvironmentVariableW(L"BAZEL_SANDBOX_NETWORK", L"block");
    }

    // cmd.exe's builtins resolve DRIVE-RELATIVE source paths (e.g. copy's
    // "external\foo\bar.h") via the child's own current directory, which we set
    // below through lpCurrentDirectory / SetCurrentDirectoryW - no environment
    // manipulation is needed.
    SetCurrentDirectoryW(o.workingDir.c_str());

    // Standard handles (with optional redirection).
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdOutFile = nullptr;
    HANDLE hStdErrFile = nullptr;
    if (!o.stdoutPath.empty()) {
        hStdOutFile = OpenOutputFile(o.stdoutPath);
        hStdOut = hStdOutFile;
    }
    if (!o.stderrPath.empty()) {
        hStdErrFile = OpenOutputFile(o.stderrPath);
        hStdErr = hStdErrFile;
    }
    // Make each std handle a valid, inheritable handle for the child (see
    // PrepareStdHandle). Any NUL device we open here is closed after the child
    // starts. The file handles from -l/-L are already inheritable NUL-safe.
    HANDLE nulIn = nullptr, nulOut = nullptr, nulErr = nullptr;
    hStdIn = PrepareStdHandle(hStdIn, /*forRead*/ true, &nulIn);
    hStdOut = PrepareStdHandle(hStdOut, /*forRead*/ false, &nulOut);
    hStdErr = PrepareStdHandle(hStdErr, /*forRead*/ false, &nulErr);

    // Job object so the whole process tree can be terminated together.
    HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
    if (hJob != nullptr) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        jeli.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli,
                                sizeof(jeli));
    }

    // Reconstruct the child command line from the parsed argv. Handles the
    // cmd.exe "/c <command>" shape specially so cmd receives literal quotes (see
    // BuildChildCommandLine); other tools get standard CommandLineToArgvW escaping.
    std::wstring cmdLine = BuildChildCommandLine(o.args);
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdIn;
    si.hStdOutput = hStdOut;
    si.hStdError = hStdErr;
    PROCESS_INFORMATION pi{};

    // Create the sandboxed process suspended with DetoursServices.dll injected,
    // using upstream Detours directly. DetourCreateProcessWithDllEx wires the
    // DLL into the child's import table; because the child is suspended the DLL
    // has not run yet, so we can attach the manifest payload and assign the job
    // before anything executes. Child/grandchild propagation is handled inside
    // DetoursServices.dll itself (it re-injects using the DLL path carried in
    // the manifest), so the launcher only injects this first process.
    BOOL created = DetourCreateProcessWithDllExW(
        /*lpApplicationName*/ nullptr, cmdBuf.data(),
        /*lpProcessAttributes*/ nullptr, /*lpThreadAttributes*/ nullptr,
        /*bInheritHandles*/ TRUE, CREATE_SUSPENDED,
        /*lpEnvironment*/ nullptr,
        o.workingDir.c_str(), &si, &pi, dllAnsi.c_str(),
        /*pfCreateProcessW*/ nullptr);

    if (!created) {
        dline(L"CreateProcess failed (gle=" + std::to_wstring(GetLastError()) + L")");
        fwprintf(stderr,
                 L"BazelSandbox: DetourCreateProcessWithDllEx failed (gle=%lu)\n",
                 GetLastError());
        return 2;
    }

    HANDLE hProcess = pi.hProcess, hThread = pi.hThread;
    dline(L"child started, pid " + std::to_wstring(pi.dwProcessId));

    // Attach the file-access manifest so DetoursServices.dll finds it (via
    // DetourFindPayload under kManifestGuid) when its DllMain runs.
    if (!DetourCopyPayloadToProcess(hProcess, kManifestGuid, payload.data(),
                                    static_cast<DWORD>(payload.size()))) {
        dline(L"payload copy failed (gle=" + std::to_wstring(GetLastError()) + L")");
        fwprintf(stderr,
                 L"BazelSandbox: DetourCopyPayloadToProcess failed (gle=%lu)\n",
                 GetLastError());
        TerminateProcess(hProcess, 1);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        if (hJob) CloseHandle(hJob);
        return 2;
    }

    // Put the child in the job before it runs so the whole tree is contained.
    if (hJob != nullptr) {
        AssignProcessToJobObject(hJob, hProcess);
    }

    ResumeThread(hThread);

    DWORD exitCode = 0;
    DWORD waitMs = (o.timeoutSecs == kInfiniteTime)
                       ? INFINITE
                       : o.timeoutSecs * 1000;
    DWORD wr = WaitForSingleObject(hProcess, waitMs);
    if (wr == WAIT_TIMEOUT) {
        dline(L"timeout after " + std::to_wstring(o.timeoutSecs) + L" s");
        fwprintf(stderr, L"BazelSandbox: timeout after %u s, terminating\n",
                 o.timeoutSecs);
        if (o.killDelaySecs != kInfiniteTime) {
            // Give the tree a grace period, then force-kill via the job.
            WaitForSingleObject(hProcess, o.killDelaySecs * 1000);
        }
        if (hJob != nullptr) {
            TerminateJobObject(hJob, 1);
        } else {
            TerminateProcess(hProcess, 1);
        }
        WaitForSingleObject(hProcess, 5000);
        exitCode = 1;
    } else {
        GetExitCodeProcess(hProcess, &exitCode);
    }
    dline(L"child exit code: " + std::to_wstring(exitCode));

    // Collect resource-usage statistics from the job before we close it.
    WriteStats(o.statsPath, hJob);

    // Discard undeclared scratch the tree created (linux-sandbox parity), unless
    // --sandbox_debug (-D) asked us to keep it for inspection. Done before closing
    // the SHM mapping (the created-set lives there) and after the tree has exited.
    if (o.execrootWritable && o.debugPath.empty()) {
        CleanupCreatedScratch(createdShm.mapping);
    }

    if (hStdOutFile) CloseHandle(hStdOutFile);
    if (hStdErrFile) CloseHandle(hStdErrFile);
    if (nulIn) CloseHandle(nulIn);
    if (nulOut) CloseHandle(nulOut);
    if (nulErr) CloseHandle(nulErr);
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    if (hJob) CloseHandle(hJob);
    if (createdShm.mutex) CloseHandle(createdShm.mutex);
    if (createdShm.mapping) CloseHandle(createdShm.mapping);

    if (dbgFp) fclose(dbgFp);
    return static_cast<int>(exitCode);
}
