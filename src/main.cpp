// BazelSandbox.exe: a standalone Windows process sandbox that reproduces
// BuildXL's BazelSandbox using only upstream Detours + the vendored
// DetoursServices enforcement engine. See plan.md and README.md.

#include <windows.h>

#include <detours.h>

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
        L"  -N         allow only loopback network access (block external)\n"
        L"  -n         block all network access (no loopback either)\n"
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
            } else if (name == L"N") {
                if (o.networkPolicy == 2) Die(L"-N and -n are mutually exclusive");
                o.networkPolicy = 1;
            } else if (name == L"n") {
                if (o.networkPolicy == 1) Die(L"-N and -n are mutually exclusive");
                o.networkPolicy = 2;
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
    uint32_t flags = Flag_FailUnexpectedFileAccesses | Flag_MonitorNtCreateFile |
                     Flag_MonitorChildProcesses | Flag_MonitorZwCreateOpenQueryFile |
                     Flag_IgnoreReparsePoints | Flag_IgnoreFullReparsePointResolving;

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

    ManifestBuilder mb(flags, /*extraFlags*/ 0, dllAnsi, dllAnsi);
    mb.SetReportPath(o.tracePath);

    // Whole file system read-only.
    mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
    // Block the working directory by default.
    if (!mb.AddScope(o.workingDir, Policy_MaskAll, Policy_Deny))
        Die(L"bad working dir: " + o.workingDir);
    dbg(L"na", o.workingDir);
    // Allow reading the tool itself.
    if (!mb.AddScope(toolPath, Policy_MaskAll, Policy_AllowRead))
        Die(L"bad tool path: " + toolPath);
    dbg(L"ro", toolPath);

    for (const auto& p : o.readonlyFiles) {
        if (!mb.AddScope(p, Policy_MaskAll, Policy_AllowRead)) Die(L"bad -r: " + p);
        dbg(L"ro", p);
    }
    for (const auto& p : o.writableFiles) {
        if (!mb.AddScope(p, Policy_MaskAll, Policy_AllowAll)) Die(L"bad -w: " + p);
        dbg(L"rw", p);
    }
    for (const auto& p : o.blockedFiles) {
        if (!mb.AddScope(p, Policy_MaskAll, Policy_Deny)) Die(L"bad -b: " + p);
        dbg(L"na", p);
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

    std::wstring cmdLine = BuildCommandLine(o.args);
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
        /*bInheritHandles*/ TRUE, CREATE_SUSPENDED, /*lpEnvironment*/ nullptr,
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

    if (hStdOutFile) CloseHandle(hStdOutFile);
    if (hStdErrFile) CloseHandle(hStdErrFile);
    if (nulIn) CloseHandle(nulIn);
    if (nulOut) CloseHandle(nulOut);
    if (nulErr) CloseHandle(nulErr);
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    if (hJob) CloseHandle(hJob);

    if (dbgFp) fclose(dbgFp);
    return static_cast<int>(exitCode);
}
