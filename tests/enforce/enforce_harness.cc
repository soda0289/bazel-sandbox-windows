#include "tests/enforce/enforce_harness.h"

#include <windows.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "rules_cc/cc/runfiles/runfiles.h"

namespace bsx {
namespace {

using rules_cc::cc::runfiles::Runfiles;

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

// Resolves the runfiles rlocationpath held in environment variable `envName`
// through the runfiles library and returns the absolute path (wide). Returns
// empty if the variable is unset.
std::wstring ResolveFromEnv(Runfiles* rf, const char* envName) {
    const char* v = std::getenv(envName);
    if (v == nullptr || *v == '\0') return std::wstring();
    std::string loc = rf->Rlocation(v);
    if (loc.empty()) return std::wstring();
    return Utf8ToWide(loc);
}

// Standard Windows CommandLineToArgvW-convention argument escaping (matches how
// the launcher re-parses its own argv). Only quotes when necessary.
std::wstring EscapeArg(const std::wstring& s) {
    if (!s.empty() && s.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return s;
    }
    std::wstring r = L"\"";
    for (auto it = s.begin();; ++it) {
        unsigned backslashes = 0;
        while (it != s.end() && *it == L'\\') {
            ++it;
            ++backslashes;
        }
        if (it == s.end()) {
            r.append(backslashes * 2, L'\\');
            break;
        } else if (*it == L'"') {
            r.append(backslashes * 2 + 1, L'\\');
            r.push_back(*it);
        } else {
            r.append(backslashes, L'\\');
            r.push_back(*it);
        }
    }
    r.push_back(L'"');
    return r;
}

void WriteFileContent(const std::filesystem::path& p, const char* content) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (content != nullptr) f << content;
}

}  // namespace

const Tools& GetTools() {
    static const Tools* tools = [] {
        std::string error;
        std::unique_ptr<Runfiles> rf(Runfiles::CreateForTest(&error));
        Tools* t = new Tools();
        if (rf == nullptr) {
            ADD_FAILURE() << "failed to init runfiles: " << error;
            return t;
        }
        t->sandbox = ResolveFromEnv(rf.get(), "ENFORCE_SANDBOX");
        t->probe = ResolveFromEnv(rf.get(), "ENFORCE_PROBE");
        t->probeLpa = ResolveFromEnv(rf.get(), "ENFORCE_PROBE_LPA");
        t->stdioLauncher = ResolveFromEnv(rf.get(), "ENFORCE_STDIO");
        return t;
    }();
    return *tools;
}

void EnforceTest::SetUp() {
    const Tools& t = GetTools();
    ASSERT_FALSE(t.sandbox.empty()) << "BazelSandbox not resolved from runfiles";
    ASSERT_FALSE(t.probe.empty()) << "probe not resolved from runfiles";

    const char* base = std::getenv("TEST_TMPDIR");
    std::filesystem::path root =
        base ? std::filesystem::path(Utf8ToWide(base)) : std::filesystem::temp_directory_path();
    // Per-test subdirectory keyed by the current test's full name.
    const ::testing::TestInfo* info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    std::string leaf = std::string(info->test_suite_name()) + "." + info->name();
    tempRoot_ = root / "sbx" / Utf8ToWide(leaf);
    std::error_code ec;
    std::filesystem::remove_all(tempRoot_, ec);
    std::filesystem::create_directories(tempRoot_, ec);
}

void EnforceTest::TearDown() {
    std::error_code ec;
    std::filesystem::remove_all(tempRoot_, ec);
}

std::wstring EnforceTest::NewWorkspace() {
    std::filesystem::path ws = tempRoot_ / std::to_wstring(++counter_);
    std::error_code ec;
    std::filesystem::create_directories(ws / L"sub", ec);
    WriteFileContent(ws / L"a.txt", "x");
    WriteFileContent(ws / L"src.txt", "x");
    WriteFileContent(ws / L"seed.txt", "seed-data");
    WriteFileContent(ws / L"keep.txt", "");
    // Normalize to backslashes: Win32 ops tolerate '/', but the native
    // NtCreateFile probe builds "\??\" + path, and the NT object parser rejects
    // forward slashes (TEST_TMPDIR often uses them) with OBJECT_NAME_NOT_FOUND.
    return ws.make_preferred().wstring();
}

std::wstring EnforceTest::Join(const std::wstring& dir, const std::wstring& name) {
    return (std::filesystem::path(dir) / name).make_preferred().wstring();
}

int EnforceTest::RunProbe(const std::vector<std::wstring>& sandboxArgs,
                          const std::vector<std::wstring>& probeArgs) {
    return RunProbeImpl(true, sandboxArgs, probeArgs);
}

int EnforceTest::RunProbeRaw(const std::vector<std::wstring>& sandboxArgs,
                             const std::vector<std::wstring>& probeArgs) {
    return RunProbeImpl(false, sandboxArgs, probeArgs);
}

int EnforceTest::RunProbeImpl(bool hermetic,
                              const std::vector<std::wstring>& sandboxArgs,
                              const std::vector<std::wstring>& probeArgs) {
    const Tools& t = GetTools();

    std::vector<std::wstring> args;
    if (hermetic) args.push_back(L"-H");
    for (const auto& a : sandboxArgs) args.push_back(a);
    args.push_back(L"--");
    args.push_back(t.probe);
    for (const auto& a : probeArgs) args.push_back(a);
    return RunExe(t.sandbox, args);
}

int EnforceTest::RunSandbox(const std::vector<std::wstring>& sandboxArgs) {
    return RunExe(GetTools().sandbox, sandboxArgs);
}

int EnforceTest::RunExe(const std::wstring& exe,
                        const std::vector<std::wstring>& args) {
    std::wstring cmd = EscapeArg(exe);
    for (const auto& a : args) {
        cmd.push_back(L' ');
        cmd += EscapeArg(a);
    }
    return RunCommandLine(cmd);
}

int EnforceTest::RunCommandLine(const std::wstring& cmd) {
    // Send the child's std handles to NUL so the probe's (rare) output does not
    // pollute the test log. All three must be valid inheritable handles.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE nulRead = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, nullptr);
    HANDLE nulWrite = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nulRead;
    si.hStdOutput = nulWrite;
    si.hStdError = nulWrite;

    PROCESS_INFORMATION pi{};
    std::wstring mutableCmd = cmd;
    const wchar_t* cwd = launchDir_.empty() ? nullptr : launchDir_.c_str();
    BOOL ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr,
                             /*bInheritHandles*/ TRUE, 0, nullptr, cwd, &si, &pi);
    if (nulRead != INVALID_HANDLE_VALUE) CloseHandle(nulRead);
    if (nulWrite != INVALID_HANDLE_VALUE) CloseHandle(nulWrite);
    if (!ok) {
        ADD_FAILURE() << "CreateProcess failed (" << GetLastError() << ")";
        return kHarnessError;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = kHarnessError;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

bool EnforceTest::HasSymlinkPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    LUID luid{};
    bool result = false;
    if (LookupPrivilegeValueW(nullptr, SE_CREATE_SYMBOLIC_LINK_NAME, &luid)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
        std::vector<BYTE> buf(size);
        if (size > 0 &&
            GetTokenInformation(token, TokenPrivileges, buf.data(), size, &size)) {
            auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
            for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                if (tp->Privileges[i].Luid.LowPart == luid.LowPart &&
                    tp->Privileges[i].Luid.HighPart == luid.HighPart) {
                    result = true;
                    break;
                }
            }
        }
    }
    CloseHandle(token);
    return result;
}

const std::wstring& EnforceTest::SandboxPath() { return GetTools().sandbox; }
const std::wstring& EnforceTest::ProbePath() { return GetTools().probe; }
const std::wstring& EnforceTest::ProbeLpaPath() { return GetTools().probeLpa; }
const std::wstring& EnforceTest::StdioPath() { return GetTools().stdioLauncher; }

bool EnforceTest::Exists(const std::wstring& p) {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(p), ec);
}

void EnforceTest::WriteText(const std::wstring& p, const std::string& content) {
    std::ofstream f(std::filesystem::path(p), std::ios::binary | std::ios::trunc);
    f << content;
}

void EnforceTest::MakeDirs(const std::wstring& p) {
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(p), ec);
}

std::string EnforceTest::ReadText(const std::wstring& p) {
    std::ifstream f(std::filesystem::path(p), std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

std::vector<unsigned char> EnforceTest::ReadBytes(const std::wstring& p) {
    std::string s = ReadText(p);
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::wstring EnforceTest::ReadWideText(const std::wstring& p) {
    // Files written by the launcher's --trace channel are UTF-16LE with no BOM.
    std::string bytes = ReadText(p);
    size_t n = bytes.size() / sizeof(wchar_t);
    std::wstring w(n, L'\0');
    if (n) std::memcpy(w.data(), bytes.data(), n * sizeof(wchar_t));
    return w;
}

std::wstring EnforceTest::CmdExe() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ComSpec", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH && Exists(buf)) return std::wstring(buf, n);
    UINT m = GetSystemDirectoryW(buf, MAX_PATH);
    std::filesystem::path p = std::filesystem::path(std::wstring(buf, m)) / L"cmd.exe";
    return p.wstring();
}

std::wstring EnforceTest::SysWow64Whoami() {
    wchar_t buf[MAX_PATH];
    UINT m = GetWindowsDirectoryW(buf, MAX_PATH);
    std::filesystem::path p =
        std::filesystem::path(std::wstring(buf, m)) / L"SysWOW64" / L"whoami.exe";
    return Exists(p.wstring()) ? p.wstring() : std::wstring();
}

bool EnforceTest::MakeJunction(const std::wstring& link, const std::wstring& target) {
    RunExe(CmdExe(), {L"/c", L"mklink", L"/J", link, target});
    return Exists(link);
}

bool EnforceTest::MakeFileSymlink(const std::wstring& link, const std::wstring& target) {
    RunExe(CmdExe(), {L"/c", L"mklink", link, target});
    return Exists(link);
}

bool EnforceTest::MakeDirSymlink(const std::wstring& link, const std::wstring& target) {
    RunExe(CmdExe(), {L"/c", L"mklink", L"/D", link, target});
    return Exists(link);
}

}  // namespace bsx
