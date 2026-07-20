#include "tests/e2e/e2e_harness.h"

#include <windows.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "rules_cc/cc/runfiles/runfiles.h"

namespace bsxe2e {
namespace {

using rules_cc::cc::runfiles::Runfiles;

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

// Standard CommandLineToArgvW-convention argument escaping (matches how the
// launcher re-parses its own argv). Only quotes when necessary.
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

// Shared runfiles instance (resolved once).
Runfiles* GetRunfiles() {
    static Runfiles* rf = [] {
        std::string error;
        Runfiles* r = Runfiles::CreateForTest(&error);
        if (r == nullptr) {
            ADD_FAILURE() << "failed to init runfiles: " << error;
        }
        return r;
    }();
    return rf;
}

std::wstring ResolveFromEnv(const char* envName) {
    const char* v = std::getenv(envName);
    if (v == nullptr || *v == '\0') return std::wstring();
    Runfiles* rf = GetRunfiles();
    if (rf == nullptr) return std::wstring();
    std::string loc = rf->Rlocation(v);
    if (loc.empty()) return std::wstring();
    return Utf8ToWide(loc);
}

// Runs a full command line, capturing stdout+stderr into `out`. Returns the
// child's exit code (or -1 on spawn failure).
int RunCapture(const std::wstring& cmd, std::string* out) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        ADD_FAILURE() << "CreatePipe failed (" << GetLastError() << ")";
        return -1;
    }
    // The read end must not be inherited by the child.
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    HANDLE nulRead = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa, OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nulRead;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;

    PROCESS_INFORMATION pi{};
    std::wstring mutableCmd = cmd;
    BOOL ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr,
                             /*bInheritHandles*/ TRUE, 0, nullptr, nullptr, &si, &pi);
    // Close our copies of the write ends so the read loop terminates on child exit.
    CloseHandle(writePipe);
    if (nulRead != INVALID_HANDLE_VALUE) CloseHandle(nulRead);
    if (!ok) {
        ADD_FAILURE() << "CreateProcess failed (" << GetLastError() << ")";
        CloseHandle(readPipe);
        return -1;
    }

    std::string buf;
    char chunk[4096];
    DWORD n = 0;
    while (ReadFile(readPipe, chunk, sizeof(chunk), &n, nullptr) && n > 0) {
        buf.append(chunk, n);
    }
    CloseHandle(readPipe);

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = static_cast<DWORD>(-1);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (out) *out = std::move(buf);
    return static_cast<int>(code);
}

}  // namespace

const std::wstring& OverlayTest::SandboxPath() {
    static const std::wstring* p = new std::wstring(ResolveFromEnv("E2E_SANDBOX"));
    return *p;
}

std::wstring OverlayTest::ToolFromEnv(const char* envName) {
    return ResolveFromEnv(envName);
}

std::wstring OverlayTest::CmdExe() {
    wchar_t sysdir[MAX_PATH];
    UINT n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"cmd.exe";
    return (std::filesystem::path(sysdir) / L"cmd.exe").wstring();
}

void OverlayTest::SetUp() {
    ASSERT_FALSE(SandboxPath().empty())
        << "BazelSandbox not resolved from runfiles (E2E_SANDBOX)";

    const char* base = std::getenv("TEST_TMPDIR");
    std::filesystem::path root =
        base ? std::filesystem::path(Utf8ToWide(base)) : std::filesystem::temp_directory_path();
    const ::testing::TestInfo* info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    std::string leaf = std::string(info->test_suite_name()) + "." + info->name();
    tempRoot_ = root / "e2e" / Utf8ToWide(leaf);
    std::error_code ec;
    std::filesystem::remove_all(tempRoot_, ec);
    std::filesystem::create_directories(tempRoot_, ec);
}

void OverlayTest::TearDown() {
    std::error_code ec;
    std::filesystem::remove_all(tempRoot_, ec);
}

std::wstring OverlayTest::NewWorkspace() {
    std::filesystem::path ws = tempRoot_ / std::to_wstring(++counter_);
    std::error_code ec;
    std::filesystem::create_directories(ws, ec);
    return ws.make_preferred().wstring();
}

std::wstring OverlayTest::Join(const std::wstring& dir, const std::wstring& name) {
    return (std::filesystem::path(dir) / name).make_preferred().wstring();
}

RunResult OverlayTest::RunArgs(const std::vector<std::wstring>& args) {
    std::wstring cmd = EscapeArg(SandboxPath());
    for (const auto& a : args) {
        cmd.push_back(L' ');
        cmd += EscapeArg(a);
    }
    RunResult r;
    r.code = RunCapture(cmd, &r.out);
    return r;
}

std::wstring OverlayTest::WriteBat(const std::vector<std::wstring>& lines) {
    // @echo off keeps the transcript clean so assertions only see tool output.
    // Each line runs regardless of the previous one's success (matches a plain
    // script); tests assert on content.
    std::wstring bat =
        (tempRoot_ / (L"run_" + std::to_wstring(++counter_) + L".bat")).wstring();
    std::ofstream f(std::filesystem::path(bat), std::ios::binary | std::ios::trunc);
    f << "@echo off\r\n";
    for (const auto& line : lines) {
        std::string u;
        int n = WideCharToMultiByte(CP_UTF8, 0, line.data(), (int)line.size(),
                                    nullptr, 0, nullptr, nullptr);
        u.resize(n);
        WideCharToMultiByte(CP_UTF8, 0, line.data(), (int)line.size(), u.data(), n,
                            nullptr, nullptr);
        f << u << "\r\n";
    }
    return bat;
}

RunResult OverlayTest::RunOverlay(const std::wstring& ws,
                                  const std::vector<std::wstring>& toolCmd) {
    std::vector<std::wstring> args = {L"--write-overlay", L"-W", ws, L"--"};
    for (const auto& a : toolCmd) args.push_back(a);
    return RunArgs(args);
}

RunResult OverlayTest::RunFiltered(const std::wstring& ws,
                                   const std::vector<std::wstring>& declaredInputs,
                                   const std::vector<std::wstring>& toolCmd) {
    std::vector<std::wstring> args = {L"--filter-inputs", L"-W", ws};
    for (const auto& in : declaredInputs) {
        args.push_back(L"-r");
        args.push_back(in);
    }
    args.push_back(L"--");
    for (const auto& a : toolCmd) args.push_back(a);
    return RunArgs(args);
}

RunResult OverlayTest::RunOverlayBat(const std::wstring& ws,
                                     const std::vector<std::wstring>& lines) {
    return RunOverlay(ws, {CmdExe(), L"/c", WriteBat(lines)});
}

RunResult OverlayTest::RunFilteredBat(const std::wstring& ws,
                                      const std::vector<std::wstring>& declaredInputs,
                                      const std::vector<std::wstring>& lines) {
    return RunFiltered(ws, declaredInputs, {CmdExe(), L"/c", WriteBat(lines)});
}

bool OverlayTest::Exists(const std::wstring& p) {
    std::error_code ec;
    return std::filesystem::exists(std::filesystem::path(p), ec);
}

void OverlayTest::WriteText(const std::wstring& p, const std::string& content) {
    std::ofstream f(std::filesystem::path(p), std::ios::binary | std::ios::trunc);
    f << content;
}

std::string OverlayTest::ReadText(const std::wstring& p) {
    std::ifstream f(std::filesystem::path(p), std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::vector<std::wstring> OverlayTest::Snapshot(const std::wstring& dir) {
    std::vector<std::wstring> out;
    std::error_code ec;
    std::filesystem::path base(dir);
    if (!std::filesystem::exists(base, ec)) return out;
    for (auto it = std::filesystem::recursive_directory_iterator(base, ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        out.push_back(std::filesystem::relative(it->path(), base, ec).make_preferred().wstring());
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace bsxe2e
