// Regression harness for the std-handle bug that surfaced when Bazel drives the
// launcher. Bazel starts BazelSandbox.exe with STARTF_USESTDHANDLES and
// bInheritHandles=TRUE, supplying inheritable stdout/stderr pipe handles but NO
// stdin (hStdInput = NULL). Under that combination the child of BazelSandbox
// would receive an invalid stdin handle and fail with "The handle is invalid"
// (e.g. coreutils cp / uutils), because with STARTF_USESTDHANDLES every slot
// must be a valid, inheritable handle.
//
// This harness reproduces that setup: it launches
//   BazelSandbox.exe -- probe stdio
// with a NULL stdin and inheritable stdout/stderr (redirected to a temp file),
// using STARTF_USESTDHANDLES + bInheritHandles=TRUE. If the launcher's
// std-handle handling is correct, the grandchild "probe stdio" sees three
// usable handles and exits 0; the harness forwards that exit code.
//
// (We mark stdout/stderr inheritable, as Bazel does for its pipes. A
// non-inheritable handle passed via STARTF_USESTDHANDLES is dangling in the
// child and its validity is indeterminate, so that variant is intentionally not
// modeled here.)
//
// Usage:  stdio_launcher <BazelSandbox.exe> <probe.exe> <scratch-file>
// Exit:   0            = probe stdio succeeded (handles were repaired correctly)
//         non-zero     = the bug is present (or the harness itself failed)

#include <windows.h>

#include <cstdio>
#include <string>

namespace {

constexpr int kHarnessError = 50;

std::wstring Quote(const std::wstring& s) { return L"\"" + s + L"\""; }

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 4) {
        fwprintf(stderr,
                 L"usage: stdio_launcher <sandbox> <probe> <scratchfile>\n");
        return kHarnessError;
    }
    const std::wstring sandbox = argv[1];
    const std::wstring probe = argv[2];
    const std::wstring scratch = argv[3];

    // An inheritable handle to a scratch file, standing in for the inheritable
    // pipe handles Bazel supplies for stdout/stderr.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hOut = CreateFileW(scratch.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                              &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (hOut == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"stdio_launcher: cannot open scratch file\n");
        return kHarnessError;
    }

    std::wstring cmd = Quote(sandbox) + L" -- " + Quote(probe) + L" stdio";
    std::wstring mutableCmd = cmd;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;  // Bazel does not provide a stdin (the real bug).
    si.hStdOutput = hOut;    // Inheritable, as Bazel's pipe handles are.
    si.hStdError = hOut;

    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr,
                             /*bInheritHandles*/ TRUE, 0, nullptr, nullptr, &si,
                             &pi);
    if (!ok) {
        fwprintf(stderr, L"stdio_launcher: CreateProcess failed (%lu)\n",
                 GetLastError());
        CloseHandle(hOut);
        return kHarnessError;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = kHarnessError;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hOut);
    return static_cast<int>(code);
}
