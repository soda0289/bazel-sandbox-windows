// GoogleTest harness for the BazelSandbox enforcement suites (gtest port of the
// old tests/lib/harness.ps1 + tests/enforce/*.ps1). Each test spawns the real
// launcher as a child:
//
//     BazelSandbox [-H] <sandbox args...> -- <probe.exe> <probe args...>
//
// and asserts the sandboxed probe's integer exit code. The probe binary is the
// system-under-test *actor* (it performs one filesystem/network op and exits
// with a stable code); it stays a separate process because it must be sandboxed.
//
// The launcher + probe binaries are carried as `data` on the cc_test and their
// runfiles rlocationpaths are handed in via environment variables set by the
// BUILD rule (ENFORCE_SANDBOX / ENFORCE_PROBE / ENFORCE_PROBE_LPA /
// ENFORCE_STDIO); EnforceEnv resolves them through the rules_cc runfiles library.
// BazelSandbox carries DetoursServices.dll in its own runfiles co-located with
// the exe (--enable_runfiles), so the launcher finds the hook DLL next to itself.

#ifndef TESTS_ENFORCE_ENFORCE_HARNESS_H_
#define TESTS_ENFORCE_ENFORCE_HARNESS_H_

#include <windows.h>

#include <filesystem>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace bsx {

// Probe exit codes (must match tests/probe.cpp). A single source of truth would
// be nicer; kept in sync by hand for the pilot.
constexpr int kOk = 0;            // operation allowed / succeeded
constexpr int kDenied = 10;       // sandbox denied (ERROR_ACCESS_DENIED)
constexpr int kNotFound = 11;     // path reported absent (FILE/PATH_NOT_FOUND)
constexpr int kOtherError = 20;   // some other error
constexpr int kBadUsage = 30;     // probe usage error
constexpr int kBadStdHandle = 40; // std-handle check failed
constexpr int kHarnessError = 50; // harness-level failure

// Resolved, absolute paths to the tools under test (set once per process).
struct Tools {
    std::wstring sandbox;    // BazelSandbox.exe
    std::wstring probe;      // probe.exe
    std::wstring probeLpa;   // probe_lpa.exe (long-path aware)
    std::wstring stdioLauncher;  // stdio_launcher.exe (may be empty)
};

// Resolves the tool paths from runfiles once and returns the shared instance.
const Tools& GetTools();

// Test fixture: owns a per-test temp root and hands out freshly seeded
// workspaces (NewWorkspace = the old New-Workspace, i.e. before-each isolation),
// and wraps launching the sandbox.
class EnforceTest : public ::testing::Test {
   protected:
    void SetUp() override;
    void TearDown() override;

    // Creates a unique, freshly seeded workspace directory and returns its path.
    // Layout mirrors New-Workspace: a.txt/src.txt (content "x"), seed.txt
    // ("seed-data"), keep.txt (empty), and an empty sub/ directory.
    std::wstring NewWorkspace();

    // Joins a workspace path with a child name.
    static std::wstring Join(const std::wstring& dir, const std::wstring& name);

    // Runs "BazelSandbox -H <sandboxArgs> -- <probe> <probeArgs>" and returns the
    // child exit code. -H forces hermetic mode (the enforcement suites validate
    // the deny/grant machinery, which only applies under hermetic reads).
    int RunProbe(const std::vector<std::wstring>& sandboxArgs,
                 const std::vector<std::wstring>& probeArgs);

    // Like RunProbe but passes NO implicit -H (caller controls the read mode).
    int RunProbeRaw(const std::vector<std::wstring>& sandboxArgs,
                    const std::vector<std::wstring>& probeArgs);

    // Runs "BazelSandbox <sandboxArgs>" directly: no implicit -H, no "--", and
    // no probe appended. The caller supplies the entire tail (including its own
    // "--" and target). Used by the launcher CLI-contract and cross-bitness
    // cases, which target the launcher itself rather than the probe.
    int RunSandbox(const std::vector<std::wstring>& sandboxArgs);

    // Runs an arbitrary executable with the given args and returns its exit
    // code. Std handles go to NUL. Used to drive stdio_launcher and mklink.
    int RunExe(const std::wstring& exe, const std::vector<std::wstring>& args);

    // Sets the working directory used for subsequently launched children (the
    // launcher resolves relative scope paths against its own cwd). Empty = inherit
    // the test process cwd. Reset automatically per test (fresh fixture).
    void SetLaunchDir(const std::wstring& dir) { launchDir_ = dir; }

    // Resolved tool paths (for spawn args and direct launches).
    static const std::wstring& SandboxPath();
    static const std::wstring& ProbePath();
    static const std::wstring& ProbeLpaPath();
    static const std::wstring& StdioPath();

    // The per-test temp root (parent of the workspaces); for scratch that must
    // live outside any workspace, e.g. a custom --overlay-dir.
    const std::filesystem::path& TempRoot() const { return tempRoot_; }

    // True if the current token holds SeCreateSymbolicLinkPrivilege.
    static bool HasSymlinkPrivilege();

    // --- filesystem helpers (used by tests that inspect real on-disk state) ---
    // Public (static) so free helpers in the test TUs can use them too.
   public:
    static bool Exists(const std::wstring& p);
    static void WriteText(const std::wstring& p, const std::string& content);
    static void MakeDirs(const std::wstring& p);
    static std::string ReadText(const std::wstring& p);             // raw bytes
    static std::wstring ReadWideText(const std::wstring& p);        // UTF-16LE -> wstring
    static std::vector<unsigned char> ReadBytes(const std::wstring& p);

    // cmd.exe resolved from the OS system directory (env-independent).
    static std::wstring CmdExe();
    // 32-bit SysWOW64\whoami.exe path, or empty if absent (non-x64 hosts).
    static std::wstring SysWow64Whoami();

    // mklink helpers via cmd.exe. Return true iff the link now exists.
    bool MakeJunction(const std::wstring& link, const std::wstring& target);
    bool MakeFileSymlink(const std::wstring& link, const std::wstring& target);
    bool MakeDirSymlink(const std::wstring& link, const std::wstring& target);

   private:
    int RunProbeImpl(bool hermetic,
                     const std::vector<std::wstring>& sandboxArgs,
                     const std::vector<std::wstring>& probeArgs);
    int RunCommandLine(const std::wstring& cmd);

    std::filesystem::path tempRoot_;
    std::wstring launchDir_;
    unsigned counter_ = 0;
};

}  // namespace bsx

#endif  // TESTS_ENFORCE_ENFORCE_HARNESS_H_
