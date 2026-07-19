// GoogleTest harness for the write-overlay real-tool end-to-end suites.
//
// Unlike the enforcement suites (tests/enforce/*), these tests drive the real
// launcher against *real third-party tools* to validate the write-overlay VFS
// against the OS-API patterns the synthetic probe cannot replicate. Each test
// runs a single sandbox invocation:
//
//     BazelSandbox --write-overlay -W <execroot> -- <tool> <args...>
//
// and asserts three things: (1) a read-back marker appears in the tool's
// captured stdout (overlay read-after-write); (2) a created file appears in the
// tool's own directory listing (overlay enumeration splice); (3) the real
// execroot on disk is byte-for-byte unchanged (every write was redirected into
// the process-private backing store). Because the backing store is per
// invocation, a write and its read-back must share one invocation - so a case
// that needs several ops sequences them inside one cmd .bat.
//
// The launcher rides as `data` on the cc_test and its runfiles rlocationpath is
// handed in via E2E_SANDBOX; real tools are handed in via their own env vars
// (each test TU knows its own names) and resolved through the rules_cc runfiles
// library. BazelSandbox carries DetoursServices.dll co-located in its runfiles.

#ifndef TESTS_E2E_E2E_HARNESS_H_
#define TESTS_E2E_E2E_HARNESS_H_

#include <windows.h>

#include <filesystem>
#include <string>
#include <vector>

#include "gtest/gtest.h"

namespace bsxe2e {

// Outcome of one sandbox invocation: the launcher/tool exit code and the
// combined stdout+stderr captured from the child.
struct RunResult {
    int code = -1;
    std::string out;
};

// Fixture: owns a per-test temp execroot and drives the write-overlay launcher.
class OverlayTest : public ::testing::Test {
   protected:
    void SetUp() override;
    void TearDown() override;

    // Absolute path to the resolved BazelSandbox.exe (from E2E_SANDBOX). Empty
    // if it could not be resolved (SetUp asserts non-empty).
    static const std::wstring& SandboxPath();

    // Resolves a tool's runfiles rlocationpath (held in environment variable
    // `envName`) to an absolute path. Returns empty if the var is unset or the
    // runfiles entry is missing - callers GTEST_SKIP in that case.
    static std::wstring ToolFromEnv(const char* envName);

    // cmd.exe resolved from the OS system directory (env-independent). Used only
    // to *sequence* several tool ops inside one invocation (see header note);
    // it is not itself the tool under test.
    static std::wstring CmdExe();

    // Creates a fresh empty execroot directory for the current test and returns
    // its (backslash-normalized) path. Reset per test (fresh fixture).
    std::wstring NewWorkspace();

    // Joins a workspace path with a child name (backslash-normalized).
    static std::wstring Join(const std::wstring& dir, const std::wstring& name);

    // Runs "BazelSandbox --write-overlay -W <ws> -- <toolCmd...>" and returns
    // the exit code plus captured stdout+stderr.
    RunResult RunOverlay(const std::wstring& ws,
                         const std::vector<std::wstring>& toolCmd);

    // Writes `content` to a .bat file in the temp root and runs it under the
    // overlay via cmd.exe (/c). `lines` are joined with CRLF + "&& " semantics
    // is up to the caller; each entry becomes its own line. Returns the run
    // result. Used to sequence multiple tool ops in one invocation.
    RunResult RunOverlayBat(const std::wstring& ws,
                            const std::vector<std::wstring>& lines);

    // --- filesystem helpers -------------------------------------------------
    static bool Exists(const std::wstring& p);
    static void WriteText(const std::wstring& p, const std::string& content);
    static std::string ReadText(const std::wstring& p);

    // Sorted list of paths (relative to `dir`) of every entry under `dir`,
    // recursively. Used to assert the real execroot is unchanged.
    static std::vector<std::wstring> Snapshot(const std::wstring& dir);

    const std::filesystem::path& TempRoot() const { return tempRoot_; }

   private:
    std::filesystem::path tempRoot_;
    unsigned counter_ = 0;
};

}  // namespace bsxe2e

#endif  // TESTS_E2E_E2E_HARNESS_H_
