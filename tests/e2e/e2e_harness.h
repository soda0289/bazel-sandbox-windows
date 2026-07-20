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
// A second mode, RunFiltered / RunFilteredBat, drives the *input-filtering*
// path Bazel relies on in production:
//
//     BazelSandbox --filter-inputs -W <execroot> -r <in> ... -- <tool> <args>
//
// Only the declared -r inputs are visible to the tool; every other real file
// under the execroot is masked NOT_FOUND and hidden from enumeration. Filtering
// cases assert a real tool reads its declared inputs but neither reads nor
// enumerates undeclared siblings.
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

   public:
    // Static utilities are public so free helper functions in the test TUs can
    // call them (matches the enforce harness convention).

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

    // Joins a workspace path with a child name (backslash-normalized).
    static std::wstring Join(const std::wstring& dir, const std::wstring& name);

    // --- filesystem helpers -------------------------------------------------
    static bool Exists(const std::wstring& p);
    static void WriteText(const std::wstring& p, const std::string& content);
    static std::string ReadText(const std::wstring& p);

    // Sorted list of paths (relative to `dir`) of every entry under `dir`,
    // recursively. Used to assert the real execroot is unchanged.
    static std::vector<std::wstring> Snapshot(const std::wstring& dir);

    // Runs "BazelSandbox --write-overlay -W <ws> -- <toolCmd...>" and returns
    // the exit code plus captured stdout+stderr. Public so free helper
    // functions in the test TUs can drive it (matches the static-helper
    // convention above).
    RunResult RunOverlay(const std::wstring& ws,
                         const std::vector<std::wstring>& toolCmd);

    // Runs "BazelSandbox --filter-inputs -W <ws> -r <in> ... -- <toolCmd...>"
    // and returns the exit code plus captured stdout+stderr. This drives the
    // *input-filtering* mode Bazel relies on in production: `declaredInputs`
    // are the only real in-cone files a tool may see - every other real file
    // under the execroot is masked NOT_FOUND and hidden from enumeration. Use
    // it to assert a real tool observes declared inputs but not undeclared
    // siblings. Public so free helpers in the test TUs can drive it.
    RunResult RunFiltered(const std::wstring& ws,
                          const std::vector<std::wstring>& declaredInputs,
                          const std::vector<std::wstring>& toolCmd);

    // Writes `lines` to a .bat and runs it under the input-filtering mode via
    // cmd.exe (/c) - the RunFiltered analogue of RunOverlayBat, for sequencing
    // several tool ops in one filtered invocation.
    RunResult RunFilteredBat(const std::wstring& ws,
                             const std::vector<std::wstring>& declaredInputs,
                             const std::vector<std::wstring>& lines);

    // Writes `lines` to a .bat in the temp root and runs it under the overlay
    // via cmd.exe (/c). Each entry becomes its own line (written verbatim, so
    // the caller controls "&&"/errorlevel sequencing). Public so free helpers
    // in the test TUs can sequence several ops in one invocation (e.g. run a
    // build then read an emitted file back THROUGH the overlay).
    RunResult RunOverlayBat(const std::wstring& ws,
                            const std::vector<std::wstring>& lines);

   protected:
    // Creates a fresh empty execroot directory for the current test and returns
    // its (backslash-normalized) path. Reset per test (fresh fixture).
    std::wstring NewWorkspace();

    // Writes `content` to a .bat file in the temp root and runs it under the
    // overlay via cmd.exe (/c). `lines` are joined with CRLF + "&& " semantics
    // is up to the caller; each entry becomes its own line. Returns the run
    // result. Used to sequence multiple tool ops in one invocation.

    const std::filesystem::path& TempRoot() const { return tempRoot_; }

   private:
    // Builds the launcher command line from a full arg vector (everything after
    // the exe, including "--" and the tool tail) and runs it, capturing output.
    RunResult RunArgs(const std::vector<std::wstring>& args);
    // Writes `lines` to a fresh .bat under the temp root and returns its path.
    std::wstring WriteBat(const std::vector<std::wstring>& lines);

    std::filesystem::path tempRoot_;
    unsigned counter_ = 0;
};

}  // namespace bsxe2e

#endif  // TESTS_E2E_E2E_HARNESS_H_
