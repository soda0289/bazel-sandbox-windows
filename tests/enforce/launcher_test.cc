// Launcher features Bazel depends on: exact exit-code forwarding, -W working
// directory, -T/-t timeout+grace, @response-file expansion, -l/-L stdio
// redirection, relative-path scope resolution, -D/--trace/-S diagnostics, the
// std-handle repair a Bazel-style launch requires, the cross-bitness guard, the
// CLI error contract, and BuildChildCommandLine argument round-tripping.
//
// gtest port of tests/enforce/launcher.ps1.

#include <chrono>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// Writes each token on its own line (CRLF), matching Set-Content -Encoding Ascii;
// the launcher's response-file parser reads one token per line.
void WriteRsp(const std::wstring& path, const std::vector<std::wstring>& lines) {
    std::wstring text;
    for (const auto& l : lines) {
        text += l;
        text += L"\r\n";
    }
    int n = WideCharToMultiByte(CP_ACP, 0, text.data(), (int)text.size(), nullptr, 0,
                                nullptr, nullptr);
    std::string bytes(n, '\0');
    WideCharToMultiByte(CP_ACP, 0, text.data(), (int)text.size(), bytes.data(), n,
                        nullptr, nullptr);
    EnforceTest::WriteText(path, bytes);
}

std::vector<std::string> NonEmptyLines(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n' || c == '\r') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

// Exit-code fidelity: the launcher forwards the child's exact exit code.
TEST_F(EnforceTest, ExitCodeForwarded7) {
    auto ws = NewWorkspace();
    EXPECT_EQ(7, RunProbe({L"-W", ws}, {L"exit", L"7"}));
}

TEST_F(EnforceTest, ExitCodeForwarded213) {
    auto ws = NewWorkspace();
    EXPECT_EQ(213, RunProbe({L"-W", ws}, {L"exit", L"213"}));
}

// -W sets the child's current directory.
TEST_F(EnforceTest, WorkingDirSetForChild) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws}, {L"cwdis", ws}));
}

// -T terminates a long-running child (exit 1); a short child under a generous
// timeout completes normally.
TEST_F(EnforceTest, TimeoutKillsLongChild) {
    auto ws = NewWorkspace();
    EXPECT_EQ(1, RunProbe({L"-W", ws, L"-T", L"1"}, {L"sleep", L"10000"}));
}

TEST_F(EnforceTest, GenerousTimeoutLetsChildFinish) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-T", L"30"}, {L"sleep", L"200"}));
}

// -t adds a grace period between the -T timeout and the force-kill.
TEST_F(EnforceTest, GraceStillForceKillsAfterTimeout) {
    auto ws = NewWorkspace();
    auto start = std::chrono::steady_clock::now();
    int rc = RunProbe({L"-W", ws, L"-T", L"1", L"-t", L"3"}, {L"sleep", L"30000"});
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    EXPECT_EQ(1, rc);
    EXPECT_GE(sec, 2.5);
    EXPECT_LT(sec, 20.0);
}

TEST_F(EnforceTest, GraceReturnsEarlyOnChildExit) {
    auto ws = NewWorkspace();
    auto start = std::chrono::steady_clock::now();
    int rc = RunProbe({L"-W", ws, L"-T", L"1", L"-t", L"30"}, {L"sleep", L"2500"});
    double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    EXPECT_EQ(1, rc);
    EXPECT_LT(sec, 15.0);
}

// @response-file expansion: options read from a file are applied.
TEST_F(EnforceTest, ResponseFileAppliesReadScope) {
    auto ws = NewWorkspace();
    auto rsp = Join(ws, L"args.rsp");
    WriteRsp(rsp, {L"-W", ws, L"-r", ws});
    EXPECT_EQ(kOk, RunProbe({L"@" + rsp}, {L"read", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, ResponseFileWithoutReadKeepsDeny) {
    auto ws = NewWorkspace();
    auto rsp = Join(ws, L"args.rsp");
    WriteRsp(rsp, {L"-W", ws});
    EXPECT_EQ(kDenied, RunProbe({L"@" + rsp}, {L"read", Join(ws, L"a.txt")}));
}

// Relative scope paths resolve against the launcher's current directory.
TEST_F(EnforceTest, RelativeScopeResolvesToLauncherCwd) {
    auto ws = NewWorkspace();
    SetLaunchDir(ws);
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", L"a.txt"}, {L"read", Join(ws, L"a.txt")}));
}

// -l / -L route the child's stdout/stderr to the given files.
TEST_F(EnforceTest, StdioRedirectionCapturesStreams) {
    auto ws = NewWorkspace();
    auto lOut = Join(ws, L"l_out.txt");
    auto lErr = Join(ws, L"l_err.txt");
    EXPECT_EQ(kOk, RunProbe({L"-l", lOut, L"-L", lErr}, {L"stdio"}));
    EXPECT_TRUE(Exists(lOut));
    EXPECT_TRUE(Exists(lErr));
    EXPECT_EQ("o", ReadText(lOut));
    EXPECT_EQ("e", ReadText(lErr));
}

// Std-handle repair (regression): stdio_launcher reproduces Bazel's launch
// (STARTF_USESTDHANDLES, inheritable stdout/stderr, no stdin).
TEST_F(EnforceTest, StdHandlesValidUnderBazelStyleLaunch) {
    auto ws = NewWorkspace();
    auto scratch = Join(ws, L"stdio_out.txt");
    ASSERT_FALSE(StdioPath().empty()) << "stdio_launcher not resolved";
    EXPECT_EQ(kOk, RunExe(StdioPath(), {SandboxPath(), ProbePath(), scratch}));
}

// -D writes launcher diagnostics; --trace writes a per-access report. Neither
// changes enforcement.
TEST_F(EnforceTest, DebugAndTraceDoNotChangeEnforcement) {
    auto ws = NewWorkspace();
    auto dbgFile = Join(ws, L"debug.log");
    auto traceFile = Join(ws, L"trace.txt");
    auto aTxt = Join(ws, L"a.txt");
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-D", dbgFile, L"--trace", traceFile},
                            {L"read", aTxt}));
    ASSERT_TRUE(Exists(dbgFile));
    std::string dbg = ReadText(dbgFile);
    EXPECT_GT(dbg.size(), 0u);
    EXPECT_NE(dbg.find("child exit code: 0"), std::string::npos);
    ASSERT_TRUE(Exists(traceFile));
    std::wstring trace = ReadWideText(traceFile);
    EXPECT_GT(trace.size(), 0u);
    EXPECT_NE(trace.find(L"a.txt"), std::wstring::npos);
}

// -S writes child resource-usage statistics as a tools.protos.ExecutionStatistics
// protobuf: it starts with the length-delimited resource_usage field (tag 0x0A)
// whose declared length matches the payload.
TEST_F(EnforceTest, StatsFileIsWellFormedProto) {
    auto ws = NewWorkspace();
    auto statsFile = Join(ws, L"stats.pb");
    auto aTxt = Join(ws, L"a.txt");
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-S", statsFile}, {L"read", aTxt}));
    ASSERT_TRUE(Exists(statsFile));
    auto b = ReadBytes(statsFile);
    ASSERT_GE(b.size(), 2u);
    EXPECT_EQ(0x0A, b[0]);
    EXPECT_LT(b[1], 0x80);  // single-byte varint length
    EXPECT_EQ(b.size() - 2, static_cast<size_t>(b[1]));
}

// Cross-bitness guard: the launcher refuses a non-x64 target UP FRONT (exit 3),
// reading its PE machine type without ever spawning it.
TEST_F(EnforceTest, NonX64TargetRefusedBeforeSpawn) {
    std::wstring w32 = SysWow64Whoami();
    if (w32.empty()) GTEST_SKIP() << "no 32-bit system binary (SysWOW64 absent)";
    auto ws = NewWorkspace();
    EXPECT_EQ(3, RunSandbox({L"-W", ws, L"--", w32}));
}

// CLI error contract: distinct, non-zero, never hanging.
TEST_F(EnforceTest, NonexistentTargetFailsSpawn) {
    auto ws = NewWorkspace();
    EXPECT_EQ(2, RunSandbox({L"-W", ws, L"--", Join(ws, L"does-not-exist.exe")}));
}

TEST_F(EnforceTest, NoCommandAfterSeparatorIsUsageError) {
    auto ws = NewWorkspace();
    EXPECT_EQ(1, RunSandbox({L"-W", ws, L"--"}));
}

TEST_F(EnforceTest, UnknownFlagRejected) {
    auto ws = NewWorkspace();
    EXPECT_EQ(1, RunSandbox({L"-Z", L"-W", ws, L"--", ProbePath(), L"read", ProbePath()}));
}

// BuildChildCommandLine escaped regime: a space-bearing token reaches the child
// intact as a single argument.
TEST_F(EnforceTest, EscapedRegimeSpaceArgStaysOneToken) {
    auto ws = NewWorkspace();
    auto outEsc = Join(ws, L"echo_escaped.txt");
    auto rspEsc = Join(ws, L"escaped.rsp");
    WriteRsp(rspEsc, {L"-W", ws, L"-l", outEsc, L"--", ProbePath(), L"echoargs", L"a b", L"c"});
    EXPECT_EQ(kOk, RunSandbox({L"@" + rspEsc}));
    ASSERT_TRUE(Exists(outEsc));
    auto lines = NonEmptyLines(ReadText(outEsc));
    ASSERT_EQ(2u, lines.size());
    EXPECT_EQ("a b", lines[0]);
    EXPECT_EQ("c", lines[1]);
}

// Verbatim regime: cmd.exe receives its tail unescaped, so real quotes survive.
TEST_F(EnforceTest, VerbatimRegimeCmdQuotesPreserved) {
    auto ws = NewWorkspace();
    auto outCmd = Join(ws, L"echo_cmd.txt");
    auto rspCmd = Join(ws, L"cmd.rsp");
    WriteRsp(rspCmd, {L"-W", ws, L"-l", outCmd, L"--", L"cmd.exe", L"/c", L"echo \"a b\""});
    EXPECT_EQ(kOk, RunSandbox({L"@" + rspCmd}));
    ASSERT_TRUE(Exists(outCmd));
    std::string out = ReadText(outCmd);
    // Trim trailing whitespace/newlines.
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' ||
                            out.back() == ' ' || out.back() == '\t'))
        out.pop_back();
    EXPECT_EQ("\"a b\"", out);
}

}  // namespace
}  // namespace bsx
