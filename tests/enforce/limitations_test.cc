// KNOWN LIMITATIONS of the vendored engine, characterized so a future rewrite
// that fixes one will make the corresponding assertion change loudly. None is an
// under-deny that silently defeats a declared deny via a normal long path; they
// are edge cases. Environment-dependent outcomes are recorded (RecordProperty)
// rather than asserted, matching the old Note-Exit observations.
//
// gtest port of tests/enforce/limitations.ps1.

#include <windows.h>

#include <filesystem>
#include <string>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// Directory enumeration (FindFirstFile/FindNextFile) is NOT enforced: a denied
// workdir can still be listed. File opens are still enforced; only the listing is
// visible. Potential info-leak surface.
TEST_F(EnforceTest, KnownGapEnumerateInDeniedWorkdirAllowed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws}, {L"enumerate", ws}));
}

// 8.3 short names are hashed in long form and not cross-matched, so an exact -b
// block can be evaded via the short name. Short-name generation may be disabled
// per volume, so short-name outcomes are recorded, not asserted; only the
// deterministic long-name control is asserted.
TEST_F(EnforceTest, KnownGap83ShortName) {
    auto ws = NewWorkspace();
    auto longFile = Join(ws, L"longfilename.txt");
    WriteText(longFile, "y");
    wchar_t shortBuf[MAX_PATH];
    DWORD n = GetShortPathNameW(longFile.c_str(), shortBuf, MAX_PATH);
    std::wstring shortFile = (n > 0 && n < MAX_PATH) ? std::wstring(shortBuf, n) : L"";
    if (shortFile.empty() || shortFile.find(L'~') == std::wstring::npos ||
        !Exists(shortFile)) {
        GTEST_SKIP() << "no 8.3 name on volume";
    }
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", longFile},
                                {L"write", longFile}));
    int shortWrite = RunProbe({L"-W", ws, L"-r", ws, L"-w", ws, L"-b", longFile},
                              {L"write", shortFile});
    RecordProperty("short_name_vs_exact_b", shortWrite);  // 0 = bypass

    auto longSub = Join(ws, L"longsubdir");
    MakeDirs(longSub);
    WriteText(Join(longSub, L"f.txt"), "z");
    DWORD ns = GetShortPathNameW(longSub.c_str(), shortBuf, MAX_PATH);
    std::wstring shortSub = (ns > 0 && ns < MAX_PATH) ? std::wstring(shortBuf, ns) : L"";
    if (!shortSub.empty() && shortSub.find(L'~') != std::wstring::npos) {
        int subRead = RunProbe({L"-W", ws}, {L"read", (std::filesystem::path(shortSub) / L"f.txt").wstring()});
        RecordProperty("short_name_vs_subtree_deny", subRead);  // 0 = bypass
    }
}

namespace {
// Creates a >MAX_PATH directory tree + d.txt inside the given workspace using the
// \\?\ extended-length form. Returns the deep dir path (WITHOUT \\?\), or empty
// if the environment cannot create it.
std::wstring MakeDeepDir(const std::wstring& ws) {
    std::wstring deep = ws;
    for (int i = 1; i <= 20; ++i)
        deep = (std::filesystem::path(deep) / (L"longsegmentname_" + std::to_wstring(i))).wstring();
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(L"\\\\?\\" + deep), ec);
    if (ec) return L"";
    EnforceTest::WriteText(L"\\\\?\\" + deep + L"\\d.txt", "x");
    if (deep.size() <= 260) return L"";
    if (!EnforceTest::Exists(L"\\\\?\\" + deep + L"\\d.txt")) return L"";
    return deep;
}

bool LongPathsEnabled() {
    DWORD val = 0, sz = sizeof(val);
    LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Control\\FileSystem",
                           L"LongPathsEnabled", RRF_RT_REG_DWORD, nullptr, &val, &sz);
    return rc == ERROR_SUCCESS && val == 1;
}
}  // namespace

// Long paths (> MAX_PATH). A non-long-path-aware child that passes a raw >260 path
// (no \\?\) has it truncated by its own Win32 layer before the engine sees it, so
// a legitimate -r access is over-denied; the \\?\ form works correctly. This is a
// child-side issue, not the launcher's.
TEST_F(EnforceTest, KnownGapLongPath) {
    auto ws = NewWorkspace();
    std::wstring deep = MakeDeepDir(ws);
    if (deep.empty()) GTEST_SKIP() << ">260 path not creatable here";
    std::wstring deepFile = deep + L"\\d.txt";

    // Recorded, not gated (10=denied or 11=not-found; both reflect truncation).
    int rawOutcome = RunProbe({L"-W", ws, L"-r", deep}, {L"read", deepFile});
    RecordProperty("raw_over_260_r_over_restricts", rawOutcome);

    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", L"\\\\?\\" + deep}, {L"read", L"\\\\?\\" + deepFile}));
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", L"\\\\?\\" + deepFile}));
}

// Contrast: a long-path-aware child (probe_lpa) passes the same raw >260 path
// straight through, so a declared -r is honored and an undeclared access is still
// denied. Requires LongPathsEnabled=1 and the probe_lpa binary.
TEST_F(EnforceTest, LongPathAwareChild) {
    if (ProbeLpaPath().empty()) GTEST_SKIP() << "probe_lpa missing";
    if (!LongPathsEnabled()) GTEST_SKIP() << "LongPathsEnabled=0";
    auto ws = NewWorkspace();
    std::wstring deep = MakeDeepDir(ws);
    if (deep.empty()) GTEST_SKIP() << ">260 path not creatable here";
    std::wstring deepFile = deep + L"\\d.txt";

    // Drive the launcher directly with probe_lpa as the target.
    auto runLpa = [&](const std::vector<std::wstring>& sandboxArgs,
                      const std::vector<std::wstring>& probeArgs) {
        std::vector<std::wstring> a = {L"-H"};
        for (auto& s : sandboxArgs) a.push_back(s);
        a.push_back(L"--");
        a.push_back(ProbeLpaPath());
        for (auto& s : probeArgs) a.push_back(s);
        return RunSandbox(a);
    };
    EXPECT_EQ(kOk, runLpa({L"-W", ws, L"-r", deep}, {L"read", deepFile}));
    EXPECT_EQ(kDenied, runLpa({L"-W", ws}, {L"read", deepFile}));
}

// Case-insensitive matching is ASCII-only. The engine upper-cases with
// _towupper_l(invariant), which folds a-z but NOT non-ASCII letters, so a
// non-ASCII path is matched case-SENSITIVELY.
TEST_F(EnforceTest, AsciiCaseFolds) {
    auto ws = NewWorkspace();
    auto ascii = Join(ws, L"asciidir");
    MakeDirs(ascii);
    WriteText(Join(ascii, L"f.txt"), "a");
    std::wstring upper = ascii;
    for (auto& c : upper) c = towupper(c);
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", upper}, {L"read", Join(ascii, L"f.txt")}));
}

namespace {
// Uppercases like .NET ToUpperInvariant (folds Latin-1 é -> É), matching the old
// PowerShell $x.ToUpperInvariant(). Plain towupper() under the C locale leaves
// non-ASCII letters untouched, which would collapse the gap these tests pin.
std::wstring UpperInvariant(const std::wstring& s) {
    if (s.empty()) return s;
    int n = LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, s.c_str(),
                         static_cast<int>(s.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, s.c_str(),
                 static_cast<int>(s.size()), out.data(), n);
    return out;
}
}  // namespace

TEST_F(EnforceTest, KnownGapNonAsciiCaseNotFoldedOverDeny) {
    auto ws = NewWorkspace();
    auto acc = Join(ws, std::wstring(L"caf\u00E9"));  // café (é = U+00E9)
    MakeDirs(acc);
    auto accFile = Join(acc, L"f.txt");
    WriteText(accFile, "a");
    std::wstring upper = UpperInvariant(acc);
    // Over-deny: an upper-cased non-ASCII -r scope does NOT match the lower-cased
    // access, so a legitimate read is denied.
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", upper}, {L"read", accFile}));
}

TEST_F(EnforceTest, KnownGapNonAsciiBlockBypassedByCase) {
    auto ws = NewWorkspace();
    auto acc = Join(ws, std::wstring(L"caf\u00E9"));
    MakeDirs(acc);
    auto accFile = Join(acc, L"f.txt");
    WriteText(accFile, "a");
    std::wstring upper = UpperInvariant(acc);
    // Under-deny: an upper-cased non-ASCII -b block is bypassed by the lower-cased
    // access (0 = the block leaked).
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-b", upper}, {L"read", accFile}));
}

// Reparse-point escape. The engine is configured with IgnoreReparsePoints +
// IgnoreFullReparsePointResolving, so it enforces on the path AS REQUESTED. A
// reparse point inside an ALLOWED scope pointing OUTSIDE every scope lets the
// access reach the outside target, even though a direct access is denied.
TEST_F(EnforceTest, KnownGapReparsePointEscape) {
    auto ws = NewWorkspace();
    auto inside = Join(ws, L"inside");
    auto outside = Join(ws, L"outside");
    MakeDirs(inside);
    MakeDirs(outside);
    WriteText(Join(outside, L"o.txt"), "orig");
    auto esc = Join(inside, L"esc");
    ASSERT_TRUE(MakeJunction(esc, outside));
    // Control: a direct write to the outside target (in neither -r nor -w) is denied.
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", inside, L"-w", inside},
                                {L"write", Join(outside, L"o.txt")}));
    // Gap: the same target reached THROUGH a junction inside the -w scope is
    // allowed (0 = the write escaped confinement to an undeclared location).
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", inside, L"-w", inside},
                            {L"write", Join(esc, L"o.txt")}));
}

}  // namespace
}  // namespace bsx
