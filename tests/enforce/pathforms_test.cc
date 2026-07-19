// Path-form canonicalization. The engine canonicalizes every access before
// matching policy, so a file in a denied scope must stay denied however its path
// is spelled. These guard against a future rewrite reintroducing a
// canonicalization gap.
//
// gtest port of tests/enforce/pathforms.ps1.

#include <string>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

TEST_F(EnforceTest, DenyNotBypassedByForwardSlashes) {
    auto ws = NewWorkspace();
    std::wstring denied = Join(ws, L"a.txt");
    std::wstring fwd = denied;
    for (auto& c : fwd)
        if (c == L'\\') c = L'/';
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", fwd}));
}

TEST_F(EnforceTest, DenyNotBypassedByDotComponent) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", ws + L"\\.\\a.txt"}));
}

TEST_F(EnforceTest, DenyNotBypassedByDotDotComponent) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", ws + L"\\sub\\..\\a.txt"}));
}

TEST_F(EnforceTest, DenyNotBypassedByExtendedLengthPrefix) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", L"\\\\?\\" + Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, DenyNotBypassedByUpperCase) {
    auto ws = NewWorkspace();
    std::wstring upper = Join(ws, L"a.txt");
    for (auto& c : upper) c = towupper(c);
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", upper}));
}

TEST_F(EnforceTest, DenyNotBypassedByAlternateDataStream) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", Join(ws, L"a.txt") + L"::$DATA"}));
}

// The NUL device is not a real file and must not be sandboxed.
TEST_F(EnforceTest, NulDeviceNotSandboxed) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws}, {L"read", L"NUL"}));
}

// Non-ASCII (Unicode) path handling: café / я / 文. Windows paths are UTF-16 end
// to end, so a non-ASCII path must be enforced exactly like an ASCII one when the
// case matches. (Case-INsensitive matching of non-ASCII is a separate,
// characterized gap - see limitations_test.cc.)
TEST_F(EnforceTest, NonAsciiPathAllowedWhenDeclared) {
    auto ws = NewWorkspace();
    std::wstring uniDir = Join(ws, std::wstring(L"caf\u00E9_\u044F_\u6587"));
    MakeDirs(uniDir);
    std::wstring uniFile = Join(uniDir, L"data.txt");
    WriteText(uniFile, "payload");
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", uniDir}, {L"read", uniFile}));
}

TEST_F(EnforceTest, NonAsciiPathDeniedWhenUndeclared) {
    auto ws = NewWorkspace();
    std::wstring uniDir = Join(ws, std::wstring(L"caf\u00E9_\u044F_\u6587"));
    MakeDirs(uniDir);
    std::wstring uniFile = Join(uniDir, L"data.txt");
    WriteText(uniFile, "payload");
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", uniFile}));
}

TEST_F(EnforceTest, NonAsciiExactBlockHolds) {
    auto ws = NewWorkspace();
    std::wstring uniDir = Join(ws, std::wstring(L"caf\u00E9_\u044F_\u6587"));
    MakeDirs(uniDir);
    std::wstring uniFile = Join(uniDir, L"data.txt");
    WriteText(uniFile, "payload");
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws, L"-b", uniFile}, {L"read", uniFile}));
}

}  // namespace
}  // namespace bsx
