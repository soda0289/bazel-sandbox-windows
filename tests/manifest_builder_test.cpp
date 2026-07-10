// Lightweight, framework-free unit tests for the native FileAccessManifest
// serializer (src/manifest_builder.cpp). Returns 0 if all checks pass, non-zero
// (and prints the first failure) otherwise. Registered with CTest as
// "manifest_unit".

#include "manifest_builder.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace bazelsandbox;

static int g_failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            wprintf(L"FAIL: %S (line %d): %S\n", __func__, __LINE__,       \
                    #cond);                                                \
            ++g_failures;                                                  \
        }                                                                  \
    } while (false)

namespace {

uint32_t ReadU32LE(const std::vector<uint8_t>& b, size_t at) {
    return static_cast<uint32_t>(b[at]) | (static_cast<uint32_t>(b[at + 1]) << 8) |
           (static_cast<uint32_t>(b[at + 2]) << 16) |
           (static_cast<uint32_t>(b[at + 3]) << 24);
}

ManifestBuilder MakeBuilder(uint32_t flags = Flag_FailUnexpectedFileAccesses |
                                             Flag_MonitorNtCreateFile |
                                             Flag_MonitorChildProcesses) {
    return ManifestBuilder(flags, /*extraFlags*/ 0, "x86.dll", "x64.dll");
}

// The hash must match DetoursServices.dll's NormalizeAndHashPath byte-for-byte;
// these golden values pin the FNV-1 constants, code-unit byte order, and the
// towupper normalization. A regression here is exactly what caused a past
// fail-fast, so keep the goldens.
void TestHashGoldens() {
    struct Case {
        const wchar_t* in;
        const wchar_t* normalized;
        uint32_t hash;
    } cases[] = {
        {L"C:", L"C:", 0x128E58F2u},
        {L"users", L"USERS", 0x3E58B87Fu},
        {L"Writable", L"WRITABLE", 0x34AAE547u},
        {L"a.txt", L"A.TXT", 0x5C8EE5E8u},
    };
    for (const auto& c : cases) {
        std::wstring normalized;
        uint32_t h = testing::HashFragment(c.in, normalized);
        CHECK(normalized == c.normalized);
        CHECK(h == c.hash);
    }
    // Hashing is case-insensitive: lower and upper inputs collide.
    std::wstring n1, n2;
    CHECK(testing::HashFragment(L"users", n1) ==
          testing::HashFragment(L"USERS", n2));
}

// The blob starts with the DebugOff flag, then injection timeout, and later the
// two flag words. These are the fields ParseFileAccessManifest reads first.
void TestHeaderLayout() {
    ManifestBuilder mb = MakeBuilder(Flag_FailUnexpectedFileAccesses);
    mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
    std::vector<uint8_t> blob = mb.Build(/*injectionTimeoutMins*/ 7);

    CHECK(blob.size() > 16);
    CHECK(ReadU32LE(blob, 0) == 0xDB600000u);  // DebugFlag = DebugOff
    CHECK(ReadU32LE(blob, 4) == 7u);           // injection timeout minutes
}

// Building twice with identical inputs must be byte-for-byte deterministic.
void TestDeterministic() {
    std::vector<uint8_t> a, b;
    {
        ManifestBuilder mb = MakeBuilder();
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        mb.AddScope(L"C:\\Windows", Policy_MaskAll, Policy_AllowRead);
        a = mb.Build(10);
    }
    {
        ManifestBuilder mb = MakeBuilder();
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        mb.AddScope(L"C:\\Windows", Policy_MaskAll, Policy_AllowRead);
        b = mb.Build(10);
    }
    CHECK(a == b);
}

// Adding a path scope must grow the serialized tree (new nodes are emitted).
void TestScopeGrowsTree() {
    std::vector<uint8_t> bare, withScope;
    {
        ManifestBuilder mb = MakeBuilder();
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        bare = mb.Build(10);
    }
    {
        ManifestBuilder mb = MakeBuilder();
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        CHECK(mb.AddScope(L"C:\\Users\\test\\out", Policy_MaskAll,
                          Policy_AllowAll));
        withScope = mb.Build(10);
    }
    CHECK(withScope.size() > bare.size());
}

// Different flags must produce different bytes (flags are actually serialized).
void TestFlagsAffectBlob() {
    std::vector<uint8_t> a, b;
    {
        ManifestBuilder mb = MakeBuilder(Flag_FailUnexpectedFileAccesses);
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        a = mb.Build(10);
    }
    {
        ManifestBuilder mb =
            MakeBuilder(Flag_FailUnexpectedFileAccesses | Flag_MonitorChildProcesses);
        mb.AddRootScope(Policy_MaskAll, Policy_AllowRead);
        b = mb.Build(10);
    }
    CHECK(a != b);
}

}  // namespace

int main() {
    TestHashGoldens();
    TestHeaderLayout();
    TestDeterministic();
    TestScopeGrowsTree();
    TestFlagsAffectBlob();

    if (g_failures == 0) {
        wprintf(L"manifest_builder_test: all checks passed\n");
        return 0;
    }
    wprintf(L"manifest_builder_test: %d check(s) failed\n", g_failures);
    return 1;
}
