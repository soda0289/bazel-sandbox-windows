// Scope model: read-only root, blocked working directory, -r/-w/-b precedence,
// single-file scopes, and child-process propagation of the file policy.
//
// gtest port of tests/enforce/scopes.ps1.

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// Whole filesystem is read-only by default: reading the probe binary is allowed.
TEST_F(EnforceTest, ReadAllowedOnReadOnlyRoot) {
    EXPECT_EQ(kOk, RunProbe({}, {L"read", ProbePath()}));
}

// Working directory is denied by default.
TEST_F(EnforceTest, WriteToBlockedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"write", Join(ws, L"out.txt")}));
}

TEST_F(EnforceTest, ReadInBlockedWorkdirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", Join(ws, L"seed.txt")}));
}

// -r re-enables reads; -w re-enables writes.
TEST_F(EnforceTest, ReadScopeAllowsReadInWorkdir) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws}, {L"read", Join(ws, L"seed.txt")}));
}

TEST_F(EnforceTest, WriteScopeAllowsWriteInWorkdir) {
    auto ws = NewWorkspace();
    auto okFile = Join(ws, L"ok.txt");
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws}, {L"write", okFile}));
    EXPECT_TRUE(Exists(okFile));
}

// A read-only (-r) scope is truly read-only: it permits reads but denies every
// mutation. This guards against a rewrite accidentally granting write access
// through a read scope.
TEST_F(EnforceTest, ReadScopeDeniesWrite) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws}, {L"write", Join(ws, L"n.txt")}));
}

TEST_F(EnforceTest, ReadScopeDeniesDelete) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws}, {L"delete", Join(ws, L"src.txt")}));
}

TEST_F(EnforceTest, ReadScopeDeniesMkdir) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws}, {L"mkdir", Join(ws, L"nd")}));
}

TEST_F(EnforceTest, ReadScopeDeniesRename) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws},
                                {L"rename", Join(ws, L"src.txt"), Join(ws, L"d.txt")}));
}

// -b overrides an enclosing -w for a specific file; siblings stay writable.
TEST_F(EnforceTest, BlockFileOverrideInsideWriteDirDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-w", ws, L"-b", Join(ws, L"keep.txt")},
                       {L"write", Join(ws, L"keep.txt")}));
}

TEST_F(EnforceTest, WriteSiblingStillWritable) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-w", ws, L"-b", Join(ws, L"keep.txt")},
                            {L"write", Join(ws, L"other.txt")}));
}

// -b makes a path fully inaccessible: it blocks reads too, not just writes.
TEST_F(EnforceTest, BlockBlocksReadOfBlockedFile) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws, L"-b", Join(ws, L"a.txt")},
                                {L"read", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, BlockSiblingStillReadableUnderRead) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-b", Join(ws, L"a.txt")},
                            {L"read", Join(ws, L"src.txt")}));
}

// A single-FILE -r grants exactly that file, not its siblings.
TEST_F(EnforceTest, SingleFileReadAllowsThatFile) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", Join(ws, L"a.txt")},
                            {L"read", Join(ws, L"a.txt")}));
}

TEST_F(EnforceTest, SingleFileReadDeniesSiblings) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", Join(ws, L"a.txt")},
                                {L"read", Join(ws, L"src.txt")}));
}

// Nested precedence: a more-specific -w child overrides a -r parent.
TEST_F(EnforceTest, WriteChildOverridesReadParent) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", Join(ws, L"sub")},
                            {L"write", Join(ws, L"sub\\new.txt")}));
}

TEST_F(EnforceTest, ReadParentStaysReadOnlyOutsideWriteChild) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws, L"-r", ws, L"-w", Join(ws, L"sub")},
                                {L"write", Join(ws, L"top.txt")}));
}

// Case-insensitive scope matching (path-hash normalization guard).
TEST_F(EnforceTest, CaseInsensitiveReadScopeMatch) {
    auto ws = NewWorkspace();
    std::wstring upper = ws;
    for (auto& c : upper) c = towupper(c);
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", upper}, {L"read", Join(ws, L"a.txt")}));
}

// Child-process propagation: the policy survives process hops (probe -> probe).
TEST_F(EnforceTest, ChildProcessPropagationDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws},
                                {L"spawn", ProbePath(), L"write", Join(ws, L"child.txt")}));
}

TEST_F(EnforceTest, Depth3PropagationWriteDenied) {
    auto ws = NewWorkspace();
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws},
                       {L"spawn", ProbePath(), L"spawn", ProbePath(), L"write",
                        Join(ws, L"deep.txt")}));
}

// Multiple disjoint scopes on one invocation each take effect independently; a
// path in none of them stays denied.
TEST_F(EnforceTest, MultipleDisjointReadScopes) {
    auto ws = NewWorkspace();
    auto d1 = Join(ws, L"one");
    auto d2 = Join(ws, L"two");
    auto d3 = Join(ws, L"three");
    MakeDirs(d1);
    MakeDirs(d2);
    MakeDirs(d3);
    WriteText(Join(d1, L"f.txt"), "x");
    WriteText(Join(d2, L"f.txt"), "x");
    WriteText(Join(d3, L"f.txt"), "x");
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", d1, L"-r", d2}, {L"read", Join(d1, L"f.txt")}));
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", d1, L"-r", d2}, {L"read", Join(d2, L"f.txt")}));
    EXPECT_EQ(kDenied,
              RunProbe({L"-W", ws, L"-r", d1, L"-r", d2}, {L"read", Join(d3, L"f.txt")}));
}

}  // namespace
}  // namespace bsx
