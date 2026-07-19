// Reparse-point handling. Bazel's execroot is full of junctions (external/ ->
// repo cache) and, with --windows_enable_symlinks, file symlinks. Enforcement is
// a hybrid: the path AS REQUESTED is checked first (a declared -r/-w link is
// allowed without resolving the target); if that is denied, a handle-resolution
// fallback resolves the final target and re-checks THAT against the policy. So an
// undeclared link is allowed iff its resolved target is itself a DECLARED input,
// and denied iff the target lands in a denied region or is only readable via the
// whole-filesystem root baseline.
//
// gtest port of tests/enforce/reparse.ps1.

#include <string>

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

// --- Directory junctions (no privilege required) ---------------------------

TEST_F(EnforceTest, ReadThroughDeclaredJunctionAllowed) {
    auto ws = NewWorkspace();
    auto exec = Join(ws, L"jexec");
    auto real = Join(exec, L"jreal");
    auto link = Join(exec, L"link");
    MakeDirs(real);
    WriteText(Join(real, L"f.txt"), "payload");
    ASSERT_TRUE(MakeJunction(link, real));
    EXPECT_EQ(kOk, RunProbe({L"-W", exec, L"-r", link}, {L"read", Join(link, L"f.txt")}));
}

TEST_F(EnforceTest, ReadThroughUndeclaredJunctionToGrantedTargetAllowed) {
    auto ws = NewWorkspace();
    auto exec = Join(ws, L"jexec");
    auto grant = Join(exec, L"jgrant");
    auto glink = Join(exec, L"glink");
    MakeDirs(grant);
    WriteText(Join(grant, L"f.txt"), "payload");
    ASSERT_TRUE(MakeJunction(glink, grant));
    EXPECT_EQ(kOk, RunProbe({L"-W", exec, L"-r", grant}, {L"read", Join(glink, L"f.txt")}));
}

TEST_F(EnforceTest, ReadThroughUndeclaredJunctionToDeniedTargetDenied) {
    auto ws = NewWorkspace();
    auto exec = Join(ws, L"jexec");
    auto real = Join(exec, L"jreal");
    auto link = Join(exec, L"link");
    MakeDirs(real);
    WriteText(Join(real, L"f.txt"), "payload");
    ASSERT_TRUE(MakeJunction(link, real));
    EXPECT_EQ(kDenied, RunProbe({L"-W", exec}, {L"read", Join(link, L"f.txt")}));
}

// Handle-less stat parity (GetFileInformationByName, libuv's fast fs.stat path).
TEST_F(EnforceTest, StatByNameThroughUndeclaredJunctionToGrantedTargetAllowed) {
    auto ws = NewWorkspace();
    auto exec = Join(ws, L"jexec");
    auto grant = Join(exec, L"jgrant");
    auto glink = Join(exec, L"glink");
    MakeDirs(grant);
    WriteText(Join(grant, L"f.txt"), "payload");
    ASSERT_TRUE(MakeJunction(glink, grant));
    EXPECT_EQ(kOk, RunProbe({L"-W", exec, L"-r", grant}, {L"statbyname", Join(glink, L"f.txt")}));
}

TEST_F(EnforceTest, StatByNameThroughUndeclaredJunctionToDeniedTargetDenied) {
    auto ws = NewWorkspace();
    auto exec = Join(ws, L"jexec");
    auto real = Join(exec, L"jreal");
    auto link = Join(exec, L"link");
    MakeDirs(real);
    WriteText(Join(real, L"f.txt"), "payload");
    ASSERT_TRUE(MakeJunction(link, real));
    EXPECT_EQ(kDenied, RunProbe({L"-W", exec}, {L"statbyname", Join(link, L"f.txt")}));
}

// An undeclared junction whose target resolves OUTSIDE every -W deny scope, and is
// therefore readable ONLY via the whole-filesystem root baseline (not a declared
// input), is DENIED.
TEST_F(EnforceTest, ReadThroughUndeclaredJunctionToRootBaselineTargetDenied) {
    auto ws = NewWorkspace();
    auto outside = Join(ws, L"outside");
    auto exec = Join(ws, L"exec");
    MakeDirs(outside);
    MakeDirs(exec);
    WriteText(Join(outside, L"f.txt"), "payload");
    auto olink = Join(exec, L"olink");
    ASSERT_TRUE(MakeJunction(olink, outside));
    EXPECT_EQ(kDenied, RunProbe({L"-W", exec}, {L"read", Join(olink, L"f.txt")}));
}

// --- File symlinks (require SeCreateSymbolicLinkPrivilege) ------------------

class ReparseSymlinkTest : public EnforceTest {
   protected:
    void SetUp() override {
        EnforceTest::SetUp();
        if (!HasSymlinkPrivilege())
            GTEST_SKIP() << "SeCreateSymbolicLinkPrivilege not held";
    }
};

TEST_F(ReparseSymlinkTest, ReadDeclaredFileSymlinkOnLinkAllowed) {
    auto ws = NewWorkspace();
    auto target = Join(ws, L"target.txt");
    WriteText(target, "payload");
    auto linkdir = Join(ws, L"lnk");
    MakeDirs(linkdir);
    auto flink = Join(linkdir, L"flink.txt");
    if (!MakeFileSymlink(flink, target))
        GTEST_SKIP() << "symlink creation failed at runtime";
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", flink}, {L"read", flink}));
}

TEST_F(ReparseSymlinkTest, ReadDeclaredFileSymlinkOnDirAllowed) {
    auto ws = NewWorkspace();
    auto target = Join(ws, L"target.txt");
    WriteText(target, "payload");
    auto linkdir = Join(ws, L"lnk");
    MakeDirs(linkdir);
    auto flink = Join(linkdir, L"flink.txt");
    if (!MakeFileSymlink(flink, target))
        GTEST_SKIP() << "symlink creation failed at runtime";
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", linkdir}, {L"read", flink}));
}

TEST_F(ReparseSymlinkTest, ReadUndeclaredFileSymlinkDenied) {
    auto ws = NewWorkspace();
    auto target = Join(ws, L"target.txt");
    WriteText(target, "payload");
    auto linkdir = Join(ws, L"lnk");
    MakeDirs(linkdir);
    auto flink = Join(linkdir, L"flink.txt");
    if (!MakeFileSymlink(flink, target))
        GTEST_SKIP() << "symlink creation failed at runtime";
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", flink}));
}

TEST_F(ReparseSymlinkTest, WriteDeclaredFileSymlinkOnLinkAllowed) {
    auto ws = NewWorkspace();
    auto target = Join(ws, L"target.txt");
    WriteText(target, "payload");
    auto linkdir = Join(ws, L"lnk");
    MakeDirs(linkdir);
    auto flink = Join(linkdir, L"flink.txt");
    if (!MakeFileSymlink(flink, target))
        GTEST_SKIP() << "symlink creation failed at runtime";
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", flink}, {L"write", flink}));
}

// --- Directory symlinks (mklink /D, distinct from a junction) ---------------

TEST_F(ReparseSymlinkTest, ReadThroughDeclaredDirSymlinkAllowed) {
    auto ws = NewWorkspace();
    auto realdir = Join(ws, L"realdir");
    MakeDirs(realdir);
    WriteText(Join(realdir, L"f.txt"), "payload");
    auto dlink = Join(ws, L"dlink");
    if (!MakeDirSymlink(dlink, realdir))
        GTEST_SKIP() << "dir symlink creation failed at runtime";
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", dlink}, {L"read", Join(dlink, L"f.txt")}));
}

TEST_F(ReparseSymlinkTest, ReadThroughUndeclaredDirSymlinkDenied) {
    auto ws = NewWorkspace();
    auto realdir = Join(ws, L"realdir");
    MakeDirs(realdir);
    WriteText(Join(realdir, L"f.txt"), "payload");
    auto dlink = Join(ws, L"dlink");
    if (!MakeDirSymlink(dlink, realdir))
        GTEST_SKIP() << "dir symlink creation failed at runtime";
    EXPECT_EQ(kDenied, RunProbe({L"-W", ws}, {L"read", Join(dlink, L"f.txt")}));
}

TEST_F(ReparseSymlinkTest, WriteThroughDeclaredDirSymlinkAllowed) {
    auto ws = NewWorkspace();
    auto realdir = Join(ws, L"realdir");
    MakeDirs(realdir);
    WriteText(Join(realdir, L"f.txt"), "payload");
    auto dlink = Join(ws, L"dlink");
    if (!MakeDirSymlink(dlink, realdir))
        GTEST_SKIP() << "dir symlink creation failed at runtime";
    EXPECT_EQ(kOk, RunProbe({L"-W", ws, L"-r", ws, L"-w", dlink}, {L"write", Join(dlink, L"g.txt")}));
}

}  // namespace
}  // namespace bsx
