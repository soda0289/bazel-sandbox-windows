// Network sandboxing via -N (loopback only) and -n (no network). The probe
// 'connect' op returns 0 when the sandbox permits the attempt (even if the
// connection is refused, since nothing is listening) and 10 when the sandbox
// blocks it. Port 9 (discard) on loopback is refused instantly, so no real
// network or listener is required.
//
// gtest port of tests/enforce/network.ps1.

#include "gtest/gtest.h"
#include "tests/enforce/enforce_harness.h"

namespace bsx {
namespace {

TEST_F(EnforceTest, DefaultAllowsLoopbackConnect) {
    EXPECT_EQ(kOk, RunProbe({}, {L"connect", L"127.0.0.1", L"9"}));
}

TEST_F(EnforceTest, LoopbackPolicyAllowsLoopbackConnect) {
    EXPECT_EQ(kOk, RunProbe({L"-N"}, {L"connect", L"127.0.0.1", L"9"}));
}

TEST_F(EnforceTest, LoopbackPolicyBlocksExternalConnect) {
    EXPECT_EQ(kDenied, RunProbe({L"-N"}, {L"connect", L"8.8.8.8", L"53"}));
}

TEST_F(EnforceTest, NoNetworkBlocksLoopbackConnect) {
    EXPECT_EQ(kDenied, RunProbe({L"-n"}, {L"connect", L"127.0.0.1", L"9"}));
}

TEST_F(EnforceTest, NoNetworkBlocksExternalConnect) {
    EXPECT_EQ(kDenied, RunProbe({L"-n"}, {L"connect", L"8.8.8.8", L"53"}));
}

// Network policy propagates to grandchildren (probe spawns probe).
TEST_F(EnforceTest, NetworkPolicyPropagatesToChild) {
    EXPECT_EQ(kDenied,
              RunProbe({L"-N"}, {L"spawn", ProbePath(), L"connect", L"8.8.8.8", L"53"}));
}

// File enforcement still works alongside a network policy.
TEST_F(EnforceTest, NoNetworkStillAllowsReadingTool) {
    EXPECT_EQ(kOk, RunProbe({L"-n"}, {L"read", ProbePath()}));
}

}  // namespace
}  // namespace bsx
