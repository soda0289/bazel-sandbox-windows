// Builds the binary FileAccessManifest payload consumed by the vendored
// DetoursServices DLL (ParseFileAccessManifest in DetoursHelpers.cpp). This is a
// native reimplementation of the byte layout produced by BuildXL's C#
// FileAccessManifest.GetPayloadBytes, restricted to the subset that the
// BazelSandbox uses. See plan.md for the full format spec.
//
// IMPORTANT: This must be built in a RELEASE configuration (NDEBUG). The manifest
// format only emits the 0xABCDEF.. / 0xF00DCAFE "checked code" tag words in DEBUG
// builds, and the DLL only reads them in _DEBUG builds. Both the builder and the
// DLL must agree; we standardize on RELEASE (no tag words).

#pragma once

#include <windows.h>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace bazelsandbox {

// FileAccessPolicy bits (CODESYNC: DataTypes.h / FileAccessPolicy.cs).
enum FileAccessPolicy : uint32_t {
    Policy_Deny = 0x0,
    Policy_AllowRead = 0x1,
    Policy_AllowWrite = 0x2,
    Policy_AllowReadIfNonExistent = 0x4,
    Policy_AllowCreateDirectory = 0x8,
    Policy_AllowSymlinkCreation = 0x100,
    // Matches C# FileAccessPolicy.AllowAll (includes symlink creation).
    Policy_AllowAll = Policy_AllowRead | Policy_AllowReadIfNonExistent |
                      Policy_AllowWrite | Policy_AllowCreateDirectory |
                      Policy_AllowSymlinkCreation,
    // Mask semantics: (parentPolicy & Mask) | Values.
    Policy_MaskAll = 0x0,       // mask away all inherited bits
    Policy_MaskNothing = 0xFFFF, // keep all inherited bits
};

// FileAccessManifestFlag bits (CODESYNC: FileAccessManifest.cs).
enum FileAccessManifestFlag : uint32_t {
    Flag_None = 0x0,
    Flag_BreakOnAccessDenied = 0x1,
    Flag_FailUnexpectedFileAccesses = 0x2,
    Flag_ReportFileAccesses = 0x8,
    Flag_ReportUnexpectedFileAccesses = 0x10,
    Flag_MonitorNtCreateFile = 0x20,
    Flag_MonitorChildProcesses = 0x40,
    Flag_MonitorZwCreateOpenQueryFile = 0x800000,
    // Enforce policy on paths exactly as requested by the process instead of
    // resolving reparse points (junctions/symlinks) to their real targets.
    // Bazel builds an execroot full of junctions (external/ -> repo cache) and
    // declares the junction paths as inputs; resolving them would enforce on
    // out-of-execroot targets that were never declared, denying valid reads.
    Flag_IgnoreReparsePoints = 0x400,
    Flag_IgnoreFullReparsePointResolving = 0x40000000,
};

// Builds the FileAccessManifest blob for a single sandboxed process.
class ManifestBuilder {
public:
    ManifestBuilder(uint32_t flags,
                    uint32_t extraFlags,
                    std::string dllX86Ansi,
                    std::string dllX64Ansi);

    // Applies the given scope policy to the whole file system (the tree root).
    // mask/values follow (parentPolicy & mask) | values semantics.
    void AddRootScope(uint32_t mask, uint32_t values);

    // Applies a cone scope policy at the given absolute path (and its subtree).
    // The path is canonicalized with GetFullPathNameW to match the DLL's runtime
    // canonicalization, then split into fragments the same way the DLL does.
    // Returns false if the path cannot be canonicalized.
    bool AddScope(const std::wstring& path, uint32_t mask, uint32_t values);

    // Finalizes policies and serializes the whole payload.
    std::vector<uint8_t> Build(uint32_t injectionTimeoutMins);

private:
    struct Node {
        // Normalized (upper-cased) path fragment; empty for the root node.
        std::wstring normalizedFragment;
        uint32_t hash = 0;

        // Scope accumulators (see ApplyConeScope). Defaults: MaskNothing/Deny.
        uint32_t coneMask = Policy_MaskNothing;
        uint32_t coneValues = Policy_Deny;
        uint32_t nodeMask = Policy_MaskNothing;
        uint32_t nodeValues = Policy_Deny;

        // Finalized policies (computed in Finalize).
        uint32_t conePolicy = 0;
        uint32_t nodePolicy = 0;

        // Children keyed by normalized fragment.
        std::map<std::wstring, std::unique_ptr<Node>> children;
    };

    Node* AddPathFragments(const std::wstring& canonicalPath);
    void Finalize(Node* node, uint32_t parentPolicy);
    void SerializeNode(const Node* node, std::vector<uint8_t>& out) const;

    uint32_t flags_;
    uint32_t extraFlags_;
    std::string dllX86_;
    std::string dllX64_;
    Node root_;
};

}  // namespace bazelsandbox

namespace bazelsandbox {
namespace testing {
// Test-only accessor for the internal path-fragment hash/normalizer used by the
// serializer. Exposed so unit tests can pin the FNV-1 algorithm (a mismatch
// against the DLL's NormalizeAndHashPath is a real bug class we have hit).
uint32_t HashFragment(const std::wstring& fragment, std::wstring& normalizedOut);
}  // namespace testing
}  // namespace bazelsandbox
