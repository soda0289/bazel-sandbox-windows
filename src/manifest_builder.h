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
    // (parentPolicy-derived) writes are permitted only when the target file does
    // NOT already exist. Enforced in the DLL's PolicyResult::AllowWrite (per-process
    // "files I created" tracking): new files can be created/re-written, pre-existing
    // undeclared files cannot be clobbered. Used by the execroot-writable mode.
    // CODESYNC: FileAccessPolicy_OverrideAllowWriteForExistingFiles in DataTypes.h.
    Policy_OverrideAllowWriteForExistingFiles = 0x400,
    // Matches C# FileAccessPolicy.AllowAll (includes symlink creation).
    Policy_AllowAll = Policy_AllowRead | Policy_AllowReadIfNonExistent |
                      Policy_AllowWrite | Policy_AllowCreateDirectory |
                      Policy_AllowSymlinkCreation,
    // Marker (inert for enforcement) tagging an EXPLICITLY declared input/output grant
    // (-r/-w/-d/tool) so the DLL's handle-resolution read fallback can distinguish a
    // symlink target that is a real declared input from one merely readable via the
    // blanket root scope. <= Policy_MaskNothing so it propagates to cone descendants.
    // CODESYNC: FileAccessPolicy_DeclaredInput in DataTypes.h.
    Policy_DeclaredInput = 0x2000,
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

// FileAccessManifestExtraFlag bits (the manifest's second flag word; parsed into
// g_fileAccessManifestExtraFlags by the DLL). The values below marked "Bazel"
// are fork-specific extensions not present in BuildXL's C# enum. CODESYNC:
// FOR_ALL_FAM_EXTRA_FLAGS in vendor/detours-services/DataTypes.h.
enum FileAccessManifestExtraFlag : uint32_t {
    ExtraFlag_None = 0x0,
    // Report a denied READ of an existing-but-undeclared path as NOT_FOUND
    // instead of ACCESS_DENIED (linux-sandbox parity). Writes are unaffected.
    ExtraFlag_DeniedReadsAsNotFound = 0x400,
    // Remove undeclared (non-read-allowed) children from directory enumerations.
    ExtraFlag_FilterDirectoryEnumeration = 0x800,
    // Model W write-overlay (experimental kill-switch). Enables enumeration
    // INSERTION of process-private overlay files. Off by default; the shipped
    // subtractive path is unchanged. See docs/design/detours-write-overlay-vfs.md.
    ExtraFlag_WriteOverlay = 0x1000,
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

    // Enables file-access reporting. When set, the serialized manifest carries a
    // report block naming this file; the injected DLL opens it (OPEN_ALWAYS,
    // append) and writes a BuildXL-format report line for every intercepted
    // access. An empty path (the default) emits a size-0 report block, i.e. no
    // reporting (pure enforcement). CODESYNC: ManifestReport in DataTypes.h; the
    // caller must also set Flag_ReportFileAccesses / Flag_ReportUnexpectedFileAccesses
    // for lines to actually be emitted.
    void SetReportPath(std::wstring reportPath);

    // Sets the name of the launcher-created shared-memory region that backs the
    // cross-process "files created by this tree" set (execroot-writable mode).
    // The name is serialized into the manifest payload (a padded WCHAR block
    // right before the manifest tree) so it reaches every child through the
    // payload rather than the environment. An empty name (the default) emits a
    // size-0 block (no created-files tracking). CODESYNC: g_bazelCreatedShmName /
    // ParseFileAccessManifest in the DLL.
    void SetCreatedShmName(std::wstring name);

    // Sets the Model W write-overlay backing-store root (absolute path). Serialized
    // into the manifest payload as a padded WCHAR block right after the created-shm
    // block (and before the manifest tree), so it reaches every child through the
    // re-copied payload rather than the environment. An empty path (the default)
    // emits a size-0 block (no overlay). CODESYNC: g_bazelWriteOverlayRoot /
    // ParseFileAccessManifest in the DLL.
    void SetWriteOverlayRoot(std::wstring root);

    // Sets the Model W write-overlay SOURCE root (absolute path): the real
    // directory subtree whose undeclared writes are redirected into the backing
    // store. The DLL strips this prefix from a virtual path to compute the backing
    // path. Serialized as a padded WCHAR block right after the backing-root block
    // (and before the manifest tree). An empty path (the default) emits a size-0
    // block. CODESYNC: g_bazelOverlaySourceRoot / ParseFileAccessManifest in the DLL.
    void SetOverlaySourceRoot(std::wstring root);

    // Applies a cone scope policy at the given absolute path (and its subtree).
    // The path is canonicalized with GetFullPathNameW to match the DLL's runtime
    // canonicalization, then split into fragments the same way the DLL does.
    // Returns false if the path cannot be canonicalized.
    bool AddScope(const std::wstring& path, uint32_t mask, uint32_t values);

    // Applies a NODE-only scope policy at the given absolute path: it affects the
    // policy the DLL enforces for that EXACT path (its NodePolicy) without changing
    // the cone policy inherited by the subtree. The DLL uses the node policy on an
    // exact-path match and the nearest ancestor's cone policy for anything deeper
    // (PolicyResult_common.cpp). This lets us reveal + allow create/write on a
    // single directory (e.g. a declared output's parent dir) while keeping its
    // subtree Deny, so undeclared children inside it stay hidden and unwritable -
    // exactly what an output-dir grant needs. mask/values follow
    // (conePolicy & mask) | values semantics for the node. Returns false if the
    // path cannot be canonicalized.
    bool AddNodeScope(const std::wstring& path, uint32_t mask, uint32_t values);

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
    std::wstring reportPath_;
    std::wstring createdShmName_;
    std::wstring writeOverlayRoot_;
    std::wstring overlaySourceRoot_;
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
