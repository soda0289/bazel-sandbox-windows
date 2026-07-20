#include "manifest_builder.h"

#include <cassert>
#include <cwctype>

namespace bazelsandbox {
namespace {

// Bucket offset flags (CODESYNC: DataTypes.h FileAccessBucketOffsetFlag).
constexpr uint32_t kChainStart = 0x01;
constexpr uint32_t kChainContinuation = 0x02;

// Reimplements StringOperations.cpp's NormalizeAndHashPath exactly, so the path
// hash-tree the launcher serializes matches DetoursServices.dll's runtime
// lookups byte-for-byte. The DLL hashes each path fragment as 32-bit FNV-1 over
// its NormalizePathChar'd (Windows: towupper) UTF-16 code units, folding each
// code unit low byte first then high byte; it also stores the normalized
// (upper-cased) code units in the tree. We reproduce both here so the launcher
// depends only on Detours, not on any BuildXL code.
uint32_t NormalizeAndHashFragment(const std::wstring& fragment,
                                  std::wstring& normalizedOut) {
    constexpr uint32_t kFnv1Basis = 2166136261u;
    constexpr uint32_t kFnv1Prime = 16777619u;
    uint32_t hash = kFnv1Basis;
    normalizedOut.clear();
    normalizedOut.reserve(fragment.size());
    for (wchar_t ch : fragment) {
        wchar_t c = static_cast<wchar_t>(towupper(ch));
        normalizedOut.push_back(c);
        hash = (hash * kFnv1Prime) ^ static_cast<uint8_t>(c & 0xFF);
        hash = (hash * kFnv1Prime) ^ static_cast<uint8_t>((c >> 8) & 0xFF);
    }
    return hash;
}

bool IsSep(wchar_t c) { return c == L'\\' || c == L'/'; }

void PutU32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

void PutU64(std::vector<uint8_t>& out, uint64_t v) {
    PutU32(out, static_cast<uint32_t>(v & 0xFFFFFFFF));
    PutU32(out, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFF));
}

void PatchU32(std::vector<uint8_t>& out, size_t at, uint32_t v) {
    out[at + 0] = static_cast<uint8_t>(v & 0xFF);
    out[at + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[at + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[at + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// WriteChars: uint32 char-count, then each UTF-16 code unit (2 bytes LE).
// A null/empty string writes just the count 0.
void PutChars(std::vector<uint8_t>& out, const std::wstring* s) {
    uint32_t len = (s == nullptr) ? 0u : static_cast<uint32_t>(s->size());
    PutU32(out, len);
    for (uint32_t i = 0; i < len; i++) {
        wchar_t c = (*s)[i];
        out.push_back(static_cast<uint8_t>(c & 0xFF));
        out.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
    }
}

// PaddedByteString(ASCII): ((len+4) & ~3) bytes, NUL-filled + terminated,
// 4-byte aligned. Matches FileAccessManifest.cs PaddedByteString.
uint32_t PaddedAnsiLength(const std::string& s) {
    return static_cast<uint32_t>((s.size() + 4) & ~static_cast<size_t>(3));
}

void PutPaddedAnsi(std::vector<uint8_t>& out, const std::string& s) {
    uint32_t total = PaddedAnsiLength(s);
    for (size_t i = 0; i < total; i++) {
        out.push_back(i < s.size() ? static_cast<uint8_t>(s[i]) : 0);
    }
}

// Canonicalizes an absolute path the way the DLL does before tree traversal,
// and returns the string used for tree fragments (type prefix stripped).
bool CanonicalizeForTree(const std::wstring& path, std::wstring& out) {
    // Win32-NT style (\\?\ or \??\): text after the 4-char prefix is already an
    // absolute path; the tree does not contain the prefix.
    if (path.size() >= 4 && (path[0] == L'\\') &&
        (path[1] == L'\\' || path[1] == L'?') &&
        (path[2] == L'?' || path[2] == L'.') && path[3] == L'\\') {
        out = path.substr(4);
        return !out.empty();
    }

    wchar_t buf[MAX_PATH];
    DWORD n = GetFullPathNameW(path.c_str(), MAX_PATH, buf, nullptr);
    if (n == 0) {
        return false;
    }
    if (n < MAX_PATH) {
        out.assign(buf, n);
    } else {
        std::vector<wchar_t> big(n);
        DWORD n2 = GetFullPathNameW(path.c_str(), n, big.data(), nullptr);
        if (n2 == 0 || n2 >= n) {
            return false;
        }
        out.assign(big.data(), n2);
    }
    // Strip a local-device prefix (\\.\) for tree traversal; keep drive paths.
    if (out.size() >= 4 && out[0] == L'\\' && out[1] == L'\\' &&
        out[2] == L'.' && out[3] == L'\\') {
        out = out.substr(4);
    }
    return true;
}

}  // namespace

ManifestBuilder::ManifestBuilder(uint32_t flags,
                                 uint32_t extraFlags,
                                 std::string dllX86Ansi,
                                 std::string dllX64Ansi)
    : flags_(flags),
      extraFlags_(extraFlags),
      dllX86_(std::move(dllX86Ansi)),
      dllX64_(std::move(dllX64Ansi)) {}

void ManifestBuilder::SetReportPath(std::wstring reportPath) {
    reportPath_ = std::move(reportPath);
}

void ManifestBuilder::SetWriteOverlayRoot(std::wstring root) {
    writeOverlayRoot_ = std::move(root);
}

void ManifestBuilder::SetOverlaySourceRoot(std::wstring root) {
    overlaySourceRoot_ = std::move(root);
}

void ManifestBuilder::AddRootScope(uint32_t mask, uint32_t values) {
    // ApplyConeFileAccess on the root node.
    root_.coneMask = mask & root_.coneMask;
    root_.coneValues = values | root_.coneValues;
}

ManifestBuilder::Node* ManifestBuilder::AddPathFragments(
    const std::wstring& canonicalPath) {
    Node* node = &root_;
    size_t i = 0;
    const size_t len = canonicalPath.size();
    while (i < len) {
        // Skip leading separators (matches GetPartialPathAndRemainder).
        while (i < len && IsSep(canonicalPath[i])) {
            i++;
        }
        size_t start = i;
        while (i < len && !IsSep(canonicalPath[i])) {
            i++;
        }
        if (i == start) {
            break;  // trailing separators only
        }
        std::wstring fragment = canonicalPath.substr(start, i - start);

        // Normalize + hash exactly as DetoursServices.dll does at runtime.
        std::wstring normalized;
        DWORD hash = NormalizeAndHashFragment(fragment, normalized);

        auto it = node->children.find(normalized);
        if (it == node->children.end()) {
            auto child = std::make_unique<Node>();
            child->normalizedFragment = normalized;
            child->hash = hash;
            Node* raw = child.get();
            node->children.emplace(normalized, std::move(child));
            node = raw;
        } else {
            node = it->second.get();
        }
    }
    return node;
}

bool ManifestBuilder::AddScope(const std::wstring& path,
                               uint32_t mask,
                               uint32_t values) {
    std::wstring canonical;
    if (!CanonicalizeForTree(path, canonical)) {
        return false;
    }
    Node* leaf = AddPathFragments(canonical);
    // ApplyConeFileAccess on the leaf.
    leaf->coneMask = mask & leaf->coneMask;
    leaf->coneValues = values | leaf->coneValues;
    return true;
}

bool ManifestBuilder::AddNodeScope(const std::wstring& path,
                                   uint32_t mask,
                                   uint32_t values) {
    std::wstring canonical;
    if (!CanonicalizeForTree(path, canonical)) {
        return false;
    }
    Node* leaf = AddPathFragments(canonical);
    // ApplyNodeFileAccess on the leaf: touch only the node policy accumulators so
    // the cone policy (inherited by the subtree) is left untouched. Finalize()
    // computes nodePolicy = (conePolicy & nodeMask) | nodeValues.
    leaf->nodeMask = mask & leaf->nodeMask;
    leaf->nodeValues = values | leaf->nodeValues;
    return true;
}

void ManifestBuilder::Finalize(Node* node, uint32_t parentPolicy) {
    node->conePolicy = (parentPolicy & node->coneMask) | node->coneValues;
    node->nodePolicy = (node->conePolicy & node->nodeMask) | node->nodeValues;
    for (auto& kv : node->children) {
        Finalize(kv.second.get(), node->conePolicy);
    }
}

void ManifestBuilder::SerializeNode(const Node* node,
                                    std::vector<uint8_t>& out) const {
    const size_t nodeStart = out.size();

    PutU32(out, node->hash);
    PutU32(out, node->conePolicy);
    PutU32(out, node->nodePolicy);
    PutU32(out, 0);           // PathId (unused)
    PutU64(out, 0);           // ExpectedUsn (Lo,Hi)

    const uint32_t childCount = static_cast<uint32_t>(node->children.size());
    // bucketCount = childCount == 0 ? 0 : (uint)(childCount / 0.7)
    const uint32_t bucketCount =
        childCount == 0 ? 0u
                        : static_cast<uint32_t>(static_cast<double>(childCount) / 0.7);
    PutU32(out, bucketCount);

    const size_t offsetsPos = out.size();
    for (uint32_t i = 0; i < bucketCount; i++) {
        PutU32(out, 0);  // placeholder, patched below
    }

    // Fragment (normalized UTF-16 incl. terminating NUL, padded to 4 bytes).
    // The root has an empty fragment -> a single uint32 0 (invalid fragment).
    if (node->normalizedFragment.empty()) {
        PutU32(out, 0);
    } else {
        for (wchar_t c : node->normalizedFragment) {
            out.push_back(static_cast<uint8_t>(c & 0xFF));
            out.push_back(static_cast<uint8_t>((c >> 8) & 0xFF));
        }
        out.push_back(0);  // NUL terminator (2 bytes)
        out.push_back(0);
        while ((out.size() & 0x3) != 0) {
            out.push_back(0);
        }
    }

    if (bucketCount == 0) {
        return;
    }

    std::vector<uint32_t> offsets(bucketCount, 0);
    for (const auto& kv : node->children) {
        const Node* child = kv.second.get();
        uint32_t index = child->hash % bucketCount;
        if (offsets[index] != 0) {
            offsets[index] |= kChainStart;
            index = (index + 1) % bucketCount;
            while (offsets[index] != 0) {
                offsets[index] |= kChainContinuation;
                index = (index + 1) % bucketCount;
            }
        }
        const uint32_t childOffset = static_cast<uint32_t>(out.size() - nodeStart);
        assert((childOffset & (kChainStart | kChainContinuation)) == 0);
        offsets[index] = childOffset;
        SerializeNode(child, out);
    }

    for (uint32_t i = 0; i < bucketCount; i++) {
        PatchU32(out, offsetsPos + static_cast<size_t>(i) * 4, offsets[i]);
    }
}

std::vector<uint8_t> ManifestBuilder::Build(uint32_t injectionTimeoutMins) {
    Finalize(&root_, Policy_Deny);

    std::vector<uint8_t> out;

    // 1. DebugFlag: 0xDB600000 (DebugOff)
    PutU32(out, 0xDB600000u);
    // 2. InjectionTimeout (minutes)
    PutU32(out, injectionTimeoutMins);
    // 3. Breakaway child processes: count 0
    PutU32(out, 0);
    // 4. Translation paths: count 0
    PutU32(out, 0);
    // 5. Error dump location: WriteChars(null)
    PutChars(out, nullptr);
    // 6. Flags
    PutU32(out, flags_);
    // 7. Extra flags
    PutU32(out, extraFlags_);
    // 8. PipId (int64)
    PutU64(out, 0);
    // 9. Report block. Empty path => size 0 (no report block, pure enforcement).
    // Otherwise a report *path* block: Size = byte length of the field holding a
    // NUL-terminated WCHAR path, padded up to a 4-byte multiple. Padding matters:
    // every following block (and the whole manifest tree) must stay 4-aligned, or
    // serialized child offsets pick up low bits that the DLL reuses as bucket
    // chain flags (kChainStart/kChainContinuation) -> tree corruption. The padded
    // size is always even, so the DLL's IsReportHandle() low-bit test reads 0 and
    // it opens the path directly. CODESYNC: ManifestReport in DataTypes.h.
    if (reportPath_.empty()) {
        PutU32(out, 0);
    } else {
        const uint32_t rawBytes =
            static_cast<uint32_t>((reportPath_.size() + 1) * sizeof(wchar_t));
        const uint32_t paddedBytes = (rawBytes + 3u) & ~3u;
        PutU32(out, paddedBytes);
        const auto* pb = reinterpret_cast<const uint8_t*>(reportPath_.c_str());
        out.insert(out.end(), pb, pb + rawBytes);
        out.insert(out.end(), paddedBytes - rawBytes, 0u);
    }
    // 10. Dll block
    {
        uint32_t l0 = PaddedAnsiLength(dllX86_);
        uint32_t l1 = PaddedAnsiLength(dllX64_);
        PutU32(out, l0 + l1);  // total size
        PutU32(out, 2);        // dll count
        PutU32(out, 0);        // offset[0]
        PutU32(out, l0);       // offset[1]
        PutPaddedAnsi(out, dllX86_);
        PutPaddedAnsi(out, dllX64_);
    }
    // 11. Substitute process shim: ShimAllProcesses 0, WriteChars(null)
    PutU32(out, 0);
    PutChars(out, nullptr);
    // 11.5 Model W write-overlay backing-store root (Bazel fork). Padded WCHAR
    // block laid out exactly like the report block (block 9): a size word (padded
    // byte count of the NUL-terminated WCHAR path region) followed by the path +
    // padding, so the following manifest tree stays 4-byte aligned. Empty root =>
    // size 0 (no overlay). Carried in the payload rather than an environment
    // variable so it reaches every child robustly. CODESYNC:
    // g_bazelWriteOverlayRoot / ParseFileAccessManifest in the DLL.
    if (writeOverlayRoot_.empty()) {
        PutU32(out, 0);
    } else {
        const uint32_t rawBytes =
            static_cast<uint32_t>((writeOverlayRoot_.size() + 1) * sizeof(wchar_t));
        const uint32_t paddedBytes = (rawBytes + 3u) & ~3u;
        PutU32(out, paddedBytes);
        const auto* pb = reinterpret_cast<const uint8_t*>(writeOverlayRoot_.c_str());
        out.insert(out.end(), pb, pb + rawBytes);
        out.insert(out.end(), paddedBytes - rawBytes, 0u);
    }
    // 11.6 Model W write-overlay SOURCE root (Bazel fork). Same padded WCHAR block
    // layout as block 11.5, serialized right after it so the manifest tree stays
    // 4-byte aligned. Empty root => size 0 (no source root). CODESYNC:
    // g_bazelOverlaySourceRoot / ParseFileAccessManifest in the DLL.
    if (overlaySourceRoot_.empty()) {
        PutU32(out, 0);
    } else {
        const uint32_t rawBytes =
            static_cast<uint32_t>((overlaySourceRoot_.size() + 1) * sizeof(wchar_t));
        const uint32_t paddedBytes = (rawBytes + 3u) & ~3u;
        PutU32(out, paddedBytes);
        const auto* pb = reinterpret_cast<const uint8_t*>(overlaySourceRoot_.c_str());
        out.insert(out.end(), pb, pb + rawBytes);
        out.insert(out.end(), paddedBytes - rawBytes, 0u);
    }
    SerializeNode(&root_, out);

    return out;
}

namespace testing {
uint32_t HashFragment(const std::wstring& fragment, std::wstring& normalizedOut) {
    return NormalizeAndHashFragment(fragment, normalizedOut);
}
}  // namespace testing

}  // namespace bazelsandbox
