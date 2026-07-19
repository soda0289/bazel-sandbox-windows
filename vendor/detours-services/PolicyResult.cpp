// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "PolicyResult.h"
#include "DetoursHelpers.h"
#include "SendReport.h"
#include "FilesCheckedForAccess.h"

#include "UtilityHelpers.h"
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
    // Cross-process set of file/dir paths CREATED by the sandboxed process tree
    // during this run (a path first written/created when it did not already exist).
    // Used by AllowWrite / read-back / enumeration under FileAccessPolicy_Override
    // AllowWriteForExistingFiles (the Bazel windows-sandbox "execroot-writable" mode)
    // so that, matching linux-sandbox's shared writable execroot:
    //   * writing a brand-new file (fresh scratch / undeclared output) is allowed,
    //   * any process in the tree may RE-write / read back / delete a path the tree
    //     created, while
    //   * writing over a file that already existed before the tree touched it (an
    //     undeclared input / source file) is denied - preserving the no-clobber
    //     guarantee even though the whole execroot cone is nominally writable.
    //
    // The set is backed by a named shared-memory region the launcher creates per
    // invocation and every injected DLL - in the whole process tree - attaches to.
    // The region name is carried in the manifest payload (g_bazelCreatedShmName,
    // parsed in ParseFileAccessManifest) so it propagates to every child via the
    // payload that is re-copied verbatim on injection, independent of the child's
    // environment block. This is required because tools fork: e.g.
    // JavaBuilder creates _javac/*_tmp/native_headers in one process and cleans it up
    // in another; a per-process set would hide the first process's creations from the
    // second (empty class jars, "directory not empty" cleanup failures). The region
    // is per-launcher-invocation, so there is no leakage between concurrent actions.
    // Each process also keeps a local cache (mirrors the shared log, so lookups do not
    // rescan). When the region is absent (no --execroot-writable, or the standalone
    // enforcement tests), the tracker degrades to a purely per-process set.
    struct CreatedShmHeader {
        volatile long long usedBytes;  // bytes of records written into the data region
        long long capacity;            // usable data-region size in bytes
    };

    class CreatedFilesTracker {
    public:
        static CreatedFilesTracker& GetInstance() {
            static CreatedFilesTracker instance;
            return instance;
        }

        bool WasCreated(const std::wstring& path) {
            SyncFromShared();
            std::shared_lock<std::shared_mutex> lock(m_lock);
            return m_set.find(path) != m_set.end();
        }

        void MarkCreated(const std::wstring& path) {
            {
                std::unique_lock<std::shared_mutex> lock(m_lock);
                if (!m_set.insert(path).second) {
                    return;  // already recorded locally (and thus in shared, if any)
                }
            }
            AppendToShared(path);
        }

        // Return the immediate child component names of `dir` for every indexed path
        // strictly under `dir`. For C:\ws\pkg\a.txt and C:\ws\pkg\sub\b.txt with
        // dir==C:\ws\pkg this yields {"a.txt","sub"}. Matching is case-insensitive on
        // the "<dir>\" prefix; the returned component is the substring up to the next
        // separator. De-duplicated (case-insensitively).
        void ListChildren(const std::wstring& dir, std::vector<std::wstring>& out) {
            SyncFromShared();
            std::wstring prefix = dir;
            while (!prefix.empty() && (prefix.back() == L'\\' || prefix.back() == L'/')) {
                prefix.pop_back();
            }
            prefix.push_back(L'\\');
            const size_t prefixLen = prefix.size();
            std::unordered_set<std::wstring, CaseInsensitiveStringHasher, CaseInsensitiveStringComparer> seen;
            std::shared_lock<std::shared_mutex> lock(m_lock);
            for (const std::wstring& p : m_set) {
                if (p.size() <= prefixLen) {
                    continue;
                }
                if (_wcsnicmp(p.c_str(), prefix.c_str(), prefixLen) != 0) {
                    continue;
                }
                size_t sep = p.find_first_of(L"\\/", prefixLen);
                std::wstring comp = (sep == std::wstring::npos)
                    ? p.substr(prefixLen)
                    : p.substr(prefixLen, sep - prefixLen);
                if (comp.empty()) {
                    continue;
                }
                if (seen.insert(comp).second) {
                    out.push_back(comp);
                }
            }
        }

    private:
        CreatedFilesTracker() { InitShared(); }
        CreatedFilesTracker(const CreatedFilesTracker&) = delete;
        CreatedFilesTracker& operator=(const CreatedFilesTracker&) = delete;

        void InitShared() {
            const wchar_t* name = g_bazelCreatedShmName;
            if (name == nullptr || name[0] == L'\0') {
                return;  // no shared region -> per-process fallback
            }
            m_mutex = OpenMutexW(SYNCHRONIZE, FALSE, (std::wstring(name) + L".mtx").c_str());
            m_mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
            if (m_mapping == nullptr) {
                return;
            }
            m_view = static_cast<BYTE*>(MapViewOfFile(m_mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
            if (m_view == nullptr) {
                CloseHandle(m_mapping);
                m_mapping = nullptr;
            }
        }

        CreatedShmHeader* Header() const { return reinterpret_cast<CreatedShmHeader*>(m_view); }
        BYTE* Data() const { return m_view + sizeof(CreatedShmHeader); }

        // Pull any records appended by other processes since our last sync into the
        // local cache. Records are [uint32 nameBytes][wchar_t name...] padded to 4.
        void SyncFromShared() {
            if (m_view == nullptr) {
                return;
            }
            long long used = Header()->usedBytes;  // publish-after-write => safe to read
            if (m_localOffset >= used) {
                return;
            }
            std::vector<std::wstring> fresh;
            if (m_mutex != nullptr) WaitForSingleObject(m_mutex, INFINITE);
            used = Header()->usedBytes;
            BYTE* data = Data();
            while (m_localOffset + static_cast<long long>(sizeof(uint32_t)) <= used) {
                uint32_t nameBytes = *reinterpret_cast<uint32_t*>(data + m_localOffset);
                long long recEnd = m_localOffset + static_cast<long long>(sizeof(uint32_t)) + nameBytes;
                if (recEnd > used) {
                    break;  // partial record (should not happen under the mutex)
                }
                const wchar_t* chars =
                    reinterpret_cast<const wchar_t*>(data + m_localOffset + sizeof(uint32_t));
                fresh.emplace_back(chars, nameBytes / sizeof(wchar_t));
                long long rec = static_cast<long long>(sizeof(uint32_t)) + nameBytes;
                rec = (rec + 3) & ~3ll;  // 4-byte align next record
                m_localOffset += rec;
            }
            if (m_mutex != nullptr) ReleaseMutex(m_mutex);

            if (!fresh.empty()) {
                std::unique_lock<std::shared_mutex> lock(m_lock);
                for (auto& p : fresh) m_set.insert(std::move(p));
            }
        }

        // Append a path record to the shared region so other processes in the tree
        // observe it. No-op (per-process only) when there is no shared region.
        void AppendToShared(const std::wstring& path) {
            if (m_view == nullptr) {
                return;
            }
            uint32_t nameBytes = static_cast<uint32_t>(path.size() * sizeof(wchar_t));
            long long rec = static_cast<long long>(sizeof(uint32_t)) + nameBytes;
            rec = (rec + 3) & ~3ll;
            if (m_mutex != nullptr) WaitForSingleObject(m_mutex, INFINITE);
            CreatedShmHeader* h = Header();
            long long used = h->usedBytes;
            if (used + rec <= h->capacity) {
                BYTE* p = Data() + used;
                *reinterpret_cast<uint32_t*>(p) = nameBytes;
                memcpy(p + sizeof(uint32_t), path.data(), nameBytes);
                // Publish the record only after its bytes are fully written.
                h->usedBytes = used + rec;
            }
            if (m_mutex != nullptr) ReleaseMutex(m_mutex);
        }

        std::unordered_set<std::wstring, CaseInsensitiveStringHasher, CaseInsensitiveStringComparer> m_set;
        std::shared_mutex m_lock;
        HANDLE m_mapping = nullptr;
        HANDLE m_mutex = nullptr;
        BYTE* m_view = nullptr;
        long long m_localOffset = 0;  // bytes of the shared log already merged locally
    };
}

bool PolicyResult::Initialize(PCPathChar path)
{
    assert(m_isIndeterminate);
    assert(path);

    CanonicalizedPathType canonicalizedPath = CanonicalizedPath::Canonicalize(path);
    if (canonicalizedPath.IsNull()) {
        // This policy remains indeterminate.
        return false;
    }

    Initialize(canonicalizedPath);
    return true;
}

void PolicyResult::Initialize(CanonicalizedPathType const& canonicalizedPath)
{
    // Initializing from a canonicalized path without a cursor; use the global tree root as the start cursor, and the entire path (without the type prefix)
    // as the search 'suffix' (we aren't resuming a search - we are starting a new one).
    // For reporting it is important that we preserve the \\?\ or \??\ prefix; \\?\C: and C: are different!
    // The former refers to a device. The other is drive-relative (based on current directory of that drive).
    // But for evaluating special cases and traversing the manifest tree, we strip the prefix (the tree shouldn't have \\?\ in it for example).
    InitializeFromCursor(canonicalizedPath, g_manifestTreeRoot, nullptr);
}

void PolicyResult::InitializeFromCursor(CanonicalizedPathType const& canonicalizedPath, PolicySearchCursor const& policySearchCursor, PCPathChar const searchSuffix)
{
    assert(m_isIndeterminate);
    assert(m_canonicalizedPath.IsNull());
    assert(!canonicalizedPath.IsNull());

    // The path is already canonicalized; now we are committed to set a policy, which doesn't fail.
    // We will do so via special-case rules (no policy search or cursor) or via the policy tree (which is searched, producing a cursor).
    m_canonicalizedPath = canonicalizedPath;

    TranslateFilePath(std::wstring(canonicalizedPath.GetPathString()), m_translatedPath);
    wchar_t const* translatedSearchSuffix = searchSuffix != nullptr ? searchSuffix : GetTranslatedPathWithoutTypePrefix();
    size_t searchSuffixLength = wcslen(translatedSearchSuffix);

    PolicySearchCursor newCursor = FindFileAccessPolicyInTreeEx(policySearchCursor, translatedSearchSuffix, searchSuffixLength);
    Initialize(canonicalizedPath, newCursor);

    // Special-case rules (Windows staged-deletion, device/named-stream paths, code-coverage
    // artifacts, special tools) classify the FULL path - they call GetRootLength, inspect the
    // drive-letter prefix, match filename suffixes, etc. They must therefore be evaluated
    // against the full translated path, NOT the cursor-relative search suffix. When extending
    // a directory policy to a child (GetPolicyForSubpath), searchSuffix is only the child leaf
    // (e.g. "secret.txt"); feeding that leaf to the device-path detection misclassifies any
    // subpath of a Win32Nt (\\?\) or LocalDevice (\\.\) directory as a non-drive device and
    // wrongly grants AllowAll (leaking undeclared entries through the Bazel enumeration filter).
    wchar_t const* fullTranslatedPath = GetTranslatedPathWithoutTypePrefix();
    size_t fullTranslatedPathLength = wcslen(fullTranslatedPath);

    if (GetSpecialCaseRulesForWindows(fullTranslatedPath, fullTranslatedPathLength, /*out*/ m_policy)) 
    {
#if SUPER_VERBOSE
        Dbg(L"match (special case rules for Windows): %s - policySearchCursor: %x, searchSuffix: %s", canonicalizedPath.GetPathString(), policySearchCursor, searchSuffix);
#endif // SUPER_VERBOSE
    }
    else if (GetSpecialCaseRulesForCoverageAndSpecialDevices(fullTranslatedPath, fullTranslatedPathLength, canonicalizedPath.Type, /*out*/ m_policy)) {
#if SUPER_VERBOSE
        Dbg(L"match (special case rules for coverage and special devices): %s - policySearchCursor: %x, searchSuffix: %s", canonicalizedPath.GetPathString(), policySearchCursor, searchSuffix);
#endif // SUPER_VERBOSE
    }
    else if (GetSpecialCaseRulesForSpecialTools(fullTranslatedPath, fullTranslatedPathLength, /*out*/ m_policy))
    {
#if SUPER_VERBOSE
            Dbg(L"match (special case rules for special tools): %s - policySearchCursor: %x, searchSuffix: %s", canonicalizedPath.GetPathString(), policySearchCursor, searchSuffix);
#endif // SUPER_VERBOSE
    }
}

PolicyResult PolicyResult::GetPolicyForSubpath(wchar_t const* pathSuffix) const {
    assert(!m_isIndeterminate);
    assert(!m_canonicalizedPath.IsNull());

    size_t extensionStartIndex = 0;
    CanonicalizedPathType extendedPath = m_canonicalizedPath.Extend(pathSuffix, &extensionStartIndex);

    PolicyResult subpolicy;
    if (m_policySearchCursor.IsValid()) {
        subpolicy.InitializeFromCursor(extendedPath, m_policySearchCursor, &extendedPath.GetPathString()[extensionStartIndex]);
    }
    else {
        subpolicy.Initialize(extendedPath);
    }

    return subpolicy;
}

void PolicyResult::ReportIndeterminatePolicyAndSetLastError(FileOperationContext const& fileOperationContext) const
{
    assert(IsIndeterminate());

    WriteWarningOrErrorF(L"Could not determine policy for file path '%s'.",
        fileOperationContext.NoncanonicalPath);
    MaybeBreakOnAccessDenied();

    // We certainly are not allowing an access, and are not reporting due to an explicit ask of the calling engine.
    // This is a bit odd but really only relevant to this case, and presently just informs the 'explicit report' flag.
    // TODO: Could have a ReportFileAccess overload instead.
    AccessCheckResult fakeAccessCheck = AccessCheckResult(RequestedAccess::None, ResultAction::Deny, ReportLevel::Report);

    ReportFileAccess(
        fileOperationContext,
        FileAccessStatus::FileAccessStatus_CannotDeterminePolicy,
        *this,
        fakeAccessCheck,
        ERROR_SUCCESS,
        -1);
}

bool PolicyResult::AllowWrite(bool basedOnlyOnPolicy) const {

    bool isWriteAllowedByPolicy = (m_policy & FileAccessPolicy_AllowWrite) != 0;

    // When the scope requests that writes be overridden based on file existence
    // (the Bazel windows-sandbox "execroot-writable" mode - the execroot cone is
    // granted AllowWrite|OverrideAllowWriteForExistingFiles) we ENFORCE inline
    // instead of only reporting to managed code (BuildXL's original behavior):
    //   * a write to a path that did NOT exist at the first write is allowed
    //     (fresh scratch / undeclared output, like linux-sandbox's writable execroot),
    //   * a subsequent re-write of a path this process already created is allowed, and
    //   * a write over a pre-existing file this process did not create is DENIED,
    //     preserving the no-clobber guarantee for undeclared inputs / source files.
    // IndicateUntracked() is true only for AllowAll scopes (declared -w outputs); those
    // bypass this check and stay freely overwritable. basedOnlyOnPolicy callers (static
    // policy probes) also bypass it.
    if (!basedOnlyOnPolicy && !IndicateUntracked() && isWriteAllowedByPolicy && OverrideAllowWriteForExistingFiles()) {
        // Key the tracker on the type-prefix-stripped path (plain "C:\...") rather than the
        // raw canonicalized string. The same on-disk file reaches AllowWrite under different
        // path-type prefixes depending on which syscall produced the name: a create via
        // NtCreateFile carries "\??\C:\..." while a later delete/rename resolves the handle via
        // DetourGetFinalPathByHandle to "\\?\C:\...". Both are classified Win32Nt but keep their
        // (differing) 4-char prefix in GetPathString(), so keying on that string caused a file a
        // process had just created to miss the "created this run" lookup and be wrongly denied as
        // a clobber of a pre-existing file (e.g. zip/cygwin's create-temp-then-rename-over-output,
        // which failed to delete its own temp). GetTranslatedPathWithoutTypePrefix() normalizes
        // \??\, \\?\ and plain C:\ to the same key.
        const std::wstring path(GetTranslatedPathWithoutTypePrefix());
        CreatedFilesTracker& tracker = CreatedFilesTracker::GetInstance();

        // Backing store is the source of truth (design doc §6.3): if this action
        // already has a shadow of the path in its write-overlay backing store, it was
        // created/redirected by this run, so re-writes are allowed. This is consulted
        // BEFORE the SHM created-set (which is retained only as the legacy
        // --execroot-writable fallback until it is removed): under --write-overlay a
        // file's presence in the backing store, not an index entry, is what makes it
        // "created this run".
        if (OverlayBackingExists(path)) {
            return true;
        }

        if (tracker.WasCreated(path)) {
            // We already saw this path not exist and created it; allow re-writes.
            return true;
        }

        DWORD error = GetLastError();
        bool fileExists = ExistsAsFile(m_canonicalizedPath.GetPathString());
        SetLastError(error);

        if (fileExists) {
            // Pre-existing file that this process did not create.
            if (ShouldWriteOverlay()) {
                // Model W: the write will be REDIRECTED to a process-private overlay
                // backing store (see ResolveOverlayOpenPath in DetouredFunctions.cpp),
                // so the real pre-existing file is never mutated. Allow it and record
                // the path so reads redirect to the overlay copy and enumeration keeps
                // showing it. This is the structural A8 fix: an undeclared input can
                // be "written" without ever being clobbered on disk.
                tracker.MarkCreated(path);
                return true;
            }
            // Deny the write so an undeclared input / source file is never clobbered.
            return false;
        }

        // Brand-new path: allow, and remember it so the tool can re-write its own file.
        tracker.MarkCreated(path);
        return true;
    }

    return isWriteAllowedByPolicy;
}

bool PolicyResult::WasCreatedInThisProcess() const {
    const std::wstring path(GetTranslatedPathWithoutTypePrefix());
    // Backing store is the source of truth (design doc §6.3): a path shadowed in the
    // write-overlay backing store was created/redirected by this action, so it stays
    // visible to reads and enumeration (the IsEnumChildVisible / CheckReadAccess
    // carve-outs) even though its static policy denies undeclared reads. Checked
    // before the SHM created-set, which remains only as the legacy fallback.
    if (OverlayBackingExists(path)) {
        return true;
    }
    return CreatedFilesTracker::GetInstance().WasCreated(path);
}

void PolicyResult::MarkCreatedInThisProcess() const {
    CreatedFilesTracker::GetInstance().MarkCreated(
        std::wstring(GetTranslatedPathWithoutTypePrefix()));
}

#if _WIN32
void ListOverlayChildren(const std::wstring& dir, std::vector<std::wstring>& outNames) {
    CreatedFilesTracker::GetInstance().ListChildren(dir, outNames);
}
#endif // _WIN32