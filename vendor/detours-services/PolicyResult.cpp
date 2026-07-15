// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "PolicyResult.h"
#include "DetoursHelpers.h"
#include "SendReport.h"
#include "FilesCheckedForAccess.h"

#include "UtilityHelpers.h"
#include <shared_mutex>
#include <string>
#include <unordered_set>

namespace {
    // Per-process set of file paths that THIS process created via a write to a path
    // that did not exist at the time of its first write. Used by AllowWrite when the
    // scope carries FileAccessPolicy_OverrideAllowWriteForExistingFiles (the Bazel
    // windows-sandbox "execroot-writable" mode) so that:
    //   * writing a brand-new file (fresh scratch / undeclared output) is allowed, and
    //   * the tool may freely RE-write a file it just created, while
    //   * writing over a file that already existed before the process touched it (an
    //     undeclared input / source file) is denied - preserving the no-clobber
    //     guarantee even though the whole execroot cone is nominally writable.
    // Lifetime is the process; it is intentionally NOT shared with child processes.
    class CreatedFilesTracker {
    public:
        static CreatedFilesTracker& GetInstance() {
            static CreatedFilesTracker instance;
            return instance;
        }

        bool WasCreated(const std::wstring& path) {
            std::shared_lock<std::shared_mutex> lock(m_lock);
            return m_set.find(path) != m_set.end();
        }

        void MarkCreated(const std::wstring& path) {
            std::unique_lock<std::shared_mutex> lock(m_lock);
            m_set.insert(path);
        }

    private:
        CreatedFilesTracker() = default;
        CreatedFilesTracker(const CreatedFilesTracker&) = delete;
        CreatedFilesTracker& operator=(const CreatedFilesTracker&) = delete;

        std::unordered_set<std::wstring, CaseInsensitiveStringHasher, CaseInsensitiveStringComparer> m_set;
        std::shared_mutex m_lock;
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
        const std::wstring path(m_canonicalizedPath.GetPathString());
        CreatedFilesTracker& tracker = CreatedFilesTracker::GetInstance();

        if (tracker.WasCreated(path)) {
            // We already saw this path not exist and created it; allow re-writes.
            return true;
        }

        DWORD error = GetLastError();
        bool fileExists = ExistsAsFile(m_canonicalizedPath.GetPathString());
        SetLastError(error);

        if (fileExists) {
            // Pre-existing file that this process did not create: deny the write so an
            // undeclared input / source file is never clobbered.
            return false;
        }

        // Brand-new path: allow, and remember it so the tool can re-write its own file.
        tracker.MarkCreated(path);
        return true;
    }

    return isWriteAllowedByPolicy;
}

bool PolicyResult::WasCreatedInThisProcess() const {
    return CreatedFilesTracker::GetInstance().WasCreated(
        std::wstring(m_canonicalizedPath.GetPathString()));
}