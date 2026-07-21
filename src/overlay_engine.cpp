// overlay_engine.cpp - Bazel write-overlay (Model W) redirect + input-filter helpers.
//
// Project-owned code. This is NOT part of the vendored Microsoft BuildXL
// DetoursServices engine under vendor/; it was extracted from the file-system hooks
// in vendor/detours-services/DetouredFunctions.cpp to keep project-authored logic
// out of the vendored translation unit and shrink the vendor patch. See
// docs/design/detours-write-overlay-vfs.md.
//
// Licensed under this repository's own terms (see README "License"). No Microsoft
// MIT grant applies to this file.

#include "stdafx.h"

#include "overlay_engine.h"

#include "DetouredScope.h"
#include "HandleOverlay.h"
#include "MetadataOverrides.h"
#include "DetoursHelpers.h"
#include "FileAccessHelpers.h"
#include "PolicyResult.h"
#include "globals.h"

// ---------------------------------------------------------------------------
// Model W write-overlay: write/read redirection to a process-private backing
// store (ShouldWriteOverlay()). Undeclared writes in the write-overlay redirect
// cone are redirected under g_bazelWriteOverlayRoot (mirroring the virtual path)
// so the real execroot is never mutated and each action's scratch is isolated.
// The backing copy's on-disk existence is the record: reads redirect to it and
// enumeration inserts it (ListBackingChildren). All policy/reporting still runs on
// the VIRTUAL path; only the path handed to the Real_ call is swapped. Everything
// here is gated by ShouldWriteOverlay().
// ---------------------------------------------------------------------------

// True if `pr` names an undeclared write target in the write-overlay redirect cone
// (OverrideAllowWriteForExistingFiles) that should be redirected. That bit is set
// ONLY on the execroot cone under --write-overlay; declared -w
// outputs and -d output dirs are granted with Policy_MaskAll (no inheritance) and
// without the override bit, so they are naturally excluded and land in the real
// execroot where Bazel harvests them in place. (Note: IndicateUntracked() is NOT a
// usable discriminator here - the cone's policy equals the DLL's AllowAll mask, so
// both the cone and declared -w outputs report untracked.)
bool ShouldRedirectToOverlay(const PolicyResult& pr)
{
    return ShouldWriteOverlay()
        && g_bazelWriteOverlayRoot != nullptr
        && g_bazelWriteOverlayRoot[0] != L'\0'
        && pr.OverrideAllowWriteForExistingFiles();
}

// Map a virtual (plain "X:\...") path to its backing-store path by stripping the
// overlay source root (g_bazelOverlaySourceRoot) and appending the remainder under
// the backing root, e.g. with source root C:\ws and backing \\?\<root>,
// C:\ws\a\b.txt -> \\?\<root>\a\b.txt. The \\?\ prefix keeps deep paths under the
// MAX_PATH ceiling. The source-root strip is case-insensitive and tolerant of a
// trailing separator on either side. If the source root is unset or the virtual
// path is not under it (should not happen: the redirect cone == the source root by
// construction), we fall back to a full drive-letter mirror (\\?\<root>\C\ws\...)
// as defensive insurance. Returns "" if the input is not a drive-letter path.
std::wstring OverlayBackingPath(const std::wstring& virtualPath)
{
    if (virtualPath.size() < 3 || virtualPath[1] != L':')
    {
        return std::wstring();
    }

    // Preferred path: strip the overlay source root prefix (case-insensitive).
    if (g_bazelOverlaySourceRoot != nullptr && g_bazelOverlaySourceRoot[0] != L'\0')
    {
        std::wstring src(g_bazelOverlaySourceRoot);
        while (!src.empty() && src.back() == L'\\') src.pop_back();  // trim trailing sep
        const size_t n = src.size();
        const bool prefixMatch =
            virtualPath.size() >= n &&
            _wcsnicmp(virtualPath.c_str(), src.c_str(), n) == 0 &&
            // Ensure a full path-segment boundary: either an exact match or the
            // next char in the virtual path is a separator (avoids C:\ws matching
            // C:\wsX). At the exact-match boundary the remainder is empty.
            (virtualPath.size() == n || virtualPath[n] == L'\\');
        if (prefixMatch)
        {
            std::wstring rest = virtualPath.substr(n);  // "\a\b.txt" or ""
            std::wstring backing = L"\\\\?\\";
            backing += g_bazelWriteOverlayRoot;
            if (!rest.empty() && rest.front() != L'\\') backing += L'\\';
            backing += rest;
            return backing;
        }
    }

    // Defensive fallback: full drive-letter mirror (\\?\<root>\<drive>\<rest>).
    std::wstring backing = L"\\\\?\\";
    backing += g_bazelWriteOverlayRoot;
    backing += L'\\';
    backing += virtualPath[0];          // drive letter (colon dropped)
    backing += virtualPath.substr(2);   // "\ws\scratch.txt"
    return backing;
}

// Create every ancestor directory of a backing FILE path (incremental prefixes).
// Nested Win32 calls pass through to the real API (DetouredScope disables nested
// Reverse of OverlayBackingPath: map a physical backing-store path back to the
// virtual (real cone) path it stands in for, so a tool that canonicalizes an
// overlay-redirected handle observes the LOGICAL execroot path, not the private
// backing location. Without this the JVM class loader (which canonicalizes each
// classpath entry via GetFinalPathNameByHandle and requires the resource's
// canonical path to stay under the classpath dir's canonical path) rejects every
// class read out of an overlay-redirected file - because the redirect copies the
// file up into the backing store and the handle's final path leaks as
// "\\?\<backingRoot>\...". Handles the primary source-root-strip mapping
// (backingRoot + rest -> sourceRoot + rest); returns false (no rewrite) for any
// path not under the backing root. `finalPath` may carry a \\?\ or \??\ prefix,
// which is preserved on the rewritten result. Kill-switched with the overlay.
bool ReverseOverlayFinalPath(const std::wstring& finalPath, std::wstring& out)
{
    if (!ShouldWriteOverlay()
        || g_bazelWriteOverlayRoot == nullptr || g_bazelWriteOverlayRoot[0] == L'\0'
        || g_bazelOverlaySourceRoot == nullptr || g_bazelOverlaySourceRoot[0] == L'\0')
    {
        return false;
    }

    std::wstring prefix;
    std::wstring body(finalPath);
    if (body.compare(0, 4, L"\\\\?\\") == 0) { prefix = L"\\\\?\\"; body.erase(0, 4); }
    else if (body.compare(0, 4, L"\\??\\") == 0) { prefix = L"\\??\\"; body.erase(0, 4); }

    std::wstring root(g_bazelWriteOverlayRoot);
    while (!root.empty() && root.back() == L'\\') root.pop_back();
    const size_t n = root.size();
    // The final path must be the backing root itself or a descendant of it, at a
    // full path-segment boundary (so <root> does not match <root>Suffix).
    if (body.size() < n || _wcsnicmp(body.c_str(), root.c_str(), n) != 0) return false;
    if (body.size() != n && body[n] != L'\\') return false;

    std::wstring src(g_bazelOverlaySourceRoot);
    while (!src.empty() && src.back() == L'\\') src.pop_back();
    out = prefix + src + body.substr(n);   // sourceRoot + "\rest" (or "" at exact match)
    return true;
}

// detours on this thread), so no policy is re-applied. Failures are benign
// (ERROR_ALREADY_EXISTS or a parent that a later step recreates).
void EnsureBackingParentDirs(const std::wstring& backingPath)
{
    size_t start = (backingPath.compare(0, 4, L"\\\\?\\") == 0) ? 4 : 0;
    for (size_t i = start; i < backingPath.size(); ++i)
    {
        if (backingPath[i] == L'\\')
        {
            std::wstring dir = backingPath.substr(0, i);
            if (dir.size() > start)
            {
                CreateDirectoryW(dir.c_str(), nullptr);
            }
        }
    }
}

bool OverlayPathExists(const std::wstring& p)
{
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// True if `p` exists and is a directory.
bool OverlayIsDirectory(const std::wstring& p)
{
    DWORD attrs = GetFileAttributesW(p.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// List the immediate child names present in this action's backing store under the
// virtual directory `virtualDir` (plain "X:\..." form). This is the Model W
// "backing store is the source of truth" enumeration source (see design doc
// §6.3): the overlay entries to splice into a directory listing are exactly the
// children of the mirrored backing subdirectory, obtained via one OS directory
// scan - O(children-in-this-dir) - rather than a walk of a whole-tree index. The
// backing subdirectory exists only once some
// path under it has been redirected (EnsureBackingParentDirs mirrors ancestors),
// so an absent backing dir simply contributes nothing. "." and ".."
// are skipped. Nested FindFirstFile/FindNextFile pass through to the real API
// (DetouredScope disables nested detours on this thread), so no policy is applied
// to the backing scan itself.
void ListBackingChildren(const std::wstring& virtualDir, std::vector<std::wstring>& out)
{
    const std::wstring backingDir = OverlayBackingPath(virtualDir);
    if (backingDir.empty() || !OverlayIsDirectory(backingDir))
    {
        return;
    }

    std::wstring pattern = backingDir;
    while (!pattern.empty() && (pattern.back() == L'\\' || pattern.back() == L'/'))
    {
        pattern.pop_back();
    }
    pattern += L"\\*";

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        return;
    }
    do
    {
        const wchar_t* nm = fd.cFileName;
        if (nm[0] == L'.' && (nm[1] == L'\0' || (nm[1] == L'.' && nm[2] == L'\0')))
        {
            continue; // skip "." and ".."
        }
        out.push_back(std::wstring(nm));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// Cross-TU (declared in PolicyResult.h): true if `virtualPathNoPrefix` (plain
// "X:\..." form) has a shadow in THIS action's Model W backing store. This is the
// "backing store is the source of truth" primitive (design doc §6.3): PolicyResult
// treats "exists in the backing store" as "created by this action this run", so the
// rewrite-vs-clobber decision (AllowWrite) and the enumeration/read visibility
// carve-out (HasOverlayBackingShadow) are answered from the filesystem. Because
// the backing store is shared by
// the whole action tree (per-invocation root in the manifest), this is inherently
// cross-process-consistent. Returns false whenever the overlay is inactive (no
// --write-overlay / no root). Callers are always inside an active DetouredScope,
// so the nested
// GetFileAttributesW passes through to the real API (no policy re-applied).
bool OverlayBackingExists(const std::wstring& virtualPathNoPrefix)
{
    if (!ShouldWriteOverlay() ||
        g_bazelWriteOverlayRoot == nullptr ||
        g_bazelWriteOverlayRoot[0] == L'\0')
    {
        return false;
    }
    const std::wstring backing = OverlayBackingPath(virtualPathNoPrefix);
    return !backing.empty() && OverlayPathExists(backing);
}

// True if an EXISTING real file at this policy's path is HIDDEN from the
// sandboxed process by the Bazel input filter (--filter-inputs): an undeclared
// input that the read/enumeration hooks make appear absent (denied reads masked
// to NOT_FOUND; undeclared children removed from listings).
//
// The predicate must be independent of the write-overlay backing store: by the
// time this runs the write pre-check (PolicyResult::AllowWrite) has already
// seeded a backing shadow for a pre-existing undeclared file under --write-overlay,
// so CheckReadAccess / HasOverlayBackingShadow would spuriously report it visible.
// Instead we consult only the STATIC manifest policy, mirroring the enumeration
// filter's visibility rule (IsEnumChildVisible): a path is visible iff its policy
// allows read (a declared input, or under a declared directory-input cone) or it
// is an exact ancestor node leading to a declared input. Everything else is an
// undeclared input the filter hides.
//
// Gated on ShouldDeniedReadsAsNotFound() (set only by --filter-inputs): without
// the filter the execroot cone grants blanket read, nothing is hidden, and this
// returns false - so CREATE_NEW keeps its plain fail-if-exists behavior.
bool OverlayRealFileHiddenByFilter(const PolicyResult& policyResult)
{
    if (!ShouldDeniedReadsAsNotFound())
    {
        return false;
    }
    return !(policyResult.AllowRead() || policyResult.IsExactManifestNode());
}

// Decide the path to hand to Real_CreateFileW for a Model W redirect, preparing
// the backing store as needed. Returns the backing path (to open instead of the
// virtual path) or "" to leave the open on the real virtual path.
//
//  * Write-intent open of a redirectable path: ensure backing dirs, copy-up the
//    real file first when the disposition preserves existing content, and return
//    the backing path (its on-disk existence is the record of the redirect).
//  * Read-intent open of a path whose backing already exists (this action wrote
//    it): return the backing path so the read sees the overlay copy.
//  * Otherwise: return "" (open the real path unchanged).
std::wstring ResolveOverlayOpenPath(
    const PolicyResult& policyResult,
    DWORD dwDesiredAccess,
    DWORD dwCreationDisposition)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }

    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return std::wstring();
    }

    // Directory-handle resolution. When the directory exists on the REAL disk we
    // must NOT redirect: enumeration (NtQueryDirectoryFile) has to list the REAL
    // directory so real entries are returned, and the overlay's own children are
    // spliced in separately by InsertOverlayEntries. Redirecting a real directory's
    // open to the backing store would enumerate ONLY the backing dir - dropping real
    // siblings AND double-listing the overlay files that insertion then re-adds.
    //
    // An OVERLAY-ONLY directory (present in the backing store but not on the real
    // disk - e.g. a scratch dir created via CreateDirectoryW, which Model W redirects
    // into the backing store) has no real directory to open, so we DO redirect its
    // handle to the backing directory. The OS then enumerates the backing children
    // directly; InsertOverlayEntries detects the absent real dir and adds nothing, so
    // there is no double-listing. Under --filter-inputs those backing children stay
    // visible via the HasOverlayBackingShadow (backing-existence) enumeration
    // carve-out. The backing dir exists as soon as any file under it is written
    // (EnsureBackingParentDirs), so the real-dir-first ordering here is load-bearing.
    const std::wstring realWidePath = L"\\\\?\\" + virtualPath;
    if (OverlayIsDirectory(realWidePath))
    {
        return std::wstring();
    }
    if (OverlayIsDirectory(backing))
    {
        return backing;
    }

    const bool wantsWrite = WantsWriteAccess(dwDesiredAccess);
    const bool backingExists = OverlayPathExists(backing);

    if (wantsWrite)
    {
        // CREATE_NEW must fail if the file already exists in the MERGED view (real
        // execroot OR this action's overlay) AND that existing file is VISIBLE to
        // the tool. When we have no backing copy yet but the real undeclared file
        // exists and is visible, redirecting to the (absent) backing path would let
        // CREATE_NEW wrongly succeed against an empty backing file. Leave the open
        // on the real path: CREATE_NEW does not open or mutate an existing file, so
        // the OS fails it with ERROR_FILE_EXISTS - the correct merged-view result -
        // without touching the real bytes.
        //
        // Exception (linux-sandbox parity): under --filter-inputs an undeclared
        // pre-existing file is HIDDEN (its reads are masked to NOT_FOUND), so the
        // merged view treats it as ABSENT. CREATE_NEW must then SUCCEED into the
        // backing store, matching linux-sandbox whose throwaway execroot never
        // contains the undeclared file. In that case we fall through to
        // create-in-backing below (the real bytes remain untouched). Without
        // --filter-inputs the file is visible, so we keep the fail-if-exists
        // behavior above.
        //
        // (If the backing copy already exists, we fall through and redirect; Real
        // CREATE_NEW then fails against the existing backing file, which is likewise
        // correct. If neither exists, we create the new file in the backing store.)
        if (dwCreationDisposition == CREATE_NEW && !backingExists)
        {
            const std::wstring realWideNew = L"\\\\?\\" + virtualPath;
            if (OverlayPathExists(realWideNew) && !OverlayRealFileHiddenByFilter(policyResult))
            {
                return std::wstring();
            }
        }

        EnsureBackingParentDirs(backing);

        // Copy-up: if we have not captured this path yet and the real file exists
        // and the disposition keeps existing content, seed the backing copy so the
        // tool observes the current bytes (open-to-modify). TRUNCATE/CREATE_ALWAYS
        // discard content, and CREATE_NEW starts empty, so no copy is needed there.
        if (!backingExists &&
            dwCreationDisposition != CREATE_ALWAYS &&
            dwCreationDisposition != TRUNCATE_EXISTING &&
            dwCreationDisposition != CREATE_NEW)
        {
            const std::wstring realWide = L"\\\\?\\" + virtualPath;
            if (OverlayPathExists(realWide.c_str()))
            {
                CopyFileW(realWide.c_str(), backing.c_str(), TRUE /*failIfExists*/);
            }
        }

        // The backing copy now exists on disk; reads redirect to it (OverlayBackingExists)
        // and enumeration splices it in (ListBackingChildren).
        return backing;
    }

    // Read-intent: only redirect when this action already has a backing copy.
    if (backingExists)
    {
        return backing;
    }
    return std::wstring();
}

// See overlay_engine.h.
std::wstring ResolveOverlayWorkingDirectory(const wchar_t* workingDirectory)
{
    if (!ShouldWriteOverlay() || workingDirectory == nullptr || workingDirectory[0] == L'\0')
    {
        return std::wstring();
    }

    PolicyResult policy;
    if (!policy.Initialize(workingDirectory))
    {
        return std::wstring();
    }

    // A process-private overlay scratch directory (one this action created, redirected
    // into the backing store) has no counterpart on the real execroot, so CreateProcess
    // cannot set it as the child's current directory - the launch fails with
    // ERROR_DIRECTORY (267). Resolve it to the concrete backing directory so the child
    // starts with a real cwd. ResolveOverlayOpenPath returns "" when the directory
    // exists on the real disk (no redirect needed) or lies outside the overlay cone.
    return ResolveOverlayOpenPath(policy, GENERIC_READ, OPEN_EXISTING);
}

// Model W (write-overlay) delete/rename-source resolution. Decides how removing
// policyResult's path must be handled so the real execroot is NEVER mutated. See
// docs/design/detours-write-overlay-vfs.md §6.3.1 (backing-store-as-truth, no
// whiteout markers). On RedirectToBacking, backingOut receives the backing-store
// path the unlink/move must operate on instead of the real path.
// (OverlayDeleteAction is declared in overlay_engine.h.)
OverlayDeleteAction ResolveOverlayDelete(PolicyResult& policyResult, std::wstring& backingOut)
{
    backingOut.clear();
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return OverlayDeleteAction::PassThrough;
    }

    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return OverlayDeleteAction::PassThrough;
    }

    const std::wstring realWide = L"\\\\?\\" + virtualPath;
    const bool backingExists = OverlayPathExists(backing.c_str());
    const bool realExists = OverlayPathExists(realWide.c_str());
    const bool hiddenByFilter = OverlayRealFileHiddenByFilter(policyResult);

    if (backingExists)
    {
        // Written-over lower file with the real original still visible (permissive
        // mode): removing the backing copy would re-expose the real bytes, which we
        // cannot hide without mutating the real execroot. Deny.
        if (realExists && !hiddenByFilter)
        {
            return OverlayDeleteAction::DenyAccess;
        }
        // Backing-only file, or written-over lower whose real original stays hidden
        // by the input filter: remove the backing copy. The tool's merged view then
        // shows the path as gone.
        backingOut = std::move(backing);
        return OverlayDeleteAction::RedirectToBacking;
    }

    // No backing copy exists.
    if (realExists)
    {
        // Pre-existing lower-only file: the real bytes are read-only and must never be
        // deleted. Under the input filter the file is hidden, so the merged view has no
        // such entry -> NOT_FOUND no-op. In permissive mode it is a visible undeclared
        // input -> deny the clobber.
        return hiddenByFilter ? OverlayDeleteAction::NotFound : OverlayDeleteAction::DenyAccess;
    }

    // Neither backing nor real exists: nothing to redirect; let the real call return
    // NOT_FOUND on its own.
    return OverlayDeleteAction::PassThrough;
}

// Model W rename destination resolution. The move's destination half mirrors the
// filter-aware CREATE_NEW of §5.6.2: when policyResult is inside the write-overlay
// redirect cone, the moved file must land in the backing store (creating parent
// dirs), never the real execroot. Returns the backing dest path, or "" to pass the
// destination through to the real path unchanged (e.g. a declared -w output).
std::wstring ResolveOverlayRenameDest(PolicyResult& policyResult)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }
    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty())
    {
        return std::wstring();
    }
    EnsureBackingParentDirs(backing);
    return backing;
}

// Model W (write-overlay) probe/metadata resolution. For a read-only metadata query
// (GetFileAttributes(Ex), GetFileInformationByName, exact FindFirstFile) of a path that
// has a backing copy, return the backing path so the query observes the scratch file
// the action wrote - so stat of a file the process created in the overlay works. Returns
// "" to probe the real path unchanged. Mirrors the read-intent branch of
// ResolveOverlayOpenPath (redirect only when a backing copy already exists).
std::wstring ResolveOverlayProbePath(PolicyResult& policyResult)
{
    if (!ShouldRedirectToOverlay(policyResult))
    {
        return std::wstring();
    }
    const std::wstring virtualPath(policyResult.GetTranslatedPathWithoutTypePrefix());
    std::wstring backing = OverlayBackingPath(virtualPath);
    if (backing.empty() || !OverlayPathExists(backing.c_str()))
    {
        return std::wstring();
    }
    return backing;
}

// ---------------------------------------------------------------------------
// Directory-enumeration input filtering + write-overlay enumeration splice.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Bazel directory-enumeration input filtering (see docs/design/detours-input-filtering.md).
//
// When ShouldFilterDirectoryEnumeration() is set, directory listings hide
// entries that are not declared inputs so that undeclared files are invisible to
// the sandboxed process, matching linux-sandbox / processwrapper-sandbox (which
// enumerate a constructed symlink forest rather than the real execroot).
//
// An entry is visible iff:
//   - it is "." or ".." (always kept), or
//   - its resolved policy allows read (a declared input, or anything under a
//     declared directory-input cone), or
//   - it is an exact node in the manifest policy tree, i.e. an ancestor
//     directory that leads to a declared input. Such directories carry an
//     inherited Deny policy but must remain visible so the input can be reached.
// ---------------------------------------------------------------------------


bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name, size_t nameChars)
{
    // Always keep the "." and ".." pseudo-entries.
    if ((nameChars == 1 && name[0] == L'.') ||
        (nameChars == 2 && name[0] == L'.' && name[1] == L'.'))
    {
        return true;
    }

    std::wstring childName(name, nameChars);
    PolicyResult childPolicy = directoryPolicyResult.GetPolicyForSubpath(childName.c_str());

    // Be conservative: if we somehow can't determine a policy, don't hide.
    if (childPolicy.IsIndeterminate())
    {
        return true;
    }

    return childPolicy.AllowRead() || childPolicy.IsExactManifestNode()
#if _WIN32
        // Reveal entries this process created in a write-overlay scratch scope
        // (OverrideAllowWriteForExistingFiles), matching linux-sandbox's readable+
        // writable throwaway execroot. Without this a tool cannot see (jar, clean,
        // or re-open) the outputs it just wrote under an undeclared scratch subtree:
        // e.g. JavaBuilder writes .class files into _javac/<lib>_classes then walks
        // that tree to build the class jar and to clean it up - if the enumeration
        // hides the process's own files the jar comes out empty and the recursive
        // delete leaves a non-empty directory (RemoveDirectory -> ACCESS_DENIED).
        // Undeclared PRE-EXISTING inputs are not created by this process and stay
        // hidden, preserving hermeticity. Mirrors the CheckReadAccess carve-out.
        || (childPolicy.OverrideAllowWriteForExistingFiles() && childPolicy.HasOverlayBackingShadow())
#endif
        ;
}

// Convenience overload for null-terminated Win32 names (WIN32_FIND_DATAW.cFileName).
bool IsEnumChildVisible(const PolicyResult& directoryPolicyResult, const wchar_t* name)
{
    return IsEnumChildVisible(directoryPolicyResult, name, wcslen(name));
}

// Returns the byte offsets of the FileNameLength field and the FileName field
// within a FILE_*_INFORMATION record for the given NtQueryDirectoryFile info
// class. Returns false for classes we do not know how to filter (the caller must
// then leave the buffer untouched). Offsets assume the natural x64 layout of the
// documented structures.
static bool TryGetDirInfoLayout(ULONG infoClass, ULONG& fileNameLengthOffset, ULONG& fileNameOffset)
{
    switch (infoClass)
    {
    case 1:  fileNameLengthOffset = 60; fileNameOffset = 64;  return true; // FileDirectoryInformation
    case 2:  fileNameLengthOffset = 60; fileNameOffset = 68;  return true; // FileFullDirectoryInformation
    case 3:  fileNameLengthOffset = 60; fileNameOffset = 94;  return true; // FileBothDirectoryInformation
    case 12: fileNameLengthOffset = 8;  fileNameOffset = 12;  return true; // FileNamesInformation
    case 37: fileNameLengthOffset = 60; fileNameOffset = 104; return true; // FileIdBothDirectoryInformation
    case 38: fileNameLengthOffset = 60; fileNameOffset = 80;  return true; // FileIdFullDirectoryInformation
    default: return false;
    }
}

// Maps a GetFileInformationByHandleEx directory-enumeration info class to the
// equivalent NtQueryDirectoryFile info class understood by TryGetDirInfoLayout
// (the underlying FILE_*_DIR_INFO structures are byte-for-byte identical). Also
// returns the "continue" variant of the class to use when re-querying for the
// next batch (Restart variants would otherwise rewind and loop forever).
// Returns false for classes we do not know how to filter.
bool TryMapHandleDirInfoClass(
    FILE_INFO_BY_HANDLE_CLASS handleClass,
    ULONG& ntInfoClass,
    FILE_INFO_BY_HANDLE_CLASS& continueClass)
{
    switch ((int)handleClass)
    {
    case 10: // FileIdBothDirectoryInfo
    case 11: // FileIdBothDirectoryRestartInfo
        ntInfoClass = 37; continueClass = (FILE_INFO_BY_HANDLE_CLASS)10; return true;
    case 14: // FileFullDirectoryInfo
    case 15: // FileFullDirectoryRestartInfo
        ntInfoClass = 2;  continueClass = (FILE_INFO_BY_HANDLE_CLASS)14; return true;
    default:
        return false;
    }
}

// Filters a packed chain of FILE_*_INFORMATION records in-place, dropping entries
// whose names are not visible under directoryPolicyResult and re-linking the
// surviving records via NextEntryOffset. Surviving records stay at their original
// byte offsets; hidden records are simply left unreferenced. Returns the number of
// visible records kept, or SIZE_MAX if the info class is not one we know how to
// filter (in which case the buffer is left untouched).
//
// bufferLen is the number of valid bytes in `buffer` (the caller's buffer). The
// walk is bounded against it: a record whose fixed header would extend past the
// buffer stops the scan rather than over-reading, and a final record's name is
// clamped to what actually fits. This guards the case where an upstream re-query
// copies back only a truncated prefix of the OS-produced chain, leaving a record's
// NextEntryOffset pointing past the caller's buffer.
size_t FilterDirectoryInformation(
    PVOID buffer,
    ULONG infoClass,
    ULONG bufferLen,
    const PolicyResult& directoryPolicyResult)
{
    ULONG nameLenOff, nameOff;
    if (!TryGetDirInfoLayout(infoClass, nameLenOff, nameOff))
    {
        return SIZE_MAX;
    }

    // Minimum bytes we must be able to read at a record before touching its fixed
    // header: NextEntryOffset (4 bytes at 0), the name-length field, and the start
    // of the name at nameOff.
    ULONG headerMin = static_cast<ULONG>(sizeof(ULONG));
    if (nameLenOff + static_cast<ULONG>(sizeof(ULONG)) > headerMin) headerMin = nameLenOff + static_cast<ULONG>(sizeof(ULONG));
    if (nameOff > headerMin) headerMin = nameOff;

    BYTE* base = reinterpret_cast<BYTE*>(buffer);
    ULONG offset = 0;
    BYTE* lastKept = nullptr;
    size_t kept = 0;

    for (;;)
    {
        // Bound the fixed-header read against the caller's buffer. A malformed or
        // truncated chain that points past the buffer stops the walk here.
        if (offset > bufferLen || bufferLen - offset < headerMin)
        {
            break;
        }

        BYTE* rec = base + offset;
        ULONG next = *reinterpret_cast<ULONG*>(rec);
        ULONG nameLen = *reinterpret_cast<ULONG*>(rec + nameLenOff);
        const wchar_t* name = reinterpret_cast<const wchar_t*>(rec + nameOff);

        // Clamp the name to what actually fits so IsEnumChildVisible never
        // reads past the end of the buffer on a truncated final record.
        ULONG availNameBytes = bufferLen - offset - nameOff;
        if (nameLen > availNameBytes)
        {
            nameLen = availNameBytes;
        }
        size_t nameChars = nameLen / sizeof(wchar_t);

        if (IsEnumChildVisible(directoryPolicyResult, name, nameChars))
        {
            if (lastKept != nullptr)
            {
                *reinterpret_cast<ULONG*>(lastKept) = static_cast<ULONG>(rec - lastKept);
            }
            lastKept = rec;
            kept++;
        }

        if (next == 0)
        {
            break;
        }
        offset += next;
    }

    if (lastKept != nullptr)
    {
        *reinterpret_cast<ULONG*>(lastKept) = 0; // terminate the surviving chain
    }

    return kept;
}


// Applies the Bazel enumeration filter to the result of an Nt/Zw QueryDirectoryFile
// call, re-querying the underlying handle (continuing the scan) as needed so that
// we never hand back a batch that contains only hidden entries. Updates result /
// reportedError / lastError to reflect the filtered output. `buffer`/`bufferSize`
// is the (possibly larger) working buffer actually passed to the Real API;
// FileInformation/Length is the caller's buffer that ultimately receives the data.
void ApplyEnumerationFilterNt(
    QueryDirectoryFileFn realFn,
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult,
    NTSTATUS& result, DWORD& reportedError, DWORD& lastError)
{
    for (;;)
    {
        if (!NT_SUCCESS(result))
        {
            break;
        }

        size_t kept = FilterDirectoryInformation(FileInformation, (ULONG)FileInformationClass, Length, directoryPolicyResult);
        if (kept == SIZE_MAX || kept > 0)
        {
            // Either an info class we don't filter (leave as-is), or we kept at
            // least one visible entry.
            break;
        }

        // All entries in this batch were hidden. Continue the scan to fetch the
        // next batch and filter again, until we find a visible entry or run out.
        result = realFn(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            buffer, bufferSize, FileInformationClass, ReturnSingleEntry, FileName,
            FALSE /* RestartScan: continue from where we left off */);
        reportedError = RtlNtStatusToDosError(result);
        lastError = GetLastError();

        if (buffer != FileInformation && NT_SUCCESS(result))
        {
            memcpy_s(FileInformation, Length, buffer, Length);
        }
    }
}

// SL_* query flags for NtQueryDirectoryFileEx (from ntifs.h).
#ifndef SL_RESTART_SCAN
#define SL_RESTART_SCAN 0x00000001
#endif
#ifndef SL_RETURN_SINGLE_ENTRY
#define SL_RETURN_SINGLE_ENTRY 0x00000002
#endif


// Ex-form analogue of ApplyEnumerationFilterNt for NtQueryDirectoryFileEx,
// whose ReturnSingleEntry/RestartScan booleans are folded into a QueryFlags mask.
// Re-queries clear SL_RESTART_SCAN so the scan advances instead of restarting.
void ApplyEnumerationFilterNtEx(
    QueryDirectoryFileExFn realFn,
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass, ULONG QueryFlags,
    PUNICODE_STRING FileName,
    PVOID buffer, ULONG bufferSize,
    const PolicyResult& directoryPolicyResult,
    NTSTATUS& result, DWORD& reportedError, DWORD& lastError)
{
    for (;;)
    {
        if (!NT_SUCCESS(result))
        {
            break;
        }

        size_t kept = FilterDirectoryInformation(FileInformation, (ULONG)FileInformationClass, Length, directoryPolicyResult);
        if (kept == SIZE_MAX || kept > 0)
        {
            break;
        }

        ULONG continueFlags = QueryFlags & ~static_cast<ULONG>(SL_RESTART_SCAN);
        result = realFn(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            buffer, bufferSize, FileInformationClass, continueFlags, FileName);
        reportedError = RtlNtStatusToDosError(result);
        lastError = GetLastError();

        if (buffer != FileInformation && NT_SUCCESS(result))
        {
            memcpy_s(FileInformation, Length, buffer, Length);
        }
    }
}

// ---------------------------------------------------------------------------
// Model W write-overlay: enumeration INSERTION (experimental, ShouldWriteOverlay).
//
// The subtractive filter above removes undeclared children so a tool cannot see
// files it is not entitled to. The Model W write-overlay needs the opposite move
// on top of it: a file that a tool created but that was REDIRECTED off the real
// execroot into a process-private overlay must still APPEAR when the tool lists
// the directory it "wrote" the file into. Since that file is not present in the
// real directory the OS enumerated, its record has to be constructed and spliced
// into the returned FILE_*_INFORMATION chain.
//
// This is the counterpart to the subtractive filter and reuses the same layout
// table (TryGetDirInfoLayout). It is gated entirely behind ShouldWriteOverlay(),
// so with the flag off the shipped enumeration path is byte-for-byte unchanged.
//
// The names to insert are sourced from the real per-process backing store (see
// GetOverlayTestSyntheticNames / ListBackingChildren below). Remaining full-feature scope
// (tracked as mw-enum-classes): only the primary Detoured_NtQueryDirectoryFile
// call site is wired here - the Ex/Zw siblings, the Win32 FindFirstFile layer, and
// GetFileInformationByHandleEx are still filter-only.
// ---------------------------------------------------------------------------

// Supplemental TEST-ONLY source of names to inject into every enumerated directory.
// Parsed once from the BAZEL_SANDBOX_OVERLAY_TEST_NAMES environment variable (empty by
// default => contributes nothing). This is NOT part of the real feature: it lets
// the enforce suite exercise the record-construction / chain-relinking / emit-once
// mechanics in isolation, without first performing a redirected write. In normal
// operation the overlay entries come from the on-disk backing store (ListBackingChildren
// in InsertOverlayEntries); this env var is merely unioned in when present.
static const std::vector<std::wstring>& GetOverlayTestSyntheticNames()
{
    static const std::vector<std::wstring> names = []() {
        std::vector<std::wstring> v;
        wchar_t buf[2048];
        DWORD n = GetEnvironmentVariableW(L"BAZEL_SANDBOX_OVERLAY_TEST_NAMES", buf, ARRAYSIZE(buf));
        if (n > 0 && n < ARRAYSIZE(buf))
        {
            std::wstring s(buf, n);
            size_t start = 0;
            while (start <= s.size())
            {
                size_t sep = s.find(L';', start);
                size_t len = (sep == std::wstring::npos) ? std::wstring::npos : sep - start;
                std::wstring tok = s.substr(start, len);
                if (!tok.empty()) v.push_back(tok);
                if (sep == std::wstring::npos) break;
                start = sep + 1;
            }
        }
        return v;
    }();
    return names;
}

static inline ULONG AlignUp8(ULONG v) { return (v + 7u) & ~7u; }

// Wildcard match for a synthetic overlay entry name against the caller's
// enumeration expression (e.g. "*.txt"), using ntdll!RtlIsNameInExpression - the
// SAME matcher the filesystem itself applies to real entries. This gives exact NT
// semantics (case-insensitive, and native handling of the DOS wildcard
// metacharacters DOS_STAR '<', DOS_QM '>', DOS_DOT '"' that the I/O manager may
// substitute for '*'/'?'/'.'), so overlay entries are filtered identically to the
// real ones - unlike usvfs, which hand-converts '"'->'.' and runs its own glob.
// An empty or "*" expression matches everything (the common Bazel case).
typedef BOOLEAN (NTAPI* RtlIsNameInExpression_t)(PUNICODE_STRING, PUNICODE_STRING, BOOLEAN, PWCH);
typedef WCHAR (NTAPI* RtlUpcaseUnicodeChar_t)(WCHAR);

static bool OverlayNameMatchesFilter(const std::wstring& name, const std::wstring& expr)
{
    if (expr.empty() || expr == L"*" || expr == L"*.*")
    {
        return true;
    }

    static RtlIsNameInExpression_t s_pRtlIsNameInExpression = []() -> RtlIsNameInExpression_t {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlIsNameInExpression_t>(
                           GetProcAddress(ntdll, "RtlIsNameInExpression"))
                     : nullptr;
    }();
    static RtlUpcaseUnicodeChar_t s_pRtlUpcaseUnicodeChar = []() -> RtlUpcaseUnicodeChar_t {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlUpcaseUnicodeChar_t>(
                           GetProcAddress(ntdll, "RtlUpcaseUnicodeChar"))
                     : nullptr;
    }();

    if (s_pRtlIsNameInExpression == nullptr)
    {
        return true; // fail-open: can't match, so don't hide the entry.
    }

    // With IgnoreCase==TRUE and no UpcaseTable, RtlIsNameInExpression upcases the
    // Name itself but requires the Expression to ALREADY be uppercase. Upcase with
    // the SAME system table the matcher uses (ntdll!RtlUpcaseUnicodeChar) so non-ASCII
    // patterns fold identically; fall back to an ASCII-only fold if unavailable.
    std::wstring up = expr;
    for (wchar_t& c : up)
    {
        if (s_pRtlUpcaseUnicodeChar != nullptr)
        {
            c = s_pRtlUpcaseUnicodeChar(c);
        }
        else if (c >= L'a' && c <= L'z')
        {
            c = (wchar_t)(c - 32);
        }
    }

    UNICODE_STRING uExpr;
    uExpr.Buffer = const_cast<wchar_t*>(up.c_str());
    uExpr.Length = (USHORT)(up.size() * sizeof(wchar_t));
    uExpr.MaximumLength = (USHORT)((up.size() + 1) * sizeof(wchar_t));

    UNICODE_STRING uName;
    uName.Buffer = const_cast<wchar_t*>(name.c_str());
    uName.Length = (USHORT)(name.size() * sizeof(wchar_t));
    uName.MaximumLength = (USHORT)((name.size() + 1) * sizeof(wchar_t));

    return s_pRtlIsNameInExpression(&uExpr, &uName, TRUE, nullptr) != FALSE;
}

// Join a directory (plain "X:\..." form) and a child name with a single separator.
std::wstring JoinDirAndName(const std::wstring& dir, const std::wstring& name)
{
    std::wstring d = dir;
    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    return d + L'\\' + name;
}

// Build (once) this handle's point-in-time overlay entry snapshot for `enumDir`
// (plain "X:\..." form): the immediate backing-store children of enumDir that are
// ABSENT from the real directory, unioned with the test-only synthetic names, and
// sorted case-insensitively so the emit-once cursor indexes a STABLE ordering
// across the multi-call enumeration protocol. Captured exactly once per scan
// (OverlayEnumStarted gate) so a concurrent write by another process/thread in the
// action tree cannot re-order/resize this in-flight enumeration (which would make
// the cursor skip or duplicate an entry). Shared by every enumeration hook (NT
// packed-buffer + Win32 FindNextFile), so all APIs see the same overlay tail.
//
// The primary source is this action's BACKING STORE (design doc §6.3, "backing
// store is the source of truth"): the children of the mirrored backing subdirectory
// are exactly the files this process (or a peer in the tree, via the shared backing
// root) "wrote" that were redirected off the real execroot and are therefore absent
// from the real listing the OS just produced. This is one OS directory scan
// (O(children)), not an O(total-created) walk of a cross-process index.
void EnsureOverlayEnumSnapshot(const std::wstring& enumDir, HandleOverlayRef& overlay)
{
    if (overlay->OverlayEnumStarted)
    {
        return;
    }
    std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;
    names.clear();
    // Overlay-only directory: when the enumerated dir is ABSENT from the real disk,
    // the handle was redirected to (and the OS just enumerated) the backing dir
    // itself, so its children are already present in the OS result. Splicing them
    // would double-list every entry. Mirrors the InsertOverlayEntries guard for the
    // NT path; also covers the Win32 Find handle synthesized for an overlay-only
    // directory search. (The gap #2 synthesize path always enumerates a REAL dir, so
    // this guard never suppresses it.)
    if (!enumDir.empty() && !OverlayIsDirectory(L"\\\\?\\" + enumDir))
    {
        overlay->OverlayEnumStarted = true;
        return;
    }
    if (!enumDir.empty())
    {
        ListBackingChildren(enumDir, names);
    }
    for (const std::wstring& e : GetOverlayTestSyntheticNames())
    {
        bool dup = false;
        for (const std::wstring& n : names)
        {
            if (_wcsicmp(n.c_str(), e.c_str()) == 0) { dup = true; break; }
        }
        if (!dup) names.push_back(e);
    }
    // Drop any name that already exists on the real disk in this directory: the OS
    // enumeration returns it in some call, so inserting it would duplicate the entry.
    // (Copy-ups of pre-existing files land here.) Purely new overlay files remain.
    if (!enumDir.empty())
    {
        std::wstring base = enumDir;
        while (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
        std::vector<std::wstring> kept;
        kept.reserve(names.size());
        for (std::wstring& nm : names)
        {
            std::wstring full = base + L"\\" + nm;
            if (GetFileAttributesW(full.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                kept.push_back(std::move(nm));
            }
        }
        names.swap(kept);
    }
    std::sort(names.begin(), names.end(),
        [](const std::wstring& a, const std::wstring& b) { return _wcsicmp(a.c_str(), b.c_str()) < 0; });
    overlay->OverlayEnumStarted = true;
}

// Deterministic 64-bit id synthesized from a (case-insensitive) path, used to fill
// the FileId field of the *Id* directory-info classes so repeated enumerations of
// the same overlay entry return a STABLE id and distinct names get distinct ids.
// FNV-1a over the lower-cased UTF-16 code units; the top bit is cleared so the id
// stays positive and cannot collide with the "no id" sentinel some tools test for.
static LONGLONG SynthOverlayFileId(const std::wstring& path)
{
    unsigned long long h = 1469598103934665603ULL;
    for (wchar_t c : path)
    {
        wchar_t lc = (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
        h ^= (unsigned long long)(unsigned short)lc;
        h *= 1099511628211ULL;
    }
    return (LONGLONG)(h & 0x7fffffffffffffffULL);
}

// Populate the fixed-header metadata of a synthetic directory-info record from the
// backing file's real attributes/size/timestamps, so a tool that reads size, times,
// or FILE_ATTRIBUTE_DIRECTORY off an enumerated overlay entry sees correct values
// (critical for overlay-only SUBDIRECTORIES, which must report the directory bit so
// tools recurse into them). Classes 1/2/3/37/38 share the FILE_*_DIRECTORY_INFORMATION
// header layout through FileAttributes (offset 56); FileNamesInformation (class 12)
// carries no metadata and is left as-is. `rec` must already be zeroed through nameOff.
// Failures to stat the backing file are benign (fields stay zeroed).
static void FillOverlayDirRecordMetadata(BYTE* rec, ULONG infoClass, const std::wstring& backingFullPath)
{
    if (infoClass == 12)
    {
        return; // FileNamesInformation: name only.
    }
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(backingFullPath.c_str(), GetFileExInfoStandard, &fad))
    {
        return;
    }
    auto putTime = [&](ULONG off, const FILETIME& ft) {
        LARGE_INTEGER li; li.LowPart = ft.dwLowDateTime; li.HighPart = (LONG)ft.dwHighDateTime;
        *reinterpret_cast<LONGLONG*>(rec + off) = li.QuadPart;
    };
    putTime(8,  fad.ftCreationTime);
    putTime(16, fad.ftLastAccessTime);
    putTime(24, fad.ftLastWriteTime);
    putTime(32, fad.ftLastWriteTime); // ChangeTime ~ LastWriteTime (best effort)
    LARGE_INTEGER size; size.LowPart = fad.nFileSizeLow; size.HighPart = (LONG)fad.nFileSizeHigh;
    *reinterpret_cast<LONGLONG*>(rec + 40) = size.QuadPart;                    // EndOfFile
    LONGLONG alloc = (size.QuadPart + 4095) & ~((LONGLONG)4095);
    *reinterpret_cast<LONGLONG*>(rec + 48) = alloc;                            // AllocationSize
    *reinterpret_cast<ULONG*>(rec + 56) = fad.dwFileAttributes;                // FileAttributes
    // FileId for the Id classes (offset differs by class; see TryGetDirInfoLayout).
    if (infoClass == 37)      *reinterpret_cast<LONGLONG*>(rec + 96) = SynthOverlayFileId(backingFullPath);
    else if (infoClass == 38) *reinterpret_cast<LONGLONG*>(rec + 72) = SynthOverlayFileId(backingFullPath);
}

// Win32 analogue of the NT record emit: fill `data` with the next un-emitted overlay
// entry for this handle's snapshot (advancing OverlayEnumCursor), sourced from the
// backing store, or return false when the snapshot is exhausted. Used by the Win32
// FindNextFileW hook to append overlay files after the real enumeration ends.
bool NextOverlayFindDataW(const std::wstring& enumDir, HandleOverlayRef& overlay, LPWIN32_FIND_DATAW data)
{
    EnsureOverlayEnumSnapshot(enumDir, overlay);
    const std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;

    // Advance past any snapshot entries that don't match the caller's wildcard
    // (they'll never match on a later call either - same filter), emitting the
    // first match. Cursor advances permanently so each entry is considered once.
    while (overlay->OverlayEnumCursor < names.size() &&
           !OverlayNameMatchesFilter(names[overlay->OverlayEnumCursor], overlay->OverlayEnumFilter))
    {
        overlay->OverlayEnumCursor++;
    }
    if (overlay->OverlayEnumCursor >= names.size())
    {
        return false;
    }
    const std::wstring& nm = names[overlay->OverlayEnumCursor];
    const std::wstring backing = OverlayBackingPath(JoinDirAndName(enumDir, nm));

    memset(data, 0, sizeof(*data));
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(backing.c_str(), GetFileExInfoStandard, &fad))
    {
        data->dwFileAttributes = fad.dwFileAttributes;
        data->ftCreationTime   = fad.ftCreationTime;
        data->ftLastAccessTime = fad.ftLastAccessTime;
        data->ftLastWriteTime  = fad.ftLastWriteTime;
        data->nFileSizeHigh    = fad.nFileSizeHigh;
        data->nFileSizeLow     = fad.nFileSizeLow;
    }
    else
    {
        data->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    size_t n = nm.size();
    if (n > MAX_PATH - 1) n = MAX_PATH - 1;
    memcpy(data->cFileName, nm.c_str(), n * sizeof(wchar_t));
    data->cFileName[n] = L'\0';
    data->cAlternateFileName[0] = L'\0';
    overlay->OverlayEnumCursor++;
    return true;
}

// Capture the caller's enumeration wildcard onto the handle, ONCE per scan (like
// usvfs's Searches::Info::searchPattern). The pattern is only supplied on the first
// NtQueryDirectoryFile(Ex)/Zw call and is NULL on continuation calls, so remembering
// it here lets the deferred exhaustion splice honor it. Reset (and re-captured) on a
// RestartScan so a re-scan can use a different pattern.
void CaptureOverlayEnumFilter(HandleOverlayRef& overlay, PUNICODE_STRING FileName, bool restartScan)
{
    if (overlay == nullptr)
    {
        return;
    }
    if (restartScan)
    {
        overlay->OverlayEnumFilterSet = false;
        overlay->OverlayEnumFilter.clear();
    }
    if (!overlay->OverlayEnumFilterSet && FileName != nullptr && FileName->Length > 0)
    {
        overlay->OverlayEnumFilter.assign(FileName->Buffer, FileName->Length / sizeof(wchar_t));
        overlay->OverlayEnumFilterSet = true;
    }
}

// Splices synthetic overlay entries into a directory-enumeration result produced
// by Nt/Zw QueryDirectoryFile. Runs AFTER the subtractive filter, so it never
// re-hides what it inserts. Only the info classes understood by TryGetDirInfoLayout
// are handled; any other class is passed through untouched (fail-open).
//
// Two cases are handled, matching how enumeration APIs drive the OS:
//   - result == STATUS_SUCCESS: real entries are present. Synthetic records are
//     appended after the surviving chain (unless ReturnSingleEntry, in which case
//     the caller's single slot is already filled and synthetics wait for the
//     exhaustion call below).
//   - result == STATUS_NO_MORE_FILES / STATUS_NO_SUCH_FILE: the real scan is done.
//     If synthetics remain unemitted they are written into the fresh buffer and
//     the status is rewritten to STATUS_SUCCESS so the caller keeps reading.
//
// overlay->OverlayEnumCursor tracks how many synthetic entries have already been
// emitted for this handle, so each is returned exactly once across the multi-call
// enumeration protocol. RestartScan resets the cursor.
void InsertOverlayEntries(
    PVOID FileInformation,
    ULONG Length,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG infoClass,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    const std::wstring& enumDir,
    HandleOverlayRef& overlay,
    NTSTATUS& result)
{
    if (overlay == nullptr)
    {
        return;
    }

    ULONG nameLenOff, nameOff;
    if (!TryGetDirInfoLayout(infoClass, nameLenOff, nameOff))
    {
        return; // class we cannot construct: leave the OS result untouched.
    }

    // Overlay-only directory: if the enumerated directory does NOT exist on the real
    // disk, this handle was redirected to (and the OS just enumerated) the backing
    // store itself (see ResolveOverlayOpenPath's directory branch). The backing
    // children are therefore already present in the OS result; sourcing them again
    // from ListBackingChildren and splicing would double-list every entry. Leave the
    // buffer untouched. (A directory present on real disk enumerates the real dir and
    // DOES get its overlay-only children spliced below.)
    if (!enumDir.empty())
    {
        const std::wstring realWideDir = L"\\\\?\\" + enumDir;
        if (!OverlayIsDirectory(realWideDir))
        {
            return;
        }
    }

    // A new scan (first call, or an explicit RestartScan) invalidates any snapshot.
    if (RestartScan)
    {
        overlay->OverlayEnumStarted = false;
        overlay->OverlayEnumCursor = 0;
        overlay->OverlayEnumSnapshot.clear();
    }

    // Capture (once) this handle's overlay entry snapshot; reused for every call.
    EnsureOverlayEnumSnapshot(enumDir, overlay);

    const std::vector<std::wstring>& names = overlay->OverlayEnumSnapshot;

    if (names.empty())
    {
        return;
    }

    if (overlay->OverlayEnumCursor >= names.size())
    {
        return; // every synthetic entry has already been emitted for this handle.
    }

    const NTSTATUS kStatusSuccess     = (NTSTATUS)0x00000000;
    const NTSTATUS kStatusNoMoreFiles = (NTSTATUS)0x80000006;
    const NTSTATUS kStatusNoSuchFile  = (NTSTATUS)0xC000000F;

    const bool realSuccess = NT_SUCCESS(result);
    const bool realExhausted = (result == kStatusNoMoreFiles || result == kStatusNoSuchFile);

    // Emit synthetic entries ONLY after the real enumeration has reported exhaustion,
    // never interleaved into a call that still carried real records. This mirrors
    // usvfs (hook_NtQueryDirectoryFile): all "regular" results are returned first
    // across as many calls as the caller needs, and virtual entries are appended only
    // once regularComplete. Interleaving synthetics into a real-SUCCESS buffer is
    // fragile under a small caller buffer that spans many calls - the OS keeps its
    // own scan position while we advance ours, and getting the two cursors to agree
    // per-call invites skipped or duplicated entries. Deferring to exhaustion makes
    // each synthetic depend only on our own emit-once cursor, so it appears exactly
    // once regardless of how the real portion was chunked. Standard enumeration loops
    // (FindNextFile, libuv, NtQueryDirectoryFile callers) always call until they get
    // a non-success status, so the exhaustion call is guaranteed to be made.
    if (realSuccess)
    {
        return; // real records still flowing: leave this buffer untouched.
    }
    if (!realExhausted)
    {
        return; // a genuine error: don't fabricate a result on top of it.
    }

    // Exhaustion: append synthetic records from offset 0. Each record: zeroed fixed
    // header, FileNameLength set, NextEntryOffset relinked, name copied in.
    BYTE* base = reinterpret_cast<BYTE*>(FileInformation);
    ULONG usedEnd = 0;
    BYTE* prevRec = nullptr;
    ULONG prevOff = 0;
    ULONG writeOff = AlignUp8(usedEnd);
    ULONG lastWrittenEnd = usedEnd;
    bool emittedAny = false;

    while (overlay->OverlayEnumCursor < names.size())
    {
        const std::wstring& nm = names[overlay->OverlayEnumCursor];
        // Skip entries that don't match the caller's wildcard (see gap #1); advance
        // the cursor permanently so each snapshot entry is considered exactly once.
        if (!OverlayNameMatchesFilter(nm, overlay->OverlayEnumFilter))
        {
            overlay->OverlayEnumCursor++;
            continue;
        }
        ULONG nameBytes = static_cast<ULONG>(nm.size() * sizeof(wchar_t));
        ULONG recSize = nameOff + nameBytes;
        if (static_cast<size_t>(writeOff) + recSize > Length)
        {
            break; // no room in the caller's buffer for another record.
        }

        BYTE* rec = base + writeOff;
        memset(rec, 0, nameOff);                                   // fixed header
        *reinterpret_cast<ULONG*>(rec) = 0;                        // NextEntryOffset (last)
        *reinterpret_cast<ULONG*>(rec + nameLenOff) = nameBytes;   // FileNameLength
        memcpy(rec + nameOff, nm.c_str(), nameBytes);              // FileName[]
        // Fill attributes/size/timestamps/FileId from the backing file so the entry
        // is indistinguishable from a real one (esp. the directory bit for subdirs).
        FillOverlayDirRecordMetadata(rec, infoClass, OverlayBackingPath(JoinDirAndName(enumDir, nm)));

        if (prevRec != nullptr)
        {
            *reinterpret_cast<ULONG*>(prevRec) = writeOff - prevOff; // link prior -> this
        }

        prevRec = rec;
        prevOff = writeOff;
        lastWrittenEnd = writeOff + recSize;
        emittedAny = true;
        overlay->OverlayEnumCursor++;

        writeOff = AlignUp8(writeOff + recSize);

        // Honor the single-entry contract in the exhaustion case (one record/call).
        if (ReturnSingleEntry)
        {
            break;
        }
    }

    if (emittedAny)
    {
        result = kStatusSuccess;
        if (IoStatusBlock != nullptr)
        {
            IoStatusBlock->Status = kStatusSuccess;
            IoStatusBlock->Information = lastWrittenEnd;
        }
    }
}

// Model W write-overlay, narrow-filter FindFirstFile gap fix. A Win32
// FindFirstFileExW whose wildcard matches ONLY overlay-only files (so the real
// directory returns ERROR_FILE_NOT_FOUND and no Find handle is opened) would never
// surface those files, because the overlay tail is normally appended on FindNextFile
// exhaustion of an existing real handle. Here we synthesize that handle: if the real
// directory exists and has at least one overlay-only child matching `filterExpr`, we
// (re)open the directory enumeration with a match-all "*" pattern to obtain a real
// Find handle, register it, CONSUME all the (non-matching) real entries up front, and
// return the first matching overlay entry as the FindFirstFile result. Subsequent
// FindNextFileW calls then hit real exhaustion immediately and continue emitting the
// (pattern-filtered) overlay tail via the normal TryAppendOverlayFindDataW path.
// Returns a valid Find handle (with lpFindFileData filled) or INVALID_HANDLE_VALUE if
// there is nothing to synthesize (caller keeps the original not-found result).
HANDLE TrySynthesizeOverlayFindFirstW(
    const std::wstring& dirPath,
    const std::wstring& filterExpr,
    AccessCheckResult const& dirAccessCheck,
    PolicyResult const& dirPolicy,
    LPWIN32_FIND_DATAW lpFindFileData,
    FINDEX_INFO_LEVELS fInfoLevelId,
    FINDEX_SEARCH_OPS fSearchOp,
    DWORD dwAdditionalFlags)
{
    std::wstring base = dirPath;
    while (!base.empty() && (base.back() == L'\\' || base.back() == L'/')) base.pop_back();
    if (base.empty())
    {
        return INVALID_HANDLE_VALUE;
    }

    // Cheap pre-check: is there at least one overlay-only child matching the filter?
    std::vector<std::wstring> children;
    ListBackingChildren(base, children);
    bool anyMatch = false;
    for (const std::wstring& nm : children)
    {
        std::wstring realFull = base + L"\\" + nm;
        if (GetFileAttributesW(realFull.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            continue; // exists on the real disk; the OS listing already covers it.
        }
        if (OverlayNameMatchesFilter(nm, filterExpr))
        {
            anyMatch = true;
            break;
        }
    }
    if (!anyMatch)
    {
        return INVALID_HANDLE_VALUE;
    }

    // Open the enumeration with match-all to obtain a real handle we can return.
    std::wstring wildAll = base + L"\\*";
    WIN32_FIND_DATAW scratch;
    memset(&scratch, 0, sizeof(scratch));
    HANDLE h = Real_FindFirstFileExW(
        wildAll.c_str(), fInfoLevelId, &scratch, fSearchOp, nullptr, dwAdditionalFlags);
    if (h == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE; // directory vanished; keep the not-found result.
    }

    RegisterHandleOverlay(h, dirAccessCheck, dirPolicy, HandleType::Find);
    HandleOverlayRef ov = TryLookupHandleOverlay(h);
    if (ov == nullptr)
    {
        FindClose(h);
        return INVALID_HANDLE_VALUE;
    }
    ov->OverlayEnumFilter = filterExpr;
    ov->OverlayEnumFilterSet = true;

    // Consume the real entries up front. By precondition none match the narrow filter
    // (the narrow FindFirstFile returned not-found), so we skip them all; a defensive
    // match short-circuits and returns the real entry.
    bool haveReal = true; // scratch currently holds the first real entry (".").
    while (haveReal && !OverlayNameMatchesFilter(scratch.cFileName, filterExpr))
    {
        haveReal = (Real_FindNextFileW(h, &scratch) != FALSE);
    }
    if (haveReal)
    {
        *lpFindFileData = scratch;
        ScrubShortFileName(lpFindFileData);
        return h;
    }

    // Reals exhausted with no match: emit the first (filtered) overlay entry.
    if (NextOverlayFindDataW(base, ov, lpFindFileData))
    {
        return h;
    }
    FindClose(h);
    return INVALID_HANDLE_VALUE;
}


// Model W write-overlay: emit the next process-private overlay entry (a backing-
// store file absent from the real directory) into a WIN32_FIND_DATAW, one per call,
// tracked by the per-handle emit-once cursor. Returns TRUE and sets last error to
// ERROR_SUCCESS if an entry was produced; FALSE (leaving the caller's exhaustion
// state intact) otherwise. Kill-switched by ShouldWriteOverlay(). Shared by both
// FindNextFileW exhaustion points: the outer real-exhaustion branch and the inner
// --filter-inputs filter loop (which would otherwise return FALSE and skip the
// overlay tail).
bool TryAppendOverlayFindDataW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    if (!ShouldWriteOverlay())
    {
        return false;
    }

    // Building this handle's overlay snapshot below calls Win32 APIs that clobber
    // the thread's last error: ListBackingChildren (FindFirstFile), OverlayBackingPath
    // (GetEnvironmentVariableW -> ERROR_ENVVAR_NOT_FOUND/203 when the overlay-dir var
    // is absent), and GetFileAttributesW on not-yet-existing paths. Our callers invoke
    // us only after the real enumeration ended with ERROR_NO_MORE_FILES and rely on
    // that error SURVIVING when we produce no entry - a stat/scandir loop (e.g. CPython
    // importlib's os.scandir) treats any error other than ERROR_NO_MORE_FILES as a hard
    // failure and raised OSError [WinError 203] on every overlay-enabled run. Preserve
    // and restore the incoming last error on the no-entry path so the caller's
    // end-of-enumeration contract holds; only the produced-entry path sets SUCCESS.
    const DWORD savedError = GetLastError();

    HandleOverlayRef ov = TryLookupHandleOverlay(hFindFile);
    if (ov == nullptr || ov->Type != HandleType::Find)
    {
        SetLastError(savedError);
        return false;
    }

    std::wstring enumDir(ov->Policy.GetTranslatedPathWithoutTypePrefix());
    if (NextOverlayFindDataW(enumDir, ov, lpFindFileData))
    {
        SetLastError(ERROR_SUCCESS);
        return true;
    }

    SetLastError(savedError);
    return false;
}
