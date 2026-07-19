// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Facility for associating extra data to a HANDLE, without actually replacing the handle itself.
// This allows associating key data such as normalized path and effective policy at the time of handle open,
// for use in HANDLE-only APIs such as GetFileInformationByHandle.
//
// HANDLE is effectively typed as void*. Why not indirect handles by returning a pointer to some structure wrapping the real handle?
// That's only viable so long as ALL HANDLE-consuming APIs are detoured (even boring things like GetHandleInformation); otherwise
// any missing API would reject our fake HANDLEs, or crash.
//
// Instead, we define a process-global HANDLE -> overlay map and return all HANDLEs unmodified.

#include "FileAccessHelpers.h"
#include "PolicyResult.h"

enum class HandleType {
    File,
    Directory,
    // Pseudo-handle as used by FindFirstFile
    Find
};

// Per-handle overlay data.
struct HandleOverlay {
    // Constructs a handle overlay for a handle, wrapping the creating operation's policy / access check.
    // The policy represents what operations should be allowed via operations on this handle.
    HandleOverlay(AccessCheckResult const& accessCheck, PolicyResult const& policy, HandleType type)
        : Policy(policy), AccessCheck(accessCheck), Type(type), EnumerationHasBeenReported(false),
          OverlayEnumStarted(false), OverlayEnumCursor(0), OverlayEnumFilterSet(false) { }

    HandleOverlay(const HandleOverlay& other) = default;
    HandleOverlay& operator=(const HandleOverlay&) = default;

    PolicyResult Policy;
    AccessCheckResult AccessCheck;
    HandleType Type;

    // This flag is set when a directory handle enumeration is reported to BuildXL
    // by NtQueryDirectoryFile. It prevents multiple reports for the same directory
    // (some big enumerations require multiple calls to NtQueryDirectoryFile).
    bool EnumerationHasBeenReported;

    // Model W write-overlay (experimental): per-handle enumeration insertion state.
    // A directory enumeration is a POINT-IN-TIME snapshot spanning one or more
    // NtQueryDirectoryFile calls. OverlayEnumSnapshot is the set of process-private
    // overlay entries to splice into this handle's listing, captured ONCE at the
    // start of the scan (first call, or after RestartScan) so that concurrent writes
    // to the same directory by other processes/threads in the action tree cannot
    // shift the entry ordering mid-scan (which would make the cursor skip/duplicate).
    // OverlayEnumCursor is how many of those snapshot entries have already been
    // emitted, so each is returned exactly once. OverlayEnumStarted distinguishes
    // "snapshot not yet taken" from "snapshot taken, possibly empty". All three are
    // reset on RestartScan and only consulted when ShouldWriteOverlay().
    //
    // NOTE: this state is per-HANDLE and is NOT synchronized. Concurrent enumeration
    // of the SAME handle from multiple threads is unsupported (and races the internal
    // OS scan position regardless) - this matches the existing single-threaded-per-
    // handle assumption behind EnumerationHasBeenReported above. Distinct handles on
    // the same directory (the common cross-thread/cross-process case) each get their
    // own overlay and snapshot, so they are independent and safe.
    bool OverlayEnumStarted;
    std::vector<std::wstring> OverlayEnumSnapshot;
    size_t OverlayEnumCursor;

    // Model W write-overlay: the caller's enumeration wildcard (e.g. "*.txt"),
    // captured ONCE at the start of the scan - like usvfs's Searches::Info::searchPattern -
    // so overlay entries spliced at exhaustion honor the same pattern the OS applied to
    // the real entries. Empty / "*" means match-all. The pattern is only supplied on the
    // first NtQueryDirectoryFile call (and is NULL on continuation calls), so it must be
    // remembered here. For the SYNTHESIZED Win32 FindFirstFile handle (the narrow-filter
    // gap fix) the real entries are consumed up-front, so only the overlay tail (filtered
    // by this pattern) is ever returned from that handle.
    std::wstring OverlayEnumFilter;
    bool OverlayEnumFilterSet;
};

// Sets up structures for recording handle overlays.
// This function is suitable for DllMain - it does not assume that CRT memory allocation is available.
void InitializeHandleOverlay();

// Thread-safe, counted reference to a HandleOverlay. Since disposal of a handle (e.g. CloseHandle) may run concurrently with some access to the handle
// (though that may result in downstream failures), we do not assume that finding an overlay (by valid HANDLE) guarantees lifetime for the duration
// of the calling (HANDLE-using) function. Instead, looking up a handle creates a new HandleOverlayRef (atomically), and so a HandleOverlay is not
// deallocated until all uses of it are complete.
typedef std::shared_ptr<HandleOverlay> HandleOverlayRef;

// Creates or replaces an overlay for the given handle (intended for the time at which a handle is created).
// The new overlays wraps the policy / access check determined for the handle so far.
// The policy represents what operations should be allowed via operations on this handle.
void RegisterHandleOverlay(HANDLE handle, AccessCheckResult const& accessCheck, PolicyResult const& policy, HandleType type);

// Tries to look up an existing overlay for the given handle. The returned ref may wrap nullptr in the event that there was no overlay found.
HandleOverlayRef TryLookupHandleOverlay(HANDLE handle, bool drain = true);

// If an overlay exists for the given handle, disassociates it from the handle. Future calls to TryLookupHandleOverlay for the handle will no
// longer succeed. Concurrent users that already have a ref to the overlay may continue to use it safely.
void CloseHandleOverlay(HANDLE handle, bool inRecursion = false);

// Adds a closed handle to the closed handle list.
void AddClosedHandle(HANDLE handle);

// Remove all closed handlefrom the overlay map.
void RemoveClosedHandles();
