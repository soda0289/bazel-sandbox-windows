# Vendored source provenance

This directory vendors the native Windows sandbox enforcement engine from
[microsoft/BuildXL](https://github.com/microsoft/BuildXL), plus a few shared
headers. It is **vendored deliberately** (rather than fetched or patched at build
time) so the build is self-contained, offline, and reproducible, and so unused
files can be stripped. See the repository `README.md` for why we keep it vendored.

## Upstream source

- **Repository:** https://github.com/microsoft/BuildXL
- **Pinned commit:** `13c5c9d4a2c80da70038cb4cf81e4833a3422f68` (branch `main`)

| Local path                 | Upstream path                                  |
| -------------------------- | ---------------------------------------------- |
| `detours-services/`        | `Public/Src/Sandbox/Windows/DetoursServices/`  |
| `sandbox-common/`          | `Public/Src/Sandbox/Common/` (selected headers)|

Only one header is taken from `Common/`: `ReportType.h`. We do **not** vendor
`Common/FileAccessManifest.{h,cpp}`; the manifest blob is built by our own
`src/manifest_builder.cpp` instead. (`ConcurrentQueue.h` and
`FileAccessManifest.h` were previously vendored but are unused and were
removed.)

## Divergence from upstream

The vendored engine started as a close-to-upstream copy. At the baseline tag
(`vendored-buildxl-baseline-13c5c9d`, before the 2026-07-21 hard fork below),
**twelve vendored files diverge from upstream** and every other file is
byte-identical; that is the state [`detours-services.patch`](./detours-services.patch)
records. The changes below are all additive parity work for this project (they
extend behaviour, they do not rewrite BuildXL's enforcement) and fall into a few
groups:

**Network sandbox (`-N` / `-n`)** — the implementation lives outside the vendored
tree in `src/network_detours.{h,cpp}`; the vendored edits are just the wiring:

- `DetoursServices.cpp` — include `network_detours.h`; call
  `bazelsandbox::InitializeAndAttachNetworkDetours()` in `DllProcessAttach`.
- `DetouredFunctions.cpp` — include `network_detours.h`; add two `\Device\Afd`
  deny blocks (the `-n` syscall-layer hardening) in `Detoured_ZwCreateFile` and
  `Detoured_NtCreateFile`; strip a UTF-8 BOM from the file header.

**linux-sandbox read/enumeration parity** — makes an undeclared existing input
look *absent* (NOT_FOUND) rather than permission-denied, and hides it from
directory listings, matching linux-sandbox's symlink forest (`--filter-inputs`):

- `DataTypes.h` — two fork FAM extra-flags (`DeniedReadsAsNotFound` 0x400,
  `FilterDirectoryEnumeration` 0x800) and a `FileAccessPolicy_DeclaredInput`
  (0x2000) marker bit (inert for enforcement; used only by the read fallback).
- `FileAccessHelpers.h`, `PolicyResult.{h,cpp}`, `PolicyResult_common.cpp` —
  read-denial masking (`DenialError(maskReadsAsNotFound)`), the
  `IsColocatedModuleMetadataRead` `package.json` carve-out, and the
  `IsExactManifestNode` / `DeclaredInput` helpers.
- `DetouredFunctions.cpp` — apply the NOT_FOUND masking uniformly across every
  read/probe hook (`GetFileAttributesW`/`ExW`, `GetFileInformationByName`,
  `FindFirstFileEx` single-file probe, `CreateFileW`/`NtCreateFile` read paths,
  and the `CopyFileW`/`CreateHardLinkW` *source*-read paths); filter undeclared
  children out of the `NtQueryDirectoryFile`/`ZwQueryDirectoryFile` enumerations;
  add the symlink/junction handle-resolution read fallback used to rescue
  reparse points whose real target is a declared input.

**New hook** — `GetFileInformationByName` (the handle-less fast stat path modern
libuv/Node use) was not detoured upstream:

- `DetouredFunctionTypes.h`, `DetouredFunctions.h`, `globals.h` — typedef, enum,
  declaration and global for the new detour.
- `DetouredFunctions.cpp`, `DetoursServices.cpp` — `Detoured_GetFileInformationByName`
  (dynamically resolved from `kernelbase.dll` so the DLL still loads on OS builds
  that lack the API) and its dynamic attach.

**`--write-overlay` per-action backing store (Model W)** — lets a tool freely
create / re-write / delete undeclared scratch in the execroot while the real
execroot is never mutated (matching linux-sandbox's throwaway writable execroot):
undeclared writes are redirected into a process-private backing directory
(`g_bazelWriteOverlayRoot`, mirroring the virtual path), reads and directory
enumeration are served from that backing store, and a pre-existing undeclared input
is never clobbered. The backing store is on disk and shared by the whole action
tree (per-invocation root in the manifest), so it is inherently cross-process and
its file-existence expresses deletes/renames — there is **no** separate created-set
index or shared-memory region:

- `globals.h`, `DetoursServices.cpp` — declaration/definition of
  `g_bazelWriteOverlayRoot` (the per-invocation backing-store root).
- `DetoursHelpers.cpp` — `ParseFileAccessManifest` reads the write-overlay backing
  root from a trailing block in the manifest payload (so it propagates to every
  child on injection, independent of the child's environment block).
- `PolicyResult.h`, `PolicyResult.cpp` — the inline enforcement of
  `OverrideAllowWriteForExistingFiles` in `AllowWrite` (create-new allowed,
  rewrite-own allowed, clobber-existing redirected), and `HasOverlayBackingShadow`
  (backing-store-authoritative read/enumeration visibility).
- `DetouredFunctions.cpp` — call-site grafts that invoke the redirect/enumeration
  helpers (`OverlayBackingExists`, `ListBackingChildren`, `ResolveOverlayOpenPath`,
  `ResolveOverlayDelete`, `ResolveOverlayRenameDest`, and the enumeration-splice
  `InsertOverlayEntries`). The helper *bodies* live outside the vendored tree in
  `src/overlay_engine.{h,cpp}` (see the note below); the vendored file only holds the
  grafts and the `#include "overlay_engine.h"`.
- `HandleOverlay.h` — five per-handle enumeration-snapshot fields on the
  `HandleOverlay` struct (`OverlayEnumStarted`, `OverlayEnumSnapshot`,
  `OverlayEnumCursor`, `OverlayEnumFilter`, `OverlayEnumFilterSet`) so a directory
  enumeration splices its overlay children exactly once, in wildcard order, across
  the multiple `NtQueryDirectoryFile` calls a single scan may take.

**Project-authored helpers moved out of the vendored tree** — the write-overlay
(Model W) redirect logic and the directory-enumeration input-filter / overlay-splice
logic are original to this project (no upstream counterpart). Their bodies now live
in `src/overlay_engine.{h,cpp}` (project-owned; see that file's header) rather than
inline in the vendored `DetouredFunctions.cpp`. That translation unit is compiled
into the vendored `//vendor:detours_services` library (it needs `stdafx.h` + the
vendored types), so the only remaining edits to `DetouredFunctions.cpp` are the
call-site grafts that invoke those helpers plus a single `#include`. This keeps the
`DetouredFunctions.cpp` hunk in `detours-services.patch` roughly a third smaller and
makes the project/upstream licensing boundary explicit.

The exact diff is captured in [`detours-services.patch`](./detours-services.patch)
(unified diff, paths relative to a BuildXL checkout root). At the baseline tag it
applies cleanly to the pinned commit:

```sh
# from the root of a BuildXL checkout at commit 13c5c9d
git apply --check /path/to/vendor/detours-services.patch
```

Note the patch documents *only* the in-place edits to the vendored files. It does
not include the new files this project adds (`src/network_detours.*`,
`src/overlay_engine.*`, `src/manifest_builder.cpp`, `src/main.cpp`, etc.), which are
original to this repository, nor any files removed from the vendored copy (see below).

## Removed / not-vendored upstream files

To keep the tree to what this Windows-only project actually compiles, some
upstream files are intentionally absent:

- **Non-Windows platform headers** — `stdafx-mac-interop.h`, `stdafx-mac-kext.h`,
  `stdafx-unix-common.h`. These were only ever `#include`d from `stdafx.h` inside
  its non-Windows platform branches, which were never taken here. As of the
  Windows-only preprocessor unwrap `stdafx.h` includes `stdafx-win.h`
  unconditionally and those branches (and their MAC_OS/__linux__/__APPLE__
  macros) no longer exist. (`stdafx-linux.h` was never vendored for the same
  reason.)
- **`ManifestIterator.{cpp,h}`** — not in the build's source list and only
  self-referenced; dead on this build.
- **`Common/FileAccessManifest.cpp`** — replaced by `src/manifest_builder.cpp`.
- **`SubstituteProcessExecution.{cpp,h}`** — removed 2026-07-21 (hard fork). The
  substitute-process shim let BuildXL swap a child's image for a plugin-selected
  one; this launcher never enables it (the manifest always carried an empty shim
  block), so the whole subsystem was dead. The one still-live helper it held,
  `FindApplicationNameFromCommandLine` (used by the job-object breakaway check),
  was relocated verbatim into `DetoursHelpers.cpp`. The now-unused shim block was
  also dropped from the manifest wire format (`ManifestSubstituteProcessExecutionShim_t`
  in `DataTypes.h` + the producer block in `src/manifest_builder.cpp` + the parse
  block in `DetoursHelpers.cpp`, removed in lockstep).
- **`DeviceMap.{cpp,h}`** — removed 2026-07-21 (hard fork). BuildXL used the NT
  DOS-device-map feature to give a sandboxed process a private drive-letter view;
  it was already compiled as no-op stubs here (`FEATURE_DEVICE_MAP` undefined, so
  `CurrentMappingHandle()` returned `INVALID_HANDLE_VALUE` and `ApplyMapping()`
  returned `false`), making every device-map branch dead. The `RemapDevices` /
  `PathMapping` / `CurrentMappingHandle` / `ApplyMapping` API and its two call
  sites in `DetouredProcessInjector` were removed, along with a vestigial include
  in `DetoursHelpers.cpp`. The `_mapDirectory` member is retained as an inert,
  always-`INVALID_HANDLE_VALUE` slot so the injector's handle-passing layout is
  unchanged (behavioral no-op).

As of the **2026-07-21 hard fork**, feature areas we do not use at runtime
(reporting, timestamp faking, substitute-process shim, full reparse-point
resolution, DeviceMap) are being **removed outright** rather than left compiled —
this repository no longer tracks upstream, so "keep it close to upstream" no
longer applies. See the build's source list in `BUILD.bazel` for the current set
of compiled translation units, and the repository `README.md` "Intentionally
dropped" section for the feature-level rationale.

## Hard fork — no longer tracking upstream (2026-07-21)

As of 2026-07-21 this vendored engine is a **hard fork**: it no longer tracks
`microsoft/BuildXL`, and dead BuildXL scaffolding is being removed outright.

The pinned commit above, the divergence description, and
[`detours-services.patch`](./detours-services.patch) describe the **last
upstream-tracking baseline**, frozen at git tag
**`vendored-buildxl-baseline-13c5c9d`**. At that tag the patch was verified to
apply cleanly in both directions (reverse against the vendored tree, forward
against pristine `13c5c9d`), and its a-side blob hashes match upstream
byte-for-byte. From the fork point onward the vendored tree diverges further
(files removed and edited); the patch is retained as a **historical and
licensing record**, not a live diff, and is **not** regenerated for post-fork
changes.

To recover pristine upstream or inspect the original divergence, check out the
baseline tag and reverse-apply the patch there:

```sh
git checkout vendored-buildxl-baseline-13c5c9d
git apply --reverse -p6 --directory=vendor/detours-services vendor/detours-services.patch
```

### Post-fork dead-code removals

Removals made after the baseline tag (each verified with a full build +
`bazel test //tests:all`):

- **SubstituteProcessExecution** — deleted `SubstituteProcessExecution.{cpp,h}`
  (see removed-files list above).
- **DeviceMap** — deleted `DeviceMap.{cpp,h}` (see removed-files list above).
- **Process-data + process-detouring-status reporting** — removed
  `ReportProcessData` / `ReportProcessDetouringStatus` (`SendReport.{cpp,h}`),
  their gated call sites in `DetoursServices.cpp`, the now-orphan
  `RetrieveParentProcessId`, and the `ProcessDetouringStatus` enum
  (`DataTypes.h`). Gated on the `LogProcessData` / `LogProcessDetouringStatus`
  manifest flags, which this launcher never sets.
- **Message-count semaphores** — removed the `g_messageCountSemaphore` /
  `g_messageSentCountSemaphore` open/release machinery (`DetoursHelpers.cpp`,
  `DetoursServices.cpp`, `SendReport.cpp`, `globals.h`). Gated on the
  `CheckDetoursMessageCount` flag / report-pipe mode, neither of which this
  launcher uses.
- **LaunchDebugger** — removed the unused `LaunchDebugger()` helper (both
  definitions in `DebuggingHelpers.cpp` and its `DebuggingHelpers.h` decl).
- **Injector pipe / report-pipe handshake (wire-format change)** — removed the
  three fixed injector handles (device-map, remote-injector pipe, report pipe)
  and the WOW64→Native64 remote-injection handshake. Deleted from
  `DetouredProcessInjector.{h,cpp}`: the `_mapDirectory` / `_remoteInjectorPipe`
  / `_reportPipe` members, `NeedRemoteInjection`, `RemoteInjectProcess`, the
  explicit `Init(remoteInjectorPipe, reportPipe, …)` overload, the
  `SetAlwaysRemoteInjectFromWow64Process` setter + `_alwaysRemoteInject…`
  field, the dead `GetInjectionData` accessor, the `MapDirectory` /
  `RemoteInjectorPipe` / `ReportPipe` getters, and the never-exported
  `DetouredProcessInjector_Create/_Destroy/_Inject` C wrappers. In
  `DetoursHelpers.cpp` the report-PIPE branch collapsed to report-FILE only.
  `c_minHandleCount` is now `0`; the payload wrapper written by `src/main.cpp`
  drops the three `INVALID_HANDLE_VALUE` slots — the wire format is now
  `[u32 totalSize][u32 handleCount=0][manifest bytes]`. Producer (main.cpp),
  deserializer (`Init`) and re-serializer (`LocalInjectProcess`, used for
  grandchild injection) were changed in lockstep; the launcher-injection e2e
  test (grandchild coverage) passes. The inert
  `AlwaysRemoteInjectDetoursFrom32BitProcess` extra-flag bit is kept for layout
  stability.
- **USN reporting / verification (manifest-record wire-format change)** — removed
  the NTFS Update-Sequence-Number machinery BuildXL used for incremental-build
  change detection (we do pure enforcement, so nothing consumes it and USN never
  denied — it only reported). Deleted: `TryGetUsn` + the USN check/report block
  in `DetouredFunctions.cpp` (it *was* executed for exact-file scopes because the
  builder wrote `ExpectedUsn = 0`, not `NoUsn`); the `usn` parameter threaded
  through `ReportIfNeeded` (`DetoursHelpers.{h,cpp}`) and
  `ReportFileAccess`/`SendReportString` (`SendReport.{h,cpp}`) incl. the `Usn`
  column in the `--trace` line; `PolicyResult::{ReportUsnAfterOpen,GetExpectedUsn}`;
  `PolicySearchCursor::GetExpectedUsn` and the dead
  `#ifdef BUILDXL_NATIVES_LIBRARY` `FindFileAccessPolicyInTree` export
  (`PolicySearch.{h,cpp}`); and from `DataTypes.h` the `NoUsn` macro, the
  `ExpectedUsnLo/Hi` fields + `ExpectedUsnPartType` + `GetExpectedUsn` in
  `ManifestRecord_t`. **Wire-format change:** each manifest record shrank by 8
  bytes (28→20-byte fixed prefix, still 4-aligned); `src/manifest_builder.cpp`
  drops the `PutU64(0)` ExpectedUsn field in lockstep. Record navigation is all
  field-relative and child offsets are record-relative, so the layout stays
  self-consistent; `manifest_unit` + the exact-file enforce tests pass. The
  `FileAccessPolicy` bit `0x20` (`ReportUsnAfterOpen`) is left as a reserved gap.

- **Input-file timestamp virtualization** — removed BuildXL's optional
  normalization of input (read-only) file timestamps to a fixed "well-known"
  value (a build-determinism feature; Bazel does its own input hashing, so it
  has no consumer here). The launcher never set `NormalizeReadTimestamps`, but
  the override still *ran*: the manifest never set the per-scope
  `FileAccessPolicy_AllowRealInputTimestamps` (0x200) bit, so
  `PolicyResult::ShouldOverrideTimestamps` returned true on allowed reads and
  `OverrideTimestampsForInputFile` executed its `else` branch, silently bumping
  any timestamp earlier than Feb-2002 up to that constant — a latent behavior
  quirk on genuinely old files. Deleted: `OverrideTimestampsForInputFile` (the
  template + `FILE_BASIC_INFO` overload), `NewInputTimestamp`, and
  `GetNewInputTimestampAsLargeInteger` (`MetadataOverrides.{h,cpp}`, keeping the
  still-live `ScrubShortFileName`); the 5 `ShouldOverrideTimestamps` /
  `OverrideTimestampsForInputFile` call blocks in `DetouredFunctions.cpp`
  (`GetFileAttributesExW`, `FindFirstFileExW`, `FindNextFile`,
  `GetFileInformationByHandleEx`, `GetFileInformationByHandle`);
  `PolicyResult::{ShouldOverrideTimestamps,AllowRealInputTimestamps}`; and from
  `DataTypes.h` the `FileAccessManifestFlag::NormalizeReadTimestamps` (0x800)
  flag (its auto-generated accessors had no remaining consumer) plus the
  `FileAccessPolicy_AllowRealInputTimestamps` (0x200) policy bit (left as a
  reserved gap). No wire-format size change. Sandboxed children now observe
  files' real timestamps. Build + 10/10 tests pass.

- **Compiled-out preprocessor branches (`DetoursServices.cpp` + companions)** —
  our build defines only `DETOURS_SERVICES_NATIVES_LIBRARY` (see
  `vendor/BUILD.bazel`), never `BUILDXL_NATIVES_LIBRARY` and never the
  perf-instrumentation switches `MEASURE_DETOURED_NT_CLOSE_IMPACT` /
  `MEASURE_REPARSEPOINT_RESOLVING_IMPACT` (both `#define`d to `0`). Those
  branches were therefore dead. In `DetoursServices.cpp`: unwrapped the
  always-true `#ifdef DETOURS_SERVICES_NATIVES_LIBRARY` guards around
  `DllProcessAttach`/`DllProcessDetach`/`DllMain`, deleted the `#elif
  defined(BUILDXL_NATIVES_LIBRARY)` alternative bodies + the `#else #error`, the
  `MEASURE_*` global-counter definitions and their update/print blocks, and the
  standalone `#ifdef BUILDXL_NATIVES_LIBRARY` block (`IsDetoursDebug` +
  `CreateDetachedProcess`, ~85 lines). Stripped the matching `MEASURE_*` blocks
  in `HandleOverlay.cpp`, `DetouredFunctions.cpp`, and the `extern` decls +
  `#define ... 0` switches in `globals.h`; removed the now-defunct
  `IsDetoursDebug` decl from `DetoursServices.h`. Pure compiled-out removal — no
  behavior change; build + 10/10 tests pass. (The remaining `#ifdef
  BUILDXL_NATIVES_LIBRARY` stub block in `DebuggingHelpers.cpp` was removed in a
  follow-up.)

- **Dead BUILDXL stubs in `DebuggingHelpers.cpp`** — removed the
  `#ifdef BUILDXL_NATIVES_LIBRARY` alternative `Dbg` /
  `HandleDetoursInjectionAndCommunicationErrors` stub bodies (never defined in
  this build). Pure compiled-out removal; build + 10/10 tests pass.

- **Cross-platform preprocessor guards (Windows-only unwrap)** — this project is
  Windows-only, so every non-Windows conditional was dead. Removed all
  `MAC_OS_LIBRARY` / `MAC_OS_SANDBOX` / `__linux__` / `__APPLE__` handling and
  unwrapped the always-true `#if _WIN32` guards (keeping the Windows body,
  dropping the `#else` / `#elif` branches) across `stdafx.h` (now just
  `#include "stdafx-win.h"`; the `MAC_OS_* 0` and `__linux__/__APPLE__ 0` defines
  and the platform-select `#if __linux__ / #elif __APPLE__ / #else` are gone),
  `targetver.h`, `DebuggingHelpers.h`, `PolicySearch.h`, `DataTypes.h`,
  `FilesCheckedForAccess.{h,cpp}`, `StringOperations.{h,cpp}` (incl. the
  `utf8proc` include and the non-Windows `NormalizePathChar` branches),
  `FileAccessHelpers.h`, `PolicyResult.h` (dropped the non-Windows
  `PolicyResult` member set / accessors and the `bxl_observer.hpp` include), and
  `PolicyResult_common.cpp` (dropped the non-Windows `AllowWrite` definitions).
  Pure compiled-out removal — the Windows code path is unchanged; build + 10/10
  tests pass. The never-vendored non-Windows platform headers remain absent (see
  removed-files list).

The corresponding `FileAccessManifestFlag` bits (`LogProcessData`,
`LogProcessDetouringStatus`, `CheckDetoursMessageCount`) are kept as inert
definitions so the manifest flag layout is unchanged. The `--trace`
flat-file access-reporting path (`ReportFileAccess` → `SendReportString` →
report-file append) is deliberately **retained**.

- **Diagnostic scaffolding (`SUPER_VERBOSE`) + ETW TraceLogging + dead
  `g_parentProcessId`** — removed three inert diagnostic facilities.
  `SUPER_VERBOSE` was `#define`d to `0`; its ~40 `#if SUPER_VERBOSE` blocks
  (verbose per-hook tracing) across `DetouredFunctions.cpp`, `DetoursHelpers.cpp`,
  `PolicyResult.cpp`, `DebuggingHelpers.cpp` were dead — stripped along with the
  `#define`/`#undef`. The `ENABLE_TRACE_LOGGING` (`#define 0`) ETW provider was
  never written to (all `TraceLoggingWrite`s sat behind the guard), yet the
  provider was still declared/defined and `TraceLoggingRegister`/`Unregister`'d
  unconditionally — removed the provider (`g_detoursServicesTraceProvider`),
  the register/unregister calls, the guarded writes in `SendReport.cpp`, the
  `ENABLE_TRACE_LOGGING` define, and the `<TraceLoggingProvider.h>` includes.
  `g_parentProcessId` was defined but never read (its last reader,
  `RetrieveParentProcessId`, went with the process-data reporting) — deleted.
  Pure dead-code removal; build + 10/10 tests pass. (`g_FileAccessManifestPipId`
  was left write-only after this change; it is removed in a later entry.)
- **Dead `CreateDetouredProcess` public wrapper + its exclusive helpers** — the
  standalone `CreateDetouredProcess` API (BuildXL's managed side used to P/Invoke
  it) is not exported by this DLL (only `BazelSandboxDetoursServicesAnchor` is)
  and is called nowhere in-tree; `main.cpp` creates the first child via upstream
  `DetourCreateProcessWithDllExW`, and the live grandchild path is
  `InternalCreateDetouredProcess` (called from the CreateProcess hooks). Removed
  `CreateDetouredProcess` and its exclusively-used helpers — the
  `ProcessCreationAttributes` struct, `InitializeAttributeList`,
  `CreateProcAttributesForExplicitHandleInheritance`, `CreateProcessAttributes`
  (~224 lines in `DetoursServices.cpp`) — plus the header declaration. Pure
  dead-code removal; build + 10/10 tests pass.
- **Write-only `g_FileAccessManifestPipId` + its `ManifestPipId` wire block** —
  BuildXL used the PipId to correlate reported accesses back to a pip; this
  launcher's only reader was the removed ETW `TraceLoggingWrite`, leaving the
  global write-only and the manifest's PipId always emitted as `0`. Dropped the
  block from both sides of our (project-owned) wire format in lockstep: the
  builder no longer emits the `PutU64(out, 0)` PipId word (`manifest_builder.cpp`),
  the parser no longer reads it (`DetoursHelpers.cpp`), and the `g_...PipId`
  global, its externs, and the `ManifestPipId` struct (`DataTypes.h`) are gone.
  Build + 10/10 tests pass.
- **Write-only `g_manifestSize`** — assigned once at manifest-parse entry
  (`payloadSize`) and never read; carried a stale BuildXL "divide by zero"
  comment for a division that does not exist here. Definition + both externs +
  the assignment removed. Build + 10/10 tests pass.
- **Dead deferred-`NtClose` overlay-drain subsystem** — the whole background
  handle-drain machinery in `HandleOverlay.cpp` was gated on
  `UseExtraThreadToDrainNtClose()`, a FAM flag this launcher never sets, so
  `RemoveClosedHandles()` (and therefore `AddClosedHandle`, the preallocated
  `g_pClosedHandles`/`g_pClosedHandlesPool` SLists, `PopulateNtCloseListPool`,
  `CleanupNtClosedHandles`, `StartCleanupNtClosedHandlesThread`) could never run;
  `Detoured_NtClose` already always took the direct `CloseHandleOverlay` path. The
  `ShouldLogProcessData()` map-size accounting blocks were likewise dead
  (`LogProcessData` is never set). Rewrote `HandleOverlay.cpp` down to the live
  overlay map + register/lookup/close, dropped the `AddClosedHandle`/
  `RemoveClosedHandles` header decls, collapsed the `NtClose` branch, and removed
  the now-unused pool/heap-entry stat globals
  (`g_detoursAllocatedNoLockConcurentPoolEntries`, `g_detoursMaxHandleHeapEntries`,
  `g_detoursHandleHeapEntries`) and their externs. Build + 10/10 tests pass.
- **Dead `LogProcessData` memory-stats accounting + 3 never-set FAM flags** — the
  private-heap allocator (`buildXL_mem.h` `dd_malloc`/`dd_free`) tracked bytes
  under `ShouldLogProcessData()`, another flag this launcher never sets, so the
  accounting (and the `g_detoursMaxAllocatedMemoryInBytes`/
  `g_detoursHeapAllocatedMemoryInBytes` stats it fed) was dead. Removed those
  blocks and stat definitions/externs; also removed the now-unused
  `_dd_aligned_malloc`/`_dd_aligned_free` (their only caller was the deleted
  NtClose pool) and the `_aligned_malloc`/`_aligned_free` trap stubs. With every
  use gone, dropped `LogProcessData` (0x20000), `UseExtraThreadToDrainNtClose`
  (0x8000), and `UseLargeNtClosePreallocatedList` (0x4000) from
  `FOR_ALL_FAM_FLAGS` (removing their generated Check/`Should` accessors), leaving
  reserved-gap comments. Build + 10/10 tests pass.
- **Never-set `ForceReadOnlyForRequestedReadWrite` (0x200) + its 3 branches** —
  BuildXL used this to downgrade a denied read-write open to read-only; this
  launcher never sets it. Collapsed the three identical guard blocks (in
  Detoured_CreateFileW and the two Nt/ZwCreateFile paths): removed each
  `if (ForceReadOnlyForRequestedReadWrite() ...) { ... }`, dropped the now-constant
  `forceReadOnlyForRequestedRWAccess` local, simplified the following
  `if (!forceReadOnly... && accessCheck.ShouldDenyAccess())` to
  `if (accessCheck.ShouldDenyAccess())`, and removed the no-op
  `desiredAccess = !forceReadOnly... ? desiredAccess : (...)` line. Removed the
  flag from FOR_ALL_FAM_FLAGS. Behavior-preserving. Build + 10/10 tests pass.
- **Batch of never-set FAM-flag guard collapses + `g_currentProcessCommandLine`
  removal** — collapsed every remaining branch gated on a FAM flag this launcher
  never sets, then removed the now-unreferenced flags from `FOR_ALL_FAM_FLAGS`
  (their generated `Check`/`Should` accessors go with them; reserved-gap comments
  left). Flags removed (14): `DiagnosticMessagesEnabled` (0x4), `IgnoreCodeCoverage`
  (0x80), `IgnoreZwRenameFileInformation` (0x1000), `IgnoreSetFileInformationByHandle`
  (0x2000), `DisableDetours` (0x10000), `IgnoreGetFinalPathNameByHandle` (0x40000),
  `HardExitOnErrorInDetours` (0x100000), `IgnoreZwOtherFileInformation` (0x400000),
  `IgnoreNonCreateFileReparsePoints` (0x1000000), `IgnoreCreateProcessReport`
  (0x2000000), `UseLargeEnumerationBuffer` (0x4000000), `IgnorePreloadedDlls`
  (0x8000000), `DirectoryCreationAccessEnforcement` (0x10000000),
  `ProbeDirectorySymlinkAsDirectory` (0x20000000). Site collapses:
  `if (!DisableDetours())` / `if (!IgnorePreloadedDlls())` ATTACH-table and
  preloaded-DLL blocks -> bare scopes; `if (!IgnoreGetFinalPathNameByHandle())`
  ATTACH pair + the two `Detoured_GetFinalPathNameByHandle{A,W}` guards -> unwrapped;
  the `!IgnoreZwRenameFileInformation()`/`!IgnoreZwOtherFileInformation()` switch
  cases -> direct `return Handle...`; `!IgnoreNonCreateFileReparsePoints()` folded
  into the live `!IgnoreReparsePoints()`; `!IgnoreCreateProcessReport()`,
  `IgnoreSetFileInformationByHandle()`, `ProbeDirectorySymlinkAsDirectory()`,
  `DirectoryCreationAccessEnforcement()` (ternary -> read-only probe), and the five
  `ShouldUseLargeEnumerationBuffer()` large-fetch/large-buffer blocks -> removed.
  Also removed `IgnoreCodeCoverage`, `HardExitOnErrorInDetours`, and
  `DiagnosticMessagesEnabled` guard blocks in DetoursHelpers/DebuggingHelpers.
  Finally removed `g_currentProcessCommandLine` (definition + extern + the
  `GetCommandLine()` assignment + its SendReport buffer-sizing use): the args
  reporting path that once read it was already gone, so it only over-sized the
  report buffer and never appeared in output. Build + 10/10 tests pass.
- **3 more never-set FAM flags + 10 never-set FAM ExtraFlags** — after the guard
  collapses above, `ReportProcessArgs` (0x100), `LogProcessDetouringStatus`
  (0x80000), and `CheckDetoursMessageCount` (0x200000) had zero remaining
  references and were dropped from `FOR_ALL_FAM_FLAGS`. Then audited the extra-flag
  vocabulary against the builder (which only ever sets `DeniedReadsAsNotFound`,
  `FilterDirectoryEnumeration`, `WriteOverlay`): collapsed the last never-set
  extra-flag guards and removed the flags from `FOR_ALL_FAM_EXTRA_FLAGS` (10):
  `ExplicitlyReportDirectoryProbes` (0x1, ternary -> `!OpenedDirectory`),
  `PreserveFileSharingBehaviour` (0x2, two `if (!...) sharedAccess |= FILE_SHARE_DELETE`
  guards -> unconditional), `IgnoreDeviceIoControlGetReparsePoint` (0x40, dropped the
  `|| ...()` early-out term + unwrapped the DeviceIoControl ATTACH),
  `IgnoreUntrackedPathsInFullReparsePointResolving` (0x80, dead `if (Untracked && ...)`
  block removed), `MonitorCreateProcessAsUser` (0x100, `Detoured_CreateProcessAsUserW`
  never monitored -> collapsed to the `Real_` passthrough, dropping the dead
  `Detoured_CreateProcessCommonW` call which CreateProcessW still uses), and the five
  Linux-only extras never set on Windows: `EnableLinuxPTraceSandbox` (0x4),
  `EnableLinuxSandboxLogging` (0x8), `AlwaysRemoteInjectDetoursFrom32BitProcess`
  (0x10), `UnconditionallyEnableLinuxPTraceSandbox` (0x20),
  `SecurityInodeGetattrIsProbe` (0x200). Reserved-gap comments left in both macros.
  Behavior-preserving. Build + 10/10 tests pass.
- **Never-set policy bit `FileAccessPolicy_TreatDirectorySymlinkAsDirectory`
  (0x800)** — the builder never sets it, so `PolicyResult::TreatDirectorySymlinkAsDirectory()`
  always returned false; its single reader (the trailing `&& !...()` term of the
  probe-only reparse-resolution predicate in `ShouldResolveReparsePointsInPathForDeviceOrDirectorySymlink`)
  was always true. Dropped the term, the accessor, and the enum bit (reserved-gap
  comment left). Build + 10/10 tests pass.
- **Never-set policy bit `FileAccessPolicy_ReportDirectoryEnumerationAccess`
  (0x80)** — the builder never sets it, so `PolicyResult::ReportDirectoryEnumeration()`
  always returned false and the four `explicitlyReportDirectoryEnumeration =
  isEnumeration && reportDirectoryEnumeration` sites were always false. Replaced
  each two-line read with `const bool explicitlyReportDirectoryEnumeration = false;`
  (downstream report-level selection collapses accordingly); removed the accessor
  and the enum bit (reserved-gap comment left). Build + 10/10 tests pass.
- **Never-set policy bit `FileAccessPolicy_EnableFullReparsePointParsing`
  (0x1000)** — the builder never sets it on any scope, so
  `PolicyResult::EnableFullReparsePointParsing()` always returned false. Two
  consequences, both proven behavior-preserving: (1)
  `IgnoreFullReparsePointResolvingForPath(pr)` = `IgnoreFullReparsePointResolving()
  && !EnableFullReparsePointParsing()` reduced to just
  `IgnoreFullReparsePointResolving()` (no policy dependence) -> inlined all 16 call
  sites and deleted the wrapper; the `ShouldResolveReparsePointsInPath` term in
  DetoursHelpers.cpp likewise dropped the `&& !...()`. (2)
  `GetLevelToEnableFullReparsePointParsing(pr)` called
  `FindLowestConsecutiveLevelThatStillHasProperty(EnableFullReparsePointParsing)`,
  whose guard `if ((m_policy & fileAccessPolicy) != 0)` is never true when the bit
  is unset, so it always returned 0; inlined both call sites to a literal `0` (the
  `level >= 0` guards stay, runtime-valued) and deleted both
  `GetLevelToEnableFullReparsePointParsing` and the now-unused
  `FindLowestConsecutiveLevelThatStillHasProperty`. Removed the accessor and the
  enum bit (reserved-gap comment left). Build + 10/10 tests (incl. reparse) pass.
- **Never-set policy bits `FileAccessPolicy_ReportAccessIfExistent` (0x10),
  `ReportAccessIfNonExistent` (0x40), and the `ReportAccess` combo** — the builder
  never sets per-scope explicit reporting on any scope, so all three read sites
  simplified, behavior-preserving: (1) the `explicitReport` computation in
  `CheckReadAccess` (both bit-tests always 0) -> `reportLevel` reduces to
  `ReportAnyAccess(...) ? Report : Ignore`; (2) `CreateAccessCheckResult(bool)`'s
  `(m_policy & ReportAccess) != 0` test (always false) -> same reduction; (3)
  `IndicateUntracked()` = `(AllowAll) && ((m_policy & ReportAccess) == 0)` -> just
  `(m_policy & AllowAll) == AllowAll` (the second clause was always true). Removed
  all three enum entries (reserved-gap comments left). `ReportLevel::ReportExplicit`
  is untouched (still used by the enumeration/report paths). Build + 10/10 tests pass.

- **Entirely-dead `FilesCheckedForAccess` class (Phase 5)** — BuildXL used this
  case-insensitive path set to dedupe repeated access reports; this launcher has
  no consumer (`TryRegisterPath` / `IsRegistered` / `GetInstance` are called
  nowhere in `vendor/` or `src/`). Deleted `FilesCheckedForAccess.{cpp,h}`,
  dropped the three `#include "FilesCheckedForAccess.h"` lines (`PolicyResult.h`,
  `PolicyResult.cpp`, `DetoursServices.cpp`), and removed the `.cpp` from
  `vendor/BUILD.bazel` srcs. The header also carried a duplicate
  `typedef CanonicalizedPath CanonicalizedPathType;`; the identical typedef
  already lives in `PolicyResult.h` (the header every `CanonicalizedPathType`
  user includes), so nothing else needed relocation. Pure dead-code removal; build
  + 10/10 tests pass.