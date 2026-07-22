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
  `stdafx-unix-common.h`. These are only `#include`d from `stdafx.h` inside the
  `#if __linux__` / `#elif __APPLE__` branches, which are never taken here
  (`stdafx.h` forces both macros to `0`). (`stdafx-linux.h` was never vendored
  for the same reason.)
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
