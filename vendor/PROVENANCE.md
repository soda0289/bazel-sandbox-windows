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

The vendored engine is kept as close to upstream as possible. As of the pinned
commit, **eleven vendored files diverge from upstream**; every other file is
byte-identical. The changes are all additive parity work for this project (they
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
- `DetouredFunctions.cpp` — the redirect/enumeration helpers `OverlayBackingExists`,
  `ListBackingChildren`, `ResolveOverlayOpenPath`, `ResolveOverlayDelete`,
  `ResolveOverlayRenameDest`, and the enumeration-splice (`InsertOverlayEntries`).

The exact diff is captured in [`detours-services.patch`](./detours-services.patch)
(unified diff, paths relative to a BuildXL checkout root). It applies cleanly to
the pinned commit:

```sh
# from the root of a BuildXL checkout at commit 13c5c9d
git apply --check /path/to/vendor/detours-services.patch
```

Note the patch documents *only* the in-place edits to the vendored files. It does
not include the new files this project adds (`src/network_detours.*`,
`src/manifest_builder.cpp`, `src/main.cpp`, etc.), which are original to this
repository, nor any files removed from the vendored copy (see below).

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

Other feature areas we do not use at runtime (reporting, timestamp faking,
substitute-process shim, full reparse-point resolution, DeviceMap) are left in
place because their translation units are still compiled and linked; removing
them would require build and link-time surgery for little benefit. See the
build's source list in `BUILD.bazel` for the authoritative set of compiled
translation units, and the repository `README.md` "Intentionally dropped"
section for the feature-level rationale.

## Refreshing the vendored copy

1. Check out the desired BuildXL commit.
2. Copy the files listed above over this directory.
3. Reapply `detours-services.patch` (or re-add the network-sandbox wiring by hand
   if upstream has drifted), then regenerate the patch and update the pinned
   commit above.
4. Rebuild and run the full test suite (`bazel test //...`).
