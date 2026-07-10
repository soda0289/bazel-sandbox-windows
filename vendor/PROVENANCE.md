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
commit, **every vendored file is byte-identical to upstream except two**, and the
only functional change is additive wiring for this project's network-sandbox
feature (`-N` / `-n`), whose implementation lives outside the vendored tree in
`src/network_detours.{h,cpp}`:

- `detours-services/DetoursServices.cpp` — include `network_detours.h`; call
  `bazelsandbox::InitializeAndAttachNetworkDetours()` in `DllProcessAttach`.
- `detours-services/DetouredFunctions.cpp` — include `network_detours.h`; add two
  `\Device\Afd` deny blocks (the `-n` syscall-layer hardening) in
  `Detoured_ZwCreateFile` and `Detoured_NtCreateFile`; strip a UTF-8 BOM from the
  file header.

The exact diff is captured in [`detours-services.patch`](./detours-services.patch)
(unified diff, paths relative to a BuildXL checkout root). It applies cleanly to
the pinned commit:

```sh
# from the root of a BuildXL checkout at commit 13c5c9d
git apply --check /path/to/vendor/detours-services.patch
```

Note the patch documents *only* the in-place edits to the two vendored files. It
does not include the new files this project adds (`src/network_detours.*`,
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
