# Vendored DetoursServices: architecture & coupling map

This document captures how the vendored BuildXL `DetoursServices` engine is
structured, how our first-party code plugs into it, and — importantly — how
*little* of its policy/manifest surface we actually exercise. It exists so that
any future attempt to shrink, replace, or re-sync the vendored code starts from
an accurate dependency map rather than a fresh reverse-engineering pass.

All line numbers/counts below were measured against the currently vendored
snapshot (see `vendor/PROVENANCE.md` for the upstream commit). Treat them as
"accurate at time of writing," not eternal.

## 1. The two binaries

| Binary | Source | Role |
| --- | --- | --- |
| `BazelSandbox.exe` | `src/` (ours) + `@detours` | Launcher. Builds the manifest, injects the DLL into a suspended child using upstream Detours, waits, returns the child's exit code. **No BuildXL code.** |
| `DetoursServices.dll` | `//vendor:detours_services` + `src/dll_export_anchor.cpp` + `//:network_detours` | The hook DLL injected into every sandboxed process. This is the vendored BuildXL engine. |

The launcher and the DLL communicate **one-way**, at injection time only, via a
serialized **FileAccessManifest** blob (built by `src/manifest_builder.cpp`,
parsed by the DLL's `ParseFileAccessManifest`). There is no runtime IPC in our
configuration (see §5).

## 2. Build personality: `DETOURS_SERVICES_NATIVES_LIBRARY`

The vendored sources can compile into two different DLLs, selected by a macro
(`#error` enforces exactly one):

- **`DETOURS_SERVICES_NATIVES_LIBRARY`** — the injected sandbox DLL. **This is
  what we define** (`vendor/BUILD.bazel` `local_defines`).
- **`BUILDXL_NATIVES_LIBRARY`** — BuildXL's separate `BuildXLNatives.dll` (job
  objects, path-translation tables, private heap). **We never define this**, so
  every `#ifdef BUILDXL_NATIVES_LIBRARY` block is dead code for us. This is why
  `DeviceMap.cpp` compiles down to no-op stubs (its real body is in the
  `BUILDXL_NATIVES`-only branch).

## 3. Translation units by role

| Role | TUs |
| --- | --- |
| **Bootstrap** (rewritable seam) | `DetoursServices.cpp` |
| **Hooks** (the 75 `Detoured_*` functions) | `DetouredFunctions.cpp` |
| **Policy + report facade** (the "brain") | `DetoursHelpers.cpp`, `PolicyResult.cpp`, `PolicyResult_common.cpp`, `PolicySearch.cpp`, `FileAccessHelpers.cpp` |
| **Path handling** | `CanonicalizedPath.cpp`, `StringOperations.cpp`, `PathTree.cpp`, `TreeNode.cpp` |
| **Manifest parse + wire types** | `DetoursHelpers.cpp` (parse), `DataTypes.h`, `DetouredFunctionTypes.h`, `globals.h`, `sandbox-common/FileAccessManifest*` |
| **Reporting** (inert for us, see §5) | `SendReport.cpp`, `DebuggingHelpers.cpp` |
| **Support** | `DetouredScope.cpp`, `HandleOverlay.cpp`, `MetadataOverrides.cpp`, `FilesCheckedForAccess.cpp`, header-only `ResolvedPathCache.h`, `UnicodeConverter.h`, `UniqueHandle.h`, `UtilityHelpers.h`, `buildXL_mem.h`, `Assertions.cpp` |
| **Child process handling** | `DetouredProcessInjector.cpp`, `SubstituteProcessExecution.cpp` (wire-format only, inert) |
| **Inert in our build** | `DeviceMap.cpp` (stubs), `SubstituteProcessExecution.cpp`, all `BUILDXL_NATIVES_LIBRARY` blocks |

## 4. The `DetoursServices` ↔ `DetouredFunctions` contract

The boundary between the bootstrap and the hooks is **not a clean API** — it is a
tightly coupled pair that communicates through shared mutable global state and an
exact function table. Anyone rewriting `DetoursServices.cpp` (or extracting
`DetouredFunctions.cpp`) must reproduce all of the following.

### 4a. Global state (`globals.h`)
- **40** `g_*` globals declared in `globals.h`.
- The bootstrap allocates ~12 by hand (`g_hPrivateHeap`,
  `g_pDetouredProcessInjector`, `g_breakawayChildProcesses`,
  `g_pManifestTranslatePathTuples` / `LookupTable`, `g_invariantLocale`, handle
  overlay, process kind).
- The manifest parser (`DetoursHelpers.cpp`) populates ~28 more, including
  `g_manifestTreeRoot` (the policy scope tree) and
  `g_fileAccessManifestFlags` / `ExtraFlags`.
- `DetouredFunctions.cpp` reads **8** globals directly; everything else it reads
  through the accessor layer below.

### 4b. The two-way function table
- `DetouredFunctions.cpp` references **67 distinct `Real_*` function pointers**
  (the originals it calls after policy checks).
- `DetoursServices.cpp`'s `DllProcessAttach` has an `ATTACH(Name)` block that
  assigns each `Real_##Name` and calls `DetourAttach(&Real_##Name,
  Detoured_##Name)` for **72** functions.
- **Miss a `Real_` assignment** → hook calls a null pointer → crash on first use.
- **Miss an `ATTACH`** → that API is unhooked → **silent sandbox escape**.

### 4c. The facade the hooks call
`DetouredFunctions.cpp` (`DetouredFunctions.h` → `DetoursHelpers.h`, transitive)
talks to the engine through a bounded set of functions — this is the real
extraction seam:

| Facade function (`DetoursHelpers`) | Call sites in `DetouredFunctions.cpp` |
| --- | --- |
| `ReportIfNeeded` | 66 |
| `GetReportedError` | 15 |
| `WantsReadAccess` / `WantsWriteAccess` / `WantsProbeOnlyAccess` | 23 |
| `GetPolicyResult` / `GetAccessCheckResult` / `GetFileOperationContext` | 15 |
| `TranslateFilePath`, `PathContainsWildcard`, `EnumerateDirectory`, `ExistsAsFile`, `GetImagePath`, `FindApplicationNameFromCommandLine` | ~9 |

Plus ~30 inline **flag accessors** generated in `DataTypes.h`
(`CheckReadAccess`, `CheckWriteAccess`, `IgnoreReparsePoints`,
`IgnoreFullReparsePointResolving`, `ShouldDenyAccess`,
`EnforceChainOfReparsePointAccesses`, `ShouldOverrideTimestamps`, …) that read
`g_fileAccessManifestFlags` / `ExtraFlags`.

### 4d. The manifest payload
`LocateAndParseFileAccessManifest()` finds the blob (`DetourFindPayload` keyed by
`g_manifestGuid`) and parses it into `g_manifestTreeRoot` + the flag globals. The
launcher's `src/manifest_builder.cpp` writes this byte layout. **The two must
agree byte-for-byte** — note the `_DEBUG`/tag-word constraint documented in
`manifest_builder.h` (we standardize on RELEASE / no tag words).

### Why the risk is severe
A bug in any of the above usually fails **silently**: the DLL loads, injects,
the build succeeds and reports OK — while some accesses leak because a global was
uninitialized or a hook was not attached. For a security boundary, "passes tests
but under-enforces" is the worst bug class. This is why "rewrite the bootstrap"
or "reimplement the facade" is a security project, not a line-count cleanup.

## 5. How little of the policy/manifest surface we use

This is the most useful fact for future scoping: **the sandbox exercises a tiny
subset of the engine's policy model.**

### Manifest flags (`FileAccessManifestFlag`)
Upstream defines **~30** flags. `src/main.cpp` sets exactly **6**:

- `FailUnexpectedFileAccesses` — deny (block) unexpected accesses.
- `MonitorNtCreateFile`, `MonitorZwCreateOpenQueryFile` — hook the Nt/Zw layer.
- `MonitorChildProcesses` — sandbox spawned children too.
- `IgnoreReparsePoints`, `IgnoreFullReparsePointResolving` — enforce on paths as
  requested, do **not** resolve junctions/symlinks to their targets (Bazel's
  execroot is full of declared junctions).

**Extra flags (`FileAccessManifestExtraFlag`): we set 0 of 11.**

Everything else is unused, e.g. `ReportAllFileAccesses`,
`ReportAllFileUnexpectedAccesses`, `NormalizeReadTimestamps`, `LogProcessData`,
`ReportProcessArgs`, `CheckDetoursMessageCount`, `ForceReadOnlyForRequestedReadWrite`,
`DirectoryCreationAccessEnforcement`, the USN/code-coverage/preloaded-DLL flags,
and all the Linux `EnableLinux*` extras.

### Reparse points: what they are and why we ignore resolution
A **reparse point** is NTFS metadata attached to a file or directory that
redirects path resolution elsewhere. When the OS walks a path and hits one, it
re-parses the remainder against a target. The kinds that matter on Windows:

- **Junction** (`mklink /J`) — directory-only, redirects to another local
  directory; needs no special privilege. **Bazel uses these heavily** to
  assemble each action's execroot from declared inputs.
- **Directory / file symlink** (`mklink /D`, `mklink`) — can point anywhere;
  requires `SeCreateSymbolicLinkPrivilege`.

A sandbox can enforce policy against such a path two ways: **as requested** (the
literal path the process asked for, e.g. `C:\execroot\foo`) or **fully resolved**
(walk every reparse point to the final real target, then check that). We choose
*as requested* — `main.cpp` sets both `IgnoreReparsePoints` and
`IgnoreFullReparsePointResolving` — for two reasons:

1. **Bazel's execroot IS junctions.** Bazel junctions declared inputs into place.
   Full resolution would turn a *declared* path (allowed by policy) into its
   *undeclared* real target and deny legitimate reads. Enforcing on the requested
   path matches how Bazel declares dependencies.
2. **Full resolution is the heavy, high-risk subsystem we deliberately keep
   dormant.** It is BuildXL's chain-of-reparse-point walker + `ResolvedPathCache`
   + directory-symlink selective enforcement (its large `SymLinkTests` suite).
   Enabling it pulls that whole path into the hot loop; keeping it off is what
   lets `ResolvedPathCache` and the full resolver stay bypassed (see the
   inert-paths list below).

**The tradeoff (a real, accepted gap):** a reparse point that lives *inside* an
allowed scope but points *outside* every scope lets an access reach the outside
target, even though a direct access there would be denied. Full resolution is
exactly what closes that hole; we accept the gap in exchange for simplicity and
Bazel-junction compatibility. The `reparse` characterization test pins this
behavior; see also README → *Known limitations*.

### Scope policy (`FileAccessPolicy`)
Upstream defines ~13 policy bits + composites. Our entire policy model is a
simple allow/deny **cone tree** built in `main.cpp`:

| Scope | Policy | CLI |
| --- | --- | --- |
| Root (whole FS) | `AllowRead` | — (default readable) |
| Working dir (execroot) | `Deny` | `-W` |
| Tool path | `AllowRead` | (implicit) |
| Read scopes | `AllowRead` | `-r` |
| Write scopes | `AllowAll` (read + write + create dir + symlink) | `-w` |
| Block scopes | `Deny` | `-b` |

All scopes use mask `MaskAll` (`0x0`), i.e. absolute (non-inherited) policy:
`(parentPolicy & mask) | values`.

Policy bits we **never** use: `ReportAccessIfExistent`, `ReportUsnAfterOpen`,
`ReportAccessIfNonExistent`, `ReportDirectoryEnumerationAccess`,
`AllowRealInputTimestamps`, `OverrideAllowWriteForExistingFiles`,
`TreatDirectorySymlinkAsDirectory`, `EnableFullReparsePointParsing`.

### Reporting channel: off by default, opt-in via `--trace`
By default both report flags are **off** and the manifest emits a **size-0
report block** (`manifest_builder.cpp`), with **no** report pipe, injector pipe,
or device map (`main.cpp`: "all no handle"). In that default configuration:

- The sandbox is **pure API-level enforcement** — a denied access returns
  `ERROR_ACCESS_DENIED` (etc.) to the child. There is **no telemetry** back to
  the launcher; the launcher only observes the child's exit code.
- `SendReport.cpp` and the 66 `ReportIfNeeded` call sites early-return / no-op
  (they exist to feed BuildXL's dynamic-dependency discovery, which we do not
  use for scheduling).

The launcher's `--trace <file>` flag turns this channel on for **debugging
only** (it never changes enforcement decisions). When set, `main.cpp`:
1. adds `Flag_ReportFileAccesses | Flag_ReportUnexpectedFileAccesses`, and
2. calls `ManifestBuilder::SetReportPath`, which emits a report-**path** block
   (a NUL-terminated `WCHAR` path, **padded to a 4-byte multiple** so the
   manifest tree that follows stays aligned — an unpadded odd-length path shifts
   the tree and makes serialized child offsets collide with the DLL's chain-flag
   low bits; `manifest_builder_test.cpp` pins this).

We use the DLL's report-**path** mode (`ManifestReport::IsReportHandle()` reads
false → `ParseFileAccessManifest` calls `CreateFileW(ReportPath, …, OPEN_ALWAYS)`
and appends), **not** the report-**pipe** mode. So `--trace` needs no pipe,
reader thread, or payload handle slot; the report path is inherited by every
child, which each open and append to it. This re-activates `SendReport.cpp` /
`ReportIfNeeded`, but nothing else (process-data/USN/detouring-status reports
stay gated behind flags we still don't set, so the trace is file-access lines
only). See README → *Debugging: `-D` and `--trace`*.

### Consequences (dead / inert code paths for us)
Because those flags/policies are off, large parts of the engine are compiled but
never meaningfully executed in our configuration:

- Timestamp normalization + short-name scrubbing (`MetadataOverrides`) —
  gated on `NormalizeReadTimestamps` / short-name flags we don't set.
- Full reparse-point resolution + `ResolvedPathCache` — gated behind
  `IgnoreFullReparsePointResolving` (which we set), so the resolver is bypassed.
- USN reporting, directory-enumeration reporting, process-arg reporting.
- The reporting subsystem (`SendReport`, most of `DebuggingHelpers`) — inert by
  default; `--trace` re-activates the file-access report path (see above).
- `DeviceMap` (stubs), `SubstituteProcessExecution` (wire-format only).

## 6. Guidance for future shrinking / extraction

Ordered by risk:

1. **Safe** — delete provably-unreferenced files. (`ConcurrentQueue.h`,
   `FileAccessManifest.h` already removed.)
2. **Low risk, contained** — remove self-contained inert features, e.g.
   `DeviceMap` (already no-op stubs; 2 call sites in `DetouredProcessInjector` +
   1 include in `DetoursHelpers`).
3. **High risk — do not treat as cleanup:**
   - Rewriting `DetoursServices.cpp` (must reproduce §4a–4d: 40 globals, 67
     `Real_` pointers, 72 `ATTACH` entries, payload parse, process-kind gating).
     Only worth it as part of a deliberate "own the whole stack" strategy.
   - Reimplementing the `DetoursHelpers` facade (§4c) — that is the security-
     critical allow/deny + classification logic; a subtle mistake is a silent
     escape, not a crash.
   - Trimming individual hooks from `DetouredFunctions.cpp` — each spans the
     `.cpp` + `DetouredFunctionTypes.h` + `globals.h` + the `ATTACH` table, and
     breaks easy re-sync from upstream.

**Do NOT touch** `DataTypes.h`'s wire-format structs (e.g.
`ManifestSubstituteProcessExecutionShim_t`) without simultaneously updating
`src/manifest_builder.cpp` — they are the byte-for-byte launcher↔DLL contract.

Because we use such a small policy/manifest subset (§5), a *future* clean-room
sandbox would only need to reproduce: the ~6 flags, the allow/deny cone-tree
policy, path canonicalization, and the ~72 file/process hooks calling a
minimal allow/deny classifier — **not** the reporting, USN, timestamp,
substitute-process, or full-reparse machinery. That is the theoretical floor if
the vendored engine is ever replaced.

## 7. Where the broader BuildXL sandbox concepts land here

BuildXL's own sandbox overview
([`Public/Src/Sandbox/.instructions.md`](https://github.com/microsoft/BuildXL/blob/main/Public/Src/Sandbox/.instructions.md))
describes several concepts. Most are **graph-construction / managed-engine or
Linux** concerns that never reach the Windows native DLL. This section records
which ones actually exist in the vendored code, so nobody goes looking for
machinery that isn't there.

| BuildXL concept | In our Windows vendor code? | Notes |
| --- | --- | --- |
| **Detours file-access monitoring** | **Yes — this is the whole engine.** | Hooks installed at DLL-load; §3–§4. |
| **Process breakaway** | **Present but unused.** | Wire type + globals exist; we emit **count 0**. See §7a. |
| **`FileAccessManifest` / `FileAccessPolicy`** | **Yes (subset).** | The manifest we build + the cone-tree policy; §4d, §5. |
| **Filesystem modes** (`/filesystemMode`, Full Graph / Minimal Pip / +Alien) | **No.** | Zero occurrences in `vendor/` or `src/`. A managed graph/fingerprint concept — it decides which files a pip *sees* for directory fingerprinting; the native DLL only enforces the concrete manifest it is handed. |
| **Sealed directories** (Full / Partial / Source / Opaque) | **No** (one stray comment only). | A managed scheduling/caching concept. Referenced only in a `DetouredFunctions.cpp` comment about report-driven dynamic-input discovery — which we don't use (no reporting, §5). |
| **`ReportedFileAccess`** | **No (managed type).** | The native side would *emit* report messages (`SendReport.cpp` + `ReportType.h`); the `ReportedFileAccess` struct that consumes them lives in BuildXL's managed `Engine/Processes`. We run with reporting off, so nothing is emitted. |
| **`SandboxedProcess`** | **No (managed).** | BuildXL's C# process wrapper. Our equivalent is `src/main.cpp` (launcher) — deliberately *not* the BuildXL one. |
| **`AccessChecker`** | **No (Linux).** | Linux EBPF/ptrace/LD_PRELOAD access validator; irrelevant on Windows (Detours does the checking inline). |
| **Linux mechanisms** (EBPF / LD_PRELOAD / ptrace) | **No.** | We vendored only `Windows/`; none of `Linux/` or `Common/`'s Linux pieces. |

### 7a. Process breakaway — present in the wire format, unused by us
Breakaway lets a named child process **escape the sandbox entirely** (BuildXL uses
it for trusted services / compiler daemons that produce no consequential
outputs). Because a breakaway process is *not monitored*, its undeclared accesses
are invisible — a deliberate hole, only safe for trusted tools.

It is wired through the vendored engine, not just referenced in passing:
- `globals.h`: `struct BreakawayChildProcess;`,
  `g_manifestChildProcessesToBreakAwayFromJob`,
  `vector<BreakawayChildProcess>* g_breakawayChildProcesses`.
- The manifest parser (`DetoursHelpers.cpp`) reads the breakaway list; the hooks
  (`DetouredFunctions.cpp`) consult it when deciding whether a spawned child is
  detoured or allowed to run free.
- Our launcher opts out: `src/manifest_builder.cpp` writes **breakaway count 0**,
  so `g_breakawayChildProcesses` is always empty and the feature is inert.

Because we never populate the list, breakaway is a genuine **shrink candidate**
(the user has confirmed we don't need it) — but note it is *not* self-contained:
removing it touches the manifest wire format (`manifest_builder.cpp` +
`DataTypes.h`), the parser, and the child-process hook path. It is higher effort
than `DeviceMap` (§6 step 2), though lower risk than rewriting the facade, since
with an empty list the relevant branches are already never taken.

### 7b. Nothing else worth adding
The remaining `.instructions.md` material (filesystem modes, sealed directories,
`ReportedFileAccess`, `SandboxedProcess`, `AccessChecker`, the Linux dual
mechanism) describes layers **above or beside** the Windows native DLL. They are
useful background for *why the manifest looks the way it does* — BuildXL computes
allow/deny policies from sealed directories and filesystem modes and bakes the
result into the `FileAccessManifest` — but there is no corresponding code in
`vendor/` to document, shrink, or maintain. For our purposes the manifest is the
API boundary, and §4d/§5 already describe the slice of it we use.
