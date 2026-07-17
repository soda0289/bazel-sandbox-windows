# Sandbox parity findings

This catalogs concrete behavioral discrepancies discovered between this Windows
sandbox and Bazel's `linux-sandbox`, together with root causes, current status,
and the test that pins each one. It complements
[`linux-sandbox-comparison.md`](comparison/linux-sandbox-comparison.md) (which is the
architectural/feature narrative); this file is the running issue ledger.

## Framing: two reference points, two categories

> **Current model (read this first).** The `windows-sandbox` spawn strategy runs
> every action in **Mode 2 (`--filter-inputs`)**: the execroot is denied by
> default and only *declared* inputs are visible (undeclared reads report
> `NOT_FOUND`, undeclared entries are dropped from enumerations). Its north star
> is **hermetic `linux-sandbox` / remote execution (RBE)** parity — only declared
> inputs are visible — and it may be *stricter* than the default permissive
> `linux-sandbox`. The bare `BazelSandbox.exe` still has a permissive-reads
> default (a fast local fallback), but that is **not** how Bazel drives it. The
> two "goals" below are historical reference points; several early findings
> (A4/A5) were first worked around with a permissive-read default and were later
> **superseded** by the Mode 2 + marker-bit design — their entries note this.

We measure against two Linux behaviors:

* **Goal 1 - linux *default* sandbox (permissive).** The default `linux-sandbox`
  bind-mounts the real filesystem read-only and overlays the sandbox dir. Almost
  everything on the host is *readable*; only writes are confined. Our north star
  for Goal 1: **anything that reads/works under the linux default sandbox must
  also read/work under windows-sandbox, without patching individual rulesets.**
* **Goal 2 - linux *strict hermetic* sandbox.** With hermetic inputs, only
  declared inputs are visible. Our north star for Goal 2: **files that are hidden
  under strict linux should not be visible under windows-sandbox.** *This is the
  behavior the Mode 2 default now targets (hermetic/RBE parity).*

Every finding is filed under one of:

* **Category A - under-granting.** Readable/working under linux default, but
  wrongly *denied* by windows-sandbox. These are Goal-1 bugs (the more urgent
  class: they break otherwise-portable builds).
* **Category B - over-exposure.** Visible under windows-sandbox, but *hidden*
  under strict linux. These are Goal-2 hermeticity leaks.

Enforcement model recap (needed to read the findings): `-W <dir>` marks the
working dir (execroot); `-r`/`-w` add readable/writable grants; `-b` marks a path
inaccessible. **Reads have two modes.** The `windows-sandbox` strategy default is
**`--filter-inputs` (Mode 2, hermetic-style)**: the execroot is denied by default,
only `-r`/`-w` declared inputs are readable, and undeclared inputs are made
*invisible* (`NOT_FOUND` + enumeration filtering) to match hermetic
`linux-sandbox` / RBE. Without `--filter-inputs`/`-H` the bare exe is **permissive**
(whole file system readable, only writes confined) — a local fallback that mirrors
the *default* `linux-sandbox`, not the mode Bazel uses. In all modes, reads use a
hybrid check: the path *as requested* is checked first, and if denied, a
**handle-resolution fallback** resolves the reparse/final target and re-checks
*that* against the policy — but under `--filter-inputs` the fallback only rescues
targets that are **declared inputs** (carry the `DeclaredInput` marker bit),
so it cannot leak undeclared workspace files reached through the execroot symlink
forest.

---

## Category A - under-granting (Goal 1)

### A1. Runfiles / declared symlinks not materialized as readable — FIXED

* **Symptom:** actions that read through `*.runfiles` trees or `external/`
  junctions were denied.
* **Root cause:** declared link paths weren't being granted; the engine saw the
  link path, not the resolved input.
* **Fix:** name-agnostic Bazel-side **key + value link-path grant** — Bazel emits
  a read grant for every link path it creates (runfiles links, cygwin reparse
  opens, `CreateProcess` image path). Covers runfiles and `external/` uniformly
  without name matching.
* **Status:** Fixed (Bazel patch, see `files/bazel-windows-sandbox.patch`).
* **Test:** `enforce_reparse` — "read through declared junction (-r on link)
  allowed", "read declared file symlink ... allowed".

### A2. pnpm intra-store junctions (undeclared) denied — FIXED (handle-resolution)

* **Symptom:** node tooling reading through pnpm's `.pnpm` store junctions was
  denied; the junction target is a real declared input but the *link path* the
  tool opens is not itself granted.
* **Root cause:** the tool opens an undeclared junction whose resolved target
  *is* a granted input. Path-as-requested enforcement can't see that.
* **Fix:** **handle-resolution read fallback** in `DetouredFunctions.cpp`
  (`Detoured_CreateFileW` / `Detoured_NtCreateFile` / `Detoured_ZwCreateFile`):
  on a denied read with a valid final handle, resolve the target
  (`DetourGetFinalPathByHandle`) and re-check it; adopt the result if the
  resolved target is not denied. This is name-agnostic (replaced the earlier
  `.runfiles`/`node_modules` name-based "readable cone").
* **Behavior, precisely:** an undeclared junction is allowed **iff its resolved
  target is a declared input** — under `--filter-inputs` this means the target
  carries the `DeclaredInput` marker bit (`IsDeclaredInput()`), not merely
  "not denied" (see A4 and B4). It is denied/hidden if the resolved target is only
  readable via the whole-disk baseline or lands in a denied region.
* **Status:** Fixed.
* **Test:** `enforce_reparse` — "read through undeclared junction to -r-granted
  target allowed" (positive), "read through undeclared junction to denied target
  denied" (still enforced).

### A3. Absent optional input under `-r` returned ACCESS_DENIED instead of ENOENT — FIXED

* **Symptom:** tools probing for optional inputs (node module resolution,
  OpenSSL config discovery, `stat` of a maybe-file) got `ACCESS_DENIED` for a
  *non-existent* path under a read scope, instead of `FILE_NOT_FOUND`. Under
  linux default these probes just see ENOENT and move on.
* **Root cause:** read scopes denied non-existent paths.
* **Fix:** read scopes carry `Policy_AllowReadIfNonExistent`, so an absent path
  under `-r` reports not-found (matching `-w` and linux/local).
* **Status:** Fixed.
* **Test:** `enforce_filesystem` — "read absent file under -r reports not-found"
  (and the `-w` counterpart). *This is exactly the assertion the false-green
  harness had been hiding.*

### A4. `ng_package` rollup reads a declared input through the execroot symlink forest — FIXED (marker bit)

* **Symptom:** `ng_package`'s Rollup action (`AngularPackageRollup`) failed under
  the `windows-sandbox` (Mode 2 / `--filter-inputs`) with `EPERM` opening a
  package it reaches via `--preserveSymlinks` + ambient `node_modules`. Confirmed
  denied path:
  `...\execroot\_main\bazel-out\x64_windows-fastbuild-ST-<hash>\bin\...\node_modules\@shui\core-ng\package.json`.
* **Root cause:** the Windows sandbox runs **in place** in the real execroot,
  whose top-level entries (`_main/*`) are per-entry symlinks/junctions into the
  real workspace source tree. The file is reached through that symlink forest.
  Under Mode 2 the execroot is denied-by-default; the read of the *link path* was
  denied, and the handle-resolution fallback could not safely adopt the resolved
  target without risking a leak of *undeclared* workspace files reachable via the
  same whole-disk read baseline.
  > A short-lived earlier workaround made the default **permissive-read** (whole
  > execroot readable) so this "just worked"; that was **rejected and superseded**
  > because it broke hermetic/RBE parity (undeclared bazel-out files became
  > visible). No `rules_angular` patch and no filename special-casing were used.
* **Fix:** the `DeclaredInput` **marker bit** (`0x2000`), OR'd only into
  explicit `-r`/`-w`/output-dir/tool grants (never the root baseline). The
  handle-resolution read fallback now rescues a denied symlink/junction read
  **iff its resolved target carries the marker** (`IsDeclaredInput()`). The
  rolled-up package *is* a declared input, so it is allowed; undeclared workspace
  files reached through the forest are not. `src/main.cpp` sets the marker on
  explicit grants; the guard lives in `DetouredFunctions.cpp`. See
  `docs/design/detours-input-filtering.md` §3.5.
* **Status:** Fixed. Verified end to end: `:pkg` (and `:pkg_apf`) build cleanly
  under the `windows-sandbox` (Mode 2) with no ESM/EPERM error.
* **Test:** `enforce_reparse` — declared-input-through-junction cases; the
  end-to-end proof is the fusion `:pkg` build.

### A5. `ng_package` packager: `exports is not defined in ES module scope` — FIXED (same root cause as A4)

* **Symptom:** the `ng_package` packager (`AngularPackage`, the "Bundling APF"
  action) failed under the Mode 2 sandbox with `ReferenceError: exports is not
  defined in ES module scope`. Non-sandboxed and permissive-mode it succeeds.
* **Root cause (corrected):** `rules_js` patches node so module resolution does
  **not** realpath symlinks - node keeps the **logical** (symlink) path. During
  module-type resolution node therefore walks *up the logical path inside the
  execroot* reading `package.json` files. Under Mode 2 an intermediate
  `package.json` (the one that would classify the emitted `index.js` as CommonJS,
  or provide `exports`) was reached through the execroot symlink forest and, being
  a declared input read through a link, got denied — so node kept walking to the
  execroot-root `package.json` (`"type":"module"`) and treated the CommonJS file
  as ESM → `exports is not defined`. It is the *same* declared-input-through-the-
  symlink-forest problem as A4, surfaced through node's `package.json` walk instead
  of Rollup's resolver.
* **Fix:** the A4 marker-bit fix. With declared inputs reached through the forest
  allowed (and undeclared ones still hidden), node finds the correct nearer
  `package.json` and classifies the module correctly. No ruleset patch, no
  filename special-casing.
* **Status:** Fixed. Verified: the packager action succeeds under the
  `windows-sandbox` (Mode 2) in the same `:pkg`/`:pkg_apf` build.
* **Test:** covered by `enforce_reparse` (declared input reached through a
  junction/symlink is readable); the end-to-end proof is the `:pkg` build.

### A6. JavaBuilder scratch created in one process, read/cleaned in another — FIXED (cross-process created-set)

* **Symptom:** under `--execroot-writable` (Mode 2), Java compile actions produced
  **corrupt/empty class jars** and hit `DirectoryNotEmptyException` /
  "cannot clean `_javac/*_classes`" failures (e.g. `AddJarManifestEntry`,
  `analysis_cache_clear_event`). A reduced→full classpath re-execution of the same
  Java action could also inherit stale scratch.
* **Root cause:** `JavaBuilder` (and other forking tools) **create scratch in one
  process and read/clean it in another**. The "files created by the tree" set that
  `--execroot-writable` consults (to allow re-write / read-back / delete of a path
  the tree created, while still denying clobber of pre-existing undeclared inputs)
  was originally **per-process**. So the second process could not see the first
  process's creations: it read an empty/hidden `_classes` tree (empty jar) and its
  recursive clean left non-empty dirs (`RemoveDirectory` → `ACCESS_DENIED`).
* **Fix:** the created-set is a **cross-process** append-only log in a named
  shared-memory region the launcher creates per invocation; every injected DLL in
  the tree attaches to it. The region name is carried in the **manifest payload**
  (`g_bazelCreatedShmName`, parsed in `ParseFileAccessManifest`), so it is
  re-copied verbatim to every child on injection and propagates independent of the
  child's environment block (a child spawned with a custom env can't drop it). Now
  any process in the tree sees any path the tree created. Name-agnostic; no
  JavaBuilder special-casing. See `PolicyResult.cpp` (`CreatedFilesTracker`) and
  `docs/design/detours-input-filtering.md`.
* **Status:** Fixed. Verified end to end: the previously-failing
  `AddJarManifestEntry` / `analysis_cache_clear_event` Java actions build
  successfully; a full `//src:bazel` build ran **1,264 windows-sandbox Javac
  actions with zero sandbox-class failures** (green, matching the local baseline).
* **Test:** `enforce_modes` — "cross-process read of tree-created file allowed" and
  "cross-process delete of tree-created file allowed" (parent probe creates the
  file, a separate spawned child probe reads/deletes it; a per-process-only set
  would deny/hide it in the child).

### A7. Undeclared scratch left in the in-place execroot between actions — FIXED (discard-on-exit)

* **Symptom:** because the `windows-sandbox` runs **in place** in the real execroot
  (not a throwaway copy), undeclared scratch a tool created could persist after the
  action exited and be inherited by a later action or a reduced→full classpath
  re-run of the same action — unlike `linux-sandbox`, which discards its writable
  execroot overlay after every action.
* **Root cause:** no post-action cleanup of the tree's undeclared creations.
* **Fix:** the launcher discards on exit exactly the undeclared files/dirs recorded
  in the cross-process created-set (A6), matching linux-sandbox's throwaway
  execroot. Declared `-w` outputs and pre-existing undeclared files are **not** in
  the created-set and survive. Skipped under `-D` (`--sandbox_debug`), which keeps
  scratch for inspection. See `src/main.cpp` (`CleanupCreatedScratch`).
* **Status:** Fixed.
* **Test:** `enforce_modes` cleanup section — scratch file/dir removed after exit,
  child-process-created scratch removed after exit (cross-process cleanup), declared
  `-w` output preserved, pre-existing undeclared file preserved, scratch preserved
  under `-D`.

---

## Category B - over-exposure (Goal 2)

These are hermeticity leaks measured against strict linux — i.e. things that
should be hidden under the Mode 2 (`--filter-inputs`) default (whose north star is
hermetic/RBE parity) but may still leak. (In the bare permissive-reads fallback,
reads are intentionally exposed, so Category B is only meaningful under
`--filter-inputs`/`-H`.) Most are documented as **KNOWN-GAP** or **NOTE** cases in
`enforce_limitations` / `enforce_reparse` so a future tightening pass will notice
if behavior changes.

### B1. Directory enumeration — FIXED under `--filter-inputs` (default); leaks only in the bare permissive fallback

* **Under `--filter-inputs`** (the `windows-sandbox` strategy default) this is
  **closed**: undeclared entries are filtered out of `FindFirstFile`/`FindNextFile`
  and `NtQueryDirectoryFile`/`ZwQueryDirectoryFile` results, so a listing shows
  only declared inputs (matching hermetic linux-sandbox).
* **Residual (bare permissive fallback only, not how Bazel drives it):** with no
  `--filter-inputs`/`-H`, `FindFirstFile`/`FindNextFile` on a denied directory
  succeeds and lists entries (file *opens* are still enforced; only the listing
  leaks). Reads are intentionally exposed in that mode, so there is nothing to
  leak relative to its contract.
* **Test:** `enforce_modes` / `enforce_reparse` cover the filtered (default)
  behavior; `enforce_limitations` pins the permissive-fallback listing leak.

### B2. Junction-in-`-w` escape — KNOWN-GAP

* A writable scope containing an attacker-planted junction can redirect writes
  outside the scope (the write follows the junction).
* **Test:** `enforce_limitations` (reparse-escape case).

### B3. 8.3 short-name and non-ASCII case bypass of `-b` blocks — KNOWN-GAP

* A `-b` (block) entry can be bypassed via an 8.3 short name or a non-ASCII
  case-fold variant of the path.
* **Test:** `enforce_limitations` (short-name / non-ASCII cases).

### B4. Handle-resolution allowed undeclared links to merely-readable targets — FIXED under `--filter-inputs` (marker bit)

* **What (original A2 behavior):** the A2 handle-resolution fallback adopted the
  resolved target's policy whenever it was *not denied*. An undeclared junction
  resolving to a target that sits **outside the `-W` execroot** (the read-only
  root) would be allowed even though the *link path* was denied — a Goal-2 leak.
* **Fix:** the A4 `DeclaredInput` **marker bit** implements exactly the
  tightening option this entry used to defer. Under `--filter-inputs` the fallback
  now adopts the resolved target **only if it is a declared input**
  (`IsDeclaredInput()`), not merely "not denied". So an undeclared junction whose
  target is only readable via the whole-disk baseline is now **denied/hidden**,
  while a junction to a genuinely declared input is allowed. This closes the leak
  without regressing legitimate declared-input reads (A2/A4).
* **Residual:** in the bare permissive fallback (no `--filter-inputs`) the old
  not-denied behavior still applies, but reads are intentionally exposed there
  anyway, so there is nothing to leak relative to that mode's contract.
* **Test:** `enforce_reparse` — declared-vs-undeclared junction-target cases
  (declared allowed, undeclared-to-baseline hidden under filtering).

### B5. Native `NtQueryAttributesFile` / `NtQueryFullAttributesFile` are not detoured — KNOWN-GAP

* **What:** the sandbox masks *stat/attribute* probes of undeclared inputs across
  every hooked variant — `GetFileAttributesW`/`GetFileAttributesExW`,
  `GetFileInformationByName`, `FindFirstFileEx`, and the `CreateFile`/`NtCreateFile`
  read-open paths — so an undeclared file reports `NOT_FOUND` rather than
  `ACCESS_DENIED` (matching linux-sandbox; see the consistency matrix in
  `tests/enforce/modes.ps1`). However the two *handle-less* NT attribute syscalls,
  `NtQueryAttributesFile` and `NtQueryFullAttributesFile` (`ntdll`), are **not
  hooked**. A process that calls them directly — bypassing the Win32 and
  `NtCreateFile` layers — can therefore learn the existence/attributes of an
  undeclared file that the hooked paths would hide. This is an *over-exposure*
  (Goal-2) gap: it leaks presence, not content.
* **Why it is low-risk in practice:** these are not the paths the Win32 stat
  surface uses. `GetFileAttributesEx`, `stat`/`_wstat`, .NET `File.Exists`,
  Node/libuv `fs.stat` (via `GetFileInformationByName` / `NtCreateFile`), and the
  Java `WindowsFileSystemProvider` all route through hooked functions. Only code
  that deliberately issues the raw `Nt*` attribute syscalls (rare outside
  low-level tooling) bypasses the mask, and even then it obtains only metadata,
  never file contents (a content read still goes through a hooked open).
* **Fix if needed:** add `Detoured_NtQueryAttributesFile` /
  `Detoured_NtQueryFullAttributesFile` mirroring the `GetFileAttributesExW` denial
  handling (resolve the `OBJECT_ATTRIBUTES` path, run the policy check, and return
  `STATUS_OBJECT_NAME_NOT_FOUND` when the read denial should be masked). This is
  the same divergence class as the `GetFileAttributesEx` masking regression — a
  hook-variant that was never exercised — so any implementation should also gain a
  probe op + a row in the `tests/enforce/modes.ps1` consistency matrix.
* **Test:** none yet (no probe op exercises the raw `Nt*` attribute syscalls).

---

## Test-infrastructure fix (not a sandbox behavior)

### T1. `pwsh_test` targets were false-green — FIXED

* **What:** every `pwsh_test` reported PASSED regardless of assertions.
* **Root cause:** `rules_powershell`'s `process_wrapper.ps1` invokes the test via
  the call operator (`& $mainPath`) inside a `try/finally`. A plain `exit N` from
  an `&`-invoked script only sets `$LASTEXITCODE` in the caller — it does **not**
  become the process exit code — so the wrapper always returned 0.
* **Fix:** `Complete-Harness` in `tests/lib/harness.ps1` now calls
  `[Environment]::Exit($code)` (a hard CLR process exit), which forces the real
  code out through the wrapper. Verified: plain `exit`=0 (broken),
  `[Environment]::Exit`=1/0 (correct).
* **Impact:** exposed A3 (absent-under-`-r`), the >260 truncation NOTE, and the
  A2 reparse recharacterization — all previously masked.

---

## Prioritized gap TODO

Ordered by impact on the two goals. **P0** = blocks real builds (Goal 1); **P1**
= hermeticity tightening (Goal 2); **P2** = polish/robustness. There are no open
P0 items — Goal-1 (nothing that reads under default linux-sandbox is wrongly
denied) is met on every repo smoke-tested to date.

1. **P1 - B2: junction-in-`-w` write escape.** Resolve write targets through
   reparse points before allowing, or refuse writes that traverse an untrusted
   junction inside a writable scope. Applies in **all** modes (writes are always
   confined, independent of the read mode), which is why it is the highest-value
   open item. **Test:** `enforce_limitations` (reparse-escape case).
2. **P2 - B3: 8.3 short-name / non-ASCII case `-b` bypass.** Canonicalize paths
   (expand short names, normalize case-fold) before matching block entries.
   **Test:** `enforce_limitations` (short-name / non-ASCII cases).
3. **P2 - B5: detour the raw NT attribute syscalls.** Add
   `Detoured_NtQueryAttributesFile` / `Detoured_NtQueryFullAttributesFile` so a
   direct `ntdll` caller cannot probe an undeclared file's existence past the
   masked Win32/`NtCreateFile` surface. Low-risk (leaks presence, not content;
   normal stat surfaces are already hooked). Mirror the `GetFileAttributesExW`
   denial masking and add a probe op + consistency-matrix row.
4. **P2 - >260 raw-path child truncation.** Child-side (CRT truncates the raw
   path before the engine sees it); not an engine bug. Kept as a `Note-Exit`.
   Only actionable by encouraging long-path-aware manifests in child tools.

Recently resolved (moved off this list):

* **A6/A7 - execroot-writable created-set is now cross-process + discarded on
  exit.** The "files created by the tree" set lives in a manifest-payload-carried
  shared-memory region (not a per-process set), so a file created in one process is
  visible/writable/deletable in any other process of the tree (fixes JavaBuilder
  empty-jar / `DirectoryNotEmptyException`), and the launcher discards those
  undeclared creations on exit (matches linux-sandbox's throwaway execroot). See
  A6/A7. Validated by a full `//src:bazel` build: 1,264 windows-sandbox Javac
  actions, zero sandbox-class failures, green (matching the local baseline).
* **Hermetic wiring is now the default, not a flag.** The design shipped as
  **Mode 2 (`--filter-inputs`) by default**: `WindowsSandboxedSpawnRunner` calls
  `setFilterInputs(true).setExecrootWritable(true)`, so Goal-2 hermetic reads are
  on for every action without a per-build flag. (The earlier plan to add a `-H`
  opt-in flag is obsolete.)
* **B1 - directory enumeration** — closed under the `--filter-inputs` default
  (undeclared entries filtered from `FindFirstFile`/`FindNextFile` and
  `Nt/ZwQueryDirectoryFile`). See B1.
* **B4 - handle-resolution tightened to declared inputs** — the `DeclaredInput`
  marker bit makes the read fallback adopt a resolved target only if it is a
  declared input, not merely "not denied". See B4.
* **A4** (`ng_package` rollup reading an undeclared split-config `package.json`)
  and **A5** (`ng_package` packager `exports is not defined`) — both fixed by the
  Mode 2 + marker-bit design, no `rules_angular` patch. See A4/A5 above.

---

## Where the tests live

* `tests/enforce/*.ps1` — per-category probe-driven suites
  (`scopes`, `filesystem`, `network`, `launcher`, `pathforms`, `reparse`,
  `limitations`), each dot-sourcing `tests/lib/harness.ps1`.
* `tests/probe.cpp` — the probe helper; exit codes: `0`=allowed, `10`=denied,
  `20`=other error, `30`=usage.
* Run: `bazel test //tests:all --test_output=errors` (prepend
  `C:\msys64\usr\bin` to `PATH`).
