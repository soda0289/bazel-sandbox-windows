# Sandbox parity findings

This catalogs concrete behavioral discrepancies discovered between this Windows
sandbox and Bazel's `linux-sandbox`, together with root causes, current status,
and the test that pins each one. It complements
[`linux-sandbox-comparison.md`](linux-sandbox-comparison.md) (which is the
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
  explicit `-r`/`-w`/`-d`/tool grants (never the root baseline). The
  handle-resolution read fallback now rescues a denied symlink/junction read
  **iff its resolved target carries the marker** (`IsDeclaredInput()`). The
  rolled-up package *is* a declared input, so it is allowed; undeclared workspace
  files reached through the forest are not. `src/main.cpp` sets the marker on
  explicit grants; the guard lives in `DetouredFunctions.cpp`. See
  `docs/detours-input-filtering.md` §3.5.
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

---

## Category B - over-exposure (Goal 2)

These are hermeticity leaks measured against strict linux — i.e. things that
should be hidden under the Mode 2 (`--filter-inputs`) default (whose north star is
hermetic/RBE parity) but may still leak. (In the bare permissive-reads fallback,
reads are intentionally exposed, so Category B is only meaningful under
`--filter-inputs`/`-H`.) Most are documented as **KNOWN-GAP** or **NOTE** cases in
`enforce_limitations` / `enforce_reparse` so a future tightening pass will notice
if behavior changes.

### B1. Directory enumeration not enforced *without* `--filter-inputs` — KNOWN-GAP

* In the bare permissive fallback, `FindFirstFile`/`FindNextFile` on a denied
  directory succeeds and lists entries. File *opens* are still enforced; only the
  listing leaks. **Under `--filter-inputs`** (the `windows-sandbox` default) this
  is closed: undeclared entries are removed from enumeration results, so listings
  show only declared inputs.
* **Test:** `enforce_limitations` (enumeration case); `enforce_modes` /
  `enforce_reparse` cover the filtered behavior.

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
= hermeticity tightening (Goal 2); **P2** = polish/robustness.

1. **P1 - Bazel-side hermetic wiring.** The sandbox now defaults to permissive
   reads (matches default linux-sandbox) and takes `-H` for hermetic. Bazel's
   `WindowsSandboxedSpawnRunner` does not yet pass `-H`, so there is no way to
   request Goal-2 hermetic reads per build. Add a Bazel flag (mirroring
   `--experimental_use_hermetic_linux_sandbox`) that makes the runner pass `-H`.
   Until then the `-r` grants Bazel emits are redundant-but-harmless in permissive
   mode.
2. **P1 - B4: tighten handle-resolution to explicit allow scopes (hermetic mode).**
   Change the fallback to require an `-r`/`-w` match on the resolved target rather
   than "not denied". Gate behind e2e re-validation (pnpm, runfiles, cygwin) to
   avoid Goal-1 regressions. Flip the `enforce_reparse` allow-root `Note-Exit`
   into a gating `Assert-Exit 10` once done.
3. **P1 - B1: enforce directory enumeration (hermetic mode).** Filter
   `FindFirstFile`/`FindNextFile` results through the policy so denied entries are
   not listed. Highest-value Goal-2 item (broad info-leak surface).
4. **P1 - B2: junction-in-`-w` write escape.** Resolve write targets through
   reparse points before allowing, or refuse writes that traverse an untrusted
   junction inside a writable scope. Applies in both modes (writes are always
   confined).
5. **P2 - B3: 8.3 short-name / non-ASCII case `-b` bypass.** Canonicalize paths
   (expand short names, normalize case-fold) before matching block entries.
6. **P2 - >260 raw-path child truncation.** Child-side (CRT truncates the raw
   path before the engine sees it); not an engine bug. Kept as a `Note-Exit`.
   Only actionable by encouraging long-path-aware manifests in child tools.

Recently resolved (were P0 Goal-1 blockers): **A4** (`ng_package` rollup reading
an undeclared split-config `package.json`) and **A5** (`ng_package` packager
`exports is not defined`) — both fixed by the permissive-read default, no
`rules_angular` patch. See A4/A5 above.

---

## Where the tests live

* `tests/enforce/*.ps1` — per-category probe-driven suites
  (`scopes`, `filesystem`, `network`, `launcher`, `pathforms`, `reparse`,
  `limitations`), each dot-sourcing `tests/lib/harness.ps1`.
* `tests/probe.cpp` — the probe helper; exit codes: `0`=allowed, `10`=denied,
  `20`=other error, `30`=usage.
* Run: `bazel test //tests:all --test_output=errors` (prepend
  `C:\msys64\usr\bin` to `PATH`).
