# Differential smoke testing against real repos

`tests/e2e/smoke.ps1` builds a target set in a real open-source Bazel repo
**twice** — once under `--spawn_strategy=local` and once under
`--spawn_strategy=windows-sandbox,local` — and **diffs the per-target results**.
This document explains the methodology, how to run it, and the findings from the
first real-repo run (aspect-build/rules_js).

See also: `tests/e2e/README.md` (usage reference), `docs/design/detours-input-filtering.md`
(the sandbox design), `docs/comparison/linux-sandbox-comparison.md` (parity model).

## Results at a glance

| Repo / target set | Config | both pass | both fail (not ours) | pass-local / **fail-sandbox** | pass-sandbox / fail-local |
| --- | --- | ---: | ---: | ---: | ---: |
| aspect-build/rules_js `examples/` `//...` (271 targets, ~23 packages) | `--enable_runfiles`, equal-length bases | 244 | 24 | **0** | 0 |
| aspect-build/rules_js `e2e/webpack_devserver` `//...` (standalone workspace) | `--enable_runfiles`, equal-length bases | 10 | 0 | **0** | 0 |
| aspect-build/rules_ts `examples/` `//...` (single workspace) | `--enable_runfiles`, equal-length bases | 558 | 83 | **0** | 116 |
| bazel-contrib/rules_dotnet `examples/` `//...` (.NET C#/F#) | runfiles + symlink (harness defaults) | 21 | 3 | **0** | 0 |
| bazelbuild/bazel `//src/main/cpp/util:util` (native MSVC cl.exe) | runfiles + symlink (harness defaults) | 1 | 0 | **0** | 0 |
| bazelbuild/bazel `//src/.../lib/util:blocker` (Javac / JavaBuilder) | runfiles + symlink (harness defaults) | 1 | 0 | **0** (after fix; see below) | 0 |
| **bazelbuild/bazel `//src:bazel`** (full self-build, 6,651 actions, **1,264 Javac sandboxed**) | symlink, fresh bases | ✅ green | 0 | **0** | 0 |
| **abseil/abseil-cpp `//absl/strings` `//absl/base` `//absl/container:flat_hash_map`** (native MSVC C++ compile + static-lib link) | symlink, fresh bases | 3 | 0 | **0** | 0 |
| GoogleContainerTools/distroless `//...` | **BLOCKED** — repo not Bazel-9-compatible (native `sh_binary`/old `rules_go`); fails at loading in both phases | — | — | — | — |
| GerritCodeReview/gitiles `//java/com/google/gitiles:servlet` | submodule (jgit), fresh bases. Needs the jgit recipe **plus** two Windows fixes: (a) add `use_default_shell_env = True` to jgit-bazlets `transform_srcjar` (`servlet_transform.bzl`) — the `run_shell` gets no PATH so `find -exec touch` can't find `touch`; (b) `--javacopt=-Xep:NullArgumentForNonNullParameter:WARN` (errorprone drift). NOT `--config=java21` (undefined; gitiles `.bazelrc` already defaults java21). | 1 | 0 | **0** | 0 |
| eclipse-jgit/jgit `//org.eclipse.jgit:jgit` (Java + POSIX-shell stamp genrule) | symlink, fresh bases | 1 | 0 | **0** | 0 |

The `pass-sandbox / fail-local` column is not a bug: those are targets that fail
under Windows `local` (execroot leakage / cross-config resolution) but **pass** under
the sandbox — i.e. the sandbox is *more* hermetic-correct than bare `local`, matching
linux-sandbox / RBE. rules_ts has 116 such targets.

**Headline: 0 genuine sandbox regressions — nothing that builds under Windows
`local` fails under `windows-sandbox`.** The 24 "both fail" are pre-existing Windows
breakage (nextjs/rspack/vite `_linux`/`_macos` platform targets etc.), independent
of the sandbox. Reaching 0 required `--enable_runfiles` (clears the rules_js Windows
runfiles gap — see below) and equal-length output-base names (design point 3). The
regression count evolved 19 → 10 → 3 → 0 as harness false positives were removed.

## Why differential, not "does it build"

The project goal is **behavioral parity with hermetic linux-sandbox / remote
execution (RBE)**, so "did the sandbox build the target" is a weak signal — a
target can fail for reasons that have nothing to do with us (a Windows toolchain
gap, a flaky rule). What matters is whether the sandbox result **agrees with the
non-sandbox result**:

| local | sandbox | meaning |
| --- | --- | --- |
| pass | **fail** | **sandbox regression** — actionable; investigate |
| fail | fail | pre-existing Windows / toolchain breakage — not ours |
| pass | pass | good |
| fail | pass | unexpected — reported for inspection |

Only `pass-local / fail-sandbox` deltas are treated as (candidate) bugs. Per-target
status is read from Bazel's Build Event Protocol (`--build_event_json_file`), so a
whole `//...` build with `--keep_going` is compared target-by-target.

### Two design points that make the comparison valid

1. **Separate output bases.** Spawn strategy is *not* part of Bazel's action-cache
   key. If both runs shared an output base, the sandbox run would get action-cache
   hits from the local run and **never actually execute under the sandbox**. The
   harness therefore uses two different `--output_user_root`s (sharing one
   `--repository_cache` so module fetches are paid once). You can confirm the
   sandbox really ran by the build summary, e.g.
   `4167 processes: … 1311 windows-sandbox`.

2. **`windows-sandbox,local` fallback, not bare `windows-sandbox`.** Bazel advances
   to the next strategy in the list only when a strategy **refuses** a spawn (cannot
   execute that action type), never when it executes and the action **fails**. So
   every sandboxable action still genuinely runs under `windows-sandbox` (fresh
   output base ⇒ no cache short-circuit), while action types the sandbox cannot
   handle at all — persistent workers, `CopyFile`, and actions explicitly requesting
   `local` — fall back to `local` instead of producing spurious *"cannot be executed
   with any of the available strategies"* failures that would masquerade as
   regressions. A bare single-strategy list inflated the first run's regression
   count from 10 to 19 with exactly these false positives.

3. **Equal-length output-base names.** Because actions run in-place under
   `<output_base>\<hash>\execroot\_main\…`, the base directory name is a constant
   prefix on *every* action path. rules_js npm packages nest very deeply and
   `bsdtar` extracts with `--directory <dir>`, which does a `chdir` into that dir.
   Windows' `SetCurrentDirectory` is hard-capped at `MAX_PATH` (259 usable chars)
   and **ignores** `longPathAware`/`\\?\`. So if the two base names differ in
   length, a deep workdir can push the tar target dir across 259 in only the
   longer-named base, producing a `tar: could not chdir` failure that looks like a
   sandbox regression but is purely a path-length artifact. The harness names both
   bases `ob_loc`/`ob_sbx` (equal length, short) so both hit the limit identically.
   This exact trap produced 3 phantom `//webpack_cli:*` regressions in an early run
   (`ob_local` vs `ob_sandbox`, 88 vs 90-char execroots → 257 vs 259-char tar dir).

> Note: enabling `--experimental_use_windows_sandbox=yes` +
> `--experimental_windows_sandbox_path=<exe>` only *registers* the strategy (under
> both the `sandboxed` and `windows-sandbox` names). It does **not** guarantee the
> strategy is selected for a given action — selection is still governed by
> `--spawn_strategy`/`--strategy`. Naming it explicitly is what forces (and proves)
> the sandbox actually ran.

## Running

```powershell
# Curated preset (see tests/e2e/smoke-repos.psd1):
pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe -Preset rules_js

# An existing checkout (skips cloning), workspace in a sub-dir:
pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
    -RepoPath C:\src\rules_js -Subdir examples -KeepArtifacts
```

> **Hermetic-parity defaults (both applied to *both* phases):** the harness passes
> `--enable_runfiles=yes` (`-EnableRunfiles`, default `$true`) and
> `--windows_enable_symlinks` (`-WindowsSymlinks`, default `$true`) for every preset,
> so runfiles trees are always materialized and use real symlinks — matching
> linux-sandbox / RBE. Pass `-EnableRunfiles $false` / `-WindowsSymlinks $false` to
> A/B against Windows' copy/manifest defaults. Repo-specific flags still go in
> `-ExtraBuildArgs` / the preset (e.g. `--lockfile_mode=off`).

> `Subdir` must point at the Bazel **workspace root** (the dir with
> `MODULE.bazel`/`WORKSPACE`), not a package inside it. `//...` is
> workspace-root-relative, so for rules_js/rules_ts `-Subdir examples` builds the
> *entire* example workspace regardless of which package you name. Pointing it at
> `examples/npm_deps` (a package) is misleading — Bazel walks up to `examples/`
> anyway and the target set is identical.

Prerequisites (same as `mode2.ps1`): a patched Bazel
(`files/bazel-windows-sandbox.patch`), a built `//:BazelSandbox`, and
network/cert trust for module resolution. Exit codes: `0` no regressions, `1`
regressions, `2` missing prerequisite, `3` environment could not resolve modules
or clone.

## Performance / overhead (sandbox vs local)

A secondary goal of this harness is to **quantify the cost of turning the sandbox
on**. Every run now prints a timing block:

```
== timing (cold build, separate output bases) ==
   local build:    123.4s
   sandbox build:  201.7s
   sandbox / local: 1.63x  (+78.3s, +63%)
```

Because each phase uses a **separate, cold output base** (the spawn strategy is not
part of the action-cache key — see design point 1), this compares a cold local build
against a cold sandbox build of the same target set: the end-to-end wall-clock a user
pays for `--spawn_strategy=windows-sandbox`. It is a *coarse upper bound*, not a
per-action microbenchmark — fetch/analysis and any `local`-fallback actions are
counted in both phases, so the true per-sandboxed-action overhead (Detours injection
+ manifest setup + copy-in/out) is diluted by work that is identical in both runs.
Larger sandboxable-action fractions push the ratio up; fetch-heavy or fallback-heavy
graphs push it toward 1.0. Recorded timings live in the `test_findings` table.

### Measured overhead

| Repo / target set | runfiles mode | local | sandbox | overhead |
| --- | --- | ---: | ---: | ---: |
| rules_js `e2e/webpack_devserver` `//...` (10 targets) | copy (default) | 237.6s | 262.5s | **1.10x** (+24.9s, +10%) |
| rules_js `e2e/webpack_devserver` `//...` (10 targets) | **symlink** (`--windows_enable_symlinks`) | 233.0s | 235.9s | **1.01x** (+2.9s, +1%) |
| rules_js `examples/` `//...` (271 targets) | **symlink** (`--windows_enable_symlinks`) | 1209.2s | 1286.4s | **1.06x** (+77.2s, +6%) |
| rules_dotnet `examples/` `//...` (24 targets, .NET) | symlink + runfiles | 241.9s | 257.5s | **1.06x** (+15.6s, +6%) |
| **bazelbuild/bazel `//src:bazel`** (full self-build, ~6,651 actions, **1,264 Javac sandboxed**) | symlink | **4050.2s** | **3869.1s** | **0.96x** (−181.1s, −4.5%) |
| **abseil/abseil-cpp** (`strings` + `base` + `container:flat_hash_map`, native MSVC C++) | symlink, fresh bases | **116.0s** | **82.5s** | **0.71x** (−33.5s, −29%) |
| **eclipse-jgit/jgit** `//org.eclipse.jgit:jgit` (Java + slow per-file `touch` stamp genrule) | symlink, fresh bases | **399.5s** | **344.9s** | **0.86x** (−54.6s, −14%) |
| **GerritCodeReview/gitiles** `//java/com/google/gitiles:servlet` (Java servlet lib; jgit submodule + ee8 `transform_srcjar`) | submodule, fresh bases | **465.8s** | **391.0s** | **0.84x** (−74.8s, −16%) |

The **`examples/` +6% is the most trustworthy figure** — a large (271-target,
~20 min) copy-heavy graph, not noise-dominated the way the 10-target
`webpack_devserver` numbers are. The 10%→1% swing on `webpack_devserver` is
partly real (copies are intercepted per-op by Detours; symlinks aren't) and partly
run-to-run / OS-file-cache variance on a tiny graph. The rules_dotnet run
independently lands at the same **1.06x (+6%)** on a different (non-JS) toolchain,
corroborating ~6% as the steady-state overhead.

**Full Bazel self-build (`//src:bazel`).** A complete `bazel-builds-bazel` run —
6,651 actions, of which **1,264 Javac actions ran under `windows-sandbox`** — took
**3869.1s** vs a **4050.2s** local baseline: the sandbox run was actually ~181s
*faster* (−4.5%). Both builds were fully green with identical action counts, so the
takeaway is that **sandboxing added no measurable overhead on this workload** — the
per-action Detours injection cost on the Javac actions is negligible relative to
compile time, and the delta is within run-to-run variance (disk-cache warmth,
background load). Methodology identical to the other rows: fresh `--output_base`
per phase, shared `--repository_cache`, `--windows_enable_symlinks`, no
`--keep_going`; only `Javac` sandboxed. This is also the run that validated the
**cross-process created-set (manifest-payload SHM)** and **discard-on-exit scratch
cleanup** end to end (see `docs/sandbox-parity-findings.md` A6/A7): the previously
JavaBuilder-failing actions (`AddJarManifestEntry`, `analysis_cache_clear_event`)
now build cleanly, zero sandbox-class failures across all 1,264 sandboxed actions.

### Runfiles: symlinks vs copies (`--windows_enable_symlinks`)

On Windows, `--enable_runfiles` (a *build* option) only decides **whether a runfiles
tree is materialized**. **How** its entries are created — symlink vs copy — is a
*separate* **startup** option, `--windows_enable_symlinks` (default `false`):

- OFF → Bazel **copies** file entries (verified: 0 file symlinks, plain-file copies).
- ON  → file entries become real **`SymbolicLink`s** — *requires*
  `SeCreateSymbolicLinkPrivilege` (Developer Mode, or the account granted the
  "Create symbolic links" right; Bazel enables it on demand). Without the privilege
  Bazel warns and falls back to copying.

Note the pnpm-style `node_modules/.aspect_rules_js` **directory junctions** rules_js
creates are unrelated: junctions need no privilege and appear in both modes. The
harness passes `--windows_enable_symlinks` to **both** phases by default
(`-WindowsSymlinks $true`) so the differential stays apples-to-apples and reflects
the recommended hermetic-parity configuration.

## Findings — aspect-build/rules_js `examples/` (first real-repo run)

`examples/` is a single Bazel workspace (one `MODULE.bazel`); its sub-dirs
(`npm_deps`, `webpack_cli`, `nextjs`, `rspack`, `vite3`/`vite6`, `worker`,
`linked_*`, …) are **packages**, so building `//...` (271 configured targets)
exercises all ~23 example packages in one run:

| bucket | count |
| --- | --- |
| both pass | 235 |
| both fail (pre-existing Windows breakage; e.g. `_linux`/`_macos` platform targets, vite/webpack) | 26 |
| **sandbox regressions** | **10** |
| sandbox-only pass | 0 |

All 10 regressions were the same class — a `js_binary` executed as the tool of a
`genrule` / `custom_rule` / worker (`run1_cjs`, `run1_mjs`, `run11`, `test10`,
`test_js_binary_under_genrule_*`, `test_js_binary_under_custom_rule`,
`webpack-config`, `worker:my_pi`, `worker:test_pi`) — all failing with:

```
FATAL: aspect_rules_js[js_binary]: the entry_point
'…/bazel-out/x64_windows-fastbuild/bin/js_binary/require_acorn.cjs' not found
```

### Root cause — a Windows runfiles-materialization gap in rules_js (NOT a sandbox bug)

1. **Windows builds no runfiles symlink tree by default** (symlinks need
   privilege / `--enable_runfiles`). The generated js_binary launcher therefore
   exports **`JS_BINARY__NO_RUNFILES=1`**.

2. In `js/private/js_binary.sh.tpl` that flag flips how the entry point is
   resolved:

   ```sh
   if [ "${JS_BINARY__USE_EXECROOT_ENTRY_POINT:-}" ] || [ "${JS_BINARY__NO_RUNFILES:-}" ]; then
       entry_point=$(resolve_execroot_bin_path "{{entry_point_path}}")   # $EXECROOT/${BAZEL_BINDIR:-$JS_BINARY__BINDIR}/…
   else
       entry_point="$JS_BINARY__RUNFILES/{{workspace_name}}/{{entry_point_path}}" # declared runfiles tree
   fi
   ```

   - **Runfiles branch (Linux):** resolves against `$JS_BINARY__RUNFILES` — the
     **declared** runfiles tree. linux-sandbox exposes exactly the declared inputs,
     so the entry point is present ⇒ **passes**.
   - **Execroot branch (Windows, NO_RUNFILES):** resolves against
     `${BAZEL_BINDIR:-$JS_BINARY__BINDIR}`. When the js_binary runs as a **genrule
     tool**, the genrule sets `BAZEL_BINDIR` to *its own* (target = `fastbuild`)
     bindir, so the launcher looks for the entry point at
     `…/x64_windows-fastbuild/bin/js_binary/require_acorn.cjs`.

3. `bazel aquery` confirms that fastbuild path is **not a declared input** of the
   genrule (only the exec-config `bin_cjs.bat` launcher + its `.runfiles` tree are).
   The file happens to exist on disk because the *same* js_binary is independently
   built in the target config elsewhere in the `//...` build — an **execroot leak**.

4. Therefore:
   - Windows **`local`** "passes" only by reading that undeclared, leaked file.
   - Windows **`windows-sandbox`** (mode 2) correctly hides undeclared files ⇒
     *not found*.
   - **Under the true north-star (RBE / hermetic linux-sandbox) this action would
     also fail**, because the undeclared fastbuild file is not in the input set. The
     sandbox is behaving correctly; it is *exposing* real non-hermeticity that plain
     `local` masks — exactly the value of differential testing.

   Note the failure is the launcher's own `[ -f "$entry_point" ]` check *before node
   ever runs*, so it is **not** related to rules_js's node symlink patches
   (`JS_BINARY__NODE_PATCHES`), which apply on both platforms.

### Proof + fix: `--enable_runfiles`

Because the divergence is "no runfiles tree on Windows", building the runfiles tree
makes Windows take the declared-runfiles branch — and the target then **passes under
the sandbox**, restoring parity **without relaxing any sandbox enforcement**:

- `//js_binary:run1_cjs` alone, under `--spawn_strategy=windows-sandbox,local
  --enable_runfiles` → **exit 0**, 3 windows-sandbox actions.
- Full `//...` differential re-run with `--enable_runfiles`: **10 → 3** (the 10
  `js_binary` failures all cleared). The remaining 3 were `//webpack_cli:*` and
  turned out to be a **harness false positive** (unequal base-name lengths crossing
  the `SetCurrentDirectory` limit — see design point 3 above), not a sandbox bug.
  With equal-length base names the expected count is **0**.

`--enable_runfiles` forces Bazel to materialize the runfiles tree. On Windows it
uses real symlinks when `SeCreateSymbolicLinkPrivilege` is available (Developer
Mode) and otherwise **falls back to copying** the tree, so it works either way (at
a disk/time cost without the privilege). It is the recommended way to run rules_js
under `windows-sandbox` (and, more generally, to get hermetic behavior on
Windows).

## Findings — other repos

### aspect-build/rules_ts `examples/` — 0 regressions
558 both-pass, 83 both-fail, **0 pass-local/fail-sandbox**, and notably **116
pass-sandbox / fail-local**: targets (`isolated_typecheck`, `package_json_usage`,
`dts_pkg`, `transpiler/custom_*`, …) that **fail under Windows `local`** — via
execroot leakage / cross-config resolution — but **pass under the sandbox**. That is
the sandbox being *more* hermetic-correct than bare `local`, matching linux-sandbox /
RBE. The 83 both-fails are pre-existing (`//deps_pkg_transpiler:*`, `//transpiler:*`,
`resolve_json_module_transpiler:*` etc.), independent of the sandbox.

### bazel-contrib/rules_dotnet `examples/` — 0 regressions
First **non-JS toolchain** exercised (.NET SDK, C#/F#: `basic_csharp`,
`basic_fsharp`, `aspnetcore`, `runfiles_csharp`/`runfiles_fsharp`, `source_generators`,
`paket`, `expecto`). **21 both-pass, 3 both-fail, 0 regressions.** The 3 both-fails
are all `dotnet publish` targets (`//aspnetcore:publish`,
`//publish_framework_dependent:publish_dependent`,
`//publish_self_contained:publish_self_contained`) that need NuGet runtime packs and
fail in *both* phases — not sandbox bugs. Confirmed **with `--enable_runfiles=yes`
forced on** (the harness default): the `runfiles_csharp`/`runfiles_fsharp` targets
pass under runfiles-tree mode as well as manifest mode, so the parity default is safe
for non-JS rules. rules_dotnet pins Bazel 9.1.1 — an exact match for our patched
fork. Cold-build overhead: **1.06x (+15.6s, +6%)**, consistent with the rules_js
`examples/` figure.

### bazelbuild/bazel `//src/main/cpp/util:util` — 0 regressions
First **native MSVC toolchain** exercised — `//src/main/cpp/util:util` is a C++
`cc_library` compiled and linked with `cl.exe`/`link.exe` (not a managed runtime like
JS or .NET). **1 both-pass, 0 both-fail, 0 regressions**, both phases exit 0. This
confirms Detours interception is transparent to a native Windows C++ compile+link
driven by Bazel — the compiler's own temp files, `#include` scanning and PDB/obj
writes all pass through the sandbox unchanged. Timing is *not* meaningful here
(local 112.1s vs sandbox 54.5s = 0.49x): a single small target is dominated by
fetch/analysis shared by both phases, and the sandbox phase benefits from OS
file-cache warmth left by the preceding local build. Use the `examples/`-scale
figures (~6%) for overhead, not this one.

### bazelbuild/bazel `//src/.../lib/util:blocker` — 1 regression (found + FIXED)
First build to exercise **JavaBuilder / Javac** actions (rules_js/ts use Node,
rules_dotnet uses C#, and `//src/main/cpp/util` is C++-only, so no prior smoke run
ran `javac`). Building `//src/main/java/com/google/devtools/build/lib/util:blocker`
under `--spawn_strategy=windows-sandbox` failed with
`java.nio.file.AccessDeniedException` on the `_javac/blocker` scratch dir.

**Root cause** (pinned via `--sandbox_debug` + `--trace`): `Files.createDirectories`
→ `WindowsFileSystemProvider.checkAccess` probes the *not-yet-existent* ancestor
dirs of the scratch path using **`GetFileAttributesEx`**. Under `--filter-inputs`
(hermetic) the execroot cone has no read bits, so that probe is denied — but
`Detoured_GetFileAttributesExW` called `DenialError()` with no argument, returning
**`ERROR_ACCESS_DENIED`**, whereas its sibling `Detoured_GetFileAttributesW` passes
`ShouldDeniedReadsAsNotFound()` and returns **`ERROR_FILE_NOT_FOUND`**. Java treats
`ACCESS_DENIED` as `AccessDeniedException` (fatal) but `FILE_NOT_FOUND` as
`NoSuchFileException` (expected — “create it”). So a single hook-variant divergence
aborted every `javac` action. Not a write-model bug; a read-denial masking gap.

**Fix**: pass `ShouldDeniedReadsAsNotFound()` in the `GetFileAttributesExW` denial
branch (it self-guards on `IsReadOnlyAccess()`, so it is a no-op on writes). A
follow-up **consistency review of every read/probe hook** found the same masking gap
in the `CopyFileW` and `CreateHardLinkW` *source*-read paths and fixed those too.
Regression cover: a new `statex` probe op plus a **data-driven consistency matrix**
in `tests/enforce/modes.ps1` that asserts every read/probe variant
(`read`/`ntread`/`reada`/`stat`/`stata`/`statex`/`statbyname`/`findfile` +
`copy`/`hardlink` source) masks identically across undeclared / absent /
absent-nested / declared states — so any future per-hook divergence is caught
automatically. After the fix the target builds under windows-sandbox (EXIT 0,
`libblocker.jar` produced, 3 sandbox actions).

### angular / angular_material — BLOCKED (Bazel-version drift, not a sandbox result)
Both angular repos' `main` pin **Bazel 8.7.0** and set
`common --incompatible_merge_fixed_and_default_shell_env` in `.bazelrc` — a flag
**removed in Bazel 9.x**. Our patched `bazel-dev.exe` is **9.1.1**, so it rejects that
rc line at option parsing and *both* phases fail identically before any action runs
(0/0/0/0). `--lockfile_mode=off` clears a separate `MODULE.bazel.lock`-version error
but not the rc-flag wall. To exercise Angular we'd need to rebase the sandbox patch
onto Bazel 8.7.0 (or sanitize the repo `.bazelrc`).

### GoogleContainerTools/distroless `//...` — BLOCKED (repo not Bazel-9-compatible)
Another version-compat wall, not a sandbox result. distroless `HEAD` still uses
**native `sh_binary`/`sh_test`** (removed from Bazel 9 native — they now require
`load("@rules_shell//shell:sh_binary.bzl", ...)`) and pins a **`rules_go`** that
breaks under Bazel 9's module-extension API (`Error: 'Facts' value has no field or
method 'clear'` in `_download_sdk`). Both phases fail **identically at the
loading/analysis phase** (local exit 48, sandbox exit 48, **0 targets configured, 0
processes**) — no spawn ever runs, so there is **zero sandbox signal** (0/0/0/0). To
exercise it we'd need the repo patched for Bazel 9 (rules_shell loads + newer
rules_go) or run under the older Bazel it targets. Low sandbox value (Linux-centric
container tooling); deprioritized.

## Recommendations

- **For consumers:** run `windows-sandbox` builds of rules_js/rules_ts workspaces
  with `--enable_runfiles` (Developer Mode enabled). Without it, JS actions rely on
  execroot leakage and are non-hermetic — they will also fail under RBE.
- **For rules_js (upstream):** the `NO_RUNFILES` execroot branch resolves a
  js_binary's *own* entry point through the caller-supplied `BAZEL_BINDIR`, which is
  wrong when the binary is a cross-config tool. Resolving the binary's own entry
  point/data through its baked-in `$JS_BINARY__BINDIR` (already the fallback in
  `resolve_execroot_bin_path`) while still using `BAZEL_BINDIR` for the working
  directory would make the no-runfiles path hermetic for genrule tools. This is an
  upstream contribution opportunity — see `docs/e2e/rules_js-windows-runfiles.md`.
