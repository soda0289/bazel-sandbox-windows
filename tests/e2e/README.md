# End-to-end tests (opt-in)

These tests exercise the sandbox end-to-end in ways the probe-based enforcement
suites under `tests/enforce/` cannot. There are three flavours:

* **Hermetic gtest modules** (`tests/e2e/<tool>/`) drive the sandbox against a
  **Bazel-fetched, pinned real tool** and assert the **write-overlay VFS** with
  the same GoogleTest harness the enforcement suite uses. Reproducible and
  CI-friendly (the tool is downloaded + version-pinned by Bazel). See
  [Hermetic tool modules](#hermetic-tool-modules-teste2etool) below.
* **`realtools.ps1`** drives the sandbox binary *directly* against a broad matrix of
  **real third-party tools** (native shells/utilities, PowerShell 7 + 5.1,
  Microsoft/uutils coreutils, msys2 GNU coreutils, and the python/node/java/dotnet
  toolchains) to validate the **write-overlay VFS** against the OS-API patterns the
  synthetic `probe` cannot replicate. Non-hermetic: tools are discovered at
  machine paths and skipped if absent. No Bazel required.
* **`mode2.ps1` / `smoke.ps1`** drive the sandbox through a **real Bazel build** to
  validate the **Bazel <-> sandbox integration layer** (that `windows-sandbox`
  passes `--filter-inputs`, grants declared inputs, hides undeclared ones).

They are **not** part of `bazel test //tests:all`: they need real tools / a patched
Bazel / a network+cert environment, and they are comparatively slow. Run them
manually (or in a CI job that has the prerequisites).

## Hermetic tool modules (`tests/e2e/<tool>/`)

Each hermetic scenario is **its own Bazel module** (a `MODULE.bazel` per folder,
the same module-per-scenario pattern `rules_js` / `rules_python` / Bazel itself
use for their `e2e/` dirs). This lets each scenario pin its own tool toolchain
independently, keeps the heavy tool deps out of the root `MODULE.bazel`, and
keeps `bazel test //tests:all` fast. The root `.bazelignore` excludes these
dirs so the root workspace never descends into them.

How a scenario module works:

* It fetches the tool under test hermetically — e.g. `tests/e2e/coreutils`
  `http_archive`s the pinned Microsoft/uutils coreutils Windows release from
  GitHub (bump the version + `sha256` in its `MODULE.bazel` to refresh).
* It consumes the sandbox under test from this repo via `local_path_override`
  (`bazel_dep(name = "bazel_sandbox_windows")` → `path = "../../.."`), depending
  on `@bazel_sandbox_windows//:BazelSandbox` and the shared harness
  `@bazel_sandbox_windows//tests/e2e:e2e_harness`.
* The tool binaries + the launcher (with its co-located `DetoursServices.dll`)
  ride as `data`; the test resolves them from **runfiles** via env-var
  rlocationpaths (`E2E_SANDBOX`, `E2E_UU_*`, …) — no `PATH` discovery, no pwsh.

The shared harness (`tests/e2e/e2e_harness.{h,cc}`, built in the root module,
`testonly` + public) runs one `BazelSandbox --write-overlay -W <ws> -- <tool>`
invocation, captures the tool's stdout, and asserts the three overlay
invariants: (1) read-after-write, (2) enumeration splice, (3) an unchanged real
execroot. Multi-op cases sequence the tool ops inside one `cmd /c` batch because
the overlay backing store is per invocation (cmd is only the sequencer, not the
tool under test).

### Running

```powershell
cd tests/e2e/coreutils
bazel test //...
```

The first run fetches + verifies the tool archive and builds the sandbox from
this repo. Behind a TLS-inspecting proxy the module's `.bazelrc` already trusts
the Windows cert store (matches the root repo).

### Available modules

* **`coreutils`** — `http_archive`s the pinned Microsoft/uutils coreutils
  Windows release and drives `cp` (read-back + listing) and a multi-file
  enumeration case.
* **`nodejs`** — gets its Node.js interpreter from the `rules_nodejs`
  toolchain (`@nodejs_host//:node_bin`, version-pinned via
  `node.toolchain(node_version = ...)`) and adds a `rules_js` **`node_modules` write-stress** case: it
  materialises a real React + Angular dependency tree (~18k files, pinned by a
  committed `pnpm-lock.yaml`) with `npm_link_all_packages` +
  `copy_to_directory`, then has `node` copy the whole tree through the overlay,
  reads a deep file back (`@angular/core/package.json`), enumerates it, and
  asserts the thousands of writes all landed in the backing store (the real
  execroot stays empty). This exercises the overlay at scale — deep scoped
  `@scope/pkg` dirs and a high write count — which the synthetic `probe` and the
  single-file tool cases cannot. Being `rules_js`-based it fetches package
  tarballs from the npm registry at build time, so it is network-dependent (like
  `smoke.ps1`) and stays an opt-in, `.bazelignore`d module.

  It also runs two **`rules_js` `js_binary` build tests** — the "formal build"
  analogue of the hand-written script cases: instead of a bespoke script, a real
  toolchain-driven build (**vite** bundling a React app, **ngc** compiling an
  Angular app) does thousands of reads/writes through the overlay. Each drives
  the *same* native launcher `bazel run //apps/<app>:build` invokes, under the
  sandbox with the launcher's runfiles `_main` root as the write cone (`-W`); the
  bundler runs there and its output tree (`dist/`, `out/`) is redirected into the
  process-private backing store while the real runfiles tree stays byte-for-byte
  unchanged. vite prints its output summary, so its markers come from stdout;
  ngc is *silent* on success, so its test chains `&& type out\app.component.js`
  in the same invocation and asserts the Angular-only `defineComponent` marker in
  the file read back **through the overlay** — positive proof the compile emitted
  into the backing store. On Windows a `js_binary` launcher shells out to bash to
  run its `.sh` launcher (exactly what `bazel run` does), so these two tests are
  **non-hermetic**: they require **msys2 bash** at `C:\msys64\usr\bin\bash.exe`
  and self-skip if it is absent. The `-W` cone must be the **real (non-junction)
  `bazel-out` runfiles path**, never the `bazel-bin` convenience-junction form,
  or the launcher's self-location resolves output writes outside the cone
  (`EPERM`); the cc_test's runfiles library yields the real path, so it matches.

### Adding a new hermetic tool module

Copy `tests/e2e/coreutils/` to `tests/e2e/<tool>/`, then: point its
`http_archive` (or ruleset `bazel_dep`, e.g. `rules_js` for a node_modules
overlay stress test) at the new tool, wire the tool binaries into the
`cc_test`'s `data` + `env` rlocationpaths, write the `*_test.cc` against the
shared harness, and add `tests/e2e/<tool>` to the root `.bazelignore`.

## `realtools.ps1` — write-overlay VFS against real tools

Drives `BazelSandbox.exe --write-overlay` directly (no Bazel) against a matrix of
real tools, each running a small **create dir -> write file -> list -> copy ->
read back** workflow inside a single sandbox invocation. Because the backing store
is process-private and per invocation, the write and its read-back must share one
invocation. Every case asserts three things:

1. the read-back marker appears in the tool's output (overlay read-after-write);
2. the listing shows the created file (overlay enumeration splice);
3. the real execroot is byte-for-byte unchanged (every write was redirected into
   the backing store — nothing leaked onto disk).

### Why real tools (not just `probe`)

The committed `tests/enforce/` suites drive only the synthetic `probe`, which cannot
reproduce the OS-API patterns real tools use. Each family here has caught a genuine
overlay bug the probe missed, e.g. python's `os.scandir` loop (a leaked `WinError
203` from the enum snapshot), the JVM class loader's per-component path
canonicalization (in-cone classpath entries canonicalizing into the backing store),
and `CopyFile`/`CopyFileEx` (an overlay-only source coming back `NOT_FOUND` and the
destination **leaking onto the real execroot** — hit by uutils `cp` / Rust
`std::fs::copy`, native `copy`, node `fs.copyFileSync`, and .NET `File.Copy`).
The composite-op cases caught the **`mklink /H` NT-layer leak**: `cmd` creates a
hardlink via `NtSetInformationFile(FileLinkInformation)` (not `CreateHardLinkW`),
which leaked the new link onto the real execroot until `HandleFileLinkInformation`
was taught to redirect the link name into the backing store.

### Tools covered

Native `cmd` (dir/copy/findstr), PowerShell 7 and Windows PowerShell 5.1
(Get-ChildItem/Copy-Item), Microsoft/uutils coreutils and msys2 GNU coreutils
(ls/cp/cat/grep), `node`, `python`, `java` (load a class from an in-cone classpath),
`javac` (compile into the overlay) + `java`, `dotnet` (CreateDirectory / GetFiles /
File.Copy via a tiny helper built once, offline), `tar`, `xcopy`, `curl`
(`file://`), and native `cmd` composite ops (`mklink /H` hardlink, `mkdir`+`rmdir`).
Tools are discovered dynamically at machine-specific paths; any that are
absent are **skipped**, not failed.

### Running

```powershell
pwsh tests/e2e/realtools.ps1
```

Optional flags: `-Sandbox <BazelSandbox.exe>` (defaults to this repo's build) and
`-KeepArtifacts` (keep the per-case temp workspaces + generated .bat/.log scratch).

Exit codes: `0` all discovered tools passed, `1` a case failed, `2` a prerequisite
binary was missing (sandbox/DLL), `3` no real tools were found (nothing to test).

## Prerequisites (Bazel-driven tests below)

1. **A patched Bazel binary.** Apply `files/bazel-windows-sandbox.patch` to a Bazel
   checkout and build a runnable binary:
   ```powershell
   cd <bazel-checkout>
   git apply <this-repo>/files/bazel-windows-sandbox.patch   # or keep it applied
   bazel build //src:bazel-dev
   Copy-Item bazel-bin/src/bazel-dev bazel-bin/src/bazel-dev.exe
   ```
   (The stock Bazel does not pass the windows-sandbox flags these tests rely on.)

2. **The sandbox binary.** From this repo:
   ```powershell
   bazel build //:BazelSandbox
   ```
   This produces `bazel-bin\BazelSandbox.exe` with `DetoursServices.dll` beside it,
   which is the default the scripts look for.

3. **Module resolution.** Bazel needs to fetch its modules (BCR). Behind a
   corporate proxy the scripts default to trusting the Windows root cert store via
   `--host_jvm_args=-Djavax.net.ssl.trustStoreType=WINDOWS-ROOT`. Override with
   `-HostJvmArgs` (or pass `''`) if your environment differs.

## Running

```powershell
pwsh tests/e2e/mode2.ps1 -Bazel <bazel-checkout>\bazel-bin\src\bazel-dev.exe
```

Optional flags: `-Sandbox <BazelSandbox.exe>` (defaults to this repo's build),
`-OutputUserRoot <dir>`, `-HostJvmArgs <arg>`, `-KeepArtifacts`.

Exit codes: `0` all passed, `1` a check failed, `2` a prerequisite binary was
missing, `3` the environment could not resolve Bazel modules (test skipped).

## What `mode2.ps1` checks

A throwaway workspace with two genrules:

| target | reads | expectation under `windows-sandbox` |
| --- | --- | --- |
| `good` | declared input `a.txt` | builds successfully |
| `bad` | undeclared sibling `b.txt` | fails with **"cannot find the file"** (NOT_FOUND), not "Access is denied" |

A baseline build of a separate `baseline` target (a distinct action that also reads
`b.txt`) under `--spawn_strategy=local` first confirms `b.txt` is reachable, so the
sandboxed failure is genuinely the input filter hiding it and not a missing file. It
is a separate target from `bad` on purpose: a successful build of the identical
action would populate the action cache and the sandboxed run would get a cache hit
instead of re-executing.

## `smoke.ps1` — differential testing against real repos

`mode2.ps1` proves the wiring with a synthetic action. `smoke.ps1` goes wider: it
builds a target set in a **real, large open-source Bazel repo** and checks that the
sandbox result **matches** the non-sandbox result. The project's goal is parity with
hermetic linux-sandbox / RBE, so the signal we care about is not "did it build" but
"does `windows-sandbox` agree with `local`":

| local | sandbox | meaning |
| --- | --- | --- |
| pass | **fail** | **sandbox regression** — actionable, this is our bug |
| fail | fail | pre-existing Windows/toolchain breakage — not ours |
| pass | pass | good |
| fail | pass | unexpected — reported for inspection |

Per-target status is read from Bazel's Build Event Protocol
(`--build_event_json_file`), so a whole `//...` build with `--keep_going` is diffed
target-by-target. The script exits non-zero only when there is at least one
**pass-local / fail-sandbox** regression.

**Separate output bases.** The two runs use *different* `--output_user_root`s.
Spawn strategy is not part of Bazel's action-cache key, so a shared base would let
the sandbox run pick up cache hits from the local run and never actually execute
under the sandbox. The two bases share one `--repository_cache` so module/repo
fetches are paid once.

### Running

```powershell
# Curated preset (see smoke-repos.psd1):
pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe -Preset rules_js

# An arbitrary repo (clone) or an existing checkout:
pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
    -RepoUrl https://github.com/aspect-build/rules_js -Subdir examples

pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
    -RepoPath C:\src\some-repo -Subdir packages/foo -Targets //foo/... -KeepArtifacts
```

Key flags: `-Preset <name>`, `-RepoUrl`/`-Ref`/`-RepoPath`, `-Subdir` (workspace is
a sub-dir of the repo), `-Targets` (default `//...`), `-Sandbox`,
`-RepositoryCache`, `-ExtraBuildArgs`, `-HostJvmArgs`, `-KeepArtifacts`.

Exit codes: `0` no sandbox regressions, `1` one or more regressions, `2` missing
prerequisite, `3` environment could not resolve modules / clone.

### Presets (`smoke-repos.psd1`)

Curated entries, highest-signal first: `rules_js`, `rules_js_webpack_devserver`,
`rules_ts` (JS/TS ecosystem — pnpm junctions, node package.json walk-up, symlink
forests, where the hard sandbox bugs live), `angular` / `angular_material` (scoped
ng_package / ngc packages), `rules_dotnet` (.NET SDK toolchain — C#/F# compile,
publish, runfiles), `bazel_self` (native-toolchain dogfood), and `distroless`
(optional, heavyweight, Linux-centric — expect both-fail noise, low sandbox signal).
Any preset field can be overridden on the command line.
