# End-to-end tests (opt-in)

These tests exercise the sandbox end-to-end in ways the probe-based enforcement
suites under `tests/enforce/` cannot. There are two flavours:

* **`realtools.ps1`** drives the sandbox binary *directly* against a broad matrix of
  **real third-party tools** (native shells/utilities, PowerShell 7 + 5.1,
  Microsoft/uutils coreutils, msys2 GNU coreutils, and the python/node/java/dotnet
  toolchains) to validate the **write-overlay VFS** against the OS-API patterns the
  synthetic `probe` cannot replicate. No Bazel required.
* **`mode2.ps1` / `smoke.ps1`** drive the sandbox through a **real Bazel build** to
  validate the **Bazel <-> sandbox integration layer** (that `windows-sandbox`
  passes `--filter-inputs`, grants declared inputs, hides undeclared ones).

They are **not** part of `bazel test //tests:all`: they need real tools / a patched
Bazel / a network+cert environment, and they are comparatively slow. Run them
manually (or in a CI job that has the prerequisites).

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
