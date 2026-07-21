# Bazel integration tests (opt-in)

These PowerShell harnesses drive the sandbox through a **real, patched Bazel build**
to validate the Bazel <-> sandbox integration layer that the hermetic gtest modules
under `tests/e2e/` and the probe suites under `tests/enforce/` structurally
cannot. They live here (not under `tests/e2e/`) because they are integration tests
of the `windows-sandbox` strategy, not hermetic tool tests, and they need a patched
Bazel + network/cert environment. They are **not** part of `bazel test //tests:all`.

* **`sandbox-strategy-smoke.ps1`** — minimal strategy-engagement smoke: proves the
  patched Bazel actually routes actions through `BazelSandbox.exe` with
  `--filter-inputs --write-overlay` (declared input builds; undeclared read is
  NOT_FOUND; undeclared write is redirected into the overlay).
* **`overlay-concurrent-write.ps1`** — regression for the "goyacc `y.output`"
  collision: two **concurrent** sandbox actions writing the same fixed-name
  undeclared scratch file into one shared in-place execroot must both succeed,
  because each action gets its own process-private write overlay. Drives
  `BazelSandbox.exe` **directly** — no patched Bazel or network needed.
* **`smoke.ps1`** — differential real-repo smoke: builds a real open-source repo
  under both `local` and `windows-sandbox` and diffs per-target results.
## Prerequisites (Bazel-driven tests below)

1. **A patched Bazel binary.** Apply `integration/bazel-windows-sandbox.patch` to a Bazel
   checkout and build a runnable binary:
   ```powershell
   cd <bazel-checkout>
   git apply <this-repo>/integration/bazel-windows-sandbox.patch   # or keep it applied
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
pwsh tests/integration/sandbox-strategy-smoke.ps1 -Bazel <bazel-checkout>\bazel-bin\src\bazel-dev.exe
```

Optional flags: `-Sandbox <BazelSandbox.exe>` (defaults to this repo's build),
`-OutputUserRoot <dir>`, `-HostJvmArgs <arg>`, `-KeepArtifacts`.

Exit codes: `0` all passed, `1` a check failed, `2` a prerequisite binary was
missing, `3` the environment could not resolve Bazel modules (test skipped).

## What `sandbox-strategy-smoke.ps1` checks

A throwaway workspace with three genrules:

| target | reads / writes | expectation under `windows-sandbox` |
| --- | --- | --- |
| `good` | reads declared input `a.txt` | builds successfully |
| `bad` | reads undeclared sibling `b.txt` | fails with **"cannot find the file"** (NOT_FOUND), not "Access is denied" |
| `overlay` | **writes** an undeclared scratch file | builds successfully — the write is redirected into the write-overlay backing store (proves `--write-overlay` is engaged), not denied |

A baseline build of a separate `baseline` target (a distinct action that also reads
`b.txt`) under `--spawn_strategy=local` first confirms `b.txt` is reachable, so the
sandboxed failure is genuinely the input filter hiding it and not a missing file. It
is a separate target from `bad` on purpose: a successful build of the identical
action would populate the action cache and the sandboxed run would get a cache hit
instead of re-executing.

## `overlay-concurrent-write.ps1` — concurrent same-name write regression

Unlike the other two harnesses, this one needs **no patched Bazel and no network** —
it drives `BazelSandbox.exe` directly. It reproduces the historical "goyacc
`y.output`" failure at the sandbox layer.

`windows-sandbox` runs in place in one shared, persistent execroot (unlike
linux-sandbox's per-action throwaway copy). Tools like `goyacc` write a fixed-name
undeclared scratch file — `y.output` — into the execroot root. Under the old
per-action created-set model, two actions racing on that path collided: while action
A held its `y.output`, concurrent action B saw the file already on disk, absent from
B's created-set, and the no-clobber guard denied it (`ERROR_ACCESS_DENIED`).

The write-overlay model fixes this structurally — Bazel's
`WindowsSandboxedSpawnRunner` creates a unique per-action temp dir and derives
`overlayDir = <action-temp>/overlay`, so every action redirects its undeclared
writes into a **private** overlay. The test launches two overlapping
`BazelSandbox.exe` invocations that both create and briefly hold `y.output` in the
same execroot root and asserts: both exit `0`, neither reports "Access is denied",
the real execroot is untouched, and each `y.output` lands in its **own** overlay
backing store.

```powershell
pwsh tests/integration/overlay-concurrent-write.ps1
```

Optional flags: `-Sandbox <BazelSandbox.exe>` (defaults to this repo's build),
`-KeepArtifacts`. Exit codes: `0` all passed, `1` a check failed, `2` a prerequisite
binary was missing.

## `smoke.ps1` — differential testing against real repos

`sandbox-strategy-smoke.ps1` proves the wiring with a synthetic action. `smoke.ps1` goes wider: it
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
pwsh tests/integration/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe -Preset rules_js

# An arbitrary repo (clone) or an existing checkout:
pwsh tests/integration/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
    -RepoUrl https://github.com/aspect-build/rules_js -Subdir examples

pwsh tests/integration/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
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
