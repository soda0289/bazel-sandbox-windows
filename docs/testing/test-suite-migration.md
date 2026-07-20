# Test-suite modernization plan

Status: **migration complete.** All nine enforce categories are ported to
GoogleTest `cc_test` targets (`//tests:enforce_<category>_cc`) and the PowerShell
enforce suite has been retired — `tests/lib/harness.ps1` and every
`tests/enforce/*.ps1` are deleted, and the `rules_powershell` `pwsh_test`/
`pwsh_library` wiring for enforcement is removed from `tests/BUILD.bazel`. The
e2e real-tool suites (`tests/e2e/*.ps1`) remain PowerShell for the non-hermetic
native-OS lane; a **hermetic gtest lane** has been started as one Bazel module
per scenario under `tests/e2e/<tool>/` (first: `tests/e2e/coreutils`) — see §4.

## 0. Result

All nine categories pass as GoogleTest `cc_test`s, 1:1 ports of the former
`Assert-Exit`/`Assert-True`/`Note-Exit` cases:

| target | notes |
| --- | --- |
| `enforce_filesystem_cc` | 32 cases (original pilot) |
| `enforce_scopes_cc` | scope precedence, child propagation |
| `enforce_network_cc` | `-N`/`-n` + propagation |
| `enforce_launcher_cc` | exit codes, `-T`/`-t` timing, response files, `-l`/`-L`, `-D`/`--trace`/`-S`, stdio repair, cross-bitness, CLI errors, arg round-trip |
| `enforce_pathforms_cc` | canonicalization + non-ASCII |
| `enforce_reparse_cc` | junctions always; symlinks skipped without privilege |
| `enforce_limitations_cc` | known gaps; env-dependent cases use `RecordProperty`, not asserts |
| `enforce_modes_cc` | permissive vs `-H`, `--filter-inputs` matrix, `--execroot-writable`, cleanup-on-exit |
| `enforce_overlay_cc` | Model W write-overlay (env-var toggled test names) |

Harness capabilities added beyond the pilot (`tests/enforce/enforce_harness.{h,cc}`):
`RunSandbox` (launcher directly, no probe/`--`/`-H`) and `RunExe` (arbitrary exe,
for `stdio_launcher` + `mklink`); tool-path accessors (`SandboxPath`/`ProbePath`/
`ProbeLpaPath`/`StdioPath`); `SetLaunchDir` (relative-scope resolution);
filesystem helpers (`Exists`/`WriteText`/`MakeDirs`/`ReadText`/`ReadWideText`/
`ReadBytes`); `CmdExe`/`SysWow64Whoami`; and `MakeJunction`/`MakeFileSymlink`/
`MakeDirSymlink`.

Extra gotchas hit during the full migration (beyond the pilot list below):
- **Non-ASCII upper-casing.** The non-ASCII case-fold gap tests need the scope
  path upper-cased like .NET `ToUpperInvariant` (folds `é`→`É`). C `towupper`
  under the default locale leaves `é` untouched, which collapses the gap. Use
  `LCMapStringW(LOCALE_INVARIANT, LCMAP_UPPERCASE, …)` (kernel32; no `user32`
  dependency, unlike `CharUpperBuffW`).
- **Static harness helpers must be `public`.** Free helper functions in a test
  translation unit (e.g. `MakeDeepDir`, `StartsWithSeedData`) can't reach
  `protected` static members; the filesystem/`ReadText` helpers are `public`.
- **`Note-Exit` → `RecordProperty`.** Environment-dependent observations (8.3
  short-name bypass, raw >260 truncation) are recorded, never asserted.

## 0b. Pilot result (filesystem)

`//tests:enforce_filesystem_cc` — 32 `TEST_F` cases, a 1:1 port of the 32
`Assert-Exit` cases in `tests/enforce/filesystem.ps1`. **All 32 pass**, matching
the PowerShell suite exactly, and faster (~8.5s vs ~14.9s wall for the target).

Files added:
- `tests/enforce/enforce_harness.h` / `.cc` — `EnforceTest` fixture: per-test
  seeded workspace (`NewWorkspace`), `RunProbe`/`RunProbeRaw` (CreateProcessW),
  runfiles-based tool resolution, `HasSymlinkPrivilege`.
- `tests/enforce/filesystem_test.cc` — the ported cases.
- `tests/BUILD.bazel` — `enforce_harness_cc` (`cc_library`) +
  `enforce_filesystem_cc` (`cc_test`); tool rlocationpaths passed via `env`
  (`ENFORCE_SANDBOX`/`ENFORCE_PROBE`/…), same `env_inherit` list as the pwsh rule.
- `MODULE.bazel` — `bazel_dep(name = "googletest", version = "1.17.0.bcr.2")`.

Gotchas hit (fold into the remaining conversions):
- **googletest version.** On **Bazel 9.1.1** the plain `googletest` `1.17.0`
  module fails analysis (its BUILD uses the native `cc_library`, removed in Bazel
  9 and not autoloaded for external repos). Use the BCR patch revision
  **`1.17.0.bcr.2`**, which adds the `load()` statements.
- **advapi32.lib.** The token-privilege APIs (`OpenProcessToken`,
  `GetTokenInformation`, `LookupPrivilegeValueW`) need `linkopts =
  ["advapi32.lib"]` on the harness library.
- **Forward-slash paths.** `TEST_TMPDIR` often uses `/`. Win32 ops tolerate it,
  but the `ntread` probe builds `\??\` + path and the NT object parser rejects
  forward slashes with `OBJECT_NAME_NOT_FOUND` (→ a spurious `kNotFound`).
  `NewWorkspace`/`Join` normalize to backslashes via `path::make_preferred()`.
- **`--enable_runfiles`** (already in `.bazelrc`) is required so `BazelSandbox.exe`
  and its co-located `DetoursServices.dll` both materialize in the test runfiles
  tree; `Runfiles::CreateForTest` + `Rlocation` resolve the exe and the DLL sits
  beside it.

## 1. Why

The tests are a first-class part of this repo, not throwaway scripts, and the
current PowerShell integration harness is hard to read and fights the language:

- `tests/lib/harness.ps1` carries a pile of workarounds that exist only because
  the driver is PowerShell launched under `rules_powershell`:
  - a `[Environment]::Exit` hack (a plain `exit N` from an `&`-invoked script only
    sets `$LASTEXITCODE` in the wrapper, so **every failing test was silently
    reported as PASS** until this was worked around);
  - `Get-CmdExe` resolves `cmd.exe` from the system directory because a bare `cmd`
    under a scrubbed `bazel test` env makes PowerShell fall back to
    `ShellExecute("cmd")`, which pops a **modal app-picker dialog** that hangs the
    test;
  - a large `env_inherit` allow-list in `tests/BUILD.bazel` just so spawned
    children can initialize and be found on `PATH`.
- Assertions are `Assert-Exit`/`Assert-True` against integer exit codes with no
  structured output, no fixtures, and manual `New-Workspace` per case.

We want BDD-style structure (fixtures / before-each / after-each, expressive
asserts) and precise process control (call `CreateProcessW` directly instead of
wrestling with how PowerShell starts commands).

## 2. The suite is three layers — decide each separately

| Layer | Files | Role | Migration verdict |
|---|---|---|---|
| **probe** | `tests/probe.cpp` (~1400 L) | The **sandboxed child**: performs one Win32 op and exits with a stable code (0 allowed / 10 denied / 11 not-found / 20 other …). | **Stays C++, unchanged.** It is the system-under-test *actor*, not a test framework. It must be a separate process to be sandboxed. |
| **enforce** | `tests/enforce/*.ps1` (9 files, ~1600 L) + `tests/lib/harness.ps1` | Launch `BazelSandbox … -- probe <op>`, assert the child's exit code. Part of `bazel test //tests:all`. | **Port to GoogleTest (`cc_test`).** This is where the PowerShell pain lives. |
| **e2e** | `tests/e2e/<tool>/` gtest modules, `smoke.ps1`, `mode2.ps1` | Drive **real tools** / **real repo builds** under the sandbox. Opt-in, not in `bazel test //tests:all`. | **Hermetic tool half ported to GoogleTest modules** (Bazel-fetched tools); Bazel-integration scripts (`smoke.ps1`/`mode2.ps1`) stay as scripts (genuine shell orchestration). |

The friction you feel is ~entirely in the **enforce** layer. `smoke.ps1` (real
repos, network, patched Bazel) is inherently non-hermetic and stays PowerShell.

## 3. enforce → GoogleTest

### Why gtest (over Pester or Catch2)

- **Direct `CreateProcessW`.** No quoting hell, no `ShellExecute` fallback, no
  exit-code-swallowing wrapper. We already have `tests/stdio_launcher.cpp` doing
  exactly this launch pattern — the driver logic already exists in C++.
- **Fixtures = before/after-each.** `TEST_F` with `SetUp()`/`TearDown()`; a
  per-case seeded workspace becomes a fixture member (replaces `New-Workspace`).
- **Parametrized `TEST_P`.** The deny/allow and mode matrices (esp.
  `enforce/modes.ps1`) collapse into table-driven parametrized cases.
- **Readable asserts + real failure diffs.** `EXPECT_EQ(kDenied, RunProbe(...))`.
- **Bazel-native.** `bazel_dep(name = "googletest")`, `--gtest_output=xml` →
  Bazel `test.xml`; runs fully hermetically as a `cc_test` (no `env_inherit`
  allow-list, no runfiles-path dance for the driver).

Catch2 offers literal BDD macros (`SCENARIO/GIVEN/WHEN/THEN/SECTION`) if the BDD
*vocabulary* matters; gtest is more standard and more Bazel-native, and its
fixture model already is before-each/after-each. **Recommendation: gtest**, unless
the team specifically wants Given/When/Then wording.

### What moves, what stays

- **Stays:** `probe.cpp`, `probe_lpa`, `stdio_launcher.cpp`, `manifest_builder_test.cpp`
  (already a plain `cc_test`).
- **Moves:** the 9 `enforce/*.ps1` category scripts + `harness.ps1` become C++
  test sources compiled into one (or a few) `cc_test` target(s). `probe.exe`
  remains a separate binary spawned by the test via `CreateProcessW`.

### Target shape (sketch, not final)

```
tests/enforce/
  enforce_harness.h / .cc     # RunProbe(sandboxArgs, probeArgs) -> exit code;
                              # Workspace fixture (SetUp seeds a.txt/src.txt/...,
                              # TearDown removes it); probe/sandbox path discovery
                              # from runfiles (rules_cc runfiles library).
  filesystem_test.cc          # TEST_F(FilesystemTest, DeleteInDeniedWorkdirDenied)
  scopes_test.cc
  network_test.cc
  … (one .cc per current category)
```

```python
# tests/BUILD.bazel (sketch)
cc_test(
    name = "enforce_filesystem",
    srcs = ["enforce/filesystem_test.cc", "enforce/enforce_harness.cc", "enforce/enforce_harness.h"],
    data = [":probe", ":probe_lpa", ":stdio_launcher", "//:BazelSandbox"],
    deps = ["@googletest//:gtest_main", "@rules_cc//cc/runfiles"],
    local_defines = _HELPER_DEFINES,
)
```

Exit-code constants (`kOk=0`, `kDenied=10`, `kNotFound=11`, `kOther=20`, …) become
a shared `enum` used by both `probe.cpp` and the test harness (single source of
truth; today they are duplicated in a comment).

### Notes / gotchas to preserve

- **Symlink-privilege skip** (`Test-SymlinkPrivilege`) → `GTEST_SKIP()` when the
  token lacks `SeCreateSymbolicLinkPrivilege`.
- **Environment-dependent NOTE cases** (`Note-Exit`) → `RecordProperty` or a
  `GTEST_SKIP` with a message; do not assert.
- **`-H` default.** The enforce suites force hermetic mode (`Invoke-Sandbox`
  prepends `-H`); the modes suite uses the raw form. Keep both entry points in the
  harness (`RunProbe` vs `RunProbeRaw`).
- **Runfiles.** Use the `rules_cc` runfiles library to resolve `BazelSandbox.exe`
  (+ co-located `DetoursServices.dll`), `probe.exe`, `probe_lpa.exe`,
  `stdio_launcher.exe` — replacing `Resolve-PathArg`.

### Migration steps (incremental, keep-green)

1. **Pilot.** Add `googletest` to `MODULE.bazel`; port **`filesystem.ps1`** only to
   `enforce_filesystem` (`cc_test`) with the new `enforce_harness`. Prove:
   CreateProcessW launch, runfiles resolution, workspace fixture, `test.xml`
   output, and parity of results with the PowerShell version (run both side by
   side).
2. **Convert** the remaining 8 categories one at a time; each retires its `.ps1`.
3. **Delete** `harness.ps1`, `lib/`, the `pwsh_test`/`pwsh_library` rules for
   enforce, and the `env_inherit` allow-list. Update `tests/BUILD.bazel`.
4. Update `docs/README.md` + `README.md` test instructions.

Effort estimate: pilot ~0.5 day; full conversion ~2–3 days (mechanical once the
harness exists). ~1600 PS lines → ~1000 C++ lines.

## 4. e2e — BDD + hermeticity

### BDD (optional)

`smoke.ps1` / `mode2.ps1` are genuine tool/shell orchestration; C++ is a poor
fit. If BDD is wanted here, use **Pester** (`Describe/Context/It/BeforeEach/
AfterEach/Should`), vendored via `http_archive` and run through `rules_powershell`.

> **Version:** use **Pester v6** — **6.0.0 is stable** (v5.9.0 is now
> maintenance-mode; only 6.1.0-alpha is prerelease). v6 introduces the new
> `Should-*` external-assertion syntax (e.g. `Should-Be`, `Should-BeString`)
> alongside the classic `Should -Be` operator, plus native parallel runs. Pin an
> exact 6.x version, vendored via `http_archive`, run on the hermetic pwsh
> toolchain we already have (§3 correction) through `rules_powershell`.

This is lower priority than the enforce→gtest port (these suites are opt-in and
their readability matters less than the always-run enforce suite).

### Hermeticity — partial, and that's correct

The real-tool matrix splits cleanly into "can be hermetic" vs "must stay OS-native".

**Can be made hermetic (Bazel-downloaded → eligible to join `bazel test`):**

| Tool | Mechanism |
|---|---|
| node | `rules_nodejs` / `rules_js` (hermetic node toolchain) |
| python | `rules_python` (downloads a hermetic interpreter) |
| java / javac | `rules_java` hermetic JDK (`remote_java_repository` — same path Bazel uses for its own JDK) |
| dotnet | `rules_dotnet` |
| uutils coreutils | `http_archive` of the prebuilt Windows release zip from GitHub (exactly like we already fetch Detours) |
| PowerShell 7 | **`rules_powershell` toolchain** (its bzlmod `powershell` extension downloads pwsh from the official PowerShell GitHub releases, integrity-pinned, per-platform). See "PowerShell interpreter" note below. |

> **PowerShell interpreter is already hermetic.** `rules_powershell` 0.2.0 does
> **not** use system PowerShell — its own `MODULE.bazel` registers a downloaded
> pwsh toolchain (`register_toolchains("@powershell_toolchains//:all")`, default
> **7.5.4**, from `github.com/PowerShell/PowerShell/releases`, integrity-pinned),
> and toolchain registration propagates transitively, so our existing `pwsh_test`
> targets already run on that downloaded pwsh — the `pwsh_binary`/`pwsh_test` rules
> carry `toolchain.pwsh` + `toolchain.all_files` in runfiles. To pin/override the
> version, add the extension to our own `MODULE.bazel`:
> `powershell = use_extension("@rules_powershell//powershell:extensions.bzl", "powershell")` +
> `powershell.toolchain(name = "...", version = "7.5.x")` + `register_toolchains`.
> Prefer this over a manual `http_archive` of pwsh7 — the ruleset already handles
> platform selection, integrity, and wiring the interpreter into the run rules.
>
> Caveat: only the **interpreter** is hermetic. A `pwsh_test` script still spawns
> whatever *other* tools it calls (`cmd.exe`, `whoami`, node, …) from the host —
> that is why the enforce suite still needs the `env_inherit` PATH allow-list, and
> why the native-OS e2e cases below stay non-hermetic.

**Cannot / should NOT be hermetic (keep opt-in, discovery-based, OS-native):**

| Tool | Why not |
|---|---|
| `cmd.exe`, Windows PowerShell 5.1 | Part of the OS; testing real OS-native API patterns against the sandbox is the *point* |
| `mklink`, `xcopy`, System32 `curl.exe` | OS built-ins; not distributable |
| msys2 GNU coreutils | Link `msys-2.0.dll`; hermetic packaging means vendoring the whole msys2 runtime. uutils already covers the coreutils behavior axis — **drop msys2 from the hermetic set** |

**Rulesets that do *not* help on Windows:**

- **`rules_shell`** ships **no shell** on Windows; `sh_test` still needs a
  system bash (git-bash/msys2). It does not provide hermeticity here.
- **`rules_powershell`** — *correction:* it **does** provide a hermetic,
  downloaded pwsh **interpreter** via its toolchain (see the PowerShell note in
  the hermetic table above); we already consume it (pwsh 7.5.4). What it does
  **not** do is sandbox the *other* tools a script spawns — `cmd.exe`, `whoami`,
  node, etc. still come from the host. So a `pwsh_test` is "hermetic interpreter,
  host-resolved spawned tools," which is fine for the enforce suite (its only
  spawned children are our own runfiles binaries + a few OS built-ins) but does
  not make the native-OS e2e cases hermetic.

### Proposed e2e outcome

Two lanes:

1. **Hermetic e2e lane** — node / python / java / dotnet / uutils / pwsh7, all
   Bazel-downloaded. This half can finally run in CI without machine setup.
2. **Native-OS lane** — cmd / PowerShell 5.1 / mklink / xcopy / System32 curl /
   tar — driven by the always-present in-box tools in the hermetic `native`
   module (so they always run; pwsh 7 is skipped when absent). These are the
   highest-signal cases (they caught the `mklink /H` NT-link-info leak,
   CopyFileEx leak, etc.) precisely *because* they exercise real Windows tools.

`smoke.ps1` (real external repos) stays exactly as-is — non-hermetic by nature.

> **Status (hermetic lane started).** The hermetic lane is implemented as
> **one Bazel module per scenario** under `tests/e2e/<tool>/` (the
> module-per-scenario pattern `rules_js` / `rules_python` / Bazel use for their
> `e2e/` dirs) rather than as extra targets in the root module. Rationale: each
> scenario pins its own tool toolchain/version independently, the heavy tool
> deps stay out of the root `MODULE.bazel`, and `bazel test //tests:all` stays
> fast (the root `.bazelignore` excludes the scenario dirs). Each scenario
> consumes the sandbox + shared harness from this repo via `local_path_override`
> and drives a gtest `cc_test` through `tests/e2e/e2e_harness.{h,cc}` (runs one
> `--write-overlay` invocation, captures stdout, asserts read-after-write +
> enumeration splice + unchanged execroot). **Landed:** `tests/e2e/coreutils`
> (uutils coreutils via `http_archive`, `cp`/`ls`/`cat`/`mkdir`). Next candidate:
> a `rules_js` module that materializes `node_modules` (thousands of overlay
> writes) as an overlay perf + correctness stress test. Running a scenario:
> `cd tests/e2e/<tool> && bazel test //...`. See `tests/e2e/README.md`.
>
> This also fixed a cross-module portability bug: `//:BazelSandbox` hardcoded
> `/MANIFESTINPUT:src/BazelSandbox.manifest` (only valid as the main workspace);
> now `$(execpath …)` so it links when consumed as `@bazel_sandbox_windows+`.

## 5. Recommended order

1. **enforce → gtest pilot** (`filesystem` only) — proves the whole approach with
   minimal churn; this is the change that removes the most pain.
2. enforce full conversion + delete `harness.ps1`.
3. e2e hermetic lane (rules_python/js/dotnet/java + uutils/pwsh7 via http_archive).
4. (Optional) Pester-ize the remaining native-OS e2e scripts.

Layer 1 (probe) and `smoke.ps1` are out of scope for migration.
