# Integrating with Bazel (`windows-sandbox` strategy)

`BazelSandbox.exe` is the launcher Bazel invokes for its `windows-sandbox` spawn
strategy. Upstream Bazel already *knows about* a `windows-sandbox` strategy, but
its wiring is incomplete: the built-in `WindowsSandboxedSpawnRunner` only passes
`-r`/`-w`/`-b`/`-D`, rejects runfiles symlink trees outright, and never enables
the input-filtering / execroot-writable / output-directory / network flags this
sandbox implements. To get behavioral parity with `linux-sandbox` / remote
execution you must run a **patched Bazel**.

[`bazel-windows-sandbox.patch`](bazel-windows-sandbox.patch) is that patch.

## What the patch does

It only touches the Java host (no native/C++ changes), completing the
`windows-sandbox` spawn runner so it drives this launcher's full contract:

| File | Change |
|------|--------|
| `.../sandbox/WindowsSandboxUtil.java` | Adds builder support for `-n`/`-N` (network), `--filter-inputs`, `--execroot-writable`, `-D <file>`, `-S <file>`; `-D` now takes a path. |
| `.../sandbox/WindowsSandboxedSpawnRunner.java` | Materializes runfiles symlink trees (like local exec); grants both the in-place link path **and** its real target for every input (name-agnostic, covers runfiles forests + pnpm store); grants the `*.runfiles_manifest` sibling; grants each declared output file as `-w` (the launcher itself pre-creates + reveals the output parent-dir chain); enables `--filter-inputs` + `--execroot-writable` ("mode 2"); wires network blocking; spills to an `@argfile` past the `CreateProcessW` 32K command-line limit. |
| `.../sandbox/WindowsSandboxedSpawn.java` | Plumbs the sandbox-debug and statistics output paths. |
| `.../exec/local/WindowsLocalEnvProvider.java` | Also sets `TMPDIR` (msys/Cygwin `mktemp` honors only `TMPDIR`, else falls back to the shared `/tmp` the sandbox denies). |
| `.../sandbox/BUILD` | Adds the `artifacts` / `runfiles_tree` / `runfiles_tree_updater` deps the above needs. |

There are **no filename special-cases** — grants are driven purely by the
action's declared inputs/outputs.

## Target version

The patch was generated against a **recent Bazel `master`** and verified to apply
cleanly with `git apply` at commit
[`a987dfc`](https://github.com/bazelbuild/bazel/commit/a987dfc9d1474455305b82c69ea04d4bb2fb49a2)
(2026-07-16). It relies on the post-9.x `SandboxOptions` **getter** API
(`getSandboxDebug()` etc.), so it does **not** apply to the `9.1.1` release tag
as-is (that release still uses public fields, e.g. `sandboxDebug`). `master`
moves, so on a later HEAD `git apply` may need `-3` (3-way merge) or `patch -p1`;
to reproduce the exact tree, check out the pinned commit above.

> This repo's [`.bazelversion`](../.bazelversion) (`9.1.1`) pins the Bazel used to
> **build this sandbox**, which is unrelated to the Bazel you patch to *consume*
> it. The consumer `bazel-dev.exe` is built from `master`.

## Applying it and building `bazel-dev.exe`

```powershell
# 1. Get the matching Bazel source (recent master; the patch uses the post-9.x
#    SandboxOptions getter API and does NOT apply to the 9.1.1 release tag).
git clone https://github.com/bazelbuild/bazel
cd bazel
git checkout a987dfc9d1474455305b82c69ea04d4bb2fb49a2   # verified; or a nearby master

# 2. Apply the patch (from this repo).
git apply --3way C:\path\to\bazel-sandbox-windows\integration\bazel-windows-sandbox.patch

# 3. Build a Bazel binary (needs an existing Bazel/Bazelisk to bootstrap).
bazel build //src:bazel

# 4. Copy it somewhere on PATH; the smoke harness expects C:\tmp\bazel-dev.exe.
Copy-Item bazel-bin\src\bazel.exe C:\tmp\bazel-dev.exe
```

## Running a build under the sandbox

```powershell
# Build the launcher + DLL in this repo first (see the top-level README):
#   bazel build //...   ->   bazel-bin\BazelSandbox.exe (+ DetoursServices.dll)

# Then, from your consumer workspace, run the patched Bazel with the strategy.
# List "local" as a fallback so actions the sandbox refuses (never ones that
# merely fail) still run.
C:\tmp\bazel-dev.exe build //... `
  --spawn_strategy=windows-sandbox,local `
  --experimental_use_windows_sandbox=yes `
  --experimental_windows_sandbox_path=C:\path\to\bazel-sandbox-windows\bazel-bin\BazelSandbox.exe `
  --enable_runfiles=yes
```

`--windows_enable_symlinks` (a **startup** option) is recommended so runfiles
trees use real symlinks instead of copies (copies are intercepted per-op by
Detours and inflate wall-clock). It requires `SeCreateSymbolicLinkPrivilege`
(Developer Mode / the privilege granted to your account).

See [`../docs/e2e/smoke-testing.md`](../docs/e2e/smoke-testing.md) for the
differential test harness (`tests/e2e/smoke.ps1`) that exercises this end-to-end
against real repos.
