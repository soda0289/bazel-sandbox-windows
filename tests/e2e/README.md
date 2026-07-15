# End-to-end tests (opt-in)

These tests drive the sandbox through a **real Bazel build** to validate the
**Bazel <-> sandbox integration layer**, which the probe-based enforcement suites
under `tests/enforce/` cannot cover. The probe suites verify the sandbox binary's
behavior at each Windows API surface directly; these e2e tests verify that Bazel's
`windows-sandbox` strategy actually wires the sandbox up correctly (passes
`--filter-inputs`, grants declared inputs, hides undeclared ones in a real action).

They are **not** part of `bazel test //tests:all`: they need a patched Bazel and a
network/cert environment, and they are comparatively slow. Run them manually (or in
a CI job that has the prerequisites).

## Prerequisites

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
