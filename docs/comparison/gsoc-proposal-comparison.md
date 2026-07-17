# How this project compares to the "Sandboxing on Windows" GSoC proposal

This project is, in effect, an implementation of the 2018 Google Summer of Code
proposal **"Sandboxing on Windows"** by Rong Jie Loo (`rongjiecomputer`), which
proposed giving Bazel a `windows-sandbox` built on BuildXL's `DetoursServices`.
This doc compares what we built against (a) that proposal and (b) the **actual
Bazel `windows-sandbox` CLI contract** that the same author later landed in
Bazel (`WindowsSandboxUtil.java`, 2019). The second source matters more than the
first: it is the concrete integration surface a `--experimental_windows_sandbox_path`
binary must satisfy.

Sources:
- Proposal: GSoC 2018, "Sandboxing on Windows" (Bazel issue
  [#5136](https://github.com/bazelbuild/bazel/issues/5136)).
- CLI contract: `src/main/java/com/google/devtools/build/lib/sandbox/WindowsSandboxUtil.java`
  in `bazelbuild/bazel`.

## 1. Direction / architecture — we took the proposal's recommended path

| Decision | Proposal | This project |
| --- | --- | --- |
| **Language** | Weighed C# vs C++; **recommended C++** (fast startup, no .NET runtime, reuse Bazel C++, familiar to devs; con: must port some C# APIs) | **C++**. We ported BuildXL's C# `FileAccessManifest` serializer to native C++ (`src/manifest_builder.cpp`), which removes the C#→native marshalling the proposal called out as a startup-time cost. |
| **Foundation** | Use **BuildXL DetoursServices** (not raw Detours) for its Win32/symlink hook wrappers | Vendored the BuildXL **DetoursServices engine**, but link **upstream Detours from GitHub** (not BuildXL's fork) and drop **all** BuildXL managed C# code. |
| **Delivery** | Comments leaned toward a **separate binary Bazel points at** ("like sandboxfs") over an in-tree C# build | Standalone `BazelSandbox.exe`, invoked via `--experimental_windows_sandbox_path`. |
| **Build system** | Port BuildXL DScript → Bazel `BUILD` under `//third_party/BuildXLDetours` | **Bazel + rules_cc**, code under `vendor/`, upstream Detours via `http_archive`. |
| **Goal** | **I/O sandbox** to catch undeclared inputs (build correctness); escape explicitly allowed | Same. Cooperative, escapable enforcement — matches the non-goal "if the action tries to break out, it can." |

## 2. The authoritative surface: Bazel's `windows-sandbox` CLI contract

`WindowsSandboxUtil` builds the command line Bazel actually runs. It emits **only**
these flags, and we support **all** of them:

| Bazel emits | Meaning | Supported here? |
| --- | --- | --- |
| `-h` (availability probe; expects exit 0) | print usage | ✅ `-h` → usage, exit 0 |
| `-W <dir>` | working directory | ✅ |
| `-T <secs>` | timeout | ✅ |
| `-t <secs>` | kill delay after timeout | ✅ |
| `-l <file>` | redirect stdout | ✅ |
| `-L <file>` | redirect stderr | ✅ |
| `-w <path>` (repeated) | writable file/dir | ✅ |
| `-r <path>` (repeated) | readable file/dir | ✅ |
| `-b <path>` (repeated) | inaccessible file/dir | ✅ |
| `-D` | debug mode (**no argument**) | ⚠️ **see §5** — our `-D` currently *requires* a file argument |
| `--` then command | the command to run | ✅ |

**We are a superset of Bazel's contract** (we also add `-N`/`-n` network,
`--trace`, and `@response-file`). The one mismatch is `-D` (§5).

Two structural facts fall out of this file:

- **There is no `-M`/`-m` (bind mounts), no `-N`/`-n`, no `-S` (stats), no
  `-R`/`-U` (run-as-user) in the real contract.** Those proposal/linux-sandbox
  features were dropped when the Windows CLI was actually designed. So they are
  *not* integration gaps — Bazel never sends them (see §4).
- Bazel's readable set is a `Map<PathFragment, Path>` (sandbox path → real
  path), but `build()` passes **only the real paths** as `-r`. The sandbox-
  relative keys are discarded. In other words, **Bazel does not ask the sandbox
  to remap or mount paths** — it expects enforcement on the real paths, exactly
  our model.

## 3. Feature-by-feature vs. the proposal's linux-sandbox parity table

| linux-sandbox feature | Proposal's plan | This project |
| --- | --- | --- |
| RO FS, `-W`, `-w`, `-r` | reuse detoured file APIs | ✅ manifest policy cone tree (`-W`/`-w`/`-r`/`-b`) |
| `-M`/`-m` bind mounts | "no Win32 mount; reuse detours" | ❌ not implemented — **and dropped from Bazel's contract** (§4) |
| `-T` + `-t` | wait → `GenerateConsoleCtrlEvent` → `TerminateProcess` | ✅ `-T`+`-t`; force-kill via **Job Object** (no console-ctrl step) |
| tmpfs `-e` | "might never implement" (RAMDisk) | ❌ (agreed) |
| `-R`/`-U` run-as-user | `CreateProcessAsUser` | ❌ — also not in Bazel's contract |
| Kill tree on death | Windows Job Object | ✅ Job Object w/ `KILL_ON_JOB_CLOSE` |
| Network `-N` | low priority (port Chromium's) | ✅ **exceeds** — `-N` loopback + `-n` block-all via Winsock detours + `\Device\Afd` hardening |
| Fake hostname | "check purpose" | ❌ |
| PID namespace | "no Windows equivalent" | ❌ (none exists) |
| `-l`/`-L` | listed | ✅ |
| `-S` stats (protobuf) | misc | ❌ — not in Bazel's contract |
| `-D` debug | misc | ⚠️ `-D <file>` + `--trace <file>` — richer, but see §5 |

## 4. Anticipated issues — solved differently (and better)

1. **Both 32- and 64-bit DLLs required.** Proposal's workaround: check in a dummy
   32-bit DLL. We instead pass the x64 DLL for both slots and **refuse non-x64
   targets up front** (PE machine check → exit 3), so no dummy and no silent
   unsandboxed fallback. x64 only.
2. **Locked to Windows 10.0.16299 SDK** (proposal expected header collisions,
   planned to patch headers). We **retarget a modern SDK** via
   `_WIN32_WINNT=0x0A00` / `NTDDI_VERSION=0x0A000006` (see `defs.bzl`) and build
   with current MSVC — no old-SDK lock, no header patches.

## 5. Compatibility note: our `-D` diverges from Bazel's contract

Bazel's `WindowsSandboxUtil` emits `-D` **with no argument** (a boolean, gated on
`--sandbox_debug`). This project's `-D` was originally boolean too, but was later
changed to `-D <file>` for **linux-sandbox** parity (linux-sandbox's `-D` does
take a file). These two Bazel tools disagree, and our current `-D <file>` breaks
the **windows-sandbox** contract: given Bazel's `… -b X -D -- cmd`, our parser
consumes `--` as the debug-file path and then reports "missing `--`" (exit 1).

Reconciliation options (not yet applied):
- **Optional argument (recommended):** treat `-D` as boolean when the next token
  is absent, is `--`, or begins with `-`/`/`; otherwise consume it as the debug
  file. Preserves both Bazel-windows-sandbox and linux-sandbox behavior.
- Revert `-D` to boolean (Bazel-compatible) and expose the file sink under a
  separate flag (e.g. `--debug-file`).

Until reconciled, `--sandbox_debug` builds that pass `-D` would fail against this
binary.

## 6. What we don't cover
- **In-tree Bazel integration + shell-test porting** (the proposal's final phase:
  point Bazel's target at the binary, fix Unix-path assumptions in Bazel, port
  the sandbox shell tests, add a reduced GH#5640 case). We are the external
  binary; that Bazel-side work is out of scope here.
- **`-M`/`-m`, `-R`/`-U`, `-S`, fake hostname** — mostly the proposal's own
  non-goals, and none are in Bazel's windows-sandbox contract.

## 7. Should we add `-M`/`-m`? (bind mounts)

**Short answer: not worth it for Bazel; moderate work, low benefit.**

**What they do.** In linux-sandbox, `-M <source> -m <target>` bind-mounts
`source` at `target` inside the sandbox's mount namespace; combined with
`pivot_root`, this builds a *minimal view* where only declared inputs exist at
their paths and everything else is simply absent.

**Why the benefit is low here:**
1. **Bazel doesn't ask for them.** `WindowsSandboxUtil` has no `-M`/`-m` and
   discards the sandbox-relative path keys, passing only real paths as `-r`. So
   implementing them yields **zero** Bazel-integration value.
2. **Windows can't deliver the isolation that makes them valuable.** There is no
   mount namespace / `pivot_root` equivalent, so you cannot hide the rest of `C:`
   (the process still needs `C:\Windows` for system DLLs). Undeclared files stay
   reachable — which is fine, since "escape is possible" is an explicit non-goal,
   but it means `-M`/`-m` would not upgrade us from "cooperative enforcement" to
   "true isolation."
3. **Bazel already stages the execroot.** On Windows, Bazel materializes declared
   inputs (via symlinks/junctions or copies) into the execroot *before* invoking
   the sandbox. Bind-mounting is duplicate plumbing; our
   `IgnoreFullReparsePointResolving` policy already enforces on the junction path
   as-requested, interoperating with that execroot.

**What it would take (if ever needed):** parse the paired flags; for each pair
create the target as a **junction** (directories, via `FSCTL_SET_REPARSE_POINT`
or `CreateSymbolicLinkW` + `SYMBOLIC_LINK_FLAG_DIRECTORY`), a **symlink** (files
or dirs — needs `SeCreateSymbolicLinkPrivilege` / Developer Mode), or a
**hardlink** (files, same volume only, via `CreateHardLinkW`); add the target to
the read policy; clean up the links after the run; and handle the
privilege/fallback matrix. Roughly 150–250 lines plus a reparse-point helper,
privilege handling, and tests — most of the effort is in the Windows
link-creation and privilege edge cases, not the flag parsing.

**When it *would* make sense:** only if we wanted the **sandbox** (rather than
Bazel) to own execroot staging — e.g. to materialize inputs at alternate paths
without copying for a **non-Bazel / standalone** use of this binary. That is a
deliberate scope expansion, not closing an integration gap. Recommendation:
**don't implement `-M`/`-m`** unless such a concrete non-Bazel need appears.
