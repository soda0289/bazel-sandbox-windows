# `linux-sandbox` vs. this `windows-sandbox`: flag & feature comparison

This document compares Bazel's `linux-sandbox` tool with this project's
`BazelSandbox.exe` (the Windows sandbox). It exists to answer three questions:

1. Which `linux-sandbox` flags do we already implement?
2. Which ones are intentionally **not** implemented, and why they don't make
   sense on Windows?
3. Which missing ones would actually be **useful** and are worth adding?

The authoritative `linux-sandbox` flag list is its option parser
(`src/main/tools/linux-sandbox-options.cc`, getopt string
`":W:T:t:il:L:w:e:M:m:S:h:pC:HnNRUPD:"`). Our flag list is
`ParseOptions` in `src/main.cpp`.

Related docs: [`gsoc-proposal-comparison.md`](gsoc-proposal-comparison.md)
(origin + Bazel's actual `windows-sandbox` CLI contract) and
[`vendor-architecture.md`](vendor-architecture.md) (how the engine enforces).

## 1. Two different enforcement models

The comparison only makes sense with this context: the two sandboxes enforce by
fundamentally different mechanisms, which is *why* many `linux-sandbox` flags
have no Windows analog.

| | `linux-sandbox` | this `windows-sandbox` |
| --- | --- | --- |
| **Mechanism** | Kernel **namespaces** (mount, network, PID, user) + `pivot_root`/`chroot` + `setrlimit`/cgroups | **Detours** API interception (BuildXL `DetoursServices`); each file/network call is checked against a policy manifest |
| **Isolation style** | *Constructive*: build a new filesystem/PID/net view where undeclared things are **absent** | *Enforcement*: everything is still present, but disallowed operations are **denied at the API boundary** |
| **Escapability** | Strong (kernel-enforced) | Cooperative — a determined process can bypass hooks; correctness tool, not a security boundary (same non-goal linux states) |
| **Default FS** | Whole FS visible + readable; `-w` grants writes | Whole FS **read-only** by default (root scope = allow-read); the working dir is denied, then inputs re-granted |

Because our model denies at the call site rather than hiding files, the
"namespace" family of flags (`-M/-m`, `-R/-U`, `-H`, PID) is either irrelevant or
must be emulated differently.

## 2. Flag-by-flag comparison

Legend: ✅ implemented · ➕ useful, not yet implemented · 🚫 intentionally N/A on Windows

| linux flag | Meaning (linux) | Status here | Notes |
| --- | --- | --- | --- |
| `-W <dir>` | working directory | ✅ `-W` | identical |
| `-T <secs>` | timeout → SIGTERM | ✅ `-T` | we terminate via the job object |
| `-t <secs>` | grace before SIGKILL | ✅ `-t` | force-kill via `TerminateJobObject` |
| `-l <file>` | redirect stdout | ✅ `-l` | identical |
| `-L <file>` | redirect stderr | ✅ `-L` | identical |
| `-w <path>` | make path writable | ✅ `-w` | scope → `AllowAll` |
| `-r` *(none)* | — | ✅ `-r` (**extra**) | read-only grant; needed because we default-deny the working dir. Bazel's `WindowsSandboxUtil` already emits `-r` for every readable input |
| *(bind helper)* | inaccessible via bind mount | ✅ `-b` (**extra**) | make a path inaccessible; linux does this by bind-mounting an inaccessible helper (no dedicated flag) |
| `-S <file>` | stats protobuf | ✅ `-S` | job-object accounting → `ExecutionStatistics` proto (same wire format) |
| `-D <file>` | debug output file | ✅ `-D` | launcher diagnostics; also `--trace <file>` (**extra**) for a per-access report |
| `-n` | new netns, **no** loopback | ✅ `-n` | block all network (Winsock/AFD detours) |
| `-N` | new netns **with** loopback | ✅ `-N` | loopback only |
| `-C <dir>` | put subprocesses in a cgroup (resource limits + stats) | ➕ **worth adding** | Windows analog = **Job Object limits**; see §4 |
| `-i` | SIGINT → child SIGTERM then SIGKILL | ➕ minor | Ctrl-C handling; see §4 |
| `-p` | persistent process (ignore parent death) | ➕ minor | see §4 |
| `-e <dir>` | mount empty tmpfs | 🚫 | no tmpfs on Windows; see §3 |
| `-M/-m <src>/<tgt>` | bind-mount dir read-only | 🚫 | no mount namespace; see §3 and gsoc doc §7 |
| `-h <dir>` | chroot to a hermetic sandbox root | 🚫 | no `chroot`/`pivot_root`; **note:** our `-h` means *help/usage* (Bazel's availability probe calls `windows-sandbox -h` expecting exit 0) |
| `-H` | fake hostname `localhost` | 🚫 | see §3 |
| `-R` | make uid/gid **root** | 🚫 | no uid/gid model; see §3 |
| `-U` | make uid/gid **nobody** | 🚫 | see §3 |
| `-P` | gid `tty` + writable `/dev/pts` (pty) | 🚫 | Unix pseudoterminal concept; N/A |

### Our extra flags (no linux equivalent)
- **`-r <path>`** — read-only grant. On linux the whole FS is readable and the
  execroot is *constructed* to contain only inputs; we instead default-deny the
  working dir and re-grant declared inputs, so we need an explicit read grant.
- **`-b <path>`** — make a path inaccessible. linux expresses this via a bind
  mount onto an inaccessible helper file/dir; we have a first-class flag.
- **`--trace <file>`** — per-access report from the DLL (allowed/denied events).
  A Windows-only debugging aid on top of the vendored reporting channel.

## 3. Intentionally not applicable (and why)

These are **not gaps** — they encode Unix kernel abstractions Windows lacks, and
Bazel's `WindowsSandboxedSpawnRunner` never sends them.

- **`-M`/`-m` bind mounts** — Windows has no mount namespace or `pivot_root`, so
  there is no way to build a "minimal view" where undeclared files are absent
  (the process still needs `C:\Windows` for system DLLs). Bazel already stages
  the execroot (symlinks/junctions) before invoking us, and its
  `WindowsSandboxUtil` discards the sandbox-relative path keys, passing only real
  paths as `-r`. Full analysis in [`gsoc-proposal-comparison.md`](gsoc-proposal-comparison.md) §7.
- **`-h` hermetic root (chroot)** — same root cause: no `chroot`/`pivot_root`.
  Our enforcement-by-detour model achieves hermeticity by *denial*, not by
  rebasing the filesystem root. (Our `-h` is repurposed as help.)
- **`-R`/`-U` fake root/nobody** — Windows has no uid/gid; identity is a SID +
  token. There is no cheap "become root/nobody" toggle, and build actions don't
  rely on Unix uid semantics. We evaluated this and it adds no value.
- **`-H` fake hostname** — linux sets the UTS-namespace hostname to `localhost`
  to stop actions depending on the real hostname. Windows has no UTS namespace;
  the machine/DNS name can't be faked per-process without global side effects.
  Low value for build correctness.
- **`-e` tmpfs** — no in-memory filesystem primitive equivalent to `tmpfs` that
  can be scoped to one process tree. Writable scratch dirs are handled with `-w`.
- **`-P` pseudoterminal** — Unix `/dev/pts` concept; not meaningful on Windows.

## 4. Missing flags worth adding

### `-C` → Job Object resource limits (**the one real gap; recommended**)
`linux-sandbox -C <dir>` places the subprocess tree in a cgroup, which Bazel uses
both to **enforce resource limits** (`--experimental_sandbox_memory_limit_mb`,
`--experimental_sandbox_*`) and to **gather accounting**. We already put the child
tree in a **Job Object** and now read accounting out of it for `-S`; Job Objects
can *also* enforce limits:

- **Memory:** `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.JobMemoryLimit`
  (`JOB_OBJECT_LIMIT_JOB_MEMORY`) — kill/deny when the tree exceeds a byte cap.
- **CPU:** `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` (hard-cap % or weight).
- **Active process count / affinity / priority:** basic limit flags.

Proposed shape: a `--memory-limit-mb <n>` (and possibly `--cpu-rate <pct>`) flag
that sets the corresponding Job Object limit before `ResumeThread`, mapping onto
Bazel's existing sandbox limit options. **Work:** moderate (~50–100 lines +
tests); the Job Object already exists, so this is mostly `SetInformationJobObject`
calls and option plumbing. **Benefit:** real — brings resource-limit parity and
lets `--experimental_sandbox_memory_limit_mb` work on Windows. This is the
recommended next feature.

### `-i` → forward Ctrl-C to the child (**minor, nice-to-have**)
linux's `-i` makes a SIGINT reach the child as SIGTERM-then-SIGKILL so
interactive cancels are clean. The Windows analog is a console control handler
(`SetConsoleCtrlHandler`) that, on `CTRL_C_EVENT`/`CTRL_BREAK_EVENT`, calls
`TerminateJobObject` (optionally after the `-t` grace). Today a Ctrl-C from the
console likely already reaches the child via the shared console group, but wiring
it explicitly would guarantee the whole tree dies and mirror linux semantics.
**Work:** small. **Benefit:** low-to-moderate (cleaner interactive cancels).

### `-p` → persistent process / ignore parent death (**low value**)
linux's `-p` detaches the child from parent-death signals. On Windows there is no
parent-death signal by default, and our Job Object is intentionally
`KILL_ON_JOB_CLOSE` so the tree dies with the launcher — the *opposite* of `-p`.
Implementing it would mean dropping that flag conditionally. **Benefit:** low; no
known Bazel driver for it on Windows. Document as deliberately omitted unless a
concrete need appears.

## 5. Summary

- **Core parity achieved.** Every flag Bazel's `WindowsSandboxUtil` emits
  (`-W -T -t -l -L -w -r -b -D`), plus `-N/-n` network, `-S` stats, and the
  `--trace` debug aid, is implemented and tested.
- **One meaningful gap:** `-C`-style resource **limits**, best delivered as Job
  Object memory/CPU limit flags. Recommended next.
- **Everything else** (`-M/-m`, `-h`, `-R/-U`, `-H`, `-e`, `-P`) is intentionally
  omitted because it encodes Unix kernel abstractions Windows lacks; these are
  not integration gaps and Bazel never sends them.
- **Model difference to keep in mind:** we enforce by *denying API calls*, not by
  *constructing a restricted view*. That is why our extra `-r`/`-b` exist and why
  the namespace family is inapplicable.
