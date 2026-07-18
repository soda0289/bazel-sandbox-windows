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
(origin + Bazel's actual `windows-sandbox` CLI contract),
[`vendor-architecture.md`](../vendor-architecture.md) (how the engine enforces), and
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md) (the running ledger of
concrete under-granting / over-exposure discrepancies, their status, and the
prioritized gap TODO), and
[`projfs-sandbox-modes.md`](../design/projfs-sandbox-modes.md) (the proposed ProjFS-based
constructive redesign — the 3 Windows sandbox modes and their linux-sandbox
parity contract).

## 1. Two different enforcement models

The comparison only makes sense with this context: the two sandboxes enforce by
fundamentally different mechanisms, which is *why* many `linux-sandbox` flags
have no Windows analog.

| | `linux-sandbox` | this `windows-sandbox` |
| --- | --- | --- |
| **Mechanism** | Kernel **namespaces** (mount, network, PID, user) + `pivot_root`/`chroot` + `setrlimit`/cgroups | **Detours** API interception (BuildXL `DetoursServices`); each file/network call is checked against a policy manifest |
| **Isolation style** | *Constructive*: build a new filesystem/PID/net view where undeclared things are **absent** | *Enforcement*: everything is still present, but disallowed operations are **denied at the API boundary** |
| **Escapability** | Strong (kernel-enforced) | Cooperative — a determined process can bypass hooks; correctness tool, not a security boundary (same non-goal linux states) |
| **Default FS** | Whole FS visible + readable; `-w` grants writes | Whole FS **read-only** by default (root scope = allow-read); reads unconfined like linux (the working dir is readable too), `-w` grants writes. `-H` opts into **hermetic reads** (working dir denied, only `-r`/`-w` inputs readable) |

Because our model denies at the call site rather than hiding files, the
"namespace" family of flags (`-M/-m`, `-R/-U`, PID) is either irrelevant or
must be emulated differently. Note our `-H` means **hermetic reads** (not
linux-sandbox's `-H` = set hostname); read-confinement is the Windows analog of
`--experimental_use_hermetic_linux_sandbox`. By default reads are permissive to
match the default linux-sandbox (see [`sandbox-parity-findings.md`](../sandbox-parity-findings.md)).

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
- **`--filter-inputs`** — the closest analogue to linux-sandbox's *symlink forest*,
  and the **default mode** the `windows-sandbox` strategy now runs in ("Mode 2",
  matching default `linux-sandbox` reads). The Bazel runner passes it on every
  spawn. It implies `-H` (hermetic reads) and additionally makes undeclared inputs
  **invisible** rather than merely denied, so builds fail the same way they would
  on Linux when an input is not declared:
  - **Denied reads are masked as `NOT_FOUND`** (Mechanism A). On Linux an
    undeclared file simply isn't in the forest, so a read returns `ENOENT`; here an
    existing-but-undeclared file reports not-found instead of access-denied.
  - **Undeclared entries are removed from directory listings** (Mechanism B). On
    Linux `readdir` over an execroot dir only ever sees the declared inputs that
    were symlinked in; here we post-filter enumeration results so an undeclared
    file/dir is not listed. Declared files and the ancestor directories that lead
    to them stay visible. This is enforced across all enumeration surfaces
    (`FindFirstFile`, `GetFileInformationByHandleEx`, and direct
    `ntdll!NtQueryDirectoryFile` — the path Node/libuv use).
  - Writes are **not** masked: an undeclared write is still `ACCESS_DENIED`, so
    missing-output declarations still fail loudly.

  See `docs/design/detours-input-filtering.md` for the full design. This gives us
  symlink-forest-like input hermeticity **without** materializing a per-action tree
  (which is prohibitively slow on Windows NTFS / ProjFS), at effectively native
  speed.

- **`--hermetic-fs`** *(planned — "Mode 3")* — layers on top of `--filter-inputs`
  to also deny reads **outside** the execroot (except a curated OS allowlist),
  matching `linux-sandbox --experimental_use_hermetic_linux_sandbox`. Bazel will
  select it via a new **`--experimental_use_hermetic_windows_sandbox`** option
  (the direct analogue of the Linux flag), and the allowlist is seeded with
  `C:\Windows\System32` (system DLLs) + other required OS locations and extended
  through the existing **`--sandbox_add_mount_pair`** option. Not yet implemented;
  see `docs/design/detours-input-filtering.md` §Modes.

- **`--execroot-writable`** — matches the fact that linux-sandbox runs in a
  **fully writable throwaway execroot**. Because the Windows sandbox runs *in
  place* in the real execroot, we cannot simply make it writable (that would let
  a tool clobber real inputs). Instead this flag lets the tool **create** new
  files/dirs anywhere in the execroot and re-write files it created *this run*,
  while still **denying overwrites** of pre-existing undeclared/input files
  (enforced via the execroot cone's `OverrideAllowWriteForExistingFiles` bit).
  The runner passes it alongside `--filter-inputs`. It covers tools that write
  undeclared scratch inside the execroot (e.g. vite's `node_modules/.vite-temp`)
  without opening a hole to overwrite declared inputs. The files it creates this
  run are tracked in a cross-process **created-set** (shared memory, so a forked
  child's creations are visible to the parent), and the launcher **discards them
  when the process tree exits** — reproducing linux-sandbox's throwaway execroot
  so no later action, or a reduced→full classpath re-execution of the same Java
  action, inherits stale scratch. Declared `-w` outputs are never in the set and
  are preserved. Cleanup is skipped under `--sandbox_debug`.
- **Output parent directories (derived from `-w`, no CLI flag)** — linux-sandbox
  pre-creates the parent directory of every declared output in its writable
  execroot, so a tool's recursive `mkdir` of its output dir is a no-op and the
  write succeeds; linux-sandbox has no output-dir flag. `BazelSandbox.exe`
  reproduces this in place: for each `-w` (output) path it derives the parent
  directory chain (strictly below the working dir), **pre-creates those dirs on
  disk**, and applies a node-only grant (read + create-directory + write on each
  exact dir) so the tool can `stat`/enumerate them and its recursive `mkdir`
  succeeds, while each dir's subtree stays denied — undeclared files inside remain
  hidden and unwritable. (There is no `-d` flag; the launcher derives everything
  from `-w`, matching linux-sandbox's flag-free model.)

### The `DeclaredInput` marker-bit fix (execroot symlink forest)

linux-sandbox builds a fresh symlink forest so declared inputs are physically
present and everything else is absent. The Windows sandbox runs in place, where
the execroot's top-level entries (`_main/*`) are themselves per-entry
symlinks/junctions into the **real workspace source tree**. That real tree is
covered by the whole-disk read baseline, so *undeclared* workspace files were
reachable through those links — a read leak absent on Linux. The fix is a policy
marker bit `FileAccessPolicy_DeclaredInput` (`0x2000`) OR'd **only** into
explicit `-r`/`-w`/output-dir/tool grants (never the root baseline). When a denied
symlink/junction read resolves to a target carrying this marker
(`IsDeclaredInput()`), the read is rescued; otherwise it stays hidden. So
declared inputs reached through the forest stay visible while undeclared
workspace files do not leak — giving the same net visibility as the Linux
forest. See `docs/design/detours-input-filtering.md`.


  > **Note on `-r` keys vs values:** the runner now grants **both** the in-place
  > execroot KEY path of each declared input **and** its real target VALUE (plus a
  > handle-resolution fallback for out-of-execroot targets). The KEYs define the
  > visible manifest tree that Mechanism B enumerates against; the VALUEs let reads
  > that resolve through junctions/symlinks succeed.

## 3. Intentionally not applicable (and why)

These are **not gaps** — they encode Unix kernel abstractions Windows lacks, and
Bazel's `WindowsSandboxedSpawnRunner` never sends them.

- **`-M`/`-m` bind mounts** — Windows has no mount namespace or `pivot_root`, so
  there is no way to build a "minimal view" where undeclared files are absent
  (the process still needs `C:\Windows` for system DLLs). Bazel already stages
  the execroot (symlinks/junctions) before invoking us, and its
  `WindowsSandboxUtil` passes each input's in-place execroot path (the key) **and**
  its real target as `-r` grants. Full analysis in [`gsoc-proposal-comparison.md`](gsoc-proposal-comparison.md) §7.
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

## 4a. In-place execution: symlink trees, runfiles, and reparse-point handling

The deepest behavioral difference is not a flag — it is *where the action runs*.
`linux-sandbox` **constructs** a private tree and **stages only the declared
inputs** into it (bind mounts / symlinks under a fresh root). This
`windows-sandbox` runs **in place in the real execroot** and denies undeclared
access at the API boundary. Two consequences fall out of that, both discovered
while getting an Angular `ngc` / `ts_project` action from a pnpm-based monorepo
to build under `--spawn_strategy=sandboxed`. The fixes live in Bazel's
`WindowsSandboxedSpawnRunner` (see `files/bazel-windows-sandbox.patch`).

**1. Runfiles trees were never materialized.** Bazel wires
`RunfilesTreeUpdater` into the local and worker spawn runners, but not into any
sandbox runner. On Linux this is masked because the sandbox stages inputs
itself; on Windows, in-place execution meant the `.runfiles` forest a node
launcher needs simply did not exist, so tools failed with `entry_point .cjs not
found`. **Fix:** call `runfilesTreeUpdater.updateRunfiles(...)` at the top of
`prepareSpawn`, collecting the `RunfilesTree`s from the flattened inputs. It is a
no-op when the links were already built by a graph action, so calling it
unconditionally is safe.

**2. KEY vs. VALUE — grant link paths + resolve on read.** `context.getInputMapping`
maps a logical execroot path (the **key**) to the artifact's real location (the
**value**). For ordinary inputs `key == value`. For the two big in-place trees
Bazel/rulesets build out of reparse points — the **runfiles forest** and the
**aspect_rules_js pnpm `node_modules` store** (packages wired together with
directory **junctions**) — `key != value`. Upstream `WindowsSandboxUtil` grants the
**values** as readable `-r` scopes (and in fact *rejects* symlink inputs outright:
`"Windows sandbox does not support unresolved symlinks yet"`), but a tool opens the
**key/link** path, which is denied. This surfaced as a cascade of denials:
`node.bat` → `node.exe` → `@angular/compiler/package.json` (a junction into the
store).

A key upfront finding shaped the fix: **reparse-point resolution cannot re-allow a
denied link path.** In `Detoured_CreateFileW`/`NtCreateFile` the access decision is
computed from the *literal* opened path's policy; the reparse machinery
(`EnforceChainOfReparsePointAccesses`) only *adds* enforcement on the link's target
(to deny escapes to undeclared files) and never converts a deny into an allow.
Reparse resolution is a hermeticity-**tightening** mechanism, not an allow
mechanism. So the sandbox keeps reparse points ignored
(`Flag_IgnoreReparsePoints | Flag_IgnoreFullReparsePointResolving`, "Mode A"), and
access is instead opened up from two complementary, **name-agnostic** angles:

   - **Bazel side — grant each input's KEY (link path) as well as its VALUE.**
     `WindowsSandboxedSpawnRunner` now grants, for every declared input, both its
     in-place execroot location (`execRoot/key` — the literal path a tool opens) and
     its real target, plus each declared symlink key. This is driven purely by the
     input map (no `node_modules`/`.runfiles` name matching) and covers the cases a
     followed handle *cannot*: cygwin/msys resolving a symlink in userspace by
     opening the reparse point itself (`FILE_OPEN_REPARSE_POINT` — the handle refers
     to the link, not the target), and `CreateProcess` of launcher `.bat` scripts.
     Both open the link path for *all* access types, so only a direct grant covers
     them.
   - **Sandbox side — handle-resolution read fallback.** When a read/probe open is
     about to be denied on its literal path but the OS already **followed** the
     reparse chain and handed us a handle to the real file,
     `Detoured_CreateFileW`/`NtCreateFile`/`ZwCreateFile` resolve that handle
     (`GetFinalPathNameByHandle`) and re-check policy on the resolved target; if the
     *target* is a granted input, the read is allowed. This covers the pnpm store's
     **intra-store package junctions**
     (`@a+cli@v/node_modules/@scope/b → @scope+b@v/...`), which the node_modules
     linker materializes on disk but does **not** declare as inputs of the consuming
     action — so no input-driven grant can reach them. It replaces the former
     name-matched `node_modules` read cone.

   - **Also needed:** `Policy_AllowReadIfNonExistent (0x4)` on the read scopes.
     `Policy_AllowRead` alone returns `ACCESS_DENIED` (not `ENOENT`) when a tool
     probes a **non-existent** path; node/OpenSSL treat that as fatal. Adding it
     only changes the error for absent paths (never exposes content) and matches
     local/Linux behavior.
   - **Also needed:** the Windows `<exe>.runfiles_manifest` (a real sibling file of
     the tree, not a symlink and not listed among the flattened inputs) is granted
     explicitly — handle-resolution cannot help it because it resolves to itself.

**Why this is name-agnostic (and better than the old cone).** The earlier approach
granted whole `.runfiles` / `node_modules` **directory cones** matched by *name*,
which was fragile and over-granted. The hybrid instead grants exactly the declared
input link paths (runfiles entries *are* declared inputs) and lets the OS resolve
the one case that is genuinely undeclared (pnpm intra-store junctions) to a granted
target. No path-name heuristics remain, and the handle-resolution fallback is
strictly *no less* hermetic than the literal check: a link whose real target is
undeclared still resolves to a non-granted path and stays denied.

**3. Parallel actions share one execroot — undeclared fixed-name scratch can
collide.** Bazel runs many actions concurrently (`--jobs`), and each sandboxed
action is its own `BazelSandbox.exe` operating **in place in the same real
execroot**. `linux-sandbox` gives every action its **own** staged tree, so two
actions never share a physical path. Because we run in place, two concurrent
actions that both write an **undeclared, fixed-name** file into their working
directory (the execroot root) target the **same** path. The `--execroot-writable`
no-clobber guard — allow if in *this action's* created-set, else deny if the file
already exists on disk (protecting undeclared inputs) — then denies whichever
action does not "own" the on-disk copy: while action A holds
`<execroot>/y.output` (created, not yet exited/discarded), concurrent action B sees
it on disk, absent from B's per-action created-set, and gets `ERROR_ACCESS_DENIED`.
`local` never hits this only because it enforces no no-clobber at all (the
undeclared write just races, last-writer-wins; the file's content is never
consumed) — i.e. it is latent non-hermeticity that `linux-sandbox` masks with
per-action trees and our in-place model surfaces as a hard denial. This was
observed with `goyacc`'s `y.output` diagnostic side-file; see
`sandbox-parity-findings.md` §A8 for the reproduction and fix directions, and §6
below for the constructive (per-action VFS) fix that removes the class entirely.

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
- **In-place execution caveat (§4a):** because actions run in the real execroot,
  Bazel must materialize runfiles trees itself, and symlink/junction trees
  (runfiles forests, pnpm `node_modules`) are handled name-agnostically by granting
  declared-input **link paths** plus a sandbox **handle-resolution** read fallback
  for undeclared intra-store junctions — no name-based cones, and no re-allowing of
  denied links (reparse resolution only tightens hermeticity).

## 6. Future directions: closing the model gap

The hybrid grant/handle-resolution mechanism (§4a) makes symlink/junction forests
work name-agnostically, but it exists only because our **destructive** enforcement
model (deny at the API call) runs in the real execroot rather than constructing a
private view. Two deeper alternatives were considered. One is a possible
fork-minimization; the other is the strategic long-term path.

### Full reparse-point resolution (not a fix for this problem)

The vendored `DetoursServices` engine already contains BuildXL's full
reparse-point chain resolver (`EnforceChainOfReparsePointAccesses` /
`ShouldResolveReparsePointsInPath` in `DetouredFunctions.cpp`). It is tempting to
think that clearing `Flag_IgnoreReparsePoints` / `Flag_IgnoreFullReparsePointResolving`
would let the sandbox follow links to their granted targets and remove the need for
link-path grants. **It does not.** As established in §4a, reparse resolution is a
hermeticity-**tightening** mechanism: it adds enforcement on a link's *target* (to
deny escapes to undeclared files) but never converts a denied link path into an
allowed one. The access decision is still computed from the literal opened path.
Enabling it would therefore *not* re-allow the denied `node.bat` / junction opens
the link-path grant fixes.

It is also unstable in this standalone build: clearing those flags was tried and
broke a plain `coreutils cp` action with `ERROR_INVALID_HANDLE` (`os error 6`). The
resolver decomposes every opened path atom-by-atom, `DeviceIoControl`s each
component, and re-checks access against each resolved target — but it depends on
manifest machinery we deliberately stripped when we built our lean
`manifest_builder.h`: per-scope `FileAccessPolicy_EnableFullReparsePointParsing`
(0x1000) bits, the `GetLevelToEnableFullReparsePointParsing` levels, and the
resolver path cache. Running it without those bits leaves it half-configured. Making
it correct would mean **re-porting BuildXL's manifest subsystem** — re-coupling us
to exactly the code this project set out to remove — for no benefit to the symlink
problem. Not pursued.

### Handle-resolution-only (a possible fork-minimization)

A tempting simplification is to drop the Bazel-side link-path grant entirely and
rely solely on the sandbox handle-resolution fallback. This was tested and is
**insufficient**: handle-resolution only rescues opens that produce a *followed*
handle to the real target (e.g. node's `fs.read`). It cannot cover the two cases the
link-path grant handles — cygwin/msys opening the reparse point itself with
`FILE_OPEN_REPARSE_POINT` (the handle is to the link, so `GetFinalPathNameByHandle`
returns the link path), and `CreateProcess` of launcher `.bat` scripts (a separate
detour with no exposed handle). Covering those in the sandbox alone would mean
extending handle-resolution across the reparse-flagged create path, `CreateProcess`,
and the attribute-query detours (`GetFileAttributes*`, and `NtQueryAttributesFile`
which we don't currently detour) — an estimated ~80–120 lines with more TOCTOU edge
cases — to save ~10 lines of Bazel grant code. The hybrid keeps the sandbox change
minimal (~a dozen lines in three create functions) and is preferred.

### A constructive model via ProjFS (the real fix)

The clean way to match `linux-sandbox` is to stop enforcing on the real execroot
and instead **construct a restricted view**, the way linux-sandbox stages a
symlink root under a mount namespace. The Windows primitive for this is **ProjFS
(Windows Projected File System)** — the virtualization layer behind VFS for
Git / Scalar. A ProjFS provider can present a **virtual execroot** that contains
exactly an action's declared inputs, materialized lazily through provider
callbacks.

This would move us from *deny-by-policy* to *hide-by-absence*, mirroring
linux-sandbox:

- **Removes the reparse compromise entirely.** The process sees only declared
  inputs, so there is no link-path/handle-resolution machinery and reads become
  genuinely hermetic — even the pnpm intra-store junctions become non-issues
  because the store is projected, not physically linked.
- **No reparse-point ambiguity.** We own the virtual namespace, so there is no
  "policy checked against the literal link path" problem and no need to resolve
  chains at all.
- **No per-action symlink/junction churn.** Inputs are projected on demand rather
  than physically linked, similar to what `sandboxfs` (a now-deprecated FUSE layer
  Bazel built for macOS/Linux) did for symlink-heavy sandboxes.

Tradeoffs / caveats:

- **Heavier deployment.** ProjFS needs a running provider process and the optional
  Windows feature enabled — more moving parts than today's single self-contained
  `BazelSandbox.exe`.
- **Reads only.** ProjFS virtualizes *what is visible*; it does not govern
  *what may be written* or *network access*. Write-denial (`-w`/`-b`), the
  network toggles (`-n`/`-N`), and `-S` stats would still be enforced via Detours.
  A ProjFS-based sandbox is therefore a **hybrid** (ProjFS for the input view +
  Detours for writes/network), not a Detours replacement.
- **Write side — a per-action write overlay.** The symmetric fix for the write
  model (§4a consequence 3 / `sandbox-parity-findings.md` §A8) is to stop letting
  undeclared writes land in the shared real execroot and instead **redirect them
  into a per-action scratch overlay** (a temp directory unique to the action),
  transparently via Detours path rewriting or the ProjFS provider. Each action then
  gets a private write namespace — exactly like `linux-sandbox`'s throwaway
  execroot — so two concurrent actions can never collide on a fixed-name file such
  as `y.output`, and the no-clobber guard is no longer load-bearing for undeclared
  scratch. This generalizes the discard-on-exit (§A7) and the cross-action-collision
  (§A8) handling into one model and is the most linux-faithful option.
- **Sharp edges.** ProjFS is optimized for read virtualization; write-back,
  deletes, and case-sensitivity need care.
- **A separate architecture, not an incremental change.** This is a new sandbox
  design rather than a patch to the current one.

**Bottom line:** the Detours approach with the hybrid link-path grant +
handle-resolution fallback is the pragmatic default and works today; it is
name-agnostic and no less hermetic than a literal-path check. If we ever want
`linux-sandbox`-grade hermeticity on Windows, **ProjFS is the path** — a
constructive input view that eliminates the reparse-point compromise, paired with
Detours for the enforcement (writes, network, stats) ProjFS does not provide.
