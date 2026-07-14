# ProjFS-based Windows sandbox modes (design)

Status: **proposal / pre-implementation.** This doc specifies a redesign of the
Windows sandbox around the Windows Projected File System (ProjFS) so that it uses
the same **constructive** isolation model as Bazel's Linux and macOS sandboxes,
instead of the current in-place Detours-only enforcement. It defines three
execution modes and, above all, a **strict parity contract with `linux-sandbox`**
so that an action that builds under the default sandbox on a developer's Windows
machine behaves identically when the same commit runs under `linux-sandbox` in
CI.

Related docs:
[`linux-sandbox-comparison.md`](linux-sandbox-comparison.md) (flag/feature map),
[`sandbox-parity-findings.md`](sandbox-parity-findings.md) (the concrete
divergences that motivated this — A4/A5 in particular),
[`vendor-architecture.md`](vendor-architecture.md) (the current Detours engine).

---

## 1. Why change anything

### 1.1 The problem we keep hitting

The current Windows sandbox runs **in place** in the real execroot and uses
Detours to allow/deny individual file calls. It has no *constructive* view: every
real file on disk is physically present, so isolation is only as good as the
policy we can express at the API boundary. This has produced a string of
subtle, hard-to-diagnose divergences from `linux-sandbox`:

* Undeclared reads inside the execroot were denied (our old always-hermetic
  behavior), while default `linux-sandbox` allowed them — breaking `ng_package`
  (findings A4/A5).
* Fixing that by making reads *permissive* (current default) means we **do not
  isolate reads at all** — we only confine writes. That is not really a sandbox;
  it cannot catch a missing-input declaration, because everything on disk stays
  readable.
* Reparse-point / symlink handling required bespoke handle-resolution logic and
  still has known gaps (B4), because we enforce on live NTFS junctions instead of
  presenting a curated tree.

Every one of these is a symptom of the same root issue: **we enforce on the real
filesystem instead of constructing the filesystem the action is allowed to see.**

### 1.2 The guiding constraint: match `linux-sandbox`

Developers work on Windows and push to Linux CI. If the two sandboxes differ,
builds "work on my machine" and then fail in CI (or vice-versa) in ways that are
very hard to debug — exactly the failure mode we saw during testing. Therefore:

> **Parity is the primary design goal.** Each Windows mode must reproduce the
> observable filesystem semantics of a corresponding `linux-sandbox`
> configuration. Where Windows *cannot* match Linux exactly, the difference must
> be documented and, ideally, made *stricter* (fail on Windows what Linux
> forbids) rather than *looser*.

### 1.3 What `linux-sandbox` actually does (the parity target)

From `src/main/tools/linux-sandbox.cc` and `SymlinkedSandboxedSpawn` /
`AbstractSandboxSpawnRunner`:

| Aspect | Default `linux-sandbox` | Hermetic (`--experimental_use_hermetic_linux_sandbox`) |
| --- | --- | --- |
| Execroot | A **fresh** `sandbox/execroot/<workspace>` dir containing a **symlink forest of declared inputs only** | Same, but built inside a truly isolated mount root |
| Reads inside execroot | Only declared inputs exist (undeclared paths are **absent**) | Same |
| Reads outside execroot | **Whole real FS is bind-mounted read-only** → system files, toolchains, and even the real `bazel-out` are readable | **Not mounted** → only declared inputs + explicit mounts are visible |
| Writes | The **entire sandbox execroot is writable** (`writablePaths.add(sandboxExecRoot)`), plus `TEST_TMPDIR`; **everything else is read-only** | Same |
| Output collection | Declared outputs are **copied out** of the sandbox execroot afterward; undeclared writes are discarded with the throwaway dir | Same |
| Network / PID / user | namespaces | namespaces |

Two things to internalize:

1. **Reads are isolated *constructively*, not by denial.** The action sees only
   what is symlinked into its execroot; undeclared execroot paths simply don't
   exist. The rest of the FS is readable in default mode because it is
   RO-bind-mounted, *not* because Linux "allows" it per-path.
2. **Writes are confined to the sandbox execroot** (all of it, not just declared
   outputs) plus tmp. Undeclared writes are allowed *into the throwaway execroot*
   and then silently dropped. Writes anywhere else on the FS are denied.

This is the behavior the Windows modes below must reproduce.

---

## 2. How Bazel selects sandbox strategies (background)

So the mode names below line up with Bazel's model.

* **`process-wrapper` is a tool, not a strategy.** It is a small binary
  (`src/main/tools/process-wrapper`) that wraps a child for timeout/stats/signal
  handling. Local *and* sandbox execution use it.
* **Spawn strategies** are named execution backends. Each sandbox implementation
  registers under its own name **and** the shared alias `sandboxed`
  (`SandboxModule.java`):

  | Strategy class | Names | Model | Supported on |
  | --- | --- | --- | --- |
  | `ProcessWrapperSandboxedStrategy` | `sandboxed`, `processwrapper-sandbox` | symlink forest, **no** namespaces | **POSIX only** (`OS.isPosixCompatible()`) |
  | `LinuxSandboxedStrategy` | `sandboxed`, `linux-sandbox` | symlink forest **+ namespaces** | Linux |
  | `DarwinSandboxedStrategy` | `sandboxed`, `darwin-sandbox` | `sandbox-exec` profile | macOS |
  | `DockerSandboxedStrategy` | `docker` | container | any w/ docker |
  | `WindowsSandboxedStrategy` | `sandboxed`, `windows-sandbox` | **in-place + Detours** | Windows |

* **`sandboxed` is an alias, not an implementation.** Whichever OS sandbox is
  supported registers under `sandboxed` and becomes what it resolves to on that
  platform. You force a specific one with `--spawn_strategy=<name>` (global,
  first-applicable wins) or `--strategy=<Mnemonic>=<name>` (per-mnemonic).
* **`processwrapper-sandbox` does not exist on Windows today** — it is gated on
  `OS.isPosixCompatible()`. On Windows, `sandboxed` resolves to `windows-sandbox`
  (if the binary is available/enabled) or else there is no sandbox and Bazel
  falls back to `standalone`/`local`.
* **Hermetic Linux is a sub-mode, not a strategy.**
  `--experimental_use_hermetic_linux_sandbox` changes *how* `linux-sandbox`
  builds its root; it is still the `linux-sandbox` strategy.

**Key architectural gap:** Linux/macOS/`processwrapper-sandbox` are all
*constructive* (build a curated execroot). Windows is the odd one out — it is
purely *enforcement-based and in-place* (`WindowsSandboxedSpawnRunner`:
"The windows-sandbox executes in place in the execroot"; `copyOutputs()` is
empty). This proposal closes that gap.

---

## 3. Design overview

Introduce a **ProjFS virtualization provider** that builds a curated execroot as
a *virtual* directory tree, plus an optional **Detours enforcement layer** for
write/read confinement. The three modes are combinations of these two pieces,
mapped onto Bazel's strategy taxonomy:

| Mode | Name | Constructive layer | Enforcement layer | Linux analog |
| --- | --- | --- | --- | --- |
| 1 | `windows-processwrapper` (working name) | ProjFS execroot (declared inputs only) | none | `processwrapper-sandbox` |
| 2 | `windows-sandbox` | ProjFS execroot | Detours: **deny writes outside the execroot** | default `linux-sandbox` |
| 3 | `windows-hermetic-sandbox` | ProjFS execroot | Detours: **deny writes outside execroot AND deny reads outside execroot** (except an OS allowlist) | `--experimental_use_hermetic_linux_sandbox` |

The constructive layer is what makes reads correct and cheap; Detours only has to
police the *boundary* (writes always; reads in hermetic mode).

```
                       ┌─────────────────────────────────────────┐
   Bazel action  ───►  │  ProjFS virtualization root = execroot   │
   (cwd = execroot)    │  ┌─────────────────────────────────────┐ │
                       │  │ virtual symlink  a.ts  ─► \\real\...  │ │  reads follow the
                       │  │ virtual symlink  node_modules/... ─►  │ │  symlink to the real
                       │  │ (only DECLARED inputs are projected)  │ │  input file: no
                       │  └─────────────────────────────────────┘ │  hydration / copy
                       │  writes ─► scratch/output overlay          │
                       └───────────────┬───────────────────────────┘
                                       │  (Mode 2/3 only)
                              ┌────────▼─────────┐
                              │  Detours engine  │  deny writes outside execroot;
                              │  (existing DLL)  │  Mode 3: deny reads outside execroot
                              └──────────────────┘
```

---

## 4. The ProjFS constructive layer

### 4.1 ProjFS primer

ProjFS (Windows Projected File System, `ProjectedFSLib.dll`, the technology
behind VFS-for-Git) lets a user-mode **provider** back a directory subtree with
callbacks. You designate an empty dir as the *virtualization root*, call
`PrjStartVirtualizing`, and respond to enumeration / placeholder / file-data
callbacks. Entries you don't create simply don't exist in that tree.

* **Availability:** optional Windows feature ("Windows Projected File System",
  `Client-ProjFS`). Present on Windows 10 1809+ / Server 2019+.
* **Placeholders:** each projected entry starts as a *placeholder* (metadata
  only). Content is served on demand via the `GetFileData` callback and cached
  ("hydrated") on first read — this is the copy cost we want to avoid.

### 4.2 Virtual symlinks to avoid hydration (per requirement)

Instead of projecting inputs as content placeholders (which would hydrate/copy
file bytes into the provider store on first read), we project each declared input
as a **virtual symlink** pointing at the real input file in the execroot / repo
cache / `bazel-out`:

* ProjFS supports symlink placeholders (`PrjWritePlaceholderInfo2` with an
  `PRJ_EXTENDED_INFO` of type `PRJ_EXT_INFO_TYPE_SYMLINK`, Windows 10 2004+ /
  build 19041+). **Verify the exact minimum build against current docs before
  relying on it.**
* A read that traverses the projected symlink is redirected by the OS to the real
  backing file on real NTFS. **The `GetFileData` callback is never invoked** for
  that input, so there is no hydration and no byte copy — reads cost a symlink
  traversal, not a file copy. This is the core performance property.
* The provider still handles **directory enumeration** and **placeholder info**
  callbacks (cheap, metadata only) to present the tree shape; only content is
  offloaded to the symlink target.

Consequence for **input isolation**: the projected tree contains a symlink *only*
for each declared input. Undeclared execroot paths are **absent** (enumeration
never lists them, `GetPlaceholderInfo` returns not-found), reproducing Linux's
"undeclared inputs don't exist in the execroot" exactly — without copying and
without physical junctions.

### 4.3 Interaction with tools that resolve symlinks (lesson from A5)

Finding A5 taught us that `rules_js` patches Node so module resolution keeps the
**logical** path and does *not* realpath symlinks. Our projection must not defeat
that:

* Tools that call `GetFinalPathNameByHandle` / realpath on a projected symlink
  will see the **target** (real) path, not the logical execroot path. Anything
  that reasons about logical paths (Node module type resolution walking
  `package.json`) must still see the projected tree.
* **Requirement:** the projected execroot must itself contain the intermediate
  directories and `package.json` files as projected entries (symlinks to the real
  ones), so a logical-path walk up the execroot finds them. This is naturally
  satisfied if we project *every* declared input (including the `package.json`
  files), which we must. This is the constructive equivalent of the A4/A5 fix.
* **Open question:** whether projecting inputs as symlinks (vs. name-preserving
  placeholders) changes what `realpath`-based tools observe relative to Linux
  (where the forest is also symlinks). Linux uses real symlinks too, so parity is
  plausible, but this must be validated with the Node/`ng_package` case as a
  first-class test (it is our canonical logical-vs-real path probe).

### 4.4 Constructive = separate execroot (not in-place)

Today Windows runs in-place. Under ProjFS the sandbox execroot becomes the
**virtualization root** — a fresh directory per action (like Linux's
`sandbox/execroot/<workspace>`), populated with virtual-symlink inputs. Bazel
runs the action with `cwd` = this virtual execroot. This is a deliberate shift
from in-place to constructive execution, and is what brings us in line with the
other platforms.

---

## 5. The write model (per requirement + linux parity)

Linux makes the **whole sandbox execroot writable** (plus `TEST_TMPDIR`) and
copies declared outputs back afterward; writes outside are denied. To match that
observable behavior:

* **Writes inside the execroot are allowed.** Undeclared writes land in a
  scratch/output overlay and are discarded unless they are declared outputs (which
  Bazel harvests). This mirrors Linux allowing scratch writes into the throwaway
  execroot. *(This is a small but important refinement of the "only allow writes
  for outputs" idea: to stay in parity we must let actions write scratch files
  anywhere under the execroot, not only at declared output paths — Linux does, and
  many tools write temp files next to their outputs.)*
* **Writes outside the execroot are denied** in Modes 2 and 3 (Detours). This is
  the "deny writes everywhere [outside]" behavior; it is what `linux-sandbox`
  enforces via the read-only FS.
* **`TEST_TMPDIR` / the action temp** is writable in all modes (parity).

Two implementation options for capturing writes to the projected execroot
(both viable; to be decided by the spike):

* **(a) Overlay-then-copy.** ProjFS notifies on write (the placeholder is
  "converted to full"); the provider keeps modified/new files in a backing store,
  and Bazel copies declared outputs from there into the real `bazel-out` after the
  action. Closest to Linux's copy-out; keeps the real tree untouched during the
  action; costs one copy per output.
* **(b) Symlink-through to the real output path.** Declared output paths are
  projected as writable symlinks to their real `bazel-out` locations, so writes go
  straight to the execroot with no post-copy. Cheaper, but the action mutates the
  real tree live and we must ensure undeclared writes still land in the discardable
  overlay (not the real tree).

**Recommendation:** start with **(a)** for correctness/parity (it matches Linux's
copy-out semantics and keeps undeclared writes fully contained), then evaluate
**(b)** as an optimization for large outputs once parity is proven.

---

## 6. Mode specifications

For every mode: **network/write/read semantics must be verifiable against the
matching `linux-sandbox` configuration** (see §8 parity contract).

### 6.1 Mode 1 — `windows-processwrapper` (ProjFS only)

* **Filesystem:** ProjFS execroot with declared-input virtual symlinks. Rest of
  real FS visible read-only (it's outside the virtualization root; normal NTFS).
* **Reads:** undeclared *execroot* paths absent; system/toolchain reads succeed.
* **Writes:** **not enforced** (no Detours). Writes into the execroot overlay are
  captured; writes elsewhere are *not* prevented.
* **Enforcement mechanism:** none beyond the constructive tree.
* **Linux analog:** `processwrapper-sandbox` (constructive, no isolation).
* **Use case:** fast fallback; environments where Detours injection is
  undesirable; correctness-of-inputs checking without boundary enforcement.
* **Honesty note:** like Linux `processwrapper-sandbox`, this is a *weak* sandbox
  — a determined action can still write outside. Documented as such.

### 6.2 Mode 2 — `windows-sandbox` (ProjFS + Detours write-deny) — the default

* **Filesystem:** ProjFS execroot as in Mode 1.
* **Reads:** same as Mode 1 (undeclared execroot paths absent; rest of FS
  readable). **This matches default `linux-sandbox`.**
* **Writes:** Detours **denies writes outside the execroot**; writes inside the
  execroot are allowed (overlay). Declared outputs harvested (§5).
* **Enforcement mechanism:** constructive reads (ProjFS) + write-boundary
  enforcement (Detours). Detours here is *much simpler* than today — it only
  polices writes, not a read policy.
* **Linux analog:** default `linux-sandbox`.
* **Use case:** the everyday default; catches undeclared-output/stray-write bugs
  and undeclared-*input* bugs (inputs are constructively absent) while keeping
  reads permissive like Linux.

### 6.3 Mode 3 — `windows-hermetic-sandbox` (ProjFS + Detours read+write-deny)

* **Filesystem:** ProjFS execroot; additionally the action is **denied reads
  outside the execroot**, except an explicit **OS-essentials allowlist**.
* **Reads:** only declared inputs (in the projected execroot) **plus** the
  allowlist: `C:\Windows\System32` (and `SysWOW64`) system DLLs, the Windows
  registry, the machine/user cert stores, and the toolchain paths Bazel declares.
  Everything else denied. **This matches `--experimental_use_hermetic_linux_sandbox`.**
* **Writes:** denied everywhere except the execroot overlay + `TEST_TMPDIR`
  (same as Mode 2).
* **Enforcement mechanism:** ProjFS (reads inside) + Detours (deny reads outside
  execroot except allowlist; deny writes outside). This is where our existing
  `-H` deny-scope + root-scope logic is reused.
* **Linux analog:** hermetic `linux-sandbox`.
* **Use case:** CI hermeticity gate; reproduce "this only builds because it read
  something undeclared" failures deterministically.
* **Open question — the OS allowlist.** Linux hermetic mounts a minimal set of
  system paths; the Windows equivalent (which System32 DLLs, registry hives, cert
  stores, `KnownDLLs`, side-by-side assemblies, `api-ms-*` apisets) needs a
  carefully curated, documented allowlist. Getting this wrong is the main risk to
  Mode 3 usability. Start permissive-but-logged, tighten with data.

---

## 7. Bazel integration

* **New `SandboxedSpawn` implementation:** `ProjFsSandboxedSpawn` (sibling of
  `SymlinkedSandboxedSpawn`) that (1) creates the virtualization root, (2) starts
  the provider with the action's `SandboxInputs` (declared inputs → virtual
  symlinks), (3) runs the child (via `process-wrapper` for timeout/stats), (4) in
  Mode 2/3 injects the Detours DLL, (5) harvests declared outputs, (6) tears down
  virtualization.
* **Strategy registration** (`SandboxModule`): register the three under distinct
  names; keep `windows-sandbox` (Mode 2) under the `sandboxed` alias so it is the
  default on Windows. Modes selected via `--strategy=<Mnemonic>=<name>` or
  `--spawn_strategy`.
* **Flags:** a Bazel flag to opt into hermetic Mode 3 (mirroring
  `--experimental_use_hermetic_linux_sandbox`), and a flag/`AUTO` to fall back to
  Mode 1 when Detours/ProjFS is unavailable. The provider path and OS-allowlist
  are launcher options on our binary.
* **Reuse of the current engine:** the existing Detours `DetoursServices` DLL and
  manifest builder remain the enforcement layer; the launcher gains a
  ProjFS-provider mode and a `--projfs-root`-style option. The current permissive
  `-H`/default logic becomes: Mode 2 = write-only manifest; Mode 3 = the `-H`
  deny-scope manifest scoped to the virtual execroot + allowlist.

---

## 8. Parity contract and test plan

Parity is the whole point, so it must be *tested*, not asserted.

* **Parity matrix.** For a set of representative actions (a plain genrule, a
  runfiles-consuming test, a pnpm/`node_modules` action, the `ng_package`
  logical-path case, a symlink/junction traversal, an undeclared-input read, an
  undeclared-output write, an out-of-execroot write, an out-of-execroot read),
  record the outcome under: Linux default, Linux hermetic, Windows Mode 1/2/3.
  Each Windows mode's column must equal its Linux analog's column.
* **Extend the probe suite.** Add a `enforce/projfs.ps1` (and mode-crossed cases
  in `enforce/modes.ps1`) that runs `probe.exe` through the ProjFS execroot:
  undeclared-input read → absent (Mode 1/2/3); out-of-execroot write → denied
  (Mode 2/3); out-of-execroot read → allowed (Mode 2) / denied (Mode 3);
  declared-input read via virtual symlink → allowed with **no hydration** (assert
  the `GetFileData` callback count is zero).
* **Canonical regression:** the `ng_package` `:pkg_apf` build must pass under
  Mode 2 (it does today under permissive) *and* the logical-path `package.json`
  walk must resolve correctly through the projected tree (A5 guard).
* **Cross-platform CI:** the same targets built under `linux-sandbox` in CI and
  under Windows Mode 2 locally must produce the same success/failure set. A
  divergence is a P0 bug against this contract.

---

## 9. Risks and open questions

* **ProjFS availability/enablement.** Optional feature; may be absent on some
  hosts. Need detection + graceful fallback (to Mode 1 or to the current
  in-place Detours behavior).
* **Symlink-placeholder minimum build.** Confirm the exact Windows build that
  supports symlink placeholders; have a content-placeholder fallback if a host is
  too old (accepting hydration cost).
* **Callback latency.** Per-entry enumeration/placeholder callbacks add latency
  for actions with huge input trees (node_modules). Mitigate with batched
  enumeration and aggressive negative caching. The Mode-1 spike must **measure**
  this before we commit.
* **`GetFinalPathNameByHandle` / realpath semantics.** Must match Linux for
  logical-path-sensitive tools (Node). Primary validation = the `ng_package`
  case.
* **Antivirus / filter-driver interaction.** ProjFS is a filesystem filter;
  security products can interfere or add latency. Document supported configs.
* **Privilege.** Confirm ProjFS provider start does not require admin (it should
  not for user-owned roots) and that we no longer need
  `SeCreateSymbolicLinkPrivilege` / `--windows_enable_symlinks` for the execroot
  (a benefit — the current junction/symlink forest approach needs privilege).
* **Nested sandboxes / workers.** Persistent workers and actions that themselves
  spawn sandboxes need thought (nested virtualization roots).
* **Output copy cost (option a).** Large outputs pay a copy; option (b)
  mitigates but complicates containment.

---

## 10. Phased implementation plan

1. **Spike — Mode 1 provider (measurement).** Standalone provider that projects
   one real action's `SandboxInputs` as virtual symlinks into a fresh root, runs
   a probe/tool there, and measures: correctness (undeclared absent, declared
   readable, **zero hydration**), and enumeration/placeholder latency on a large
   `node_modules` tree. **Gate:** latency acceptable and virtual symlinks avoid
   hydration.
2. **Mode 1 end to end.** `ProjFsSandboxedSpawn` + Bazel strategy
   `windows-processwrapper`; parity tests for the constructive read model.
3. **Mode 2 (default).** Add the Detours write-deny layer over Mode 1; the
   write overlay + output harvest (option a); make it the `sandboxed` default on
   Windows; run the full parity matrix + `ng_package`.
4. **Mode 3 (hermetic).** Add read-deny-outside-execroot + the curated OS
   allowlist; a Bazel flag to select it; hermetic parity tests.
5. **Deprecate in-place Detours-only.** Once Mode 2 is at parity, retire the
   current permissive-in-place default (or keep it as an explicit low-fidelity
   fallback).

---

## 11. Relationship to current code

* **Kept:** the Detours `DetoursServices` engine, `manifest_builder`, the
  launcher (`src/main.cpp`), network sandboxing, and the probe-based test harness.
  The `-H` hermetic deny logic becomes Mode 3's read-enforcement layer; the
  permissive write-only policy becomes Mode 2's boundary.
* **Added:** a ProjFS provider component and a Bazel `ProjFsSandboxedSpawn` +
  strategy wiring. The launcher gains a provider/`--projfs-root` mode.
* **Changed:** Windows moves from **in-place** to **constructive** execution.
  This is the central architectural change and the source of the parity we want.
* **Superseded:** the name-agnostic link-path grants and handle-resolution
  fallback (findings A1/A2) exist to make *in-place* reads through live junctions
  work. Under the constructive model they are largely unnecessary (the projected
  tree already presents exactly the declared inputs), though handle-resolution may
  remain relevant for Mode 3's out-of-execroot read checks.
