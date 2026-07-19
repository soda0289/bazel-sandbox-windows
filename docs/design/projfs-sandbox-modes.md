# ProjFS-based Windows sandbox modes (design)

Status: **deferred (superseded for the near term).** This doc specifies a redesign of the
Windows sandbox around the Windows Projected File System (ProjFS) so that it uses
the same **constructive** isolation model as Bazel's Linux and macOS sandboxes,
instead of the current in-place Detours-only enforcement. It defines three
execution modes and, above all, a **strict parity contract with `linux-sandbox`**
so that an action that builds under the default sandbox on a developer's Windows
machine behaves identically when the same commit runs under `linux-sandbox` in
CI.

> **Why deferred:** the measurement spike (§12) confirmed the constructive model
> is *correct* (zero hydration, zero copy, undeclared paths absent) but that
> **per-file reads through a ProjFS root cost ~8 ms/open (~34× native)** — an
> intrinsic `PrjFlt` per-open tax, not hydration. Preserving native-ish speed
> requires **coarse directory-symlink projection** plus a write-overlay, a
> re-enumeration workaround, and a new provider process: substantial, subtle new
> code that would still be *slower* than what we have. We therefore chose the
> in-place, subtractive **Detours input-filtering** approach instead (see
> [`detours-input-filtering.md`](detours-input-filtering.md)), which reuses the
> existing engine and reaches the same read-isolation goal at near-native speed.
> This doc is retained for the measurements and as the reference design should a
> constructive VFS become necessary later (e.g. for full Mode 3 hermeticity).

Related docs:
[`linux-sandbox-comparison.md`](../comparison/linux-sandbox-comparison.md) (flag/feature map),
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md) (the concrete
divergences that motivated this — A4/A5 in particular),
[`vendor-architecture.md`](../vendor-architecture.md) (the current Detours engine).

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
  platform. A specific one is forced with `--spawn_strategy=<name>` (global,
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
callbacks. The provider designates an empty dir as the *virtualization root*, calls
`PrjStartVirtualizing`, and responds to enumeration / placeholder / file-data
callbacks. Entries the provider does not create simply do not exist in that tree.

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
  that input, so there is no hydration and no byte copy.
* The provider still handles **directory enumeration** and **placeholder info**
  callbacks (cheap, metadata only) to present the tree shape; only content is
  offloaded to the symlink target.

> **⚠ Measured caveat (spike, §12): no-hydration is confirmed, but per-file
> virtual-symlink reads are NOT cheap.** Every file open *inside the
> virtualization root* is intercepted by the ProjFS filter (`PrjFlt`) and
> reparse-redirected to the target, costing **~8 ms/open** on a real
> `node_modules` tree — ~34× a native open (0.23 ms) — even with hydration and
> provider callbacks both at zero. This makes naive per-file projection too slow
> for large input trees. The spike found that projecting **whole input
> directories as a single symlink** (so the files resolve on real NTFS *outside*
> the root) is near-native (**0.375 ms/file**). See §12 for the full data and the
> resulting granularity strategy.

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

> **Spike result (§12): both write paths are confirmed working.** (b) Writing
> *through* a projected virtual symlink reached the real target file on disk (no
> copy) — viable for declared outputs. (a) Creating a *new* file inside the
> virtual root produced a full, real on-disk file in the provider's backing store
> — the natural overlay for undeclared/scratch writes. So the recommended model
> is realizable: overlay for scratch + undeclared writes, optional
> symlink-through for declared outputs to skip the copy. (Note: ProjFS suppresses
> notifications for I/O issued by the *provider process itself*; a real child
> process triggers `NEW_FILE_CREATED` / `FILE_PRE_CONVERT_TO_FULL` as expected.)

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
* **Limitation:** like Linux `processwrapper-sandbox`, this is a *weak* sandbox
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
* **Extend the probe suite.** Add a `enforce/projfs_test.cc` (and mode-crossed cases
  in `enforce/modes_test.cc`) that runs `probe.exe` through the ProjFS execroot:
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
* **Per-file open latency — the top risk (measured, §12).** It is *not*
  enumeration/placeholder cost that dominates; it is that **every file open inside
  the virtualization root is intercepted by `PrjFlt` and reparse-redirected**,
  costing ~8–11 ms/open on a real `node_modules` tree (~30–40× native), even with
  hydration and provider callbacks at zero. Naive per-file projection of a large
  input tree is therefore too slow. **Mitigation (measured to work): project at
  directory granularity** — a single directory symlink whose contents resolve on
  real NTFS *outside* the root reads at ~0.375 ms/file. See §12 for the granularity
  strategy this forces.
* **Symlink-placeholder minimum build.** Confirmed working on this host (Win11
  build 26200, SDK 10.0.26100) via `PrjWritePlaceholderInfo2` +
  `PRJ_EXT_INFO_TYPE_SYMLINK`. Keep a content-placeholder fallback for hosts too
  old for symlink placeholders (accepting hydration cost).
* **`GetFinalPathNameByHandle` / realpath semantics.** Must match Linux for
  logical-path-sensitive tools (Node). Primary validation = the `ng_package`
  case.
* **Antivirus / filter-driver interaction (unquantified).** Could not be isolated:
  this host has **Tamper Protection on**, which blocks Defender exclusion changes
  even for administrators, so the "excluded vs not" A/B test was not possible. AV
  scanning of reparse/placeholder opens is a plausible additional cost on top of
  the intrinsic `PrjFlt` overhead but is unmeasured. Document supported AV configs;
  re-run the exclusion A/B on a host where Tamper Protection can be disabled.
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

   > **DONE (measurement spike, since removed).** See §12 for full data. The two
   > throwaway providers (`projfs_spike.cpp`, `projfs_spike2.cpp`) were deleted once
   > they had served their purpose. Headlines: virtual-symlink projection works with
   > **zero hydration** and **zero copy**; undeclared paths are **absent** with a
   > working negative-path cache; writes work both through-symlink (no copy) and as
   > overlay. **BUT** the pivotal finding: per-file opens through the ProjFS root
   > cost **~8 ms/file** (~34× native) — intrinsic `PrjFlt` overhead, not
   > hydration — so per-file projection is too slow for large trees, while
   > **coarse directory-symlink projection is near-native (~0.375 ms/file)**. This
   > cost is what led us to **defer the whole ProjFS model** in favor of the
   > in-place Detours input-filtering sandbox (see
   > [`detours-input-filtering.md`](detours-input-filtering.md)).
2. **Mode 1 end to end.** `ProjFsSandboxedSpawn` + Bazel strategy
   `windows-processwrapper`; parity tests for the constructive read model.
   **Adopt the §12 granularity strategy** (project declared-input *directories* as
   single symlinks; project loose individual files only when necessary).
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

---

## 12. Spike measurements and their design impact

Two throwaway providers (`projfs_spike.cpp`, `projfs_spike2.cpp`, kept under
`spike/projfs/` while in use and **removed after measurement**) validated the
design's assumptions on this host (Win11 build 26200, SDK 10.0.26100, ProjFS
`Client-ProjFS` enabled). The `projfs_spike2.cpp`
`read` mode deliberately **separated the phases** (enumerate / create placeholder
/ read via ProjFS / read direct control) so we could see *which* operation costs
what, driving each phase from the manifest to avoid ProjFS re-enumeration
artifacts (see the re-enumeration caveat below).

### 12.1 Correctness (all confirmed)

* **Virtual-symlink projection works.** Each projected file is a real
  `SymbolicLink` reparse point to its source; opening it redirects to real NTFS.
* **Zero hydration, zero copy.** The `GetFileData` callback *never* fired; the
  virtualization root's on-disk content size stayed 0. Bytes read through the
  virtual tree matched the real totals exactly.
* **Undeclared paths are absent.** 400/400 undeclared-path probes returned
  not-found. The negative-path cache works: 200 `GetPlaceholderInfo` callbacks on
  round 1, **0 on round 2**.
* **Writes.** Writing *through* a projected virtual symlink reached the real
  target file (no copy) → viable for declared outputs. Creating a *new* file in
  the root produced a full real on-disk file in the provider store → the overlay
  for scratch/undeclared writes.

### 12.2 Performance (the pivotal finding)

Measured on a real large `node_modules` tree (88,954 manifest entries;
12,513 dirs / 76,441 files; 5,928 pnpm reparse-point leaves projected as symlink
leaves without recursion for cycle-safety). Per-file numbers are over an 8,000-
file sample:

| Operation | Cost | Notes |
| --- | --- | --- |
| Manifest build (host-side walk) | 2.4–4.5 s | one-time, before virtualization |
| **P1** full-tree enumeration | 15–24 s | one-time; provider enum callbacks |
| **P2** placeholder creation (`GetPlaceholderInfo`) | 0.9–3.2 ms/file | one-time per opened input |
| **P3** read via **per-file** virtual symlink | **~8–11 ms/file** | hydration=0, provider cb=0; run-to-run variance in this range |
| **P5** read same files **direct** (no ProjFS, control) | **0.23–0.29 ms/file** | native baseline |
| **dirlink** read via **coarse directory symlink** | **0.375 ms/file** | files resolve *outside* the root |

Interpretation:

* **The bottleneck is reading, not creating symlinks — and it is intrinsic to
  ProjFS.** P3 triggers *zero* provider callbacks and *zero* hydration, yet each
  open costs ~8–11 ms. That cost is the `PrjFlt` filter intercepting every open
  *inside the virtualization root* and reparse-redirecting it. It is ~30–40× the
  native open cost (P5).
* **Windows Defender's contribution could not be isolated.** This host has
  **Tamper Protection enabled**, which blocks adding a Defender exclusion even as
  administrator, so the intended "excluded vs not" comparison could not be run.
  The one apparently-lower P3 run (7.8 ms) is within normal run-to-run variance
  and should **not** be attributed to an exclusion. AV overhead on reparse opens
  is a plausible *additional* contributor but remains unquantified here; it does
  not change the conclusion, since even the best P3 (~8 ms) is ~34× native.
* **Coarse directory-symlink projection avoids the per-file tax.** When a whole
  directory is projected as one symlink, the files underneath live on real NTFS
  *outside* the virtualization root, so their opens are not intercepted per-file —
  only the one directory-symlink prefix incurs a reparse. Result: ~0.375 ms/file,
  within ~1.6× of native (and subject to normal Defender scanning, same as any
  real file).

### 12.3 Resulting granularity strategy (design change)

Per-file virtual projection of a large input tree (tens of thousands of opens per
action) is **too slow** to ship. The design must therefore choose projection
granularity deliberately:

* **Project declared-input *directories* as single directory symlinks** where an
  action depends on a whole directory (the common case for `node_modules`
  packages, runfiles trees, and repository inputs). Near-native reads; one reparse
  per directory prefix.
* **Project individual loose files** (build files, single declared source inputs)
  as per-file virtual symlinks — acceptable because there are few of them.
* **Tension with isolation to resolve:** a coarse directory symlink exposes the
  *entire* real directory, not only the individually-declared files within it —
  weaker than Linux's per-input symlink forest. Two ways to reconcile:
  1. When Bazel declares a whole directory / tree artifact as the input (typical
     for these cases), coarse projection *is* faithful — there is no finer
     declaration to honor.
  2. When only some files in a directory are declared, either accept the coarse
     exposure (matches today's permissive default) or fall back to per-file
     projection for that directory (slow but precise) — a per-action policy knob.
* **Real NTFS symlink forest (the Linux approach), and why it is rejected.** That is the
  current approach being moved away from: it needs `SeCreateSymbolicLinkPrivilege`
  / `--windows_enable_symlinks`, physically materializes a forest, and has the
  reparse-handling issues (findings A1/A2/B4). ProjFS's advantage is *no privilege and no
  physical forest* — but only coarse projection preserves that advantage at acceptable
  read speed. This trade-off is the central engineering decision for Mode 1.

### 12.4 Behavioral caveats discovered

* **Re-enumeration loses virtual children.** Once a directory has been fully
  enumerated, ProjFS materializes it as an on-disk placeholder directory;
  re-enumerating it via `FindFirstFile` no longer lists virtual file children that
  were never individually accessed. Provider/host code must therefore drive file
  access from the manifest (by path), not by re-walking the virtual tree. (This
  bit the first phase-split attempt, which reported 0 files on the second pass.)
* **Provider-process self-I/O is not notified.** ProjFS suppresses notification
  callbacks for I/O issued by the provider process itself; a separate child
  process (the real action) triggers `NEW_FILE_CREATED` /
  `FILE_PRE_CONVERT_TO_FULL` normally. Write-capture logic must be tested with a
  child process, not the provider.
* **pnpm reparse leaves.** The manifest walker must not recurse into
  reparse-point directories (cycle/duplication risk); projecting them as symlink
  leaves is cycle-safe and, conveniently, aligns with the coarse-projection
  strategy above.

### 12.5 Follow-ups before/with Mode 1 implementation

* Prototype **coarse-by-default projection** in the provider and re-measure a full
  `ng_package` action end-to-end (not just raw reads).
* Confirm `realpath`/`GetFinalPathNameByHandle` behavior through a **directory**
  symlink matches Linux for the Node logical-path (`package.json` walk) case.
* Measure a **warm second-open** pass and worker/repeated-build reuse (does the
  ~8 ms per-file cost amortize, or is it per-open every time?).
* Decide the per-directory precise-vs-coarse policy knob and its default.
