# Detours input-filtering sandbox (design)

Status: **proposal / approved for implementation.** This doc specifies a
**subtractive, in-place** Windows sandbox that reaches the practical parity goals
of `linux-sandbox` (undeclared inputs are invisible; writes are confined) by
*filtering* what the real execroot shows the process, rather than *constructing* a
new filesystem. It is the approach now implemented (see §9) and, for the
read-isolation goal, **supersedes** the ProjFS redesign in
[`projfs-sandbox-modes.md`](projfs-sandbox-modes.md).

Related docs:
[`projfs-sandbox-modes.md`](projfs-sandbox-modes.md) (the constructive VFS
alternative — deferred, see §8),
[`linux-sandbox-comparison.md`](../comparison/linux-sandbox-comparison.md) (flag/feature map),
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md) (A4/A5 divergences that
motivate this),
[`vendor-architecture.md`](../vendor-architecture.md) (the Detours engine we build
on).

---

## 1. Why this instead of ProjFS

The ProjFS spike (see `projfs-sandbox-modes.md` §12) established the constructive
model is viable but **slow and complex**:

* Per-file reads through a ProjFS virtualization root cost **~8–11 ms/open**
  (~30–40× native) — intrinsic `PrjFlt` interception, even with zero hydration and
  zero provider callbacks.
* Avoiding that tax requires **coarse directory-symlink projection** plus a
  host-side coalescing pass over `SandboxInputs`, a re-enumeration workaround, a
  write-overlay model, and a new ProjFS provider process — a large amount of new,
  subtle code.

The overriding requirement is a sandbox that is **at least as fast as the current
Detours sandbox** and reuses what already works. The insight that reshapes the
design:

> Our Detours engine **already denies** undeclared reads (hermetic mode) and
> **already intercepts** directory enumeration. We are ~two changes away from
> "undeclared inputs are invisible" without building any VFS.

So we keep running **in place in the real execroot** (as the Windows sandbox does
today — `WindowsSandboxedSpawnRunner` "executes in place", no symlink forest, no
per-action staging) and add two subtractive behaviors:

1. **Undeclared reads fail as *absent* (`NOT_FOUND`)**, not `ACCESS_DENIED`.
2. **Undeclared entries are removed from directory enumerations** so the process
   cannot even see them.

Cost: one hash lookup per open (we already do a policy lookup there) and one
linear filter pass per enumeration (rare relative to opens). **Effectively native
speed.** No filter driver, no virtualization root, no privilege.

### 1.1 Sandbox modes (parity mapping)

Because we run in place (no throwaway symlink forest), the modes are distinguished
by *what we enforce*, not by a different filesystem. They map onto Bazel's Linux
strategies as follows:

| Mode | Linux parity target | Reads inside execroot | Reads outside execroot | Writes | Sandbox flags | Bazel selection |
| --- | --- | --- | --- | --- | --- | --- |
| **1 — processwrapper** | `processwrapper-sandbox` | undeclared hidden | allowed | **unconfined** (land harmlessly) | — | ❌ *not faithful in place* |
| **2 — sandbox** *(default)* | default `linux-sandbox` | undeclared hidden | allowed (RO) | confined to `-w`/outputs+tmp | `--filter-inputs` | default (no user flag) |
| **3 — hermetic** | `--experimental_use_hermetic_linux_sandbox` | undeclared hidden | **denied** except OS allowlist | confined | `--filter-inputs --hermetic-fs` | `--experimental_use_hermetic_windows_sandbox` |

* **Mode 1 is deliberately *not* offered in place.** Linux's `processwrapper-sandbox`
  hides undeclared inputs (symlink forest) yet does **not** enforce writes: an
  undeclared write lands harmlessly in the disposable execroot and is discarded.
  In place, that same write would hit the *real* file. Providing a harmless landing
  zone for undeclared writes requires a **constructive** execroot — precisely the
  ProjFS model deferred in [`projfs-sandbox-modes.md`](projfs-sandbox-modes.md). So
  Mode 1 is where ProjFS would return if needed; today the permissive in-place
  default stands in as a fast local fallback but is *stricter on writes* than Linux
  processwrapper (writes outside `-w` are denied, not silently dropped).
* **Mode 2 is the default** and is fully implemented: the `windows-sandbox` runner
  passes `--filter-inputs` on every spawn (`WindowsSandboxUtil.setFilterInputs`).
  Undeclared execroot inputs are invisible; outside-execroot reads stay allowed
  (read-only, since writes require an explicit `-w`); writes are confined — matching
  default `linux-sandbox`.
* **Mode 3 (planned)** layers a new `--hermetic-fs` flag on top of `--filter-inputs`
  that additionally denies reads **outside** the execroot, except a curated OS
  allowlist. This mirrors `--experimental_use_hermetic_linux_sandbox`, where only
  declared inputs plus explicit mounts are visible.
  - **Bazel selection:** a new `--experimental_use_hermetic_windows_sandbox` option
    (the direct analogue of the Linux flag) makes the runner add `--hermetic-fs`.
  - **Allowlist:** seeded by default with the OS locations a Windows process needs
    even when "hermetic" — `C:\Windows\System32` (and `SysWOW64`) for system DLLs,
    the loader/`KnownDLLs`, the registry, and the resolved toolchain — the Windows
    analogue of the paths Linux hermetic mode still bind-mounts. Users extend it
    with the existing **`--sandbox_add_mount_pair`** option (each `source[:target]`
    becomes an additional readable allowlist entry). The goal is to behave as close
    to Linux hermetic sandbox as the platform allows.
  - **Not yet implemented** — this section is the spec; the exe flag, the allowlist,
    and the Bazel option are follow-up work.

**On the `-H` flag:** `-H`/`--hermetic` (deny execroot by default, only `-r`/`-w`
visible, undeclared reads → `ACCESS_DENIED`) is retained only as the internal
building block that `--filter-inputs` sets, plus a debugging switch. It is **not a
user-facing mode**: returning `ACCESS_DENIED` for an undeclared execroot path has no
`linux-sandbox` parity (Linux makes such paths simply *absent*). Only `--filter-inputs`
(which turns those denials into `NOT_FOUND` + enumeration hiding) matches the forest.


---

## 2. What the engine already does (baseline)

Verified in the vendored `DetoursServices`:

* **Opens are intercepted and denied.** `NtCreateFile`/`CreateFileW`/`NtOpenFile`
  run the path through the manifest policy; disallowed paths return via
  `AccessCheckResult::DenialError()` / `DenialNtStatus()`.
* **Hermetic mode already confines reads.** `main.cpp` `-H`/`--hermetic` sets the
  working-dir (execroot) default policy to `Policy_Deny`; only `-r`/`-w` declared
  inputs are readable. Undeclared execroot reads are therefore *already denied*.
* **Enumeration is intercepted but never filtered.** `FindFirstFileExW` /
  `FindNextFileW` and `NtQueryDirectoryFile` / `ZwQueryDirectoryFile` are detoured,
  but the engine comment is explicit: *"we always allow enumeration and report
  it"* (`DetouredFunctions.cpp`). It only scrubs short names; it returns the real
  directory contents.

So the gaps are exactly two, and both are localized.

### 2.1 Gap A — deny error code

`PolicyResult::CheckReadAccess` (`PolicyResult_common.cpp`) always returns
`PathValidity::Valid` on a read denial (line ~118), and its own TODO notes this is
inconsistent: it means `DenialError()` yields `ERROR_ACCESS_DENIED` /
`DenialNtStatus()` yields `STATUS_ACCESS_DENIED` for an *existing but undeclared*
file. Linux semantics for such a file are **absent** (`ENOENT`). Tools branch on
this: many treat `ACCESS_DENIED` as a hard/permission error but `NOT_FOUND` as
"optional file missing, continue" — this is part of the A4/A5 divergence.

### 2.2 Gap B — enumeration leaks undeclared names

Even in hermetic mode, `dir` / `readdir` / `FindFirstFile` over the execroot lists
files the process cannot open. That is observably different from Linux (where the
file is simply not in the symlink forest) and lets non-hermetic tooling *discover*
undeclared paths.

---

## 3. Design

### 3.1 Model

Subtractive, in-place. The manifest already expresses "what may be read"
(the `-r`/`-w` scope tree). We add two enforcement behaviors gated by a new
manifest flag so the change is opt-in and testable:

* **`Flag_DeniedReadsAsNotFound`** — on a *read* denial of an existing path,
  report `NOT_FOUND` (`ERROR_FILE_NOT_FOUND` / `STATUS_OBJECT_NAME_NOT_FOUND`)
  instead of `ACCESS_DENIED`.
* **`Flag_FilterDirectoryEnumeration`** — post-filter enumeration results, removing
  any child whose full path is not read-allowed by the manifest.

These two together implement "undeclared inputs are invisible." They are the
behavioral core of a new **strict/filtering mode** layered on top of the existing
hermetic default-deny execroot policy.

### 3.2 Mechanism A — NOT_FOUND on denied read

The denial error is chosen from `AccessCheckResult::Validity` via `DenialError()`
/ `DenialNtStatus()`. Rather than change `CheckReadAccess` to lie about validity
(which feeds other logic), we thread the flag through to the point of denial: when
`Flag_DeniedReadsAsNotFound` is set **and** the access is a read (not a write —
writes must still deny to protect outputs) **and** the denial is a hard `Deny`,
substitute the not-found error at the call sites that currently do
`accessCheck.DenialError()` / `SetLastErrorToDenialError()` for reads
(`Detoured_CreateFileW`, `Detoured_NtCreateFile`, `Detoured_NtOpenFile`, and the
`GetFileAttributes`/probe paths).

Implementation choice: add a helper on `AccessCheckResult`, e.g.
`DenialError(bool maskAsNotFound)` / `DenialNtStatus(bool maskAsNotFound)`, that
returns the not-found code when `maskAsNotFound && Result == Deny &&
Access is a read`. The flag is read from the parsed manifest (global), so callers
pass `FileAccessManifestFlag has Flag_DeniedReadsAsNotFound`.

Note the engine already has *good* not-found behavior for **non-existent** probes
via `Policy_AllowReadIfNonExistent` (see `main.cpp` comment): a probe of an absent
path returns the real not-found. Mechanism A extends that so an *existent but
undeclared* path is **also** reported as not-found — making "declared" and
"exists-and-visible" the same thing, as on Linux.

### 3.3 Mechanism B — enumeration filtering

Two families to handle:

* **Win32 `FindFirstFileExW` / `FindNextFileW`.** These return one
  `WIN32_FIND_DATAW` per call. Filter by skipping entries whose full path
  (directory + `cFileName`) is not read-allowed: in `FindFirstFile`, loop with the
  real API until an allowed entry is found or exhausted; in `FindNextFile`, loop
  likewise. `.` and `..` are always kept. Short-name scrubbing already exists and
  stays.
* **`NtQueryDirectoryFile` / `ZwQueryDirectoryFile`.** The hard one. Results are a
  packed buffer of variable-length `FILE_*_INFORMATION` records chained by
  `NextEntryOffset` (0 terminates). After the real call, walk the buffer in place:
  for each record, resolve its file name against the directory and drop
  disallowed records by **re-linking `NextEntryOffset`** over them (and zeroing the
  tail / adjusting the final record's offset to 0). Must handle:
  - all info classes the process actually requests (at minimum
    `FileDirectoryInformation`, `FileFullDirectoryInformation`,
    `FileIdFullDirectoryInformation`, `FileBothDirectoryInformation`,
    `FileIdBothDirectoryInformation`, `FileNamesInformation`) — each has the name
    at a different offset;
  - `ReturnSingleEntry` (caller wants one record per call): when the single record
    is filtered out, re-issue the real call to fetch the next until an allowed one
    appears or `STATUS_NO_MORE_FILES`;
  - the restart-scan flag and the `FileName` filter argument (pass through);
  - the case where **every** remaining record is filtered → return
    `STATUS_NO_MORE_FILES` (or empty + success on the first call, matching the OS).

The allow test reuses the same manifest policy lookup used for opens
(`PolicyResult` for `dir\child`, `AllowRead()`), so "what enumerates" and "what
opens" are guaranteed consistent.

### 3.4 Where the allow-list comes from (`SandboxInputs`)

Nothing new in the wire format is strictly required: the runner already passes
declared inputs as `-r` scopes, which build the manifest policy tree. Filtering
and NOT_FOUND both consult that **same tree**. Concretely:

* `WindowsSandboxedSpawnRunner` computes the action's `SandboxInputs` (the
  per-file map `execroot-relative path → real source path`, plus symlinks) exactly
  as the Linux/`processwrapper` runners do.
* It emits those as `-r <execroot input path>` (files and/or input directories)
  the way it does today, and turns on the new mode (a launcher flag, §5).
* The DLL's existing manifest tree is the allow-list for both mechanisms — no
  separate side table.

We deliberately keep granularity decisions (coarse dir vs per-file) **out of
scope**: because we filter the *real* execroot in place, a declared input
directory is naturally represented by an `-r` cone, and its real children are
shown; undeclared siblings inside a *partially*-declared directory are hidden by
mechanism B. This is strictly finer-grained isolation than the current permissive
default, with none of the ProjFS coalescing machinery.

### 3.5 The execroot-symlink read leak and the declared-input marker

Running **in place** in the real execroot (§1) means the execroot is not a
freshly-constructed forest of only-declared inputs — it is bazel's own on-disk
tree, and `execroot/_main` is a **symlink into the real workspace source tree**
(e.g. `execroot/_main/package.json` → `C:\...\workspace\package.json`). Bazel
materializes that symlink for the *whole* workspace, independent of any single
action's declared inputs. On `linux-sandbox` the equivalent file is simply never
symlinked into the throwaway forest, so it does not exist in the sandbox view. In
place, it physically exists, so a tool that walks the real directory tree can find
it.

This collides with the **handle-resolution read fallback**. That fallback exists
for a legitimate case the input map cannot cover: the aspect_rules_js pnpm store
materializes **intra-store package junctions** (`@a+cli@v/node_modules/@scope/b →
@scope+b@v/...`) on disk that are *not* declared as inputs of the consuming
action, so no `-r` grant reaches them. When a tool opens such a junction and the OS
follows it to a real target, the fallback re-checks the *target's* policy and
allows the read if the target is permitted.

The bug: an undeclared in-execroot path like `_main/package.json` resolves (via the
execroot symlink) to a source-tree file that the **whole-filesystem root
`AllowRead` baseline** permits. The fallback would therefore rescue it — leaking an
undeclared input and breaking hermetic/RBE parity. This surfaced as the
`rules_angular ng_package` (APF) failure: node's ESM walk-up from the CJS packager
found the rescued `_main/package.json` (`"type":"module"`) and treated the tool as
ESM → `ReferenceError: exports is not defined in ES module scope`.

(The superficially-similar `text_replace` tsc `TS7016 Could not find a declaration
file for module 'picomatch'` is **not** a sandbox issue: it reproduces identically
with `--spawn_strategy=local` — picomatch@4 ships no type declarations — so it is a
Windows tsc `.mts` module-resolution discrepancy vs linux, out of scope here.)

**The fix — a declared-input marker bit.** The difference between a pnpm store
junction target (must be rescued) and a symlink-resolved source file (must stay
masked) is *not* their policy bits — both are `AllowRead` — but *why* they are
readable: the store target is under an **explicit `-r` grant**, the source file is
readable only via the **blanket root scope**. We make that distinction first-class
with a dedicated policy bit:

* `FileAccessPolicy_DeclaredInput = 0x2000` (`Policy_DeclaredInput` on the
  builder side) is OR'd into the policy of **explicit** grants only — `-r`, `-w`,
  the launcher-derived output parent dirs, and the tool path — in `main.cpp`. It
  is **not** set on `AddRootScope` (the
  whole-FS baseline), the working-dir Deny scope, or `-b`.
* Because the manifest's intermediate cone nodes inherit with
  `coneMask = Policy_MaskNothing (0xFFFF)`, the `0x2000` bit **propagates to every
  descendant of a granted directory**, so a file inside a `-r`-granted directory
  cone still carries the marker (this is why the plain
  `IsExactManifestNode()` predicate was too strict — it rejected cone descendants).
* `PolicyResult::IsDeclaredInput()` tests the bit. All four handle-resolution
  fallback sites (CreateFileW, `NtCreateFile` ×2, `GetFileInformationByName`) now
  rescue **iff** `!resolvedCheck.ShouldDenyAccess() && resolvedPolicy.IsDeclaredInput()`.

Bounds that keep it safe:

* **The marker is inert for enforcement.** Access decisions bit-test specific bits
  (`AllowRead()`, `IndicateUntracked()` = `(m_policy & AllowAll) == AllowAll`, and
  `AllowAll` excludes `0x2000`), so tagging a grant changes *nothing* about what is
  allowed — it only changes whether the resolution fallback is willing to rescue a
  followed link.
* **Root-readable-only paths are never rescued.** `_main/package.json` matches at a
  shallow node (`C:`) that inherits from the unmarked root scope, so it lacks the
  marker → not rescued → stays masked. Empirically verified under the real APF
  manifest: `_main/package.json` reports NOT_FOUND on read/stat/statbyname while
  declared `@types/node/package.json` and `index.js` still read successfully.
* **No name heuristics.** Nothing keys on `package.json` or `node_modules`; the rule
  is purely "was this target an explicitly declared grant".

---

## 4. The virtual-execroot question (fake path VFS)

The Detours sandbox began life as the Google Summer of Code prototype, which
enforced isolation by *denying* access to undeclared paths. Reaching behavioural
parity with Bazel's `linux-sandbox` and `processwrapper-sandbox`, though, demands
that undeclared inputs be *hidden* — absent from directory enumeration and
reported as `NOT_FOUND` — rather than merely rejected once a tool stumbles onto
them. The most complete form of hiding is to have Detours **synthesize a fake
execroot path** that does not exist on disk: each virtual path resolves to its
real input file on open (returning a real handle), enumerations are synthesized
from the input manifest, and nothing is staged physically. That is a userspace
path-remapping VFS — the true analog of Linux's symlink forest, with **no
physical staging at all**.

**Assessment: attractive, but defer it. Do subtractive filtering (§3) first.**

Why it is appealing:
* Truly constructive: undeclared paths have *no* virtual name (fail-closed), the
  strongest isolation.
* No physical execroot staging — potentially a real speed/IO win over any model
  that materializes a tree.
* Conceptually the same as the Linux symlink forest (return real handles behind a
  curated namespace).

Why it is a large, risky lift, and why it is deferred:
* **Every API that consumes or returns a path must be remapped**, not
  just opens: `Create/NtCreate/NtOpen`, `GetFileAttributes*`, `Delete`, `Move`,
  `CreateDirectory`, `GetFullPathName`, `SetCurrentDirectory`, section/mapping
  opens, etc. A single un-hooked path-consuming API means a valid input becomes
  *unreachable* — **fail-closed = broken build**, a far less forgiving failure mode
  than subtractive filtering (where a missed hook merely *leaks* a real file =
  weaker isolation but correct build).
* **Reverse mapping is required and hard.** Tools call
  `GetFinalPathNameByHandle` / `NtQueryObject(ObjectNameInformation)` / realpath to
  recover a path *from a handle*. With remapping we must translate the real target
  path back to the virtual execroot path, or logical-path-sensitive tools (Node —
  exactly the A5 case) break. This is BuildXL's most complex machinery (path/directory
  translation, the "device map") — the very thing this project set out to avoid.
* **Enumeration must be fully synthesized** (there is no real dir to list),
  including `.`/`..`, correct sizes/timestamps (stat the real targets), and every
  info class — strictly more work than *filtering* a real enumeration (§3.3).
* **Relative paths and cwd** resolve in the kernel for any call we do not hook;
  with a non-existent cwd those fail unless every relative-path entry point is
  covered.
* **Bazel-side change**: the runner would have to *stop* staging/executing in the
  real execroot and instead hand the input map to the sandbox — a bigger contract
  change than turning on a flag.

Net: the virtual execroot buys stronger (fail-closed) isolation and removes
staging, but reintroduces precisely the path-translation and realpath-reverse
complexity we abandoned BuildXL/ProjFS to escape, with a brittle failure mode.
Subtractive filtering delivers the *observable* parity goal (undeclared inputs
invisible, writes confined, NOT_FOUND semantics) at a fraction of the cost and
risk. Keep the virtual execroot documented as the eventual **true-hermetic (Mode
3) evolution** if fail-closed isolation or staging elimination becomes a hard
requirement; revisit then.

> **Follow-up (write-only variant).** The *write* half of this idea — redirect only
> undeclared writes into a per-action overlay while leaving reads on the real
> execroot — sidesteps the fail-closed objections above (a missed hook leaks a real
> file, it never makes an input unreachable) and closes A8/A7/B2. It is worked out
> in [`detours-write-overlay-vfs.md`](detours-write-overlay-vfs.md).

---

## 5. Launcher / CLI surface

Add an opt-in mode flag to `main.cpp` rather than overloading `-H`:

* `--filter-inputs` (working name): sets both `Flag_DeniedReadsAsNotFound` and
  `Flag_FilterDirectoryEnumeration`, and implies the hermetic default-deny
  execroot policy (so only `-r`/`-w` are visible). This is the "strict / match
  linux-sandbox reads" mode.
* Keep `-H`/`--hermetic` meaning the existing default-deny execroot; `--filter-inputs`
  is `-H` **plus** the two subtractive behaviors. (We may later make `--filter-inputs`
  the default strict mode and retire the distinction.)
* Default (no flag): unchanged permissive reads — preserved for compatibility and
  for the A4 "match default linux-sandbox" behavior.

The two flags are independent internally (useful for testing) but ship together
via `--filter-inputs`.

---

## 6. Parity with linux-sandbox

| Behavior | linux-sandbox (default) | This design (`--filter-inputs`) |
| --- | --- | --- |
| Undeclared execroot read | absent (not in forest) → `ENOENT` | denied → **`NOT_FOUND`** (mechanism A) |
| Undeclared execroot in `readdir` | not present | **filtered out** (mechanism B) |
| Declared input read | real file via symlink | real file in place (allowed by `-r`) |
| Reads outside execroot | whole FS RO-bind-mounted (readable) | whole FS `AllowRead` (readable) — matches default Linux |
| Writes inside execroot | allowed (whole execroot writable, discarded) | redirected into a process-private overlay via `--write-overlay`; real execroot never mutated, declared `-w` outputs written in place (§7) |
| Writes outside execroot | denied (RO FS) | denied (no write bit) |
| Declared output collection | copied out of throwaway execroot | already in place (in-place execution) |

A divergence to state plainly: this is **hide-in-place, not construct**. The file
physically exists, so isolation is only as strong as our API coverage — a tool
using an un-hooked syscall or a pre-opened handle could still reach a hidden file
(**fail-open**). That is the same trust model the Detours sandbox already has, and
it is sufficient for the primary goal — catching missing-input declarations — but
it is weaker than Linux's constructive guarantee. Documented, not hidden. The
virtual execroot (§4) is the path to close it if ever required.

---

## 7. Write model: `--write-overlay` (formerly `--execroot-writable`)

> **Superseded.** The `--execroot-writable` flag described in this section was
> **removed** in favor of **`--write-overlay`** (Model W), which redirects
> undeclared writes into a process-private overlay backing store instead of
> writing in place, so the real execroot is never mutated. The Bazel
> `windows-sandbox` strategy now passes `--write-overlay` (with a Bazel-owned
> `--overlay-dir`). The created-set mechanism described below is retained and
> reused by write-overlay as its **enumeration index**. For the current write
> model see [`detours-write-overlay-vfs.md`](detours-write-overlay-vfs.md). The
> text below is kept for the design history of the created-set.

By default writes stay confined to `-w` (declared outputs + temp), and Mechanism A
applies to **reads only** — write denials keep returning `ACCESS_DENIED` so
undeclared writes fail loudly rather than looking like a missing directory.

To match Linux's "the whole execroot is scratch-writable and thrown away after the
action," the Bazel `windows-sandbox` strategy historically passed
**`--execroot-writable`**. This grants the execroot cone
`AllowWrite | AllowCreateDirectory | OverrideAllowWriteForExistingFiles`, which the
DLL enforces inline (`PolicyResult::AllowWrite`) as:

- a write/create of a path that did **not** exist is allowed (fresh scratch /
  undeclared output), and the path is recorded in a **created-set**;
- a re-write / read-back / enumerate / delete of a path the process tree created
  this run is allowed (so a tool sees and cleans its own scratch); but
- a write **over a pre-existing** undeclared file is still **denied** — the
  no-clobber guarantee for source/input files survives even though the cone is
  nominally writable. Declared `-w` outputs are `AllowAll`/untracked and stay
  freely overwritable.

**Cross-process created-set.** Tools fork (JavaBuilder creates
`_javac/*_tmp/native_headers` in one process and cleans it up in another), so the
created-set is backed by a named shared-memory region the launcher creates **per
invocation** (env var `BAZEL_SANDBOX_CREATED_SHM`) and every injected DLL in the
tree attaches to. A per-process set would hide one process's creations from a
sibling (empty class jars, "directory not empty" cleanup failures).

**Discard-on-exit (the "throwaway execroot" equivalent).** Because we run
**in place**, the execroot persists between actions — and across Bazel's
reduced→full classpath **re-execution of the same Java action** (two separate
`BazelSandbox.exe` invocations sharing one execroot). A first attempt that fails
mid-way leaves scratch (`_javac/*_tmp/native_headers`) that the second attempt's
`JavaBuilder.cleanupDirectory` cannot remove — the input filter hides it, so
`RemoveDirectory` fails with `DIRECTORY_NOT_EMPTY`. To reproduce Linux's fresh
per-execution execroot, the launcher **deletes its own created-set on exit** (after
the whole process tree has exited): undeclared scratch is discarded, while declared
`-w` outputs (never in the set) are preserved for Bazel to harvest in place. This
is skipped under `-D` (`--sandbox_debug`), matching linux-sandbox keeping its
sandbox dir for inspection.

This is the concrete realization of the "discard set" refinement this section
previously deferred; the virtual execroot (§4) remains the option if fail-closed
isolation is ever required.

---

## 8. Relationship to the ProjFS doc

`projfs-sandbox-modes.md` remains the reference for the *constructive* model and
its measurements. For the **read-isolation / undeclared-input-invisibility** goal,
this filtering design is the chosen near-term implementation and supersedes ProjFS
Mode 1. ProjFS / the virtual execroot (§4) are retained as the documented
evolution if fail-closed isolation or staging elimination becomes required.

---

## 9. Implementation status & fix log

Mechanisms A and B and the write model (§7) are **implemented and tested** — the
full enforce suite is green, including the enumeration matrix across all three
code paths. What follows is the build-out record and the parity bugs surfaced
while validating against real repos (notably a large Angular/TypeScript monorepo
frontend build). It is a
*log* of what was built, not a forward-looking plan.

The canonical per-finding ledger — each discrepancy with its root cause, current
status, and the test that pins it — is
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md). Where a design
mechanism here and a discovered bug there are the same story, that doc is the
source of truth for the finding; this section keeps the implementation-level
detail (flag bits, hooked surfaces, buffer rewrites).

1. **Mechanism A — NOT_FOUND on denied read. ✅ DONE.**
   - Added `ExtraFlag_DeniedReadsAsNotFound` (0x400) +
     `ExtraFlag_FilterDirectoryEnumeration` (0x800) to `manifest_builder.h`
     and `FOR_ALL_FAM_EXTRA_FLAGS` in `DataTypes.h` (auto-generates the
     `ShouldDeniedReadsAsNotFound()` global accessor).
   - Added `AccessCheckResult::DenialError(bool)` / `DenialNtStatus(bool)` /
     `SetLastErrorToDenialError(bool)` + `IsReadOnlyAccess()`; masking applies only
     to read-only, otherwise-`ACCESS_DENIED` (Valid) denials — write denials are
     untouched.
   - Threaded `ShouldDeniedReadsAsNotFound()` into the read/open denial sites
     in `DetouredFunctions.cpp`: `CreateFileW`, `NtCreateFile`/`ZwCreateFile`,
     `NtOpenFile`/`ZwOpenFile`, `GetFileAttributes` probe, reparse-chain read check,
     and the **`FindFirstFileExW` single-file probe** (a `FindFirstFileEx` on an
     exact path with no wildcard — the existence check `cmd.exe`'s `type`,
     `GetShortPathName`, and many CRT `stat()` implementations perform). Without this
     last one, those probes returned `ACCESS_DENIED` while the matching `CreateFile`
     read returned `NOT_FOUND`, so a tool that pre-checks with `FindFirstFile` (e.g.
     `type undeclared.txt`) saw "access denied" instead of "cannot find file" —
     diverging from linux-sandbox. Enumeration (wildcard) probes are unaffected
     (they never hard-deny).
   - Launcher: `--filter-inputs` sets both extra flags and implies `-H`.
   - Probe tool gained exit code `11` (not-found) distinct from `10` (denied);
     `tests/enforce/modes_test.cc` asserts masking for `read`/`ntread`/`stat`/`findfile`,
     that a declared `-r` still reads, and that undeclared **writes** still return `10`.
   - **`GetFileInformationByName` stat-masking fix.** Modern libuv (Node 18+, here
     Node 24 / libuv 1.51) implements `fs.stat`/`fs.lstat` via the handle-less
     `GetFileInformationByName(FileStatBasicByNameInfo)` fast path (a Win8+/Win11
     `kernelbase` API) instead of opening a `CreateFile` handle — it only falls back to
     `CreateFileW(FILE_READ_ATTRIBUTES)` when that API is absent. We hooked
     `CreateFileW` and `GetFileAttributes*` but **not** `GetFileInformationByName`, so an
     undeclared *existing* file stayed **visible** to `fs.stat` (returning `isFile=true`)
     even though `open()`/`read()` of the same path were masked to `NOT_FOUND`. That
     stat/read *inconsistency* broke parity with linux-sandbox, where an undeclared input
     is simply absent from the symlink forest so **both** stat and read observe `ENOENT`.
     It surfaced in a real Vite build target as a **ViteBuild ENOENT**:
     vite's `tsconfck` does `fs.stat(tsconfig.json)` and, seeing `isFile=true`, tries to
     `readFile` it — which is masked → hard error; on Linux the same `stat` returns
     `ENOENT`, so tsconfig is treated as absent (optional) and the build succeeds.
     Fix: hook `GetFileInformationByName` (resolved dynamically from `kernelbase.dll`, so
     the DLL still loads on OSes lacking it) and apply the same `CheckReadAccess(Probe)`
     masking the `GetFileAttributesExW` detour uses — denied undeclared probes become
     `NOT_FOUND`, directories/declared inputs stay visible. Regression: new `statbyname`
     probe op (dynamically resolves the API, mirroring libuv) + `modes.ps1` asserts an
     undeclared `statbyname` is masked (`11`) and a declared one is visible (`0`). The
     pre-existing `stat` op used `GetFileAttributesW`, which was already masked, so it
     could not catch this leak.
   - **`GetFileInformationByName` handle-resolution *probe* fallback.** A follow-on parity
     bug from the same libuv stat path: node's ESM resolver `stat`s a module file *before*
     opening it, and in the aspect_rules_js pnpm layout that path traverses an **undeclared
     intra-store junction** (`@a+cli@v/node_modules/@scope/b → @scope+b@v/…`) whose real
     **target** is a granted input but the junction itself is not. `CreateFileW` reads
     already survive this via the *handle-resolution read fallback* (resolve the opened
     handle's final path with `DetourGetFinalPathByHandle`, re-check the target's policy),
     but `GetFileInformationByName` is **handle-less**, and BuildXL's fast reparse resolution
     only follows a reparse point when it is the **last** path component — here the junction
     is **mid-path**. So the literal probe was denied → masked → node threw
     `ERR_MODULE_NOT_FOUND` (`@angular/compiler/fesm2022/compiler.mjs`) before ever attempting
     the rescuable open; linux-sandbox's forest lets `stat` follow the link, so it built.
     Fix: when the literal probe denies **and the file exists**, open a transient read handle
     that follows the reparse chain (`FILE_READ_ATTRIBUTES | FILE_FLAG_BACKUP_SEMANTICS`, no
     `OPEN_REPARSE_POINT`), resolve its final path, and honor that path's read policy —
     exactly mirroring the `CreateFileW` fallback. Reads/probes only; a link whose real
     target is undeclared still resolves to a non-granted path and stays denied, so
     hermeticity is preserved. Regression: `reparse.ps1` `statbyname` cases (undeclared
     junction → -r-granted target allowed; → denied target denied).

2. **Mechanism B (Win32) — FindFirstFile/FindNextFile enumeration filter. ✅ DONE.**
   - Filter `FindFirstFileExW`/`FindNextFileW` by manifest read-policy; keep
     `.`/`..`; preserve existing short-name scrub and timestamp override.
   - Visibility predicate (shared with the Nt paths): an entry is visible iff it is
     `.`/`..`, OR `childPolicy.AllowRead()` (a declared file or anything under a
     declared directory-input cone), OR `childPolicy.IsExactManifestNode()` — an
     ancestor directory that leads to a declared input. The last case relies on
     `PolicySearchCursor.SearchWasTruncated == false`: a path that resolves to an
     exact node in the manifest tree is an ancestor of (or is) a declared input;
     a truncated search fell off the tree into an undeclared cone.
   - Test: `enumfind` probe op over a dir with mixed declared/undeclared children
     shows only declared files + ancestor dirs.

3. **Mechanism B (native) — Nt/Zw enumeration filter. ✅ DONE.**
   - In-place buffer rewrite (`FilterDirectoryInformation`) for the common
     info classes (`FileDirectoryInformation`, `FileFullDirectoryInformation`,
     `FileBothDirectoryInformation`, `FileNamesInformation`,
     `FileIdBothDirectoryInformation`, `FileIdFullDirectoryInformation`); survivors
     are re-linked via `NextEntryOffset`. A re-query loop
     (`ApplyEnumerationFilterNt` / `…Ex`) continues the scan when a whole batch
     is hidden, so callers never see a success-with-zero-visible batch.
   - Hooked **three** enumeration surfaces so every caller is covered:
     - `NtQueryDirectoryFile` / `ZwQueryDirectoryFile` — the path Node/libuv use via
       a *direct* `ntdll` call (un-nested, filtered directly).
     - `NtQueryDirectoryFileEx` — newly hooked; the modern successor used by
       `FindFirstFileEx` internals and direct callers on Windows 8+.
     - `GetFileInformationByHandleEx` (directory info classes) — this wrapper
       establishes its own `DetouredScope` before calling the real API, which
       *shields* the inner `NtQueryDirectoryFile` from the Nt-level filter (it sees a
       nested/disabled scope). So the directory-enumeration info classes
       (`FileIdBothDirectoryInfo`, `FileFullDirectoryInfo`, and their Restart
       variants) are filtered directly in the wrapper, mapping the handle info class
       to the equivalent Nt layout. This covers the .NET `Directory` APIs and some
       CRTs.
   - Tests: `tests/enforce/modes_test.cc` runs the full matrix (declared file visible,
     undeclared file hidden, ancestor dir visible, undeclared dir hidden) across all
     three probe ops: `enumfind` (Win32), `enumfindnt`
     (`GetFileInformationByHandleEx`), and `enumfindntdirect` (direct
     `ntdll!NtQueryDirectoryFile`, the Node/libuv path).
   - **`\\?\` sub-path device-classification fix.** The child-visibility predicate
     (`IsEnumChildVisible`) derives each entry's policy via
     `PolicyResult::GetPolicyForSubpath` → `InitializeFromCursor`, extending the
     directory's tree cursor by the child leaf. The special-case rules
     (`GetSpecialCaseRulesForCoverageAndSpecialDevices` etc.) were mistakenly evaluated
     against that *cursor-relative leaf* (e.g. `"secret.txt"`) while still being told
     the path's `PathType`. For a directory opened with the `\\?\` extended-length
     prefix (Node/libuv's default for `readdir`) the type is `Win32Nt`, so the
     device-path branch classified every leaf as a "non-drive device" and granted
     `FileAccessPolicy_AllowAll` — leaking *all* undeclared entries through the filter
     (they became visible **and** readable). This surfaced as a `tsc` **TS6053**:
     an undeclared `src/test-utils.ts` was returned by a `\\?\` `readdir`, matched by
     the `src/**/*.ts` include glob, then failed to open (the read is still masked).
     Fix: `InitializeFromCursor` now evaluates the special-case rules against the
     **full** translated path (`GetTranslatedPathWithoutTypePrefix()`), not the search
     suffix; the suffix is used only for the manifest-tree search. Plain (`Win32`)
     paths were unaffected (that branch is `Win32Nt`/`LocalDevice`-only) and the
     fresh-from-root case is unchanged (its suffix already *is* the full path).
     Regression: the enumeration matrix is re-run with a `\\?\`-prefixed directory.

4. **Integration + parity validation. ✅ DONE (Mode 2).**
   - The `ng_package` / `node_modules`-heavy cases build end-to-end under
     `--filter-inputs`; A4/A5 behavior matches linux-sandbox expectations (see
     parity-findings A4/A5). The opt-in `tests/integration/sandbox-strategy-smoke.ps1` exercises the
     Bazel↔sandbox integration layer.
   - Outstanding: regenerate `files/bazel-windows-sandbox.patch` after the latest
     native changes; Mode 3 (`--hermetic-fs`, §1.1) remains future work.

---

## 10. Test strategy

Tests are layered. The exhaustive op-by-op assertions live in the test files
themselves (`tests/enforce/*.ps1`, `tests/unit/*`), and each parity fix names the
test that pins it in
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md) ("Where the tests
live"). The tiers:

* **Unit (host):** the manifest carries the new flag bits (`manifest_builder`
  tests).
* **Behavioral (`probe.exe`):** denied reads → `NOT_FOUND` (not `ACCESS_DENIED`)
  across every read/stat/enumerate syscall surface (`read`/`ntread`/`stat`/
  `statbyname`/`findfile`); enumeration hides undeclared entries while keeping
  declared files and ancestor dirs (the full matrix over `enumfind`,
  `enumfindnt`, `enumfindntdirect`), re-run against `\\?\` extended-length paths
  (the Node/libuv `readdir` form); writes outside the execroot stay
  `ACCESS_DENIED`.
* **Real action:** the `ng_package` / `node_modules`-heavy build under
  `--filter-inputs`, compared against a linux-sandbox run of the same commit.
* **End-to-end (opt-in, `tests/integration/sandbox-strategy-smoke.ps1`):** drives a real Bazel build
  through the `windows-sandbox` strategy to validate the Bazel↔sandbox integration
  layer (Mode 2 emits `--filter-inputs`; declared inputs resolve; an undeclared
  input is observed as `NOT_FOUND`, not `ACCESS_DENIED`). Requires a patched Bazel
  + network/cert; intentionally **not** part of `bazel test //tests:all`. See
  `tests/e2e/README.md`.
