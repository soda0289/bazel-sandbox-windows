# Detours write-redirection overlay (per-action VFS) — design

Status: **research / proposal — NOT approved for implementation.** This doc
studies whether a **Detours-based, write-redirecting overlay VFS** is the right
way to close finding
[**A8**](../sandbox-parity-findings.md#a8-concurrent-actions-collide-on-a-fixed-name-undeclared-file-in-the-shared-in-place-execroot--open)
(and generalize A7/B2) by giving every action a private write namespace — the
Windows analog of `linux-sandbox`'s throwaway execroot. It is the concrete
build-out of the "virtual-execroot / fake-path VFS" direction sketched in
[`detours-input-filtering.md` §4](detours-input-filtering.md#4-the-virtual-execroot-question-fake-path-vfs),
narrowed to the *write* half so it stays a **fail-open** extension of what we
already ship rather than the **fail-closed** rewrite §4 warned against.

It also captures a design study of **[usvfs](https://github.com/ModOrganizer2/usvfs)**
(User-Space VFS, the Mod Organizer 2 component) — a project that already does
userspace file virtualization on Windows via `kernel32`/`ntdll` API hooking, the
same technique we use — and what we can and cannot borrow from it.

> **Licensing gate (read first).** usvfs is **GPLv3**. This project is MIT
> (Detours) + BuildXL-derived vendored code. We may **study usvfs's design and
> learn from its approach, but must not copy, paste, or mechanically translate
> its source** into this repo. Every reference below is to *design*, not code.
> Any implementation here must be clean-room and independently written.

Related docs:
[`detours-input-filtering.md`](detours-input-filtering.md) (the subtractive
in-place model we ship today; §4 = the deferred VFS question this doc extends,
§7 = the `--execroot-writable` created-set write model this doc builds on),
[`projfs-sandbox-modes.md`](projfs-sandbox-modes.md) (the *constructive* ProjFS
alternative and its performance spike),
[`sandbox-parity-findings.md`](../sandbox-parity-findings.md) (A7/A8/B2 — the
findings that motivate this),
[`linux-sandbox-comparison.md`](../comparison/linux-sandbox-comparison.md)
(§6 write-overlay note, throwaway-execroot parity),
[`vendor-architecture.md`](../vendor-architecture.md) (the Detours engine and the
6-flag / cone-tree policy slice we actually use).

---

## 1. The problem, stated precisely

We run **in place in the real execroot** — there is no per-action staging (that is
the deliberate speed win of the subtractive model, `detours-input-filtering.md`
§1). `linux-sandbox` instead gives **each action its own execroot** (a symlink
forest under `<sandbox_base>/<id>/`), so a fixed-name undeclared side-file never
collides between actions and the whole tree is thrown away afterward.

The in-place model reproduces the *throwaway* behavior with a **created-set**: a
path first created this run is allowed to be re-written/read/deleted by the action
tree, and is discarded on tree exit (§7 of the filtering doc, A7). But the
created-set is **per-action-invocation**, while the *filesystem* is shared. So:

* **A8 (open):** two concurrent actions writing the **same** fixed undeclared path
  (`goyacc`'s `y.output` at the execroot root) collide. A holds/created the real
  file; B sees it on disk, absent from B's created-set, and the no-clobber guard
  denies B → `ERROR_ACCESS_DENIED`. `local` never hits this because it enforces no
  no-clobber at all.
* **A7 (fixed):** stale undeclared scratch between actions — fixed by
  discard-on-exit, but only for paths *our* launcher created and only if the tree
  exited through us.
* **B2 (known-gap):** a junction planted inside a writable `-w` scope can redirect
  a write outside the cone.

All three share one root: **undeclared writes land on the one real shared
filesystem.** The linux-faithful cure is that they should never touch a shared
real path at all — each action should write into a **private overlay** that is
invisible to every other action and discarded at exit. That is what this doc
designs.

### 1.1 What we are explicitly *not* proposing

We are **not** proposing to virtualize *reads* (the fail-closed "fake execroot"
of §4). Reads continue to resolve against the **real** execroot exactly as today
(declared inputs allowed by `-r`; undeclared reads filtered to `NOT_FOUND`). Only
**writes** (and the reads/enumerations that must observe those writes) are
redirected. This keeps the failure mode **fail-open** (a missed hook leaks a real
file = weaker isolation but a *correct build*), never fail-closed (a missed hook
makes a real input unreachable = *broken build*). §4 of the filtering doc rejected
the full VFS precisely because it is fail-closed; the write-only overlay sidesteps
that objection.

---

## 2. The core question: map writes only, or virtualize everything?

The decisive design axis is how much of the filesystem to virtualize. Two models:

### 2.1 Model W — write-redirection overlay (proposed)

* **Reads / opens for read:** unchanged. Resolve against the real execroot;
  subtractive filter applies (`NOT_FOUND` for undeclared).
* **Writes / creates / creates-of-new:** redirect the *target path* to a private
  per-action **backing store** (temp dir or RAM disk). The real execroot file is
  never touched.
* **Reads of a path this action wrote:** served from the backing store (overlay
  read-back), so a tool sees its own scratch.
* **Enumeration:** the **real** directory is enumerated (as today) and then
  **(a) filtered** (undeclared real entries removed — already implemented) **and
  (b) augmented** with the action's overlay entries for that directory (the new
  work).
* **Deletes / renames / moves:** recorded in the overlay as tombstones / moved
  entries so subsequent reads and enumerations reflect them.

Consequence: **no two actions ever share a writable real path.** A8 disappears
structurally (each `y.output` is a different backing file). A7's discard becomes
"delete the backing store" (trivially correct — nothing was ever written to the
shared execroot). B2 is contained because the write target is resolved to the
overlay before any real-path traversal.

### 2.2 Model R — full read+write VFS (the §4 "fake execroot")

Virtualize *both* directions: synthesize the entire execroot namespace, resolve
every input open to a real handle behind a curated virtual name, synthesize all
enumerations from the manifest, redirect writes to the overlay. This is the true
Linux symlink-forest analog with **no physical staging at all**.

`detours-input-filtering.md` §4 already assessed Model R and **deferred it**: it
requires remapping paths on *every* path-consuming API (fail-closed), reverse
mapping (`GetFinalPathNameByHandle` / `NtQueryObject`) — BuildXL's "device map"
machinery we set out to avoid (`vendor-architecture.md` §2, §5) — and fully
synthesized enumeration. That assessment stands.

### 2.3 Recommendation on the axis

**Model W is the right first step (and probably the right end state) — and yes,
it is a possible solution.** It closes A8/A7/B2 while keeping the fail-open trust
model and reusing the two things we already have: (1) the real execroot for reads,
and (2) the cross-process created-set shared memory (§4), which becomes the
overlay's index. Model R buys stronger isolation we do not need for the primary
goal (catch missing-input declarations) at a cost the ProjFS spike and §4 both
concluded is not worth it.

The rest of this doc designs Model W, including its **one genuinely hard
part: enumeration insertion** (§5).

---

## 3. What usvfs does, and what transfers

usvfs is the closest existing prior art: a userspace VFS built from `kernel32` /
`ntdll` API hooks (their `thooklib`, analogous to our Detours), sharing a virtual
**directory tree in shared memory** across all hooked processes, so that a chosen
set of processes "see" files that live somewhere else. Its goals list — *links
visible only to selected processes, disappear when the session ends, overlaying,
and "virtually unlink"/replace files* — maps almost one-to-one onto what an
action-scoped write overlay needs.

| usvfs concept | Our analog | Transferable? |
| --- | --- | --- |
| API hooking of `kernel32`/`ntdll` file funcs | Our Detours `DetouredFunctions.cpp` (75 hooks) | **Already have it** — richer than usvfs's set. |
| Shared-memory **directory tree** (`src/shared/directory_tree.h`, boost::interprocess offset pointers) | Extend our created-set SHM (§4) into a path→entry map | **Design idea transfers; code does not (GPLv3).** We already have a proven append-only SHM log to grow. |
| **Overlay** (multiple sources over one target) | Overlay the per-action backing store over the real execroot dir | Yes — but we need only *one* writable layer over the real base, far simpler than usvfs's N-way overlay. |
| **Virtual unlink** (hide/replace a file) | Delete/rename tombstones in the overlay | Yes — directly relevant to the delete/move cases below. |
| Enumeration merge in `FindFirstFile*`/`NtQueryDirectoryFile` hooks (`kernel32.cpp` 57 KB, `ntdll.cpp` 55 KB) | Extend our `FilterDirectoryInformation` from *filter-only* to *filter + insert* | **Concept transfers; this is the hard part (§5).** The size of their two hook files is a fair signal of how much edge-case handling enumeration needs. |
| Reverse path lookup for handle→name queries | We would need this **only** for overlay-backed handles, not all inputs | Partially — much smaller than Model R because reads aren't virtualized. |
| Injection helper / proxy process | Our launcher `BazelSandbox.exe` | Already have it. |

**Net lesson from usvfs:** the approach is proven to work in production (MO2 has
thousands of users), which de-risks the *concept*. But the two multi-tens-of-KB
hook files for `kernel32`+`ntdll` are a fair estimate of the *enumeration and
path-canonicalization surface* you must cover to make `FindNextFileEx` and
`NtQueryDirectoryFile` correct under concurrency. That surface, not the shared
tree, is the cost center — which is exactly what §5 dissects.

---

## 4. Shared state: growing the created-set into an overlay map

We already run a **cross-process, per-invocation shared-memory** created-set
(`vendor/detours-services/PolicyResult.cpp`, `CreatedFilesTracker`): a named
region (`g_bazelCreatedShmName`, carried in the manifest payload so it reaches
every child regardless of environment), an append-only record log
`[uint32 nameBytes][wchar_t name…]` padded to 4, a `usedBytes`/`capacity` header,
a per-process local cache, and a named mutex for append/scan. This is the natural
substrate to reuse, and it already solved the hard cross-process
consistency problem (A6: JavaBuilder forks; one process creates, another cleans).

The overlay needs to store **more than a path** per entry. Proposed record
(superseding the name-only record; a manifest flag selects the format so the
plain created-set still works for the tests):

```
struct OverlayRecord {
    uint32  recBytes;       // total record length, 8-byte aligned
    uint32  kind;           // FILE | DIR | SYMLINK | JUNCTION | TOMBSTONE | RENAME_FROM
    uint64  seq;            // monotonic append index → last-writer-wins ordering
    uint32  attributes;     // FILE_ATTRIBUTE_*
    int64   fileSizeHint;   // best-effort; authoritative size is the backing file
    int64   creationTime;   // FILETIME
    int64   lastWriteTime;  // FILETIME
    int64   changeTime;
    uint32  virtNameBytes;  // canonicalized virtual (execroot) path
    uint32  backingNameBytes;// path in the backing store (0 for tombstone/dir)
    uint32  reparseTargetBytes;// for SYMLINK/JUNCTION
    // … wchar_t payloads follow, each padded to 4 …
};
```

Key properties, all inherited from the existing design:

* **Append-only + `seq`.** We never mutate a record in place (that is what makes
  the lock-light publish-after-write scheme safe). A **delete** appends a
  `TOMBSTONE` for the path; a **re-create** appends a fresh `FILE`; a **rename**
  appends `RENAME_FROM(old)` + `FILE/DIR(new)`. The **highest `seq`** for a given
  canonical path wins. This resolves the write-then-delete and write-then-move
  cases without any in-place mutation: the map
  only has to append the newest fact and let readers fold by `seq`. Each process
  keeps a folded view in its local cache (path → latest record), refreshed by the
  same `SyncFromShared` tail-scan we already have.
* **Symlink / junction writes** (`kind = SYMLINK|JUNCTION` + `reparseTargetBytes`)
  are first-class: `CreateSymbolicLink`/`DeviceIoControl(FSCTL_SET_REPARSE_POINT)`
  on a cone path record the reparse target in the overlay instead of materializing
  a real reparse point in the execroot. Enumeration reports them as reparse
  entries; opens follow them within the overlay/real namespace under policy.
* **Attributes / timestamps / permissions** ride in the record. `GetFileAttributes*`
  / `NtQueryInformationFile` / `FindNextFile` for an overlay path answer from the
  record (+ the backing file's live size), so `SetFileTime`/`SetFileAttributes`
  on scratch behave. ACLs/permissions are **out of scope** for parity (linux-
  sandbox does not model Windows ACLs and neither do we today); we store the
  attribute word only.
* **Concurrency across the action's processes/threads** is already handled: the
  region is shared by the whole tree, the mutex serializes appends, `shared_mutex`
  guards the per-process cache, and reads fold by `seq`. Multiple threads writing
  different paths never contend beyond the append mutex; two threads racing the
  *same* path get last-`seq`-wins, which matches `local`'s last-writer-wins
  non-hermeticity (A8's "how local handles it").
* **Per-action isolation is automatic.** The region is created per launcher
  invocation, so overlay entries of action A are literally in a different SHM
  region from action B. **This is the structural reason A8 dies.**

Sizing note: the current region is a fixed capacity. An overlay that captures
every scratch write of a heavy action (e.g. a Java action's `_javac` tree) needs
a larger, and ideally **growable**, region (chained mappings, or size it from a
launcher estimate). This is a concrete new requirement, not free.

---

## 5. Enumeration: filter (have) → filter + insert (need)

This is the crux. Everything else is bookkeeping; this is
where correctness lives.

### 5.1 What we have (subtractive, stateless)

`FilterDirectoryInformation` (`DetouredFunctions.cpp` ~5095) walks the info-class
record chain returned by the real `NtQueryDirectoryFile`/`FindFirstFile` family,
drops records for undeclared names via `IsEnumChildVisible`, and **rewrites the
`NextEntryOffset` chain** to splice out the dropped ones. It is applied at every
enumeration hook (`Nt`/`Zw QueryDirectoryFile[Ex]`, `FindFirstFileEx` →
`FindNextFile`). It is **stateless per call** and only ever *shrinks* the buffer —
which is why it is cheap and low-risk: the result always fits.

### 5.2 What insertion adds (constructive, stateful)

To make the action see its overlay files, we must **add** synthetic records for
overlay entries in the enumerated directory that are not already present in the
real listing (and drop real entries the overlay tombstoned). That breaks three
assumptions the filter relies on:

1. **Buffer capacity.** Inserted records can overflow the caller's buffer. The
   Win32/NT enumeration contract handles this by returning entries across
   **multiple calls** (`STATUS_SUCCESS` with a partial fill, then more on the next
   call; `STATUS_BUFFER_OVERFLOW`/`ERROR_MORE_DATA` for a single oversized entry).
   So insertion is inherently **multi-call and therefore stateful**.
2. **Per-handle cursor state.** We must remember, *for each open directory handle*,
   which synthetic overlay entries we have already handed back, so we neither
   duplicate nor skip them as the tool loops `FindNextFile`/`NtQueryDirectoryFile`.
   That means a **hook-side table keyed by directory HANDLE** holding: the folded
   overlay entry list for that dir (snapshotted at first query for stability), a
   cursor, and the `FileName` wildcard + `RestartScan` state. Handles are opened
   by us-hooked `NtCreateFile`/`CreateFile`, so we have a natural place to allocate
   this and to free it on `NtClose`.
3. **Thread-safety on one handle.** This is a real constraint. A directory
   handle can be queried from multiple threads; and more importantly Bazel runs
   many *processes*. Two sub-cases:
   * **Multiple threads, same handle:** rare but legal. The per-handle state must
     be mutex-guarded (a per-handle critical section). The kernel already
     serializes the underlying `NtQueryDirectoryFile` on the handle's file object;
     we mirror that with our own lock so the cursor advances atomically with the
     underlying call.
   * **Multiple processes:** each process opens its **own** handle to the dir, so
     per-handle state is naturally per-process — no cross-process enumeration
     cursor is needed. What must be cross-process is the **overlay content**
     (the SHM map, §4), which we snapshot into the per-handle list at first query.
     A late write by a sibling process after another process began enumerating is
     the same benign race `local` has (readdir is not atomic against concurrent
     creates on Windows either); we accept it.

### 5.3 Info-class + API surface to cover

Insertion (unlike filtering) must **construct** valid records, so it must know the
exact layout of **every** `FILE_INFORMATION_CLASS` a tool might request:
`FileDirectoryInformation`, `FileFullDirectoryInformation`,
`FileBothDirectoryInformation` (the `FindFirstFile` workhorse, has short names),
`FileIdBothDirectoryInformation`, `FileNamesInformation`,
`FileIdExtdDirectoryInformation`, … plus the Win32 layer
(`WIN32_FIND_DATA` via `FindFirstFileEx`/`FindNextFile`, and the transactional/Ex
variants). We already have `TryGetDirInfoLayout` for the offsets we *read*; we
must extend it to *emit* each class, including the short-name (8.3) field for
`FileBothDirectoryInformation` and stable `FileId`s for the Id classes (synthesize
deterministic ids). This is the bulk of usvfs's `ntdll.cpp` size and the main
implementation cost.

### 5.4 Why insertion is still bounded (the optimistic half)

The overlay is **small** relative to the real tree: it holds only what *this
action* wrote — typically a handful of scratch files per directory, not tens of
thousands of inputs. So the snapshot list per handle is short, the extra records
per call are few, and reads/opens still hit the real filesystem at native speed.
This is the decisive asymmetry vs Model R (which must synthesize *entire* input
directories, tens of thousands of entries, the case the ProjFS spike showed is
expensive). We enumerate the real dir once (cheap, as today), then append a short
overlay tail. The performance profile stays close to the subtractive model.

---

## 6. Write backing store, discard, debug, and outputs

### 6.1 Where writes land

A per-invocation backing directory, created by the launcher and passed in the
manifest (alongside `g_bazelCreatedShmName`):

* **Default: a temp directory** under the sandbox base (e.g.
  `%TMP%\bzlsbx-<pid>-<guid>\overlay\…`), mirroring the virtual path so a
  backing file is easy to locate and so relative-path/`GetFullPathName` behavior
  stays sane.
* **Optional: a RAM disk.** If the host provides one (ImDisk/`R:`), point the
  backing root there for tmpfs-like speed — a config knob, not a dependency. This
  matches `linux-sandbox` often putting `<sandbox_base>` on tmpfs.

Declared `-w` **outputs are NOT redirected** — they must land in the real
execroot where Bazel harvests them in place (we execute in place; there is no
copy-out step like linux-sandbox). Only **undeclared** writes go to the overlay.
This is the key divergence from a pure VFS and it is deliberate: outputs are the
one class that must survive on the real disk.

### 6.2 Discard, debug, and output retention — and what linux-sandbox does

The design has to match how long `linux-sandbox` keeps its forest and how
debug/outputs change that. Observed behavior:

* **Normal run:** `linux-sandbox` builds the per-action execroot (symlink forest +
  writable layer) under `<sandbox_base>/<id>/`, runs the action, then Bazel
  **moves the declared outputs out** into the real output tree and **deletes the
  entire sandbox directory immediately** afterward (asynchronously, via a deletion
  thread pool / `--experimental_sandbox_async_tree_delete_size`). It does **not**
  hold onto the forest between actions.
* **`--reuse_sandbox_directories`:** the *directory skeleton* is recycled to avoid
  re-creating the forest, but contents are reset per action — not retention of
  data.
* **`--sandbox_debug`:** Bazel **keeps** the sandbox dir and prints its path so you
  can inspect exactly what the action saw. Nothing is deleted.
* **Outputs:** exist in the sandbox execroot only until the post-action move; then
  they live in the real output tree. Undeclared writes in the forest are discarded
  with the sandbox dir.

Our overlay mirrors this precisely, and more cleanly than the in-place created-set
does today:

| Situation | Overlay behavior |
| --- | --- |
| Action succeeds | Launcher deletes the backing store + SHM region on tree exit. Undeclared scratch vanishes; declared `-w` outputs were written to the real execroot, untouched. |
| `--sandbox_debug` (`-D`) | **Keep** the backing store and print its path (like linux-sandbox keeping the sandbox dir). Also skip discard, matching today's `-D` behavior (§7 of the filtering doc). |
| Action fails / retried (reduced→full classpath) | Fresh overlay per invocation ⇒ the second attempt starts clean; no stale scratch to trip cleanup (this is A7, now structurally impossible rather than patched). |
| Action creates *many* files | All land in the overlay; capacity is the backing store's disk/RAM, not a shared execroot. **No effect on any other action's overlay** — isolation is total. |

---

## 7. Parity mapping (Model W vs linux-sandbox)

| Behavior | linux-sandbox | Model W overlay |
| --- | --- | --- |
| Undeclared read | absent → `ENOENT` | real execroot + subtractive filter → `NOT_FOUND` (unchanged) |
| Declared input read | real file via symlink | real file in place (`-r`) (unchanged) |
| Undeclared write | writable throwaway execroot | redirected to per-action overlay |
| Read-back of own scratch | sees it (same execroot) | served from overlay |
| Enumeration incl. own scratch | present in forest | real listing **filtered + overlay entries inserted** (§5) |
| Fixed-name side file (A8 `y.output`) | never collides (private execroot) | **never collides (private overlay)** ✔ |
| Delete / rename scratch | normal FS op in forest | tombstone / rename record (§4) |
| Declared `-w` output | in execroot, moved out post-action | **written to real execroot in place** (harvested in place) |
| Discard timing | sandbox dir deleted right after action | overlay + SHM deleted on tree exit; kept under `-D` |
| Isolation strength | constructive (fail-closed) | **hide/redirect in place (fail-open)** — writes private, reads real |

Divergence to keep honest: this is still **hide-and-redirect, not construct**. A tool
using an un-hooked write path could still hit the real execroot (fail-open) — the
same trust model we already document. Reads are *not* virtualized, so a declared
input can never become unreachable (the fail-closed risk §4 rejected). We buy
Linux's write isolation without Linux's read guarantee.

---

## 8. Should we go down this path? Recommendation

**Layered recommendation — do the cheap fix now; treat the overlay as a real but
later evolution; do not build the full read VFS.**

1. **Now — close A8 cheaply (no VFS).** Implement fix **A8(a)**: narrow the
   no-clobber guard to deny clobbering only **declared `-r` inputs**, treating any
   *other* pre-existing cone path as clobberable scratch (optionally plus **A8(b)**
   pre-cleaning root scratch). This closes the whole A8 class with a few lines in
   `PolicyResult::AllowWrite`, no new subsystem, no enumeration insertion, and no
   risk to the green enforce suite. It is already the recommended P1 fix in the
   findings ledger, and it is the correct immediate action.
   The residual gap A8(a) leaves — two actions still physically share the real
   path, so a *content* race is possible — is exactly the benign non-hermeticity
   `local` already tolerates (the side file's content is never consumed), so it is
   acceptable.

2. **Later — Model W overlay as the "Mode 3 / true-throwaway" evolution**, *iff* a
   concrete need appears: a real build where two actions collide on a fixed path
   whose **content is actually consumed** (a genuine hermeticity bug, not benign
   like `y.output`), or a hard requirement to guarantee no undeclared write ever
   touches the real tree. Model W is the right design for that need — it is
   feasible, it reuses our SHM and hooks, and usvfs proves the technique works —
   but it is a **multi-week lift dominated by enumeration insertion (§5)** and a
   growable SHM map (§4). Do not start it speculatively.

3. **Never (for this project's goals) — Model R full read-virtualizing VFS.** §4 of
   the filtering doc and the ProjFS spike already settled this: it reintroduces the
   path-translation / realpath-reverse / device-map complexity we left BuildXL to
   escape, is fail-closed (broken builds on a missed hook), and its enumeration
   must synthesize entire input trees (the slow case). The write-only overlay gets
   us the linux-faithful *write* isolation without any of that.

**Why not jump straight to Model W?** A8's observed symptom is a *benign*
race (goyacc's `y.output` content is discarded), and A8(a) fully satisfies the
Goal-1 bar (nothing that should build is denied) at a fraction of the cost. The
overlay's extra
value — bullet-proof write isolation and unifying A7/A8/B2 — is real but is Goal-2
polish, and §5's enumeration-insertion surface is genuinely large (usvfs's two
50-KB hook files are the cautionary measure). Spend that budget only against a
demonstrated need.

---

## 9. If Model W is greenlit: phased plan

1. **Spike enumeration insertion in isolation.** Extend `FilterDirectoryInformation`
   into a filter+insert pass for **one** info class (`FileBothDirectoryInformation`)
   plus per-handle cursor state keyed on the directory HANDLE, freed at `NtClose`.
   Prove multi-call continuation and `RestartScan` against a synthetic overlay of a
   few files. **This is the make-or-break risk; do it first.**
2. **Grow the SHM record** (§4) from name-only to `OverlayRecord`, behind a manifest
   flag; fold-by-`seq` in the per-process cache; add TOMBSTONE/RENAME. Keep the
   plain created-set format for the existing enforce tests.
3. **Write redirection** in the create/open-for-write and write hooks: allocate a
   backing file, record the entry, return a handle to the backing file; read-back
   and metadata queries consult the overlay.
4. **Backing store + discard** in the launcher: temp (or RAM-disk) root in the
   manifest; delete on tree exit; keep under `-D` and print the path.
5. **Delete / rename / reparse** cases (tombstones, rename records, symlink/junction
   records) and their enumeration/metadata reflection.
6. **Cover the remaining info classes and the Win32 `FindFirstFileEx` family.**
7. **Differential smoke** (`tests/e2e/smoke.ps1`) on the goyacc/full-repo case that
   surfaced A8, plus the Java/`ng_package` scratch-heavy actions, under both
   `local` and `windows-sandbox`; add enforce cases for overlay read-back,
   enumeration insertion, delete/rename, and cross-process visibility.

---

## 10. Open questions

* **Growable SHM.** The append-only region is fixed-capacity today. Chained
  mappings vs. a launcher-estimated size vs. spilling to a backing-store index
  file — which is simplest without reintroducing a mutable-in-place structure?
* **Short names / FileIds.** Synthesizing stable 8.3 short names and `FileId`s for
  overlay entries that some tools depend on — deterministic scheme, or omit and
  risk a tool that needs them?
* **`GetFinalPathNameByHandle` on a backing handle.** A tool that opened scratch
  and asks for its final path will get the **backing-store** path, not the virtual
  execroot path (the reverse-mapping problem, but limited to overlay handles). Does
  any real tool care for *scratch* files? (For inputs it does — the A5 Node case —
  but inputs aren't virtualized here.) Likely acceptable; confirm on smoke.
* **Backing store on a different volume.** `MoveFile` from overlay to a real `-w`
  output across volumes becomes a copy; a rename of scratch that later becomes a
  declared output needs care. Enumerate the promote-to-output paths.
* **RAM disk availability.** Worth a dependency, or keep temp-dir default and treat
  RAM disk as an opt-in host tuning only?
