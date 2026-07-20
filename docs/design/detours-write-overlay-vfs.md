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

### 1.0 The load-bearing invariant: never mutate a pre-existing file

Before any mechanism, the guarantee that must never be violated:

> **The sandbox must never overwrite, truncate, delete, rename, or otherwise
> mutate any file that existed on disk before the build started — whether it is a
> declared input or an undeclared one.**

Hiding an undeclared file (subtractive filtering) is *not* sufficient protection.
Because we run **in place** in the real execroot, a write or delete that reaches a
pre-existing real path changes the on-disk state that **future** builds read, with
no cache key to catch it:

* Overwriting an undeclared file that later becomes a **declared** input silently
  changes a future build's inputs — a non-reproducible, no-error corruption.
* **Deleting** a pre-existing file is strictly worse than overwriting it. If an
  action removes, say, a `package.json` that it happened to reach, Node's module
  resolution changes for every later action, and the deletion is permanent — there
  is no content to restore.

This is why the naive relaxation of the no-clobber guard is **rejected** (see the
A8 fix analysis and §8): "allow writing any pre-existing path that is not a
declared input, and track+discard it" cannot tell a sibling action's transient
scratch from a real undeclared source file, so it would overwrite *and then
delete* real source. That `local` (no sandbox) also mutates such files is not a
justification — it is latent non-hermeticity we tolerate there, not a behavior to
reproduce deliberately. The only safe discriminator is **provenance**: a path may
be written or deleted **only if it was demonstrably created during this build.**
Every design below is measured against this invariant.

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

## 2. Write redirection versus full virtualization

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

The price of Model W as stated is the **(b) augment** step: synthesizing overlay
entries into directory enumerations (§5) is the hard, stateful part. §2.1.1 is a
variant that pays a different, smaller price to avoid it.

### 2.1.1 Model W-stub — real placeholders, redirected content (avoids enumeration insertion)

A refinement that removes the single hardest piece of Model W. Instead of keeping
the overlay entirely virtual and *inserting* its entries into enumerations, leave
a **real (empty) placeholder file or directory at the real execroot path** for
every scratch path the action creates, and redirect only the **file *content*
(and metadata)** to the per-action backing store:

* **Create of a new undeclared path P:** create a real 0-byte placeholder at `P`
  on disk (only if `P` does not already exist — never clobbering anything), record
  `P` in the created-set, and redirect all content reads/writes of `P` to a
  per-action backing file. The placeholder is the *namespace marker*; its bytes
  are never the real content.
* **Write to a pre-existing path P:** never touch real `P`. Redirect the handle to
  a per-action backing file (copy-on-write: seed it from `P`'s current bytes if the
  open mode preserves content, else start empty). This action's later reads of `P`
  come from the backing copy; **every other action still sees the untouched real
  `P`.** No placeholder is created — `P` already exists as the namespace entry.
* **Delete / rename of P:** never delete real `P`. Record a **per-action tombstone**
  (and, for rename, a moved entry) so *this action's* reads and enumerations treat
  `P` as gone, while the real file survives for every other action and future
  builds.

Why this is attractive:

* **Enumeration needs no insertion.** New scratch shows up in a directory listing
  because a *real* placeholder is physically there — the OS lists it for free.
  Enumeration therefore stays **subtractive only** (exactly the shipped Mechanism
  B): the existing filter hides one action's placeholders from *other* actions
  (undeclared → filtered) and reveals them to the creator (created-set →
  `IsEnumChildVisible`), just as real scratch writes work today. A **delete** of a
  pre-existing entry is handled by adding its path to the per-action *hide* set —
  a subtraction, not an insertion. The stateful per-handle cursor machinery of §5
  is not needed.
* **The invariant (§1.0) still holds.** Placeholders are created **only at brand-new
  paths** (never over a pre-existing file), and content/deletes are redirected, so
  no pre-existing file is ever mutated or removed.
* **A8 is fixed.** A write to a pre-existing fixed-name path (`y.output`) is
  redirected to the backing file instead of denied, and real `P` is never written,
  so concurrent actions never collide.

Costs and limitations:

* **It still writes to the real execroot** — empty placeholders. That is weaker
  than pure Model W's "touch nothing," though still within §1.0 (new paths only,
  discarded on exit). A crash before discard can leave 0-byte stubs behind
  (A7-class leftover, harmless but untidy).
* **Metadata consistency.** A directory listing reports the *placeholder's* size
  and timestamps (0 bytes), not the backing content's. Tools that trust the
  enumerated/`stat` size without opening would see wrong values. Mitigation:
  intercept the metadata queries (`GetFileAttributesEx`, `NtQueryInformationFile`,
  the info in `FindNextFile`) to answer from the backing record — real work, but a
  *stateless per-path lookup*, not the per-handle insertion state machine.
* **Placeholder lifetime under concurrency.** Two actions using the same fixed
  scratch name share one real placeholder; whichever discards first removes it, so
  the other must **lazily re-create the placeholder if missing** (self-healing), or
  placeholders must be build-scoped (reintroducing the build-lifetime question of
  §4). Lazy re-create is the simpler default.
* **Symlink/junction scratch** cannot be represented by an empty placeholder at all
  (see §2.1.3). Those cases fall back to virtual-only handling.

Net: **Model W-stub trades pure Model W's enumeration *insertion* for (a) creating
real empty placeholders and (b) stateless metadata redirection + subtractive
tombstones.** Both are individually easier than the per-handle, all-info-class
insertion state machine, while preserving write isolation and the §1.0 invariant.
§2.1.5 evaluates whether that shortcut is worth taking and concludes it is not.

#### 2.1.2 How scratch *directories* work

A scratch directory raises the natural question: do we create the directory for
real in the execroot and drop placeholder files inside it, or map one dummy
directory node onto the per-action temp backing directory (i.e. redirect the whole
subtree)? W-stub answers this the same way it answers files: **the namespace is
real; only file *content* is redirected.**

* **Create of a scratch directory `D`:** create a **real empty directory** at the
  real execroot path `D` (only if nothing is already there — never over a
  pre-existing entry), and record `D` in the created-set. Its children are then
  ordinary W-stub entries: real placeholder files (content redirected) and, for
  nested dirs, more real empty directories. A deep scratch tree is mirrored as a
  real (but content-less) tree in the execroot.
* **Mapping a dummy directory onto the temp backing subtree — rejected.** The alternative —
  make `execroot/D` *resolve* to `temp/<action>/D` — has only two implementations,
  both rejected:
  * **A real reparse point** (`execroot/D` → `temp/<action>`): this is literally
    creating a junction/symlink in the *shared* execroot. It needs privilege, it is
    a real shared-namespace mutation visible to every other action, and a mount
    pointing outside the cone is a **B2-class escape**. It is the exact thing
    §2.1.3 rejects for scratch symlinks — so it is not available here either.
  * **Pure path-rewriting in the hooks** (no real node; intercept every open/enum
    whose path is under `execroot/D` and rewrite it to `temp/<action>/D`): now
    `execroot/D` does *not* exist in the real namespace, so a plain enumeration of
    `execroot` will not list `D` — which reintroduces the need for **enumeration
    insertion** to make `D` appear. And rewriting whole subtrees *is* the
    reverse path-translation / device-map machinery Model R was rejected for (§2.2,
    §4). Either branch re-acquires the cost W-stub exists to avoid.

  So the mirrored-real-directory approach is the only one that keeps enumeration
  subtractive. The backing store therefore holds **only file content blobs** (keyed
  by logical path); it is *not* a mounted directory subtree, and the directory
  *structure* lives in the real execroot as empty placeholder dirs.
* **Enumeration inside `D`** works for free (the OS lists the real placeholder
  children), and the existing subtractive filter hides a *concurrent* action's
  placeholders in the same shared `D` — each action sees only children in its own
  created-set, exactly as undeclared filtering already works.
* **The one new complication: removing directories on discard.** Because the
  container `D` can be shared by concurrent actions using the same path, discard
  cannot blindly `RemoveDirectory(D)` — another action may still own placeholders
  in it. Directory teardown must be **ownership-aware** (only rmdir `D` if this
  action created it *and* it holds no other live action's entries), or deferred to
  a build-scoped sweep. Full Model W avoids this entirely: its directories are
  private overlay records, torn down with the rest of the overlay.

#### 2.1.3 Why symlinks and junctions cannot be placeholders

The whole W-stub trick is to put a **real object** in the namespace so the OS does
enumeration and `stat` for us, and to override only the one thing we must — the
**content byte-stream**. That works for a regular file because a file's observable
semantics are exactly two things a placeholder + content-redirect can reproduce:
(1) *presence in a listing*, and (2) *a content stream*.

A symlink or junction carries a **third semantic that a placeholder cannot hold:
path resolution.** A reparse point is not "a file with content" — it is a directory
entry carrying reparse data (the target path), a reparse tag
(`IO_REPARSE_TAG_SYMLINK` / `IO_REPARSE_TAG_MOUNT_POINT`), and the
`FILE_ATTRIBUTE_REPARSE_POINT` bit; its behavior is *"when traversed, the
filesystem transparently redirects to the target."* An empty regular file provides
none of that:

* **Traversal.** `CreateFile(link\child)` on a real junction opens `target\child`;
  on a placeholder file it simply fails. There is no content-redirect hook that can
  reproduce "resolve every path that passes through me" — content redirection only
  intercepts *this* node's data stream, not the paths of things *underneath* it.
* **Attributes / reparse queries.** `GetFileAttributes`, the reparse tag in
  `FindFirstFile`'s `dwReserved0`, and `DeviceIoControl(FSCTL_GET_REPARSE_POINT)`
  all report reparse information a plain file lacks. Emulating a symlink would mean
  intercepting *every* one of those to fabricate reparse data.
* **Type mismatch.** A junction is a *directory* reparse point; a placeholder empty
  *file* cannot even be opened as a directory or enumerated into.

That leaves only two ways to honor a scratch symlink/junction, both rejected for
the placeholder path:

* **Create the real reparse point** in the execroot — needs
  `SeCreateSymbolicLinkPrivilege` / developer mode for symlinks, is a real
  shared-namespace mutation visible to other actions, and a mount to an absolute
  target is a **B2-class sandbox escape** (a write "inside" the scratch link lands
  outside the cone).
* **Handle it fully virtually** — track the reparse point as an overlay record,
  synthesize it into enumerations (**insertion**), and rewrite every open that
  traverses it. This reintroduces precisely the §5 insertion + path-rewriting
  machinery W-stub is designed to avoid, scoped to the reparse subset.

Full Model W has no such problem: everything is a synthesized overlay record, so a
symlink is just another record type (target + tag), and path resolution is handled
by the same hook layer that already intercepts opens.

Scratch **reparse points are rare** in Bazel actions — Bazel builds the
input symlink forest itself, *outside* the action, and most actions write plain
files and directories. Under W-stub, the handling would therefore be: **regular
files and directories as placeholders; virtual-only handling (the §5 insertion
path) for a scratch symlink/junction** — meaning it never fully escapes the
insertion machinery. That partial coverage is one of the reasons §2.1.5 concludes
against the shortcut.

#### 2.1.4 W-stub vs full Model W — downside summary

| Dimension | Model W-stub | Full Model W |
| --- | --- | --- |
| Enumeration insertion state machine (§5) | **avoided** (subtractive filter only) | required |
| Real-namespace footprint | writes real empty placeholder files + dirs into the shared execroot | touches nothing on real disk |
| Crash before discard | may leave 0-byte stubs / empty dirs (A7-class leftover) | nothing to leave — clean by construction |
| Concurrent same-name scratch | shares one real placeholder / dir → needs lazy re-create + ownership-aware rmdir | each overlay fully private; no shared real state |
| Metadata (size / timestamps) | listing/`stat` shows the *placeholder's* values → must hook every metadata query to answer from the overlay; a missed path leaks wrong values | synthesized with content, always consistent, one code path |
| Sources of truth | two — existence in real FS, content+metadata in overlay → can drift | one (the overlay) — no drift class |
| Symlinks / junctions / hardlinks / ADS | cannot be placeholders → fall back to virtual (§2.1.3) | modeled natively as record types |
| Name-type collision (same path, file in one action, dir in another) | **broken** — one shared real node has a single OS type; the opposite-type create fails, or forces a virtual fallback (§2.1.5) | per-action record carries the type → no conflict |
| Short names (8.3) / `FileId`s / case-folding | **free** from the real FS | must be synthesized (a real §5.3 cost) |
| Directory teardown | ownership-aware rmdir across concurrent actions | trivial (drop the overlay) |

The table makes the trade explicit: W-stub removes the single largest cost (the
insertion state machine) and even gets short-name/`FileId` synthesis for free, at
the price of a small real footprint in the shared namespace, a metadata-redirection
surface, ownership-aware directory teardown, and a virtual-only fallback for the
rare reparse-point case. Whether that trade is actually favorable — or whether
W-stub is an awkward middle that loses to both a cheaper non-VFS fix and to full
Model W — is examined in §2.1.5.

#### 2.1.5 Real junctions and symlinks, and an assessment of W-stub

A plausible simplification is to replace empty placeholders with reparse points:
make every scratch **directory a real junction** to the per-action temp backing
directory, and every scratch **file a real symlink** to its backing file. The
kernel then resolves the reparse point, so every open, enumeration, and `stat`
*inside* the scratch subtree transparently reaches the real backing store — real
content, **real metadata**, no content-redirect hook, no placeholder-inside-dir
bookkeeping. On its face this removes most of W-stub's cost at once.

It does not hold up, for a structural reason. The proposal splits into two
branches, and both fail:

* **If the junction/symlink is *real*,** the kernel resolves it — so we hook
  nothing inside the subtree, which is the appeal. But a reparse point in a
  directory is a **single shared-namespace object.** Two concurrent actions that
  both write `execroot\scratch` need it to point *two different ways*
  (`temp\actionA` vs `temp\actionB`); a real junction can only point one way. **That
  is A8 again**, moved from the leaf file up to the junction node — no progress.
* **If the junction/symlink is *hooked*** so it can resolve per-action, then it is a
  *virtual* reparse point: we must synthesize it into listings and rewrite every
  traversing open ourselves. That **is** the enumeration-insertion + path-rewriting
  machinery of §5 — i.e. full Model W. No simplification.

The root cause is the same one that forces the whole design: **linux-sandbox can
use a symlink forest because each action gets a private execroot (its own mount
namespace); this sandbox runs in place in one *shared* execroot.** Windows offers
no per-process bind mount. Its nearest primitive — the DOS device map
(`DefineDosDevice`) — is drive-letter-granular and per-logon-session, not
per-process, and it is precisely the BuildXL "device map" dependency this project
set out to avoid (`vendor-architecture.md` §2). A real reparse point placed in a
shared directory is, by definition, shared by every action that reads that
directory. Real junctions therefore cannot be per-action, so they reintroduce A8;
and making them virtual is just Model W under another name.

Secondary costs pile on even before that: symlinks require
`SeCreateSymbolicLinkPrivilege` / Developer Mode (a hard environment requirement to
impose on every sandbox host); a junction whose target is outside the cone is a
**B2-class escape** the reparse-resolution guard must police; and a crash before
discard leaves a *live redirecting* reparse point in the shared execroot — strictly
worse than a leftover empty file.

**A deeper flaw: W-stub privatizes content but not namespace *type*.** Because the
placeholder is a real node in the shared execroot, it has exactly one OS-level type.
If two concurrent actions create the same path as *different* types — action A does
`CreateFile(execroot\foo)` (a file), action B does `CreateDirectory(execroot\foo)`
(a directory) — the second create hits an existing node of the wrong type and
fails (`ERROR_ALREADY_EXISTS`), and B cannot create children under it. Metadata
redirection cannot rescue this: even if B's `stat`/attribute hook reports `foo` as
a directory, B's real `CreateFile(execroot\foo\child)` still reaches the kernel,
where `foo` is a file, and fails — because W-stub's premise is that the *real* node
does the real work, and the real node is the wrong type. This is not the benign
same-type sharing the lazy-recreate note handles; it is an **irreconcilable
conflict** (both actions need incompatible real nodes at one path at the same time),
and the only escape is to give the losing action fully virtual handling — the §5
insertion machinery again. The consequence is decisive: **a file-vs-directory name
collision is exactly the shared-execroot non-hermeticity the overlay exists to
eliminate, and W-stub reintroduces it.** Full Model W is immune (the type lives in
a per-action overlay record — one action's record says `foo`=file, another's says
`foo`=dir, no shared node); Option 1 (§8) does not claim to fix it and is simply no
worse than `local`, which collides here too.

**Assessment.** The comparison that matters is not whether W-stub is cheaper than
full Model W in isolation, but which *shape* of complexity is the better
investment:

* **Enumeration insertion (full Model W) is concentrated and bounded.** It is one
  hard mechanism — a per-handle cursor freed at `NtClose`, plus emitting a *finite,
  documented* set of `FILE_INFORMATION_CLASS` layouts — living in one place, proven
  workable by usvfs. It yields **one model with one source of truth**: everything is
  a synthesized record, symlinks and hardlinks included, no real footprint, no
  metadata drift, trivial teardown.
* **W-stub's complexity is diffuse and never total.** It is smaller per piece but
  spread across creation, ownership-aware teardown, metadata redirection, and
  concurrency (lazy re-create) — and it *still* falls back to insertion for reparse
  points (§2.1.3) **and for file-vs-directory name collisions** (above), so it does
  not even eliminate the machinery it was invented to avoid — and in the type-clash
  case it reintroduces the very non-hermeticity the overlay exists to remove. It
  carries **two sources of truth** (real namespace + overlay) and a real footprint
  in the shared execroot.

W-stub therefore occupies an unstable middle ground. Its sole justification is that
it is a cheap incremental overlay reusing the subtractive filter, but it is in fact
medium-complexity, partial, and throwaway scaffolding (discarded the day the real
overlay is built), so it is dominated on both sides:

* For a genuinely cheap fix **now**, build no overlay at all — use the
  **build-scoped created-set** (Option 1, §8): a few lines in `AllowWrite`, no
  placeholders, no reparse points, no enumeration work.
* For the **principled end state**, build **full Model W** with insertion: pay the
  one concentrated cost and get a clean, total, single-source-of-truth model.

Real junctions/symlinks are the right *mechanism* only in a design with per-action
execroots — which is Model R (§2.2), already rejected on cost. Bolted onto the
shared in-place execroot they reintroduce A8 and widen the escape surface. §8
carries this conclusion into the recommendation.

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

**If an overlay is built, the write-only Model W is the correct axis, not Model R.**
Model W closes A8/A7/B2, honors the §1.0 invariant, keeps the fail-open trust model,
and reuses the real execroot for reads plus the cross-process created-set (§4).
Model R (full read virtualization) buys stronger isolation the primary goal does not
need, at a cost the ProjFS spike and §4 both rejected.

The `W-stub` variant, however, is not the win it first appears (§2.1.5): its
complexity is diffuse rather than concentrated, it keeps two sources of truth, it
still falls back to insertion for reparse points and file-vs-directory collisions,
and it is throwaway scaffolding relative to a real overlay. The recommendation
developed in §8 is therefore a **two-point plan** — take the cheap non-VFS fix now
(build-scoped created-set), and, only against a demonstrated need, build **full
Model W** rather than the W-stub middle. §5 is documented in full because that
principled end state depends on it; §2.1.1–§2.1.5 remain on record as the evaluation
of the placeholder shortcut and the rationale for rejecting it.

The remainder of this document designs the overlay. §5 describes the general
enumeration problem; §2.1.1 identifies the part W-stub would remove, and §2.1.5
explains why that removal does not justify its other costs.

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
path-canonicalization surface* required to make `FindNextFileEx` and
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

Enumeration is the central mechanism **of pure Model W** — everything else is
bookkeeping. It is also **the part that Model W-stub (§2.1.1) is designed to
avoid**: by leaving a real placeholder in the namespace, the OS enumerates scratch
for free and the filter stays subtractive. This section documents the insertion
problem so the cost of the *non*-stub path is on the record, and so a future
implementer understands what abandoning placeholders would reintroduce.

> **If Model W-stub is chosen, skip §5.2–5.3.** Enumeration remains the shipped
> subtractive filter (§5.1); a delete/rename is handled by adding the pre-existing
> entry's path to the per-action hide set (still a subtraction). The only extra
> work is stateless metadata redirection (answer `stat`/`FindNextFile` size and
> timestamps from the backing record), not per-handle cursor state.

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

**Status (implemented, `mw-enum-classes`).** Overlay insertion now fires from
**every** enumeration surface, not just `NtQueryDirectoryFile`:

- `NtQueryDirectoryFile`, `ZwQueryDirectoryFile`, and `NtQueryDirectoryFileEx`
  (the Ex variant derives `RestartScan`/`ReturnSingleEntry` from its `QueryFlags`
  bits `SL_RESTART_SCAN=0x01` / `SL_RETURN_SINGLE_ENTRY=0x02`).
- `GetFileInformationByHandleEx` (the .NET `Directory` / some-CRT path), whose
  Win32 wrapper builds its own `DetouredScope` and therefore shields the inner
  `NtQueryDirectoryFile(Ex)` from the Nt-level hook — insertion **must** be wired at
  this layer directly.
- The Win32 `FindFirstFileW`/`FindNextFileW` family via `NextOverlayFindDataW`
  (synthesizes a `WIN32_FIND_DATAW`).

Synthetic records now carry **real metadata** read from the backing file
(`FillOverlayDirRecordMetadata` via `GetFileAttributesExW`): creation/last-access/
last-write/change times, end-of-file, allocation size, `FileAttributes` (so
overlay-only *directories* get `FILE_ATTRIBUTE_DIRECTORY` and tools recurse into
them), and a deterministic FNV-1a `FileId` for the Id classes
(`FileIdBothDirectoryInformation` @96, `FileIdFullDirectoryInformation` @72).
`FileNamesInformation` (class 12) carries no metadata by design. Explicit
`CreateDirectoryW` of an undeclared execroot path is redirected into the backing
store (`mw-p3-createdir`), so overlay-only subdirs both avoid mutating the real
execroot and appear (as directories) in the parent enumeration.

**Descending into an overlay-only directory.** An overlay-only subdir must also
enumerate its *own* children when a tool descends into it (recursive `dir /s`, or a
tool that `mkdir`s a scratch dir then lists it). The NT path already handles this:
`ResolveOverlayOpenPath` redirects the open of an overlay-only directory to the
backing store, so `NtQueryDirectoryFile` lists the backing children directly. The
Win32 `FindFirstFileEx` family needed an explicit fix (`mw-smoke-inner-subdir-enum`):
its nested Nt open is shielded by the wrapper's `DetouredScope`, so a search of
`objdir\*` where `objdir` is overlay-only would hit `Real_FindFirstFileExW` on the
absent real path and return `PATH_NOT_FOUND`. `ReportFindFirstFileExWAccesses` now
redirects the whole search into the backing directory when the directory component is
overlay-only. Because all children of an overlay-only dir live in the backing store,
`EnsureOverlayEnumSnapshot` suppresses the FindNextFile splice for such a handle
(real dir absent ⇒ empty snapshot) so nothing is double-listed. Under `--filter-inputs`
the backing children stay visible via the `WasCreatedInThisProcess` carve-out in
`IsEnumChildVisible`.

**Multi-call emit-once protocol (thread/process safety).** Synthetic entries are
emitted **only after** the real enumeration reports exhaustion
(`STATUS_NO_MORE_FILES` / `STATUS_NO_SUCH_FILE`), never interleaved into a
real-SUCCESS buffer — the same discipline usvfs uses. A per-handle
`OverlayEnumCursor` tracks how many overlay entries have been emitted and the
snapshot is captured once per scan (`OverlayEnumStarted`, reset on `RestartScan`),
so concurrent enumerations of the same directory on different handles are
independent, and each entry depends only on that handle's own cursor. The
`--filter-inputs` filter loop (which hides undeclared real children) also falls
through to the overlay tail on exhaustion via the shared `TryAppendOverlayFindDataW`
helper — without this the overlay entries would be lost whenever the last real
entries are all filtered out.

**Wildcard filtering and narrow-filter synthesis (implemented).**

- **Wildcard filter honored by spliced entries.** The caller's `FileName` wildcard
  (e.g. `*.txt`) is captured onto the Find/enumeration handle on the first (restart)
  call — `CaptureOverlayEnumFilter` for the NT layer, and the last path component on
  the Win32 `FindFirstFileEx` handle — mirroring usvfs's per-handle
  `Searches::Info::searchPattern`. Overlay records are then matched against it via
  `OverlayNameMatchesFilter`, which defers to `ntdll!RtlIsNameInExpression` (the real
  filesystem matcher, so DOS metacharacters `<`/`>`/`"` are handled natively). Empty,
  `*`, and `*.*` short-circuit to match-all. Applied uniformly in `NextOverlayFindDataW`
  and the `InsertOverlayEntries` emit loop, so both the NT and Win32 splice paths drop
  non-matching overlay entries.
- **Narrow-filter `FindFirstFileExW` first-result synthesized.** When a wildcard
  matches *only* overlay files, the real directory returns `ERROR_FILE_NOT_FOUND` with
  no handle. `TrySynthesizeOverlayFindFirstW` detects an overlay-only child matching
  the filter, reopens the enumeration with `\*` to obtain a real handle, registers the
  overlay + filter on it, consumes the (non-matching) real entries up front, and
  returns the first filtered overlay record — so the overlay file becomes the *first*
  result. Direct `NtQueryDirectoryFile` callers always hold a valid handle and reach
  exhaustion, so the standard splice covers them.

**Known gaps (accepted, documented).**

- **ANSI variants not overlay-aware.** `FindFirstFileExA`/`FindNextFileA` do not
  splice overlay entries. Bazel tools use the wide APIs.

**Deliberate behavior (not a gap): 8.3 short-name matching.** The OS matches a
wildcard against both a real file's long name *and* its generated 8.3 short name, so
`*.htm` returns a real `report.html` via its `REPORT~1.HTM` alias. `OverlayNameMatchesFilter`
matches the long name only, so an overlay-only `report.html` is *not* returned by
`*.htm`. This is intentional and consistent with the pre-existing `ScrubShortFileName`
policy (§ input filtering), which already hides short names from callers because they
are non-deterministic (the `~1`/`~2` suffix depends on volume state and creation order),
disabled on many modern volumes (`fsutil 8dot3name`), absent on ReFS, and legacy. A
hermetic sandbox should behave as if 8.3 aliases do not exist, so long-name-only
matching for overlay entries is the *more* correct, reproducible behavior — not a
divergence to fix.


### 5.4 Why insertion is still bounded (the optimistic half)

The overlay is **small** relative to the real tree: it holds only what *this
action* wrote — typically a handful of scratch files per directory, not tens of
thousands of inputs. So the snapshot list per handle is short, the extra records
per call are few, and reads/opens still hit the real filesystem at native speed.
This is the decisive asymmetry vs Model R (which must synthesize *entire* input
directories, tens of thousands of entries, the case the ProjFS spike showed is
expensive). We enumerate the real dir once (cheap, as today), then append a short
overlay tail. The performance profile stays close to the subtractive model.

### 5.5 Spike: the insertion mechanics are proven, behind a kill-switch

The riskiest claim above — that a synthetic record can be constructed and spliced
into a live enumeration without disturbing the shipped subtractive path — has been
validated with a working spike, gated by a revertable flag.

* **Flag.** A new `WriteOverlay` extra-flag bit (`FOR_ALL_FAM_EXTRA_FLAGS` in
  `DataTypes.h`, auto-generating `ShouldWriteOverlay()`) is mirrored launcher-side
  as `ExtraFlag_WriteOverlay` and exposed as the `--write-overlay` option. With the
  flag off the enumeration path is byte-for-byte the shipped filter — a true
  kill-switch, confirmed by the full test suite passing unchanged.
* **Insertion function.** `InsertOverlayEntries` (`DetouredFunctions.cpp`) runs
  *after* `FilterDirectoryInformation`, reuses the same `TryGetDirInfoLayout`
  offset table to construct records for any handled info class, appends them past
  the surviving chain (or emits them from offset 0 when the real scan is already
  exhausted, rewriting `STATUS_NO_MORE_FILES` back to a returned record),
  relinks `NextEntryOffset`, and bounds every write against the caller's buffer.
* **Per-handle cursor.** `HandleOverlay::OverlayEnumCursor` records how many
  synthetic entries have been emitted for a directory handle, so each is returned
  exactly once across the multi-call `FindNextFile`/`NtQueryDirectoryFile` loop and
  is reset on `RestartScan`. This is the §5.2 hook-side cursor in its simplest
  form.

The spike is intentionally narrow: the overlay-entry set is sourced from an
environment variable rather than the per-action SHM map (§4), and only the primary
`Detoured_NtQueryDirectoryFile` call site is wired (the `Ex`/`Zw` siblings, the
Win32 `FindFirstFile` layer, and `GetFileInformationByHandleEx` remain filter-only
until the full feature lands). It exists to retire the "can insertion even be
hidden behind a flag" question — it can — not to ship the overlay. The remaining
§5.2/§5.3 work (SHM-backed overlay content, all info classes and enumeration hooks,
short-name/FileId synthesis, thread-safety) is the full-feature scope.

### 5.6 Vertical slice: write/read redirect + index-sourced enumeration (implemented)

The first end-to-end slice of the full feature is implemented and verified, still
behind `--write-overlay`:

* **Write redirect.** `Detoured_CreateFileW` computes a redirected open path via
  `ResolveOverlayOpenPath`: an undeclared write in the execroot-writable cone
  (discriminated by `OverrideAllowWriteForExistingFiles()`, the bit declared
  `-w`/`-d` grants lack — `IndicateUntracked()` is *not* usable here because the
  cone's policy equals the DLL's `AllowAll` mask) is opened against
  `\\?\<overlay-root>\C\...` instead of the real path. Content-preserving
  dispositions copy-up the real file first. `PolicyResult::AllowWrite` now allows
  (marks + returns true) a write over a pre-existing undeclared file under the
  overlay, since the real file is never touched.
* **Read redirect.** Reads/stats of a path this action already wrote resolve to the
  backing copy (the created-set index records the virtual path; the backing path is
  derived, never stored).
* **Enumeration from the real index.** `InsertOverlayEntries` now sources names from
  `ListOverlayChildren` (the per-process created-set/overlay index) for the
  enumerated directory, de-dups against the real on-disk listing, and sorts for a
  stable emit-once cursor. A test-only synthetic-name source
  (`BAZEL_SANDBOX_OVERLAY_TEST_NAMES`) is retained (unioned) only for
  isolated enumeration tests.
* **Coverage.** `tests/enforce/overlay_test.cc` grows to 20 cases (real write-redirect,
  read-back, no-clobber of pre-existing bytes, index-sourced enumeration, a
  kill-switch control, cross-process enumeration, and a multi-call cursor stress)
  via new `writeenum` / `writespawnenum` / `writeenummulti` probe ops. Full suite
  10/10, flag-off unchanged. Still pending: metadata/attrs, the `OverlayRecord` SHM
  growth (tombstones/rename/sequence), delete+rename, the `NtCreateFile`/`Zw`/Win32
  enumeration hooks, and all info classes (§5.2/§5.3, §9).

#### 5.6.1 Enumeration correctness (review against usvfs)

The insertion path was reviewed against usvfs (ModOrganizer2), a mature user-space
overlay VFS that hooks the same `NtQueryDirectoryFile` to merge virtual entries into
real listings (`src/usvfs_dll/hooks/ntdll.cpp`). The designs converge: usvfs keys a
`Searches::Info` on the directory handle and gathers its virtual matches **once** on
the first query (a `std::queue` consumed as entries are emitted), resetting on
`RestartScan`; we snapshot the overlay entries once into a per-handle
`OverlayEnumSnapshot` guarded by `OverlayEnumStarted`, with an emit-once
`OverlayEnumCursor`, reset on `RestartScan`. Neither locks the per-handle
enumeration state — usvfs's `queryMutex` is committed but commented out — so
same-handle enumeration from multiple threads is unsupported in both; **distinct
handles** on the same directory (the ordinary cross-thread and cross-process case)
each own independent state and are safe. Cross-process coherence comes from the
shared index (usvfs's boost-interprocess redirection tree; our created-set SHM):
a peer's write is visible to a fresh enumeration but cannot perturb an enumeration
already in flight, because the snapshot is point-in-time.

Two corrections came out of this review, both now covered by tests:

* **Insert only after real exhaustion.** usvfs returns every real ("regular") entry
  first, across as many calls as the caller needs, and appends virtual entries only
  once `regularComplete`. Our earlier code interleaved synthetics into real-`SUCCESS`
  buffers whenever spare room remained; under a small caller buffer that spans many
  calls this double-emitted entries (the OS keeps its own scan cursor while we keep
  ours, and reconciling them per-call is unsound). `InsertOverlayEntries` now returns
  untouched on a real-`SUCCESS` call and splices only when the real scan reports
  `STATUS_NO_MORE_FILES`/`STATUS_NO_SUCH_FILE`, so each synthetic depends solely on
  our own emit-once cursor.
* **Never redirect a directory handle.** The multi-call test also exposed that the
  enumeration's directory **open** was being redirected to the backing store (the
  backing directory exists as soon as any file under it is written), so the OS
  enumerated the backing dir — dropping real siblings and duplicating the overlay
  names that insertion then re-added. `ResolveOverlayOpenPath` now leaves directory
  handles on the real path (`OverlayIsDirectory` on both the real and backing paths);
  directories always enumerate real and overlay files are added only by insertion.
  A directory that exists *only* in the overlay is a later phase (§9).

#### 5.6.2 CREATE_NEW merged-view semantics

`CREATE_NEW` (create-if-absent, fail-if-exists) must consult the **merged** view —
the real execroot *and* this action's overlay. The redirect had a hole: when no
backing copy existed yet but the real undeclared file did, the open was redirected
to the (absent) backing path, so `CREATE_NEW` wrongly *succeeded* by creating an
empty backing file over a file the tool should have seen as already present.
`ResolveOverlayOpenPath` now special-cases `CREATE_NEW` with no backing copy: if the
real file exists it leaves the open on the real path, where the OS fails it with
`ERROR_FILE_EXISTS` without opening or mutating the real bytes — the correct
merged-view result. When the backing copy already exists the open is redirected and
`CREATE_NEW` fails against it; when neither exists the new file is created in the
backing store. Pinned by two `overlay.ps1` cases (new name succeeds and stays off
the real disk; `CREATE_NEW` over a seeded undeclared file fails and preserves bytes).

The "real file exists ⇒ fail" rule above holds only while the file is **visible** to
the tool. Under `--filter-inputs` (Mode 2) an undeclared pre-existing execroot file
is *hidden*: its reads are masked to `NOT_FOUND` and it is stripped from directory
listings, exactly as if it were absent — which is precisely `linux-sandbox`'s model,
where the throwaway execroot only ever contains declared inputs. So the merged view
that `CREATE_NEW` consults must also treat a filtered file as absent, and the create
must **succeed into the backing store** (the real bytes still never change). This
gives `--filter-inputs --write-overlay` full `linux-sandbox` parity for `CREATE_NEW`:

| file on real disk | `--write-overlay` alone | `--filter-inputs --write-overlay` |
|---|---|---|
| absent | create in backing (success) | create in backing (success) |
| declared input (visible) | fail (`ERROR_FILE_EXISTS`) | fail (`ERROR_FILE_EXISTS`) |
| undeclared (hidden by filter) | fail (`ERROR_FILE_EXISTS`) | **create in backing (success)** |

`ResolveOverlayOpenPath` decides visibility with `OverlayRealFileHiddenByFilter`,
which mirrors the enumeration filter's static rule (`IsEnumChildVisible`): a path is
visible iff its manifest policy allows read (a declared input or a declared
directory-input cone) or it is an exact ancestor node leading to a declared input.
The check is deliberately **created-set independent** — by the time it runs the write
pre-check (`PolicyResult::AllowWrite`) has already recorded the pre-existing file in
the per-process created-set (so reads redirect to the overlay), which would make a
`CheckReadAccess`/`WasCreatedInThisProcess`-based probe spuriously report the file
visible. Consulting only the static policy avoids that. It is gated on
`ShouldDeniedReadsAsNotFound()` (set only by `--filter-inputs`), so without the filter
the execroot cone grants blanket read, nothing is hidden, and the plain
fail-if-exists behavior above is unchanged. Pinned by an `overlay.ps1` case:
`CREATE_NEW` over the seeded undeclared file *succeeds* (exit 0) under
`--filter-inputs --write-overlay` while the real bytes are preserved — the mirror of
the visible-file fail case decided solely by whether the filter hides the file.

#### 5.6.3 Data-structure notes vs. usvfs

usvfs stores a full **directory tree** (`TreeContainer`/`DirectoryTree`) in
boost-interprocess shared memory, because its problem is arbitrary N-to-1 directory
*mounts* (many mod folders merged onto one game directory) configured up front. Our
problem is narrower: an undeclared write is redirected to a backing path that is a
pure **mirror function** of the virtual path, so a flat name-keyed created-set SHM is
sufficient and a tree would add cost without benefit. The one place usvfs's tree is
genuinely superior is listing a directory's children: it is an O(children) node
lookup, whereas our `ListOverlayChildren` scans the flat index and extracts immediate
children by prefix — O(index). Per-action overlays are small, so this is a scaling
note, not a correctness issue; if the created-set grows large we would add a
child-index (still not a full tree). For the emit-once snapshot, usvfs consumes a
`std::queue<VirtualMatch>` (destructive pop); we keep a `std::vector` + index cursor.
The vector is the better fit here precisely because we **sort** the snapshot for a
stable cross-call ordering (a queue cannot be sorted/random-accessed) and because a
non-destructive snapshot is inspectable and cheap to reset on `RestartScan`. Neither
choice is universally better — the queue is simpler when ordering does not matter.

---

## 6. Write backing store, discard, debug, and outputs

### 6.1 Where writes land

A per-invocation backing directory, created by the launcher and passed in the
manifest (alongside `g_bazelCreatedShmName`):

* **Default: a temp directory** under the sandbox base (e.g.
  `%TMP%\bzlsbx-<pid>-<tick>\overlay\…`).
* **Configurable: `--overlay-dir <dir>`.** The launcher creates the
  per-invocation `bzlsbx-<pid>-<tick>\overlay` subtree under this caller-chosen
  directory instead of `%TMP%`. Co-locating it on the source-root **volume**
  avoids cross-volume promotion copies (§10), and pointing it at a RAM disk
  (ImDisk/`R:`) gives tmpfs-like speed — a config knob, not a dependency. This
  matches `linux-sandbox` often putting `<sandbox_base>` on tmpfs. The caller's
  directory is preserved on cleanup; only the per-invocation subtree is removed.

**Path mapping (source-root-relative).** The DLL is told both the backing root
(`g_bazelWriteOverlayRoot`) and the **overlay source root**
(`g_bazelOverlaySourceRoot`) — the real directory subtree whose undeclared writes
are redirected, which today equals the launcher working directory (`-W`). A
virtual path is mapped to its backing path by **stripping the source-root prefix**
(case-insensitive, trailing-separator tolerant) and appending the remainder under
the backing root:

```
source root   C:\ws
backing root  \\?\<overlay>
C:\ws\a\b.txt  ->  \\?\<overlay>\a\b.txt
```

This replaced an earlier full-mirror scheme that encoded the drive letter as a
subdirectory (`\\?\<overlay>\C\ws\a\b.txt`). The drive letter was redundant: the
write-redirect cone (`Policy_OverrideAllowWriteForExistingFiles`) is granted in
exactly one place — the source root — so every redirected path is under the source
root on a single volume by construction. `OverlayBackingPath` keeps the old
full-mirror form as a defensive fallback if a path is somehow not under the source
root (should never happen given the invariant). The `\\?\` prefix keeps deep
mapped paths under the `MAX_PATH` ceiling.

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
* **`--sandbox_debug`:** Bazel **keeps** the sandbox dir and prints its path so the
  contents the action saw can be inspected. Nothing is deleted.
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

### 6.3 Backing store as the single source of truth (index-free overlay)

The mechanics described so far carry overlay state in a **name-keyed created-set
SHM** (what this action has written), consulted for read/write redirection and
scanned by `ListOverlayChildren` to source enumeration inserts. A cross-process
index is a real cost: read/write lookups are O(1), but child-listing prefix-scans
the whole created-set (O(total-created-this-build) per enumeration), and the
planned `OverlayRecord` (attrs/seq/tombstone/rename) would grow that index into a
second, mutable, lock-protected data structure — the same complexity class as
usvfs's boost-interprocess directory tree.

There is a simpler model that removes the index entirely: make the **backing store
itself the source of truth**. This is the classic overlayfs *upper-layer* union:
the backing directory tree is the mutable "upper" layer, the real execroot is the
read-only "lower" layer, and overlay state is *nothing but* the contents of the
backing store. No SHM index, no log, no tree.

**Operations become filesystem queries, not index lookups:**

* **Read / open.** Probe the backing path. Present ⇒ open the backing copy. Absent
  ⇒ fall through to the real (lower) path. One `GetFileAttributes` per redirectable
  open — a kernel round-trip, negligible.
* **"Did this action write this file?"** (the `PolicyResult::AllowWrite`
  rewrite-vs-clobber decision) collapses from an SHM `WasCreated(path)` lookup to
  `OverlayPathExists(backing)`. The created-set SHM disappears.
* **Enumeration.** Merge the (policy-filtered) real directory listing with the
  backing subdirectory listing, deduplicated by name — the OS performs both scans.
  This is O(children-in-this-dir), the O(children) property that was usvfs's only
  data-structure edge (§5.6.3), obtained **without maintaining a tree** and without
  the O(total-created) `ListOverlayChildren` scan.
* **Cross-process consistency for free.** The backing root is already one
  per-invocation store shared by the whole action tree (§6.1). The filesystem *is*
  the shared data structure and NTFS provides the locking; there is no SHM region to
  propagate and no cross-process index lock to hold. The per-handle enumeration
  snapshot/cursor (§5.6.1) is unchanged — it is a per-handle concern, orthogonal to
  how overlay state is stored.

This also dissolves three standing problems as free side effects: an
**overlay-only directory** simply opens against the backing store (no special
case); a **file/directory name collision** between two actions cannot occur because
each action has a private backing store and the OS authoritatively types each name;
and the visibility predicate for reads/enumeration is exactly the static filter rule
already used for CREATE_NEW (§5.6.2, `AllowRead() || IsExactManifestNode()`), so the
merged view stays consistent across reads, probes, enumeration, and creation.

#### 6.3.1 Do we need whiteout markers? Mostly not.

A union filesystem normally needs **whiteout** markers to represent "a lower file
is *deleted*," because in a pure additive overlay *absence in the upper layer* means
"fall through to lower" — it cannot also mean "hide lower." overlayfs solves this
with `.wh.<name>` whiteouts and opaque-directory flags. The question is whether we
need that machinery, and the answer follows directly from our load-bearing
invariant (§1.0): **the overlay never mutates and never hides a real file.**
Visibility of a lower file is decided *solely* by policy and the `--filter-inputs`
read filter, independent of overlay contents. The backing store only ever **adds**
a new name or **shadows** a lower file with a private copy — it never needs to
**subtract** a lower entry. Given that invariant, a whiteout would only ever be
needed to hide a *visible* lower file after a delete, and enumerating who can be
deleted shows that case never has to be satisfied by a whiteout:

| Delete / rename-source target | `--filter-inputs --write-overlay` (parity mode) | `--write-overlay` alone (permissive) |
| --- | --- | --- |
| Backing-only (created this action) | unlink the backing copy — done | unlink the backing copy — done |
| Written-over lower file (copy in backing + original on lower) | unlink backing; the filter still hides the lower original, so it stays absent from the tool's view — **correct, no whiteout** | unlinking backing would re-expose the lower original ⇒ **deny the delete** (cannot hide it without mutating the real disk) |
| Undeclared lower-only file (no backing copy) | filter already hides it ⇒ the tool sees `NOT_FOUND` ⇒ delete is a `NOT_FOUND` no-op — **correct, no whiteout** | visible undeclared input ⇒ **deny** (no-clobber; hiding it would require a whiteout or a real-disk mutation) |
| Declared input (read-only, visible) | not writable ⇒ **deny** | not writable ⇒ **deny** |

The pattern is uniform: **a delete/rename succeeds only against backing-resident
state whose removal does not re-expose a *visible* lower file; every other case is
resolved by the existing policy/filter as `NOT_FOUND` (hidden) or `ACCESS_DENIED`
(protected), never by a whiteout.** So in the mode that matters — `--filter-inputs
--write-overlay`, the `linux-sandbox`-parity mode — **whiteouts are unnecessary**,
exactly as your intuition suggested: the subtractive read filter already hides every
undeclared lower file, so removing the backing copy is sufficient and correct.
Rename is delete-source + create-dest, and the create-dest half is precisely the
filter-aware CREATE_NEW behavior of §5.6.2 (a hidden dest is treated as absent), so
rename needs no new machinery either. Opaque-directory markers are likewise
unneeded: the only way a recreated directory could wrongly show stale children is if
those lower children were *visible*, but under the filter an undeclared directory's
children are hidden, and a declared directory with declared children cannot be
removed in the first place (its read-only contents block the `rmdir`).

**The cost is a documented limitation of the permissive (non-`--filter-inputs`)
mode:** because that mode leaves undeclared lower files *visible*, a delete or
rename that would need to make such a file disappear is **denied** rather than
silently mutating the real execroot. This is the correct, conservative choice, and
it is a *transitional* limitation only: `--filter-inputs` is the parity north star
and is slated to become always-on (the flag eventually retired — §8), and pre-existing
files are read-only in every mode regardless (§8), so the overlay never has cause to
subtract a lower entry. Delete/rename work fully in the filter mode, which is the
mode that will remain. A whiteout convention (a reserved `.wh.`-style marker confined
to the backing namespace, still "backing store as source of truth" and cross-process
/ crash-consistent via the filesystem) is therefore **not planned** — it would only
matter for a permissive mode that is on its way out.

#### 6.3.2 What this changes in the phased plan

Adopting this model retargets, rather than discards, the later Model W phases:
`mw-shm-record` (the `OverlayRecord` index) is **dropped** — its role is served by
the backing directory itself; `mw-delete-rename` becomes "unlink/rename within the
backing store, deny the cases in the table above" instead of "append a tombstone
record"; and `mw-enum-classes` (extending insertion across `NtQueryDirectoryFileEx`
/ `ZwQueryDirectoryFile` / Win32 `FindFirstFileEx`) becomes "merge real + backing
listings" in each of those hooks. The created-set SHM (currently also used by the
execroot-writable no-clobber check) is replaced build-wide by backing-store
existence, so it can be retired once the enumeration merge and the `AllowWrite`
existence check are ported. Everything stays behind the `--write-overlay`
kill-switch; with the flag off the shipped subtractive path is byte-for-byte
unchanged.

---

## 7. Parity mapping (Model W vs linux-sandbox)

| Behavior | linux-sandbox | Model W overlay |
| --- | --- | --- |
| Undeclared read | absent → `ENOENT` | real execroot + subtractive filter → `NOT_FOUND` (unchanged) |
| Declared input read | real file via symlink | real file in place (`-r`) (unchanged) |
| Undeclared write | writable throwaway execroot | redirected to per-action overlay |
| Read-back of own scratch | sees it (same execroot) | served from overlay |
| Enumeration incl. own scratch | present in forest | real listing **filtered + backing entries merged** (§6.3) |
| Fixed-name side file (A8 `y.output`) | never collides (private execroot) | **never collides (private overlay)** ✔ |
| Delete / rename scratch | normal FS op in forest | unlink / rename **within the backing store**; pre-existing files are read-only and never subtracted — no whiteouts (§6.3.1) |
| Declared `-w` output | in execroot, moved out post-action | **written to real execroot in place** (harvested in place) |
| Discard timing | sandbox dir deleted right after action | overlay deleted on tree exit; kept under `-D` |
| Isolation strength | constructive (fail-closed) | **hide/redirect in place (fail-open)** — writes private, reads real |

A divergence to state plainly: this is still **hide-and-redirect, not construct**. A tool
using an un-hooked write path could still hit the real execroot (fail-open) — the
same trust model we already document. Reads are *not* virtualized, so a declared
input can never become unreachable (the fail-closed risk §4 rejected). We buy
Linux's write isolation without Linux's read guarantee.

The enumeration row assumes pure Model W (insertion). Under **Model W-stub
(§2.1.1)** that row instead reads "real listing (scratch present as placeholders)
**+ subtractive tombstones**, metadata answered from the overlay" — same observable
result, no insertion machinery.

---

## 8. Recommendation

**Decision: build the per-action write overlay as full Model W in its index-free
"backing store is the source of truth" form (§6.3), with `--filter-inputs` as the
baseline execution mode. Do not build the W-stub middle, real junctions, or the
Model R read VFS.**

The vertical slice is already implemented behind the `--write-overlay` kill-switch:
undeclared writes redirect to a per-action backing store, reads and enumeration
present it merged over the real execroot, and `CREATE_NEW` honours that merged view,
including the filter-aware parity case (§5.6). The remaining work migrates the
overlay's *state model* from the name-keyed created-set SHM (and the once-planned
`OverlayRecord` log) to the backing directory itself (§6.3), and broadens the
enumeration merge across the remaining info classes and API families (§9).

The design rests on four commitments:

1. **`--filter-inputs` is the baseline, and long-term the only mode.** The
   subtractive read filter is the north star for `linux-sandbox` parity; the
   project's direction is for it to become always-on and the flag eventually
   retired. Everything below assumes it. The bare permissive fallback is a
   transitional convenience, not a supported target.

2. **Pre-existing files are read-only in every mode.** A real execroot file —
   declared input or undeclared source — is never mutated or deleted in place
   (§1.0). A "write" over it is shadowed into the backing store; a delete or rename
   of it is denied. Only backing-resident state (what *this action* created) is
   mutable. This holds regardless of `--filter-inputs`.

3. **No whiteout markers (§6.3.1).** Because the overlay only ever *adds* a new
   name or *shadows* a lower file with a private copy — and never *subtracts* a
   lower entry — and because a lower file's visibility is decided solely by the
   filter and read-only policy (commitments 1–2), there is no case where a delete
   must hide a *visible* lower file. Under `--filter-inputs` undeclared lower files
   are already absent; declared inputs are read-only; backing-only files are removed
   by a plain unlink. The whiteout and opaque-directory machinery every other union
   FS needs is therefore unnecessary here — a direct consequence of commitments 1
   and 2, not an independent assumption.

4. **The backing store is the one source of truth (§6.3).** It removes the SHM
   index and its O(total-created) child scan, yields O(children) enumeration via the
   OS's own directory scan, makes cross-process consistency a property of the shared
   filesystem rather than a propagated SHM region, and dissolves overlay-only
   directories and file/directory name collisions as free side effects.

**Rejections that stand unchanged.** The `W-stub` placeholder variant (§2.1.1,
§2.1.5) keeps two sources of truth and diffuse complexity and still falls back to
insertion for reparse points; real junctions/symlinks reintroduce A8 in a shared
in-place execroot and widen the escape surface (§2.1.5); and **Model R** — the full
read-virtualizing VFS — reintroduces the path-translation / realpath-reverse /
device-map complexity we left BuildXL to escape, is fail-closed (a missed hook
breaks the build), and must synthesize entire input trees on enumeration (the slow
case). The write-only overlay buys Linux's *write* isolation without Linux's
read-virtualization cost.

**On the earlier "build-scoped created-set" interim fix.** A prior revision of this
section recommended a cheap non-VFS A8 fix — a build-scoped provenance set that
allows writing a pre-existing cone path only if some action created it this build —
as a stepping stone before any overlay. That option is now **subsumed** by the
overlay: "was this created this build" becomes "does it exist in this action's
backing store," and because each action's backing store is private, no two actions
ever share a real path in the first place. The provenance-marker shortcut it
rejected (keying clobberability on `FileAccessPolicy_DeclaredInput`) remains
rejected for the same reason — that bit cannot distinguish a sibling action's
transient scratch from a real undeclared source reached through the `execroot/_main`
symlink, so it would overwrite and then delete real source, violating §1.0.

---

## 9. If the overlay is greenlit: phased plan

This plan is for **full Model W** in its index-free backing-store-as-source-of-truth
form (§6.3, §8) — the recommended shape. The `W-stub` placeholder variant (§2.1.1)
is **not** the target (§2.1.5); it is retained in this doc only as the recorded
evaluation of the shortcut. The vertical slice (write/read redirect + enumeration
insertion for the direct `NtQueryDirectoryFile` path, `CREATE_NEW` merged-view and
filter-aware semantics — §5.6) is **already implemented** behind `--write-overlay`;
the remaining phases migrate the state model onto the backing store and broaden
coverage. Everything stays behind the kill-switch; with the flag off the shipped
subtractive path is byte-for-byte unchanged.

1. **[done] Vertical slice.** Write/read redirect into the per-action backing store
   + index-sourced enumeration insertion for the direct ntdll path; `CREATE_NEW`
   merged-view + filter-aware parity (§5.6). Pinned by `tests/enforce/overlay_test.cc`.
2. **[done] Enumeration by merge (retires the index scan).** Replaced index-sourced
   insertion (`ListOverlayChildren` scanning the created-set SHM) with a **real +
   backing directory merge**: `InsertOverlayEntries` now sources overlay names from
   `ListBackingChildren` (one O(children) OS scan of the mirrored backing
   subdirectory), dedups against the real listing, and feeds the existing per-handle
   snapshot/cursor (§5.6.1). Removes the O(total-created) prefix scan.
3. **[done] Backing-store existence replaces the created-set.** `PolicyResult::
   AllowWrite` (rewrite-vs-clobber) and `WasCreatedInThisProcess` (the read /
   enumeration visibility carve-outs) now consult `OverlayBackingExists(path)` first,
   falling back to the SHM `WasCreated(path)` only for legacy `--execroot-writable`.
   **Overlay-only directories** are handled: a directory present in the backing store
   but absent on the real disk (e.g. the implicit parent of a redirected file write)
   opens the backing directory and enumerates its children directly
   (`ResolveOverlayOpenPath` directory branch + the `InsertOverlayEntries` real-dir
   guard that suppresses double-listing). The SHM is not yet deleted (it remains the
   legacy fallback and still covers explicitly-created directories — see phase 5).
4. **[done] Delete / rename.** Implemented per the §6.3.1 table. `Detoured_DeleteFileW`
   and `Detoured_MoveFileWithProgressW` (name-based) now redirect through the helpers
   `ResolveOverlayDelete` / `ResolveOverlayRenameDest` (in `DetouredFunctions.cpp`,
   next to `ResolveOverlayOpenPath`): a delete/rename-source unlinks or moves **within
   the backing store** when a backing copy exists; a pre-existing (read-only) lower
   file with no backing copy is a **NOT_FOUND no-op** under the input filter (hidden ⇒
   absent in the merged view) and a **deny** in permissive mode (removing it would
   require mutating the real execroot). The rename destination mirrors the filter-aware
   CREATE_NEW of §5.6.2 (lands in the backing store, parent dirs created). No
   tombstones, whiteouts, or opaque-directory markers. Handle-based delete/rename
   (`FILE_FLAG_DELETE_ON_CLOSE`, `FileDispositionInfo`, `FileRenameInfo`) is what
   cmd's `ren`/`move` and many runtimes actually use instead of the `MoveFile*` hooks.
   The SOURCE side rides the backing copy for free: `DELETE` counts as write access
   (`WantsWriteAccess`), so the opening `CreateFile` is routed through
   `ResolveOverlayOpenPath` onto the backing handle. But the rename **destination**
   name in `FILE_RENAME_INFO`/`FILE_RENAME_INFORMATION` is a virtual execroot path, so
   the handle rename must rewrite it into the backing store (RootDirectory=NULL + the
   backing path, Win32 `\\?\` form for `SetFileInformationByHandle`, NT `\??\` form for
   `ZwSetInformationFile`) or the move leaks the destination onto the real execroot.
   `HandleFileRenameInformation` and `RenameUsingSetFileInformationByHandle` now do
   this (mirroring the existing `HandleFileLinkInformation` hard-link redirect).
   Additionally, all three handle mutators (`HandleFileRenameInformation`,
   `RenameUsingSetFileInformationByHandle`, `HandleFileDispositionInformation`,
   `DeleteUsingSetFileInformationByHandle`) re-run `ResolveOverlayDelete` on the source
   and **deny** a real, visible in-cone input even when it inherits the writable cone's
   `OverrideAllowWriteForExistingFiles` bit — so a read-only `-r` input can never be
   renamed, moved, or deleted (matching the name-based `MoveFile*`/`DeleteFileW` hooks).
   Enforce cases in `tests/enforce/overlay_test.cc` (`writeovdelete`, `writeovdeleteh`,
   `writeovrename`, `writeovrenameh`, the handle-path read-only-input deny tests, plus
   filter/permissive lower-file delete).
   Directory moves are deferred to phase 5 (pass through unchanged).
5. **Broaden API coverage + redirect explicit `CreateDirectoryW`.**
   - **[done] Metadata/probe redirect (`mw-metadata`).** The path-based metadata hooks
     `GetFileAttributesW`, `GetFileAttributesExW`, `GetFileInformationByName`, and the
     exact (non-wildcard) `FindFirstFileEx` probe now resolve through
     `ResolveOverlayProbePath` (in `DetouredFunctions.cpp`): when the queried path has a
     backing copy, the query is (re-)issued against the backing file so a process can
     stat scratch it wrote. Handle-based metadata (`GetFileInformationByHandle(Ex)`,
     `NtQueryInformationFile`) already observe the backing file when the handle was
     opened through the redirect, so no path rewrite is needed there. Pinned by the
     `writeovstat` enforce case (all four APIs, with and without `--filter-inputs`) —
     overlay suite now 43 cases.
   - **[done] NT-layer open redirect (`mw-nt-layer`).** `Detoured_NtCreateFile` and
     `Detoured_ZwCreateFile` now redirect the open by rewriting `ObjectAttributes` to an
     absolute NT-form backing path (`\??\…`, `RootDirectory` cleared) via the shared
     `ResolveOverlayOpenPath`, mirroring the Win32 `CreateFileW` redirect. This covers
     tools that call `NtCreateFile`/`NtOpenFile`/`ZwCreateFile` directly (the CRT and
     several runtimes); Win32 opens are already redirected one layer up and are
     suppressed here by the `DetouredScope` (so no double-redirect of a path that is
     already the backing store). `NtOpenFile`/`ZwOpenFile` delegate to these. Pinned by
     the `ntwriteread` enforce case (create+write+read entirely via direct
     `NtCreateFile`, with and without `--filter-inputs`) — overlay suite now 47 cases.
   - **[done] Enumeration merge across all classes + `CreateDirectoryW` (`mw-enum-classes`).**
     The enumeration merge (real + backing splice) now fires from every enumeration
     surface: `NtQueryDirectoryFile`, `ZwQueryDirectoryFile`, `NtQueryDirectoryFileEx`,
     the Win32 `FindFirstFileW`/`FindNextFileW` family, and `GetFileInformationByHandleEx`
     (the classes usvfs also hooks). Synthetic records carry real backing-file metadata
     (times, size, `FileAttributes` incl. `FILE_ATTRIBUTE_DIRECTORY`, deterministic
     FNV-1a `FileId`) — see §5.3 for the full status, the emit-once/cursor protocol, and
     the wildcard-filtering + narrow-filter synthesis now implemented (only the ANSI
     variants remain an accepted gap). **Explicit `CreateDirectoryW` is now redirected into the backing
     store** (`mw-p3-createdir`): overlay-only directories no longer touch the real disk
     yet still appear (flagged as directories) in a parent enumeration performed via any
     layer, so the created-set SHM carve-out is no longer needed for this. Pinned by
     five new overlay cases (`writeenumgfibhe`, `writeenumfind`, `writeenumex`,
     `writeenummeta`, `writeovsubdirenum`) across permissive + `--filter-inputs` — the
     fix also closed a real parity bug where the `--filter-inputs` `FindNextFileW` filter
     loop dropped the overlay tail on exhaustion. Overlay suite now **65 cases**.
   - **[done] Kernel `CopyFile`/`CopyFileEx` redirect + real-tool e2e (`mw-copyfile`).**
     `CopyFile(Ex)(W/A)`, `CopyFileTransactedW` all funnel through `DetoursCopyFileEx`,
     which performs a *self-contained kernel copy* — it opens the source and writes the
     destination itself, so the per-open overlay redirect (`CreateFile`/`NtCreateFile`)
     never fires on either handle. Two bugs resulted: an overlay-only source (a file the
     action wrote via the overlay) came back `NOT_FOUND`, and the **destination was
     written straight to the real execroot**, leaking a scratch output onto disk. Fixed
     by resolving both halves before the real call: the source through
     `ResolveOverlayProbePath` (backing copy when one exists; a real in-cone source stays
     put) and the destination through `ResolveOverlayRenameDest` (into the backing store,
     parents ensured, virtual path marked created; a declared `-w` output stays on the
     real path). Surfaced by uutils `cp` / Rust `std::fs::copy`, and also fixes native
     `copy`, node `fs.copyFileSync`, and .NET `File.Copy`. Two further real-tool fixes
     landed alongside: the overlay enum-snapshot builder was made last-error-neutral (a
     leaked `ERROR_ENVVAR_NOT_FOUND`/203 was turning python `os.scandir`'s
     end-of-enumeration into a hard `OSError`), and the exact `FindFirstFileEx` backing
     probe now restores the *virtual* last component into `cFileName` (it was returning
     the backing dir's name for the cone root, so the JVM class loader canonicalized
     in-cone classpath entries into the backing store and failed class resolution).
     Pinned by the opt-in hermetic **`tests/e2e/<tool>/`** matrix (native cmd +
     tar/curl/PowerShell, uutils + msys2 GNU coreutils, node, python, java/javac,
     dotnet — each does create/list/copy/read-back under `--write-overlay` and
     asserts a clean real execroot).
   - **[done] Composite-op + NT link-info redirect (`mw-composite-ops`).** Same
     self-contained-kernel-op class as `mw-copyfile`, swept across the remaining hooks:
     `CopyFile2` (Win8+; not backstopped by the `NtCreateFile` hook, so it needed its own
     dynamically-attached hook mirroring `DetoursCopyFileEx`), `CreateHardLink(W/A)`,
     `CreateSymbolicLink(W/A)`, `ReplaceFile(W/A)` (was a no-op stub — now resolves the
     replaced target/replacement/backup into the backing store, copying up the real
     original when the replaced target has no backing copy yet), and `RemoveDirectory(W/A)`
     (was asymmetric with `CreateDirectoryW`: an overlay-only scratch dir could not be
     removed and a real in-cone dir would be deleted from disk — now routed through
     `ResolveOverlayDelete` like `DeleteFileW`). Crucially, the **NT-layer link path** is
     the one real tools actually take: `cmd`'s `mklink /H` (and others) open the existing
     file and issue `NtSetInformationFile(FileLinkInformation)` naming the new link,
     bypassing the `CreateHardLinkW` export hook entirely. `HandleFileLinkInformation` now
     rewrites that info buffer's link name to an NT-form backing path (`\??\` + backing,
     `RootDirectory = NULL`) so the new link lands in the overlay, not the real execroot
     (empirically confirmed: `mklink /H` no longer leaks). Symlinks whose target is itself
     an overlay-only path cannot be transparently read back (the kernel resolves the
     reparse target internally, past the detours), but the no-leak guarantee holds; the
     symlink hook also had to move its overlay redirect ahead of the default
     `IgnoreReparsePoints` early-return. Pinned by new probe ops (`writeovhardlink`,
     `writeovsymlink`, `writeovreplace`, `writeovrmdir`) + `tests/enforce/overlay_test.cc`
     cases (including a real-in-cone `rmdir` denial) and `tests/e2e/native`'s
     `NativeHardlink` (`mklink /H`) and `NativeCmdFsMutationOps` (`mkdir`+`rmdir`)
     cases.
     - **Deliberately deferred (no leak observed, lower priority):**
       `SetFileAttributes(W/A)` and `SetFileTime` are not overlay-hooked — empirically
       `attrib +r` on a real in-cone input did **not** mutate the real file (no leak),
       and `SetFileTime` on an overlay-only file may fail cosmetically; handle-based
       `SetFileInformationByHandle`/`NtSetInformationFile(FileBasicInformation)` *is*
       hooked, which is why tar's mtime-preserve works.
     - **[done] Handle-based rename overlay redirect.** `NtSetInformationFile(`
       `FileRenameInformation)` and `SetFileInformationByHandle(FileRenameInfo)` — the
       path cmd's `ren`/`move` take — now redirect the rename destination into the
       backing store (was previously intercepted for policy only, so the Win32
       `MoveFile*` hooks covered the common path but a handle rename leaked the dest onto
       the real execroot). Fixed in `HandleFileRenameInformation` /
       `RenameUsingSetFileInformationByHandle`, mirroring the `FileLinkInformation`
       hard-link redirect; pinned by `writeovrenameh` and the handle-path read-only-input
       deny enforce cases.
6. **Backing store + discard (mostly in place).** The launcher already creates the
   per-invocation backing root and embeds it in the manifest; confirm delete-on-tree
   -exit, `-D` retain + path print, and cross-volume `MoveFile` from the overlay to a
   real `-w` output (a rename that later promotes scratch to a declared output).
7. **Differential smoke + enforce.** Run `tests/e2e/smoke.ps1` on the
   goyacc/full-repo case that surfaced A8 and the Java/`ng_package` scratch-heavy
   actions, under both `local` and `windows-sandbox`; add enforce cases for merge
   enumeration, delete/rename denial of pre-existing files, overlay-only directories,
   file/directory name collisions across actions, and cross-process visibility.

---

## 10. Open questions

* **Short names / FileIds.** Synthesizing stable 8.3 short names and `FileId`s for
  overlay entries that some tools depend on — deterministic scheme, or omit and
  risk a tool that needs them? (With backing-as-truth these could come from the
  backing file's own `FileId`; confirm whether that is stable enough.)
* **`GetFinalPathNameByHandle` on a backing handle.** A tool that opened scratch
  and asks for its final path will get the **backing-store** path, not the virtual
  execroot path (the reverse-mapping problem, but limited to overlay handles). Does
  any real tool care for *scratch* files? (For inputs it does — the A5 Node case —
  but inputs aren't virtualized here.) Likely acceptable; confirm on smoke.
* **Backing store on a different volume.** `MoveFile` from the overlay to a real
  `-w` output across volumes becomes a copy; a rename of scratch that later becomes
  a declared output needs care. Enumerate the promote-to-output paths.
* **RAM disk availability.** Worth a dependency, or keep the temp-dir default and
  treat RAM disk as an opt-in host tuning only?
* **Retiring the permissive fallback.** Once `--filter-inputs` is always-on and the
  flag is dropped (§8, commitment 1), the transitional non-filter behaviors — visible
  undeclared files, denied delete/rename of them — can be removed. Track what, if
  anything, still depends on the bare permissive mode before deleting it.
