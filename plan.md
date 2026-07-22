# Vendored-engine slim-down plan

## Goal

Shrink the vendored DetouredServices engine (`vendor/detours-services/`) to the
smallest code that still implements this project's actual feature set. The
aspirational end-state is "essentially just `DetouredFunctions.cpp` (the hooks) +
`DetoursHelpers.cpp` (manifest parse + policy/report facade)", with everything
else either deleted, folded into those two TUs, or replaced by a small
project-owned helper.

### What we actually need (the whole feature set)

- Read restriction: whole-FS read-only baseline; execroot readable (default) or
  denied (`-H`/`--filter-inputs`); declared inputs `-r` readable; `-b` blocked.
- Write control: writes confined to `-w` outputs; `--write-overlay` redirects
  undeclared execroot writes into a process-private backing store.
- Input filtering: `--filter-inputs` → denied reads report NOT_FOUND + undeclared
  entries hidden from directory enumeration (linux-sandbox parity).
- Child/grandchild process injection (Detours) so the policy follows the tree.
- Optional `--trace` access report; `-D` diagnostics; `-N`/`-n` network policy;
  `-S` stats. (These live in `src/`, not the vendored engine.)

Everything else in the vendored engine is BuildXL scaffolding we do not use.

## Honest constraint

A literal two-file end-state is **not** reachable: `DetouredFunctions.cpp`
genuinely depends on the policy/path core — `PolicyResult*`, `PolicySearch`,
`CanonicalizedPath`, `PathTree`/`TreeNode`, `StringOperations`, `HandleOverlay`,
`FilesCheckedForAccess`, and the manifest wire types in `DataTypes.h`. Those are
the enforcement brain, not dead weight. The realistic target is
**DetouredFunctions + DetoursHelpers + a small policy/path core**, with the
diagnostic/reporting/injector/bootstrap files shrunk hard or folded.

## Discipline (unchanged from the dead-code campaign)

- Frozen vendor patch (`vendored-buildxl-baseline-13c5c9d`) is a historical
  record; **never regenerated** for post-fork edits.
- After every removal: `bazel build //:DetoursServices.dll //:BazelSandbox`, then
  `bazel test //tests:all --local_test_jobs=1 --test_timeout=300` (serial, 10/10).
  Native e2e (`cd tests/e2e/native; bazel test //...`) at phase boundaries.
- Small reviewable commits with the `Co-authored-by: Copilot` trailer.
- Update `vendor/PROVENANCE.md` (post-fork log) + `docs/vendor-architecture.md`.

## Baseline metrics (2026-07-22, after commit 1fc0782)

- 49 files, ~16,900 lines in `vendor/detours-services/`.
- Since baseline tag: 12 commits, −2,690 deletions; 2 subsystems deleted
  (SubstituteProcessExecution, DeviceMap).
- 65% of lines are two files: `DetouredFunctions.cpp` (7,989),
  `DetoursHelpers.cpp` (1,216).

---

## Phase 1 — quick dead-code (low risk, no wire change)

- [ ] **`SUPER_VERBOSE`** — `#define 0`; ~40 dead `#if SUPER_VERBOSE` blocks in
  DetouredFunctions/DetoursHelpers/PolicyResult/DebuggingHelpers. Strip blocks +
  define + `#undef`. (todo `dc-super-verbose`)
- [ ] **`ENABLE_TRACE_LOGGING` / ETW provider** — provider is declared, defined,
  and Register/Unregister'd but only ever written under the `#define 0` guard.
  Remove the provider, register/unregister, guarded `TraceLoggingWrite`s, the
  define, and the `<TraceLoggingProvider.h>` include. (todo `dc-tracelogging`)
- [ ] **`g_parentProcessId`** — dead global (defined, never read). (todo
  `dc-parent-pid`)
- [ ] **`CreateDetouredProcess` public wrapper** — not `dllexport`-ed, not used
  (`main.cpp` uses `DetourCreateProcessWithDllExW`; live grandchild path is
  `InternalCreateDetouredProcess`). Verify exclusive helpers
  (`CreateProcessAttributes`, `InitializeAttributeList`,
  `CreateProcAttributesForExplicitHandleInheritance`) then remove. (todo
  `dc-createdetouredprocess`)

## Phase 2 — global-state pass (the ~40 `g_*` in globals.h)

Classify each `g_*`: (live / dead / foldable-into-a-helper). Known so far:
- **Live, keep**: `Real_*` fn pointers (one per hook), `g_manifestTreeRoot`,
  `g_fileAccessManifestFlags`/`ExtraFlags`, `g_bazelWriteOverlayRoot`,
  `g_bazelOverlaySourceRoot`, `g_reportFileHandle`, `g_currentProcessCommandLine`
  (report line), `g_pDetouredProcessInjector` + `g_lpDllNameX86/X64` +
  `g_injectionTimeoutInMinutes` (child injection), `g_hPrivateHeap`,
  `g_breakawayChildProcesses` + translate-path tables, `g_ProcessKind`.
- [ ] Audit the remainder (`g_manifestSize`, `g_currentProcessId`,
  `g_FileAccessManifestPipId`, `g_manifestChildProcessesToBreakAwayFromJob`,
  `g_manifestInternalDetoursErrorNotificationFileString` /
  `g_internalDetoursErrorNotificationFile`, `g_BreakOnAccessDenied`) for
  removability or narrowing. (todo `dc-globals-audit`)
- [ ] Fold small single-caller helpers that only exist to touch a global into
  their caller where it shrinks the file/header surface.

## Phase 3 — FAM flag / ExtraFlag simplification (collapse never-set branches)

We only ever SET: `FailUnexpectedFileAccesses`, `MonitorNtCreateFile`,
`MonitorChildProcesses`, `MonitorZwCreateOpenQueryFile`, `IgnoreReparsePoints`,
`IgnoreFullReparsePointResolving` (+ optional `ReportFileAccesses` /
`ReportUnexpectedFileAccesses` under `--trace`).

Flags the DLL branches on at runtime but we NEVER set (collapse to the off-path
and delete the branch + the flag from `FOR_ALL_FAM_FLAGS`, leaving a reserved-gap
comment; keep hex values stable):
- [ ] `ForceReadOnlyForRequestedReadWrite` (6), `UseExtraThreadToDrainNtClose`
  (5), `UseLargeEnumerationBuffer` (5), `IgnoreZwOtherFileInformation` (4),
  `IgnoreGetFinalPathNameByHandle` (3), `DisableDetours` (2),
  `IgnoreZwRenameFileInformation` (1), `IgnoreSetFileInformationByHandle` (1),
  `UseLargeNtClosePreallocatedList` (1), `IgnoreNonCreateFileReparsePoints` (1),
  `IgnoreCreateProcessReport` (1), `IgnorePreloadedDlls` (1),
  `DirectoryCreationAccessEnforcement` (1), `ProbeDirectorySymlinkAsDirectory`
  (1), `IgnoreCodeCoverage` (1), `ReportProcessArgs` (1),
  `HardExitOnErrorInDetours` (1). (todo `dc-fam-flags`)
- [ ] Consider hardcoding the always-SET flags too (e.g. always
  MonitorNtCreateFile) and deleting the guards + the manifest wiring.
- [ ] ExtraFlags: drop the BuildXL-only enumerators we never set (Linux/PTrace,
  32-bit remote inject, MonitorCreateProcessAsUser, etc.), keeping our fork bits
  (`DeniedReadsAsNotFound`, `FilterDirectoryEnumeration`, `WriteOverlay`).

## Phase 4 — simplify the manifest / PolicyManifest surface

Idea (per user): our CLI maps a handful of options onto BuildXL's rich
`FileAccessPolicy` bitset + scope tree. Reduce to what we use.

- [ ] Audit which `FileAccessPolicy` bits we ever set from `manifest_builder`:
  `AllowRead`, `AllowReadIfNonExistent`, `AllowWrite`, `AllowCreateDirectory`,
  `AllowSymlinkCreation` (via AllowAll), `OverrideAllowWriteForExistingFiles`,
  `DeclaredInput`, `Deny`, plus mask semantics. Delete the never-set
  `FileAccessPolicy` bits + their DLL branches (`ReportAccessIfExistent`,
  `ReportAccessIfNonExistent`, `ReportDirectoryEnumerationAccess`,
  `TreatDirectorySymlinkAsDirectory`, `EnableFullReparsePointParsing`, the
  reserved gaps). (todo `dc-policy-bits`)
- [ ] Decide whether to **always enable** `--filter-inputs` and `--write-overlay`
  (user is open to this). If yes: drop the CLI toggles + the conditional
  extraFlag wiring + any "subtractive off" code paths, making the DLL's behavior
  singular. Weigh against losing the permissive/default mode used by current
  e2e tests — check which e2e modules rely on non-filtered mode first.
- [ ] Evaluate replacing the wire manifest's flag words with a compact
  project-owned `Options` block IF it removes more than it costs. NOTE: the scope
  **tree** (per-subtree policy) is the core enforcement structure and must stay;
  only the flag/policy *vocabulary* is a simplification target. Likely keep the
  tree wire format, shrink the vocabulary.

## Phase 5 — fold/shrink remaining small TUs

Candidates to fold into DetouredFunctions/DetoursHelpers or a tiny helper:
- [ ] `MetadataOverrides.{cpp,h}` (7 lines each; only `ScrubShortFileName`) →
  fold into DetouredFunctions or StringOperations.
- [ ] `DetouredScope.{cpp,h}`, `Assertions.{cpp,h}`,
  `PolicyResult_common.cpp` (fold into PolicyResult.cpp?).
- [x] `FilesCheckedForAccess.{cpp,h}` — **deleted** (entirely dead class).
- [ ] `SendReport.{cpp,h}` — trim to the single retained report-line path.
- [ ] `DebuggingHelpers.{cpp,h}` — trim to the live error/event-log path.
- [ ] `DetouredProcessInjector.{cpp,h}` — already gutted; see if the residual can
  fold into DetoursServices/DetoursHelpers.

## Phase 6 — bootstrap (`DetoursServices.cpp`) cleanup / possible rewrite

- [ ] Delete the stale multi-hundred-line BuildXL doc comment.
- [ ] Regenerate the `ATTACH()` table from the live hook set only.
- [ ] Reassess a hand-rewrite once Phases 1–5 shrink the coupling. (Higher risk:
  it shares ~40 globals + an exact hook table with DetouredFunctions.cpp — see
  `docs/vendor-architecture.md §4`.)

---

## Progress log

- 2026-07-22: plan created. Phases defined; Phase 1 todos queued.
## Progress log
- 2026-07-22: **Phase 1 complete.** Committed `c7ca9b5` (SUPER_VERBOSE/ETW/
  parent-pid) + `42ca5c6` (CreateDetouredProcess wrapper + exclusive helpers).
- 2026-07-22: **Phase 2 started (globals audit).** Removed write-only
  `g_FileAccessManifestPipId` and its `ManifestPipId` wire block (builder +
  parser + struct, in lockstep). Build + 10/10.
- 2026-07-22: also removed write-only `g_manifestSize`. Kept `g_currentProcessId`
  (live) + `g_BreakOnAccessDenied` (debug aid).
- 2026-07-22: **Phase 3 (FAM flags).** Removed dead deferred-NtClose overlay-drain
  subsystem + `LogProcessData` memory-stats (dropped `LogProcessData`,
  `UseExtraThreadToDrainNtClose`, `UseLargeNtClosePreallocatedList`). Collapsed
  never-set `ForceReadOnlyForRequestedReadWrite` triple. Then a batch of the
  remaining never-set guards (`DisableDetours`, `IgnorePreloadedDlls`,
  `IgnoreGetFinalPathNameByHandle`, `IgnoreZwRename/OtherFileInformation`,
  `IgnoreNonCreateFileReparsePoints`, `IgnoreCreateProcessReport`,
  `IgnoreSetFileInformationByHandle`, `ProbeDirectorySymlinkAsDirectory`,
  `DirectoryCreationAccessEnforcement`, `UseLargeEnumerationBuffer`,
  `IgnoreCodeCoverage`, `HardExitOnErrorInDetours`, `DiagnosticMessagesEnabled`)
  removed and dropped from `FOR_ALL_FAM_FLAGS`; also removed vestigial
  `g_currentProcessCommandLine`. Build + 10/10 after each group.
- 2026-07-22: **Phase 3 continued.** Dropped 3 more now-unreferenced FAM flags
  (`ReportProcessArgs`, `LogProcessDetouringStatus`, `CheckDetoursMessageCount`)
  and collapsed the last never-set FAM ExtraFlags, removing 10 from
  `FOR_ALL_FAM_EXTRA_FLAGS` (incl. the 5 Linux-only extras + `MonitorCreateProcessAsUser`
  -> `CreateProcessAsUserW` passthrough). Builder now sets only 3 extra flags
  (`DeniedReadsAsNotFound`, `FilterDirectoryEnumeration`, `WriteOverlay`).
  Build + 10/10.
- 2026-07-22: **Phase 4 (dc-policy-bits) complete.** Removed every never-set
  `FileAccessPolicy` bit, each its own build+10/10 commit:
  `TreatDirectorySymlinkAsDirectory` (0x800), `ReportDirectoryEnumerationAccess`
  (0x80), `EnableFullReparsePointParsing` (0x1000, also deleted the
  `IgnoreFullReparsePointResolvingForPath`/`GetLevelToEnableFullReparsePointParsing`/
  `FindLowestConsecutiveLevelThatStillHasProperty` helpers), and
  `ReportAccessIf{Existent,NonExistent}` (0x10/0x40) + the `ReportAccess` combo
  (simplified `IndicateUntracked`, `explicitReport`, `CreateAccessCheckResult`).
  Remaining bits are all builder-set: AllowRead/Write/ReadIfNonExistent/
  CreateDirectory/SymlinkCreation, OverrideAllowWriteForExistingFiles, DeclaredInput.
- 2026-07-22: **Phase 5 (dc-fold-small-tus) started.** Deleted the entirely-dead
  `FilesCheckedForAccess.{cpp,h}` class (no callers of TryRegisterPath/IsRegistered/
  GetInstance); dropped its 3 includes and the BUILD src entry. The duplicate
  `CanonicalizedPathType` typedef already lives in `PolicyResult.h`, so no
  relocation needed. Build + 10/10.
