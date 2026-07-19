# Model W write-overlay (experimental): write/read redirection + directory-
# enumeration insertion.
#
# The write overlay redirects undeclared writes in the execroot-writable cone into
# a process-private backing store, so the real execroot is never mutated: new files
# are created only in the overlay, reads of them redirect to the overlay copy, and
# a "write" over a pre-existing undeclared file leaves the real bytes intact. On top
# of that, a file that lives only in the overlay must still APPEAR when the tool
# lists the directory it "wrote" the file into - the opposite of the subtractive
# --filter-inputs move. Everything is gated by the --write-overlay kill-switch.
#
# The first block pins the enumeration-insertion mechanics using synthetic entries
# from BAZEL_SANDBOX_OVERLAY_TEST_NAMES (';'-separated names), a test-only hook that
# lets the record-construction / splice logic be tested in isolation, decoupled from
# the write path. The later blocks exercise the real feature driven by genuine
# writes (redirection, read-back, no-clobber, and index-sourced enumeration). Every
# enumeration assertion uses the direct-ntdll probe (enumfindntdirect / writeenum),
# the path Node/libuv use.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Sandbox,
    [Parameter(Mandatory)][string]$Probe,
    [string]$StdioLauncher,
    [string]$TempDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\harness.ps1')
Initialize-Harness -Sandbox $Sandbox -Probe $Probe -StdioLauncher $StdioLauncher `
    -TempDir $TempDir -Suite 'overlay'

# The DLL reads BAZEL_SANDBOX_OVERLAY_TEST_NAMES once per child process; each sandbox
# invocation is a fresh child, so toggling it here re-takes effect per case.
$env:BAZEL_SANDBOX_OVERLAY_TEST_NAMES = 'ghost.txt'

# --- Kill-switch: no insertion unless --write-overlay is passed ---------------
$ws = New-Workspace
# Flag ON: the synthetic entry appears even though no such file exists on disk.
Assert-Exit 'overlay ON: synthetic entry is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('enumfindntdirect', $ws, 'ghost.txt'))
# Flag OFF: identical env, but the shipped path is untouched - not found.
Assert-Exit 'overlay OFF: synthetic entry NOT enumerated (kill-switch)' 11 `
    (Invoke-SandboxRaw @('-W', $ws) @('enumfindntdirect', $ws, 'ghost.txt'))

# --- Real entries are preserved alongside the insertion -----------------------
$ws = New-Workspace  # seeds a.txt among others
Assert-Exit 'overlay ON: real entry still enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('enumfindntdirect', $ws, 'a.txt'))

# --- Empty result after filtering: exhaustion branch still inserts ------------
# --filter-inputs hides every undeclared child (a.txt etc.), so the real scan
# reports exhaustion with nothing visible; the overlay must still surface the
# synthetic entry (converting STATUS_NO_MORE_FILES back to a returned record).
$ws = New-Workspace
Assert-Exit 'overlay ON + filter: undeclared real entry hidden' 11 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') `
        @('enumfindntdirect', $ws, 'a.txt'))
Assert-Exit 'overlay ON + filter: synthetic entry still inserted' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') `
        @('enumfindntdirect', $ws, 'ghost.txt'))

# --- No env var => nothing injected even with the flag on ---------------------
$env:BAZEL_SANDBOX_OVERLAY_TEST_NAMES = ''
$ws = New-Workspace
Assert-Exit 'overlay ON, no overlay set: no synthetic entry' 11 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('enumfindntdirect', $ws, 'ghost.txt'))
Assert-Exit 'overlay ON, no overlay set: real entry still enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('enumfindntdirect', $ws, 'a.txt'))

# --- Write redirection: real execroot is never mutated ------------------------
# These exercise the full Model W write/read redirect (not the test-only synthetic
# names), so the overlay index is driven by real writes. BAZEL_SANDBOX_OVERLAY_TEST_NAMES
# stays empty here so only genuine redirect behavior is under test.
$env:BAZEL_SANDBOX_OVERLAY_TEST_NAMES = ''

# A brand-new undeclared file is redirected into the overlay: the write succeeds
# but the real execroot path is never created.
$ws = New-Workspace
Assert-Exit 'overlay write: new undeclared file write succeeds' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('write', (Join-Path $ws 'novel.txt'), 'x'))
Assert-True 'overlay write: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'novel.txt')))

# The process reads back the file it just wrote (read-redirect to the overlay copy),
# and the real execroot still has no such file.
$ws = New-Workspace
Assert-Exit 'overlay write+read: reads back its own overlay write' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeread', (Join-Path $ws 'rw.txt')))
Assert-True 'overlay write+read: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'rw.txt')))

# A pre-existing undeclared file can be "written" without clobbering the real bytes:
# the write is allowed (redirected) and the on-disk content is unchanged.
$ws = New-Workspace  # seeds seed.txt = "seed-data"
Assert-Exit 'overlay no-clobber: write over pre-existing file succeeds' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('write', (Join-Path $ws 'seed.txt'), 'x'))
Assert-True 'overlay no-clobber: real pre-existing bytes preserved' `
    ((Get-Content -Raw (Join-Path $ws 'seed.txt')).StartsWith('seed-data'))

# End-to-end enumeration mapping (mw-enum-map): a file written into the overlay is
# spliced into the directory listing the same action enumerates - sourced from the
# real overlay index, not the test-only synthetic names.
$ws = New-Workspace
Assert-Exit 'overlay enum-map: overlay write appears in enumeration' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenum', $ws, 'mapped.txt'))
Assert-True 'overlay enum-map: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'mapped.txt')))

# Control: without --write-overlay (but execroot-writable), the same new-file write
# lands on the REAL disk - proving the redirect is what diverts it, kill-switch clean.
$ws = New-Workspace
Assert-Exit 'control (no overlay): new file write succeeds' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--execroot-writable') @('write', (Join-Path $ws 'onreal.txt'), 'x'))
Assert-True 'control (no overlay): file IS created on real disk' `
    (Test-Path (Join-Path $ws 'onreal.txt'))

# Cross-process enumeration (the user's multi-process concern): the parent writes a
# new file into the overlay, then a SEPARATE child process enumerates the same
# directory. The child must see the parent's overlay file spliced into its listing,
# which only holds if the overlay index propagates cross-process (manifest-carried
# SHM) and each process independently snapshots + inserts from it.
$ws = New-Workspace
Assert-Exit 'overlay xproc enum: child sees parent overlay write in enumeration' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') `
        @('writespawnenum', $ws, 'xpenum.txt', (Get-Probe)))
Assert-True 'overlay xproc enum: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'xpenum.txt')))

# Multi-call enumeration cursor stress (usvfs NtQueryDirectoryFileExVirtualFile
# analogue): write several varying-length names into the overlay, then enumerate
# with a deliberately tiny buffer so NtQueryDirectoryFile must return across many
# calls. Each spliced overlay entry must appear EXACTLY once - the point-in-time
# snapshot cursor must neither skip (would give 11) nor duplicate (would give 20)
# an entry as the listing is emitted piecewise. This is the path the 64KB-buffer
# writeenum case cannot cover.
$ws = New-Workspace
Assert-Exit 'overlay multi-call: every overlay entry enumerated exactly once' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') `
        @('writeenummulti', $ws, '256',
          'aa.txt', 'bbbbbbbb.txt', 'c.txt', 'dddddddddddddddd.txt', 'ee.txt', 'f.txt'))

# CREATE_NEW merged-view semantics: create-if-absent, fail-if-exists must consult
# BOTH the real execroot and the overlay. Creating a genuinely new name succeeds and
# is redirected (real stays clean); CREATE_NEW over a pre-existing undeclared real
# file must FAIL (not silently succeed by creating an empty backing file), and the
# real bytes must survive untouched.
$ws = New-Workspace
Assert-Exit 'overlay CREATE_NEW: brand-new name succeeds' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('createnew', (Join-Path $ws 'fresh.txt')))
Assert-True 'overlay CREATE_NEW: brand-new file NOT on real disk' `
    (-not (Test-Path (Join-Path $ws 'fresh.txt')))

$ws = New-Workspace  # seeds seed.txt = "seed-data"
Assert-Exit 'overlay CREATE_NEW: over pre-existing undeclared file FAILS' 20 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('createnew', (Join-Path $ws 'seed.txt')))
Assert-True 'overlay CREATE_NEW: pre-existing real bytes preserved' `
    ((Get-Content -Raw (Join-Path $ws 'seed.txt')).StartsWith('seed-data'))

# Filter-aware CREATE_NEW (linux-sandbox parity): with --filter-inputs the same
# pre-existing undeclared file is HIDDEN (reads masked NOT_FOUND), so the merged
# view treats it as ABSENT. CREATE_NEW must then SUCCEED into the overlay backing
# store - exactly what linux-sandbox does (its throwaway execroot never contains
# the undeclared file) - while the real execroot bytes stay untouched. This is the
# mirror of the visible-file FAIL case above: same file, opposite outcome, decided
# solely by whether the input filter hides it.
$ws = New-Workspace  # seeds seed.txt = "seed-data"
Assert-Exit 'overlay CREATE_NEW + filter: over HIDDEN undeclared file SUCCEEDS' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') `
        @('createnew', (Join-Path $ws 'seed.txt')))
Assert-True 'overlay CREATE_NEW + filter: real pre-existing bytes preserved' `
    ((Get-Content -Raw (Join-Path $ws 'seed.txt')).StartsWith('seed-data'))

# Overlay-only directory (mw-p3-opendir): a file written into a subdirectory that
# does NOT exist on the real disk lands in the backing store, which creates that
# subdirectory only in the overlay. Enumerating that overlay-only directory must
# open the backing directory (no real dir exists) and list the file - the tool sees
# the directory tree it "created" purely in the overlay. Without --filter-inputs the
# backing children are visible; with it they stay visible via the backing-existence
# (WasCreatedInThisProcess) carve-out. The real execroot subdir is never created.
$ws = New-Workspace
Assert-Exit 'overlay ovdir: file in overlay-only subdir is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeovdirenum', $ws))
Assert-True 'overlay ovdir: real execroot subdir NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovsub')))

$ws = New-Workspace
Assert-Exit 'overlay ovdir + filter: file in overlay-only subdir still enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeovdirenum', $ws))
Assert-True 'overlay ovdir + filter: real execroot subdir NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovsub')))

# --- Delete/rename redirection (mw-delete-rename) -----------------------------
# A file the process wrote into the overlay must be deletable: the delete removes
# only the backing copy, and the real execroot is never touched (it never had the
# file). This is the create-temp-then-delete idiom, redirected.
$ws = New-Workspace
Assert-Exit 'overlay delete: deleting own overlay file succeeds' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeovdelete', $ws))
Assert-True 'overlay delete: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovdel.txt')))

# Deleting a pre-existing undeclared lower file must NEVER mutate the real bytes.
# Under --filter-inputs the file is HIDDEN, so the merged view has no such entry:
# the delete is a NOT_FOUND no-op (linux-sandbox parity - the throwaway execroot
# never contained it), and the real bytes survive untouched.
$ws = New-Workspace  # seeds seed.txt = "seed-data"
Assert-Exit 'overlay delete + filter: delete of HIDDEN lower file -> NOT_FOUND' 11 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') `
        @('delete', (Join-Path $ws 'seed.txt')))
Assert-True 'overlay delete + filter: real pre-existing bytes preserved' `
    ((Get-Content -Raw (Join-Path $ws 'seed.txt')).StartsWith('seed-data'))

# In permissive mode (--write-overlay alone) the pre-existing lower file is VISIBLE,
# so removing it would require mutating the real execroot - which Model W forbids.
# The delete is therefore DENIED, and the real bytes survive untouched.
$ws = New-Workspace  # seeds seed.txt = "seed-data"
Assert-Exit 'overlay delete permissive: delete of visible lower file -> denied' 10 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('delete', (Join-Path $ws 'seed.txt')))
Assert-True 'overlay delete permissive: real pre-existing bytes preserved' `
    ((Get-Content -Raw (Join-Path $ws 'seed.txt')).StartsWith('seed-data'))

# Renaming a file the process wrote into the overlay keeps the whole move inside the
# backing store: the destination reads back, and neither real path is created.
$ws = New-Workspace
Assert-Exit 'overlay rename: rename of own overlay file succeeds, dest reads back' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeovrename', $ws))
Assert-True 'overlay rename: real src NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovr_src.txt')))
Assert-True 'overlay rename: real dest NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovr_dst.txt')))

# --- Metadata redirect (mw-metadata) ------------------------------------------
# A process must be able to stat a file it wrote into the overlay: every path-based
# metadata API (GetFileAttributes(Ex), GetFileInformationByName, exact FindFirstFileEx)
# must observe the backing file, since the real execroot never has the path. Covered
# both permissively and under --filter-inputs (the backing-existence carve-out keeps
# the scratch file visible to the process that created it).
$ws = New-Workspace
Assert-Exit 'overlay metadata: stat of own overlay file works (all APIs)' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeovstat', $ws))
Assert-True 'overlay metadata: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovstat.txt')))

$ws = New-Workspace
Assert-Exit 'overlay metadata + filter: stat of own overlay file works (all APIs)' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeovstat', $ws))
Assert-True 'overlay metadata + filter: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovstat.txt')))

# --- NT-layer redirect (mw-nt-layer) ------------------------------------------
# A tool that opens files via the native NtCreateFile syscall (bypassing Win32
# CreateFileW) must still be redirected into the overlay: the OBJECT_ATTRIBUTES path
# is rewritten to the backing store. Create+write then read-back a file entirely
# through direct NtCreateFile; the real execroot must never get the path.
$ws = New-Workspace
Assert-Exit 'overlay nt-layer: direct NtCreateFile write+read redirected to overlay' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('ntwriteread', $ws))
Assert-True 'overlay nt-layer: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'ntov.txt')))

$ws = New-Workspace
Assert-Exit 'overlay nt-layer + filter: direct NtCreateFile write+read redirected' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('ntwriteread', $ws))
Assert-True 'overlay nt-layer + filter: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'ntov.txt')))

# --- Configurable backing dir (--overlay-dir) ---------------------------------
# By default the backing store is auto-created under %TMP%; --overlay-dir points it
# at a caller-chosen location (e.g. the source-root volume or a RAM disk). The write
# must still redirect (real execroot untouched), and the backing file must PHYSICALLY
# land under the custom dir. -D is passed so the per-invocation backing store is NOT
# cleaned up on exit, letting us inspect where the redirected write landed.
$ws = New-Workspace
$ovDir = Join-Path (Split-Path -Parent $ws) ('ov-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$dbg = Join-Path (Split-Path -Parent $ws) ('ovdbg-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
Assert-Exit 'overlay --overlay-dir: write redirected with custom backing dir' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay', '--overlay-dir', $ovDir, '-D', $dbg) `
        @('write', (Join-Path $ws 'custom.txt'), 'x'))
Assert-True 'overlay --overlay-dir: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'custom.txt')))
Assert-True 'overlay --overlay-dir: backing file landed under custom dir' `
    ((Test-Path $ovDir) -and `
     @(Get-ChildItem -Recurse -File -Path $ovDir -Filter 'custom.txt' -ErrorAction SilentlyContinue).Count -ge 1)

# --- Enum-classes: overlay insertion across all enumeration APIs --------------
# The overlay splice was originally wired only through NtQueryDirectoryFile. These
# cases prove a genuine overlay write is visible through EVERY enumeration surface a
# tool might use: the Win32 FindFirstFile/FindNextFile family, the
# GetFileInformationByHandleEx path (.NET / some CRTs), and the modern
# NtQueryDirectoryFileEx syscall. Driven by real writes (no test-only synthetic
# names), covering both the permissive and --filter-inputs configurations.
$env:BAZEL_SANDBOX_OVERLAY_TEST_NAMES = ''

# GetFileInformationByHandleEx (FileIdBothDirectoryInfo) surface.
$ws = New-Workspace
Assert-Exit 'overlay enum(gfibhe): own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumgfibhe', $ws, 'egfibhe.txt'))
Assert-True 'overlay enum(gfibhe): real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'egfibhe.txt')))
$ws = New-Workspace
Assert-Exit 'overlay enum(gfibhe) + filter: own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumgfibhe', $ws, 'egfibhe.txt'))

# Win32 FindFirstFile/FindNextFile surface.
$ws = New-Workspace
Assert-Exit 'overlay enum(win32find): own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumfind', $ws, 'efind.txt'))
Assert-True 'overlay enum(win32find): real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'efind.txt')))
$ws = New-Workspace
Assert-Exit 'overlay enum(win32find) + filter: own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumfind', $ws, 'efind.txt'))

# NtQueryDirectoryFileEx syscall surface.
$ws = New-Workspace
Assert-Exit 'overlay enum(ntex): own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumex', $ws, 'eex.txt'))
Assert-True 'overlay enum(ntex): real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'eex.txt')))
$ws = New-Workspace
Assert-Exit 'overlay enum(ntex) + filter: own overlay write is enumerated' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumex', $ws, 'eex.txt'))

# --- Enum-classes: synthetic-record metadata is real --------------------------
# A spliced record must carry genuine metadata read from the backing file, not a
# zeroed header: a file's EndOfFile must equal the bytes written, and a directory
# entry must have FILE_ATTRIBUTE_DIRECTORY set so tools recurse into overlay-only
# subdirs. writeenummeta returns kNotFound (11) if the file size is wrong and
# kOtherError (20) if the dir entry lacks the directory bit; kOk (0) iff both hold.
$ws = New-Workspace
Assert-Exit 'overlay enum metadata: file size + dir attribute are correct' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenummeta', $ws))
Assert-True 'overlay enum metadata: real execroot file NOT created' `
    (-not (Test-Path (Join-Path $ws 'meta.txt')))
Assert-True 'overlay enum metadata: real execroot subdir NOT created' `
    (-not (Test-Path (Join-Path $ws 'metadir')))

# --- Enum-classes: CreateDirectoryW redirect + parent splice ------------------
# CreateDirectoryW of an overlay-only subdir must redirect into the backing store
# (real execroot untouched) yet still appear - flagged as a directory - when the
# parent is enumerated via the Win32 Find family.
$ws = New-Workspace
Assert-Exit 'overlay createdir: overlay-only subdir appears in parent enum as a directory' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeovsubdirenum', $ws))
Assert-True 'overlay createdir: real execroot subdir NOT created' `
    (-not (Test-Path (Join-Path $ws 'ovsubdir')))
$ws = New-Workspace
Assert-Exit 'overlay createdir + filter: overlay-only subdir appears as a directory' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeovsubdirenum', $ws))

# --- Enum-classes: wildcard filtering of spliced overlay entries (gap #1) -----
# The overlay entries spliced into an enumeration must honor the caller's wildcard,
# exactly as the OS filters the real entries. Writing foo.txt + bar.log into the
# overlay and enumerating <dir>\*.txt must surface foo.txt and NOT bar.log.
# writeenumfilterfind/nt return kOk (0) iff <match> is listed and <nomatch> is not,
# kOtherError (20) if the non-matching entry leaked (over-inclusion).
$ws = New-Workspace
Assert-Exit 'overlay wildcard(win32find): *.txt lists foo.txt, hides bar.log' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumfilterfind', $ws, '*.txt', 'foo.txt', 'bar.log'))
$ws = New-Workspace
Assert-Exit 'overlay wildcard(win32find) + filter: *.txt lists foo.txt, hides bar.log' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumfilterfind', $ws, '*.txt', 'foo.txt', 'bar.log'))
$ws = New-Workspace
Assert-Exit 'overlay wildcard(ntdirect): *.txt lists foo.txt, hides bar.log' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumfilternt', $ws, '*.txt', 'foo.txt', 'bar.log'))
$ws = New-Workspace
Assert-Exit 'overlay wildcard(ntdirect) + filter: *.txt lists foo.txt, hides bar.log' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumfilternt', $ws, '*.txt', 'foo.txt', 'bar.log'))

# --- Enum-classes: narrow-filter FindFirstFile synthesis (gap #2) -------------
# When a narrow wildcard matches ONLY an overlay-only file, the OS returns
# ERROR_FILE_NOT_FOUND (no real entry matches, so no Find handle). The overlay must
# synthesize a Find handle so FindFirstFileW returns our file as the FIRST result.
# The seeded workspace has a.txt/src.txt/seed.txt/keep.txt but no *.log, so *.log
# has no real match. writeenumsynth returns kOk (0) iff the first result is <name>.
$ws = New-Workspace
Assert-Exit 'overlay synth(win32find): narrow *.log with no real match returns overlay file' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--write-overlay') @('writeenumsynth', $ws, '*.log', 'only.log'))
$ws = New-Workspace
Assert-Exit 'overlay synth(win32find) + filter: narrow *.log returns overlay file' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '--filter-inputs', '--write-overlay') @('writeenumsynth', $ws, '*.log', 'only.log'))

Complete-Harness
