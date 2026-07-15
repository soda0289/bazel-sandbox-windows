# Read-enforcement MODE: permissive (default) vs hermetic (-H).
#
# The default linux-sandbox makes "the entire filesystem read-only" and confines
# only writes; reads are never restricted to declared inputs. To match that
# (Goal 1), this sandbox defaults to PERMISSIVE reads: the working dir (-W) is
# readable, so undeclared reads inside the execroot succeed, while writes stay
# confined to -w. Passing -H switches to HERMETIC reads (Goal 2 /
# --experimental_use_hermetic_linux_sandbox): the working dir is denied by
# default and only -r/-w inputs are readable. This suite pins that distinction;
# every other enforce_* suite forces -H via the harness.
#
# This is the fix for the ng_package findings (docs/sandbox-parity-findings.md
# A4/A5): undeclared reads inside the execroot - split-config sibling outputs
# reached through --preserveSymlinks, and the package.json files node walks for
# module-type resolution - were denied under the old always-hermetic behavior but
# are readable under the default linux-sandbox.

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
    -TempDir $TempDir -Suite 'modes'

# --- Reads inside the working dir -------------------------------------------
$ws = New-Workspace
$f = Join-Path $ws 'a.txt'   # seeded by New-Workspace

# Permissive (default): an UNDECLARED read inside -W is allowed, matching the
# default linux-sandbox (whole FS readable). No -r grant is needed.
Assert-Exit 'permissive: undeclared read inside -W allowed' 0 `
    (Invoke-SandboxRaw @('-W', $ws) @('read', $f))
# Hermetic (-H): the same undeclared read is denied; only -r/-w expose the dir.
Assert-Exit 'hermetic: undeclared read inside -W denied' 10 `
    (Invoke-SandboxRaw @('-H', '-W', $ws) @('read', $f))
# Hermetic (-H) with an explicit -r grant: allowed.
Assert-Exit 'hermetic: read inside -W with -r allowed' 0 `
    (Invoke-SandboxRaw @('-H', '-W', $ws, '-r', $ws) @('read', $f))

# --- Absent-file probing tracks the mode ------------------------------------
$nope = Join-Path $ws 'nope.txt'
# Permissive: an absent path inside -W reports not-found (the dir is readable
# with AllowReadIfNonExistent), exactly like probing an optional input on linux.
Assert-Exit 'permissive: absent read inside -W reports not-found' 11 `
    (Invoke-SandboxRaw @('-W', $ws) @('read', $nope))
# Hermetic: an absent path inside -W with no grant is denied.
Assert-Exit 'hermetic: absent read inside -W denied' 10 `
    (Invoke-SandboxRaw @('-H', '-W', $ws) @('read', $nope))

# --- Writes are confined in BOTH modes --------------------------------------
# Permissive mode relaxes READS only; writes still require -w (unlike linux,
# where -W is read-write - windows does in-place execution against the real tree,
# so we keep writes confined to declared outputs in both modes).
Assert-Exit 'permissive: undeclared write inside -W denied' 10 `
    (Invoke-SandboxRaw @('-W', $ws) @('write', (Join-Path $ws 'w1.txt')))
Assert-Exit 'permissive: write inside -W with -w allowed' 0 `
    (Invoke-SandboxRaw @('-W', $ws, '-w', $ws) @('write', (Join-Path $ws 'w2.txt')))
Assert-Exit 'hermetic: undeclared write inside -W denied' 10 `
    (Invoke-SandboxRaw @('-H', '-W', $ws) @('write', (Join-Path $ws 'w3.txt')))

# --- -b blocks reads even in permissive mode --------------------------------
# An explicit -b (inaccessible) scope still denies reads under permissive mode,
# because a Deny scope overrides the readable working dir.
$blocked = Join-Path $ws 'sub'
'secret' | Set-Content (Join-Path $blocked 'sfile.txt')
Assert-Exit 'permissive: -b still blocks reads' 10 `
    (Invoke-SandboxRaw @('-W', $ws, '-b', $blocked) @('read', (Join-Path $blocked 'sfile.txt')))

# --- Reads OUTSIDE -W are allowed in both modes -----------------------------
# The root scope is read-only in both modes (the whole FS is readable); -H only
# tightens the working dir, not the rest of the file system.
$outside = New-Workspace
$ofile = Join-Path $outside 'a.txt'
Assert-Exit 'hermetic: read outside -W still allowed' 0 `
    (Invoke-SandboxRaw @('-H', '-W', $ws) @('read', $ofile))

# --- --filter-inputs: undeclared inputs are INVISIBLE (not just denied) ------
# Strict mode implies -H and additionally masks read denials as NOT_FOUND, so an
# undeclared input looks ABSENT (as under linux-sandbox's symlink forest) rather
# than permission-denied. Writes are NOT masked so missing-output declarations
# still fail loudly. See docs/detours-input-filtering.md (Mechanism A).
$fi = New-Workspace
$vis = Join-Path $fi 'a.txt'          # seeded by New-Workspace
$hidden = Join-Path $fi 'secret.txt'
'top secret' | Set-Content $hidden
# A declared -r input is still readable.
Assert-Exit 'filter-inputs: declared -r read allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('read', $vis))
# An undeclared EXISTING file reports NOT_FOUND (11), not ACCESS_DENIED (10).
Assert-Exit 'filter-inputs: undeclared read reports not-found (masked)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('read', $hidden))
# Same via the native NtCreateFile path (STATUS_OBJECT_NAME_NOT_FOUND).
Assert-Exit 'filter-inputs: undeclared ntread reports not-found (masked)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('ntread', $hidden))
# GetFileAttributes (stat) of an undeclared file is likewise masked.
Assert-Exit 'filter-inputs: undeclared stat reports not-found (masked)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('stat', $hidden))
# GetFileInformationByName (the handle-less fast stat path modern libuv/Node use) is masked
# too. This is the path that leaked before: GetFileAttributes was already masked, but Node's
# fs.stat went through GetFileInformationByName, so an undeclared file stayed visible to stat()
# while read() was masked -- breaking parity with linux-sandbox. Declared inputs stay visible.
Assert-Exit 'filter-inputs: undeclared statbyname reports not-found (masked)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('statbyname', $hidden))
Assert-Exit 'filter-inputs: declared statbyname visible' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('statbyname', $vis))
# FindFirstFileEx on an exact undeclared file path (the probe cmd.exe `type` uses)
# is masked too: NOT_FOUND (11), not ACCESS_DENIED (10). A declared input stays visible.
Assert-Exit 'filter-inputs: undeclared findfile reports not-found (masked)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('findfile', $hidden))
Assert-Exit 'filter-inputs: declared findfile visible' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('findfile', $vis))
# Writes are NOT masked: an undeclared write is still ACCESS_DENIED (10).
Assert-Exit 'filter-inputs: undeclared write still denied (not masked)' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('write', (Join-Path $fi 'wx.txt')))
# Contrast: plain -H (no --filter-inputs) keeps ACCESS_DENIED for undeclared reads.
Assert-Exit 'hermetic (no filter): undeclared read still denied (not masked)' 10 `
    (Invoke-SandboxRaw @('-H', '-W', $fi) @('read', $hidden))

# --- --filter-inputs: colocated UNDECLARED package.json is masked (hermetic/RBE parity) ---
# node/tsc resolve a module's real path, then walk UP the directory tree for the nearest
# package.json to decide the module type (commonjs vs module). On RBE / hermetic linux-sandbox
# the action's input root contains ONLY declared inputs, so that walk finds no undeclared
# package.json and node defaults to CommonJS. Our in-place execroot has real undeclared
# package.json files colocated with declared inputs; to match hermetic/RBE they must be
# masked NOT_FOUND, exactly like any other undeclared file. (An earlier carve-out that
# REVEALED colocated package.json was wrong -- it made us leakier than hermetic/RBE -- and
# was reverted.)
$pkg = Join-Path $fi 'package.json'     # undeclared; parent $fi IS a manifest node ($vis is -r)
'{"type":"commonjs"}' | Set-Content $pkg
Assert-Exit 'filter-inputs: colocated undeclared package.json read masked' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('read', $pkg))
Assert-Exit 'filter-inputs: colocated undeclared package.json stat masked' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('stat', $pkg))
Assert-Exit 'filter-inputs: colocated undeclared package.json statbyname masked' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('statbyname', $pkg))
Assert-Exit 'filter-inputs: colocated undeclared package.json hidden from enumeration' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('enumfind', $fi, 'package.json'))

# --- --filter-inputs: undeclared entries are hidden from directory ENUMERATION -
# Beyond masking direct reads (Mechanism A), --filter-inputs also removes
# undeclared entries from directory listings (Mechanism B), matching how
# linux-sandbox's symlink forest only contains declared inputs. An enumeration
# lists declared files and the ancestor directories that lead to declared inputs,
# but hides undeclared files and undeclared directories. This is enforced across
# all three enumeration code paths: Win32 FindFirstFile, the
# GetFileInformationByHandleEx wrapper, and direct ntdll!NtQueryDirectoryFile
# (the path Node/libuv use). See docs/detours-input-filtering.md (Mechanism B).
$en = New-Workspace
New-Item -ItemType Directory -Force -Path (Join-Path $en 'sub') | Out-Null    # ancestor of a declared input
New-Item -ItemType Directory -Force -Path (Join-Path $en 'other') | Out-Null  # undeclared directory
$enVis = Join-Path $en 'a.txt'                 # seeded by New-Workspace; declared -r
$enDeep = Join-Path $en 'sub\deep.txt'         # declared -r (makes 'sub' an ancestor)
'deep' | Set-Content $enDeep
'top secret' | Set-Content (Join-Path $en 'secret.txt')   # undeclared file
$enGrants = @('--filter-inputs', '-W', $en, '-r', $enVis, '-r', $enDeep)
foreach ($op in @('enumfind', 'enumfindnt', 'enumfindntdirect')) {
    Assert-Exit "filter-inputs: $op declared file visible" 0 `
        (Invoke-SandboxRaw $enGrants @($op, $en, 'a.txt'))
    Assert-Exit "filter-inputs: $op undeclared file hidden" 11 `
        (Invoke-SandboxRaw $enGrants @($op, $en, 'secret.txt'))
    Assert-Exit "filter-inputs: $op ancestor dir of declared input visible" 0 `
        (Invoke-SandboxRaw $enGrants @($op, $en, 'sub'))
    Assert-Exit "filter-inputs: $op undeclared dir hidden" 11 `
        (Invoke-SandboxRaw $enGrants @($op, $en, 'other'))
}

# Same guarantees when the directory is opened via the \\?\ extended-length prefix
# (the form Node/libuv use for readdir). A Win32Nt-typed directory path must resolve
# child policies through the manifest tree just like a plain Win32 path: previously the
# special-case device-path rules misclassified every subpath of a \\?\ directory as a
# non-drive device and granted AllowAll, LEAKING undeclared entries (fusion tsc TS6053:
# an undeclared src/test-utils.ts became visible to a \\?\ readdir but unreadable, so
# tsc's glob matched a file it then couldn't open). Regression guard for that leak.
$enQm = "\\?\$en"
foreach ($op in @('enumfind', 'enumfindnt', 'enumfindntdirect')) {
    Assert-Exit "filter-inputs (\\?\): $op declared file visible" 0 `
        (Invoke-SandboxRaw $enGrants @($op, $enQm, 'a.txt'))
    Assert-Exit "filter-inputs (\\?\): $op undeclared file hidden" 11 `
        (Invoke-SandboxRaw $enGrants @($op, $enQm, 'secret.txt'))
    Assert-Exit "filter-inputs (\\?\): $op ancestor dir of declared input visible" 0 `
        (Invoke-SandboxRaw $enGrants @($op, $enQm, 'sub'))
    Assert-Exit "filter-inputs (\\?\): $op undeclared dir hidden" 11 `
        (Invoke-SandboxRaw $enGrants @($op, $enQm, 'other'))
}

# --- -d: output parent directory (node-only reveal + create/write) ----------
# linux-sandbox pre-creates the parent directory of every declared output inside
# its (writable) sandbox execroot, so a tool's recursive mkdir of that dir is a
# no-op and the output write succeeds. In-place on Windows the dir already exists
# but, under --filter-inputs, the hermetic execroot hides it and denies create -
# so a tool that mkdir's its own output dir gets ACCESS_DENIED (the EPERM we hit
# on fusion's TailwindCss action). -d grants a NODE-only policy on that exact dir
# (reveal + AllowCreateDirectory + AllowWrite) WITHOUT opening its subtree, so the
# dir becomes creatable/writable while undeclared files inside it stay hidden and
# unwritable. See docs/detours-input-filtering.md.
$od = New-Workspace
$outdir = Join-Path $od 'bin'                     # existing output parent dir
New-Item -ItemType Directory -Force -Path $outdir | Out-Null
$newdir = Join-Path $od 'freshbin'                # NOT created on disk
$outfile = Join-Path $outdir 'gen.txt'            # a declared output file
$secret = Join-Path $outdir 'secret.txt'          # undeclared file inside the dir
'top secret' | Set-Content $secret

# Baseline (no -d): creating the output dir under a hermetic execroot is denied
# (write-class op, so NOT masked to not-found - it is a hard ACCESS_DENIED).
Assert-Exit 'no -d: mkdir existing output dir denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od) @('mkdir', $outdir))
Assert-Exit 'no -d: mkdir new output dir denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od) @('mkdir', $newdir))

# With -d the create call reaches the filesystem. For a brand-new dir it succeeds
# (0); for one that already exists it gets ALREADY_EXISTS (20, "other") instead of
# ACCESS_DENIED (10) - i.e. the policy now permits it (Node maps that to EEXIST and
# treats recursive mkdir as done).
Assert-Exit '-d: mkdir new output dir allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $newdir) @('mkdir', $newdir))
Assert-Exit '-d: mkdir existing output dir reaches already-exists (allowed)' 20 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $outdir) @('mkdir', $outdir))

# -d on the parent dir + -w on the declared output: the output write succeeds.
Assert-Exit '-d + -w: declared output write allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $outdir, '-w', $outfile) `
        @('write', $outfile))

# Safety: -d reveals the DIRECTORY only, not its contents. An undeclared file
# inside the -d dir is still hidden on read (NOT_FOUND, masked) and unwritable
# (ACCESS_DENIED) - the "hidden file can't be overwritten" guarantee.
Assert-Exit '-d: undeclared file in output dir still hidden (read)' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $outdir) @('read', $secret))
Assert-Exit '-d: undeclared file in output dir not writable' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $outdir) @('write', $secret))
# And enumeration of the -d dir still omits the undeclared file.
Assert-Exit '-d: undeclared file hidden from enumeration of output dir' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $od, '-d', $outdir) @('enumfind', $outdir, 'secret.txt'))

# --- --execroot-writable: create-new allowed, clobber-existing denied ----------
# linux-sandbox's throwaway execroot is fully writable, so a tool may freely create
# undeclared scratch files/dirs inside the execroot (e.g. vite's node_modules/
# .vite-temp). In-place on Windows we cannot make the whole execroot blindly
# writable without risking a real source/input file being clobbered. --execroot-
# writable grants write+create-dir on the execroot cone with
# OverrideAllowWriteForExistingFiles, so the DLL allows creating NEW paths (and re-
# writing paths created this run) but DENIES overwriting a pre-existing undeclared
# file. Declared -w outputs stay freely overwritable; -r inputs stay read-only.
$ew = New-Workspace
$ewNew = Join-Path $ew 'scratch.tmp'                # does NOT exist on disk
$ewRewrite = Join-Path $ew 'rescratch.tmp'          # fresh path, only used by rewrite
$ewWriteRead = Join-Path $ew 'wrscratch.tmp'        # fresh path, only used by writeread
$ewNewDir = Join-Path $ew 'scratchdir'              # does NOT exist on disk
$ewExisting = Join-Path $ew 'a.txt'                 # seeded by New-Workspace (undeclared)
$ewOut = Join-Path $ew 'out.txt'                    # a declared -w output (may exist)
'declared output' | Set-Content $ewOut
$ewInput = Join-Path $ew 'src.txt'                  # seeded; declared -r input

# Creating a brand-new undeclared file/dir in the execroot is allowed.
Assert-Exit 'execroot-writable: create new file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('write', $ewNew))
Assert-Exit 'execroot-writable: create new dir allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('mkdir', $ewNewDir))
# Re-writing a file created THIS run is allowed (per-process created-files cache).
# Uses a dedicated fresh path so a prior assertion's persisted file can't make the
# first of the two writes hit an already-existing file.
Assert-Exit 'execroot-writable: re-write of self-created file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('rewrite', $ewRewrite))
# Reading back a file created THIS run is allowed even though the execroot read-
# filter hides undeclared paths (matches linux; needed for vite's .vite-temp module).
Assert-Exit 'execroot-writable: read-back of self-created file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('writeread', $ewWriteRead))
# Overwriting a pre-existing undeclared file is DENIED (no clobber of real inputs).
Assert-Exit 'execroot-writable: overwrite existing undeclared file denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('write', $ewExisting))
# Overwriting a pre-existing declared -r input is DENIED (read-only, no write bit).
Assert-Exit 'execroot-writable: overwrite declared -r input denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew, '-r', $ewInput) @('write', $ewInput))
# A declared -w output stays freely overwritable even if it already exists
# (AllowAll scope => IndicateUntracked => override bypassed).
Assert-Exit 'execroot-writable: declared -w output overwrite allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew, '-w', $ewOut) @('write', $ewOut))
# Sanity: WITHOUT --execroot-writable, creating a new file in a filter-inputs
# execroot is still denied (baseline behavior unchanged).
Assert-Exit 'no execroot-writable: create new file still denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $ew) @('write', (Join-Path $ew 'nope.tmp')))

Complete-Harness