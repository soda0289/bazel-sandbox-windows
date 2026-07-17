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
# --- Consistency matrix: EVERY read/probe hook variant must mask IDENTICALLY ---
# Each op below exercises a DIFFERENT detoured hook that resolves a single path:
#   read       -> CreateFileW (GENERIC_READ)      ntread     -> NtCreateFile (read)
#   reada      -> CreateFileA (GENERIC_READ)      stat       -> GetFileAttributesW
#   stata      -> GetFileAttributesA              statex     -> GetFileAttributesExW
#   statbyname -> GetFileInformationByName        findfile   -> FindFirstFileEx (exact path)
# These hooks are near-duplicates, so a copy-paste divergence in ANY one is easy to miss and
# invisible unless a test exercises that exact API. Two such leaks have bitten us:
#   * GetFileInformationByName (Node/libuv fs.stat) once stayed VISIBLE while read() was masked.
#   * GetFileAttributesExW once returned ACCESS_DENIED instead of NOT_FOUND, breaking Java's
#     Files.createDirectories/checkAccess on its _javac scratch dir -- every Javac action failed.
# Under --filter-inputs, ALL of them MUST report NOT_FOUND (11) for (a) an undeclared existing
# file, (b) a genuinely absent path, and (c) an absent NESTED path (the mkdir -p /
# createDirectories ancestor probe), and MUST keep a declared -r input VISIBLE (0). Add a row to
# $readProbeOps whenever a new read/probe op or hook is introduced.
$absent = Join-Path $fi 'absent.txt'            # never created
$absentNested = Join-Path $fi 'no\such\deep\path'  # absent, with missing parents
$readProbeStates = @(
    @{ name = 'undeclared-existing'; path = $hidden;       want = 11 },
    @{ name = 'absent';              path = $absent;        want = 11 },
    @{ name = 'absent-nested';       path = $absentNested;  want = 11 },
    @{ name = 'declared-r-visible';  path = $vis;           want = 0  }
)
$readProbeOps = @('read', 'ntread', 'reada', 'stat', 'stata', 'statex', 'statbyname', 'findfile')
foreach ($op in $readProbeOps) {
    foreach ($st in $readProbeStates) {
        Assert-Exit "filter-inputs matrix[$op]: $($st.name)" $st.want `
            (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @($op, $st.path))
    }
}
# Compound ops that perform a SOURCE READ (CopyFile source, CreateHardLink source) must mask
# their source-read denial too -- same DenialError() divergence class as the probe hooks (they
# carried no mask flag until this sweep). The write side stays confined: link/dest is a declared
# -w output, only the undeclared SOURCE is probed, so an undeclared source reports NOT_FOUND (11).
$cpdst = Join-Path $fi 'copydst'; New-Item -ItemType Directory -Force $cpdst | Out-Null
Assert-Exit 'filter-inputs matrix[copy]: undeclared source -> not-found' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis, '-w', $cpdst) @('copy', $hidden, (Join-Path $cpdst 'o.txt')))
Assert-Exit 'filter-inputs matrix[hardlink]: undeclared source -> not-found' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis, '-w', $cpdst) @('hardlink', (Join-Path $cpdst 'lnk.txt'), $hidden))
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
Assert-Exit 'filter-inputs: colocated undeclared package.json statex masked' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $fi, '-r', $vis) @('statex', $pkg))
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
$ewWriteDelete = Join-Path $ew 'wdscratch.tmp'      # fresh path, only used by writedelete
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
# Deleting a file created THIS run is allowed. The delete resolves the name via the
# file handle (DetourGetFinalPathByHandle -> "\\?\C:\...") while the create used the
# literal path, so this guards the created-files tracker against keying on the path-type
# prefix (the bug that made zip/cygwin's create-temp-then-rename fail to delete its temp).
Assert-Exit 'execroot-writable: delete of self-created file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('writedelete', $ewWriteDelete))
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
# A tool that creates its own nested scratch tree (subdir + file) must be able to
# SEE those entries in its own directory enumerations and then recursively delete
# them - matching linux-sandbox's readable+writable execroot. Without revealing the
# process's own created scratch, the enumeration hides it: an archiver walking the
# tree produces an empty output and a recursive clean leaves a non-empty directory
# (RemoveDirectory -> ACCESS_DENIED). This is exactly JavaBuilder's _javac/*_classes
# compile -> jar -> clean flow (regression: sandbox-built jars came out corrupt).
$ewTree = Join-Path $ew 'treebase'
New-Item -ItemType Directory -Path $ewTree -Force | Out-Null
Assert-Exit 'execroot-writable: self-created scratch tree visible + deletable' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('scratchtree', $ewTree))

# CROSS-PROCESS created-set: a file created in ONE process of the tree must be
# readable / deletable by a DIFFERENT process in the same tree. This is the reason
# the created-set lives in a manifest-carried shared-memory region (not a per-process
# set): tools fork (JavaBuilder writes _javac scratch in one process and reads/cleans
# it in another). The parent probe creates the file, then spawns a separate child
# probe that reads (resp. deletes) it. Both must succeed (0); a per-process-only set
# would leave the child seeing an undeclared path -> denied (10) or hidden (11).
$ewXproc = Join-Path $ew 'xproc.tmp'          # fresh path, only used by writespawnread
Assert-Exit 'execroot-writable: cross-process read of tree-created file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) `
        @('writespawnread', $ewXproc, (Get-Probe)))
$ewXprocDel = Join-Path $ew 'xprocdel.tmp'    # fresh path, only used by writespawndelete
Assert-Exit 'execroot-writable: cross-process delete of tree-created file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) `
        @('writespawndelete', $ewXprocDel, (Get-Probe)))

# Sanity: an UNDECLARED pre-existing sibling stays hidden from enumeration even under
# --execroot-writable (only the process's OWN created entries are revealed; real
# undeclared inputs remain invisible, preserving hermeticity).
Assert-Exit 'execroot-writable: pre-existing undeclared sibling still hidden from enumeration' 11 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $ew) @('enumfind', $ew, 'a.txt'))

# Sanity: WITHOUT --execroot-writable, creating a new file in a filter-inputs
# execroot is still denied (baseline behavior unchanged).
Assert-Exit 'no execroot-writable: create new file still denied' 10 `
    (Invoke-SandboxRaw @('--filter-inputs', '-W', $ew) @('write', (Join-Path $ew 'nope.tmp')))

# --- Cleanup-on-exit: undeclared scratch discarded after the tree exits --------
# Matching linux-sandbox, which throws away its writable execroot after every
# action, the launcher deletes the undeclared files/dirs the tree created once it
# exits, so no later action (or a reduced->full classpath re-execution of the same
# Java action) inherits stale scratch. Declared -w outputs and pre-existing
# undeclared files are NOT in the created-set and must survive. Skipped under -D
# (--sandbox_debug), which keeps scratch for inspection.
$cw = New-Workspace
$cwScratch = Join-Path $cw 'scratch.tmp'   # new undeclared file (tracked scratch)
Assert-Exit 'cleanup: create undeclared scratch file allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $cw) @('write', $cwScratch))
Assert-True 'cleanup: undeclared scratch file removed after exit' `
    (-not (Test-Path $cwScratch))
Assert-True 'cleanup: pre-existing undeclared file preserved' `
    (Test-Path (Join-Path $cw 'a.txt'))

$cwDir = Join-Path $cw 'scratchdir'        # new undeclared dir (tracked scratch)
Assert-Exit 'cleanup: create undeclared scratch dir allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $cw) @('mkdir', $cwDir))
Assert-True 'cleanup: undeclared scratch dir removed after exit' `
    (-not (Test-Path $cwDir))

# Cross-process cleanup: scratch created by a SPAWNED CHILD (not the launcher's
# direct child) is recorded in the shared created-set and must be discarded on exit
# too - the launcher's cleanup is driven by the cross-process SHM region, so a
# grandchild's creations are cleaned up just like the top process's.
$cwChild = Join-Path $cw 'childscratch.tmp'
Assert-Exit 'cleanup: child-process-created scratch allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $cw) `
        @('spawn', (Get-Probe), 'write', $cwChild))
Assert-True 'cleanup: child-process-created scratch removed after exit' `
    (-not (Test-Path $cwChild))

$cwOut = Join-Path $cw 'out.declared'      # declared -w output (NOT in created-set)
Assert-Exit 'cleanup: write declared -w output allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $cw, '-w', $cwOut) @('write', $cwOut))
Assert-True 'cleanup: declared -w output preserved after exit' `
    (Test-Path $cwOut)

# Under -D (--sandbox_debug) the scratch is kept for inspection (cleanup skipped).
$cwDbg = Join-Path $cw 'dbgscratch.tmp'
$cwDbgLog = Join-Path $script:TempRoot 'cleanup-debug.out'
Assert-Exit 'cleanup: create scratch under -D allowed' 0 `
    (Invoke-SandboxRaw @('--filter-inputs', '--execroot-writable', '-W', $cw, '-D', $cwDbgLog) @('write', $cwDbg))
Assert-True 'cleanup: scratch preserved under -D (sandbox-debug)' `
    (Test-Path $cwDbg)

Complete-Harness