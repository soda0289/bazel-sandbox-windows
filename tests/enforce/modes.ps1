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
Assert-Exit 'permissive: absent read inside -W reports not-found' 20 `
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

Complete-Harness
