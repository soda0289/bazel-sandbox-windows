# Scope model: read-only root, blocked working directory, -r/-w/-b precedence,
# single-file scopes, and child-process propagation of the file policy.

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
    -TempDir $TempDir -Suite 'scopes'

# Whole filesystem is read-only by default: reading the probe binary is allowed.
Assert-Exit 'read allowed on read-only root' 0 (Invoke-Sandbox @() @('read', (Get-Probe)))

$ws = New-Workspace
# Working directory is denied by default.
Assert-Exit 'write to blocked workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('write', (Join-Path $ws 'out.txt')))
Assert-Exit 'read in blocked workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('read', (Join-Path $ws 'seed.txt')))
# -r re-enables reads; -w re-enables writes.
Assert-Exit '-r allows read in workdir' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('read', (Join-Path $ws 'seed.txt')))

$ws = New-Workspace
$okFile = Join-Path $ws 'ok.txt'
Assert-Exit '-w allows write in workdir' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('write', $okFile))
Assert-True '-w write actually created the file' (Test-Path $okFile)

# A read-only (-r) scope is truly read-only: it permits reads but denies every
# mutation. This is exactly what distinguishes -r from -w, and guards against a
# rewrite accidentally granting write access through a read scope.
$ws = New-Workspace
Assert-Exit '-r denies write'  10 (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('write',  (Join-Path $ws 'n.txt')))
Assert-Exit '-r denies delete' 10 (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('delete', (Join-Path $ws 'src.txt')))
Assert-Exit '-r denies mkdir'  10 (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('mkdir',  (Join-Path $ws 'nd')))
Assert-Exit '-r denies rename' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('rename', (Join-Path $ws 'src.txt'), (Join-Path $ws 'd.txt')))

# -b overrides an enclosing -w for a specific file; siblings stay writable.
$ws = New-Workspace
Assert-Exit '-b file override inside -w dir denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws, '-b', (Join-Path $ws 'keep.txt')) `
        @('write', (Join-Path $ws 'keep.txt')))
Assert-Exit '-w sibling still writable' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws, '-b', (Join-Path $ws 'keep.txt')) `
        @('write', (Join-Path $ws 'other.txt')))

# -b makes a path fully inaccessible: it blocks reads too, not just writes.
$ws = New-Workspace
Assert-Exit '-b blocks read of blocked file' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-b', (Join-Path $ws 'a.txt')) `
        @('read', (Join-Path $ws 'a.txt')))
Assert-Exit '-b sibling still readable under -r' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-b', (Join-Path $ws 'a.txt')) `
        @('read', (Join-Path $ws 'src.txt')))

# A single-FILE -r grants exactly that file, not its siblings.
$ws = New-Workspace
Assert-Exit 'single-file -r allows that file' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', (Join-Path $ws 'a.txt')) @('read', (Join-Path $ws 'a.txt')))
Assert-Exit 'single-file -r denies siblings' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', (Join-Path $ws 'a.txt')) @('read', (Join-Path $ws 'src.txt')))

# Nested precedence: a more-specific -w child overrides a -r parent.
$ws = New-Workspace
Assert-Exit '-w child overrides -r parent (write allowed)' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', (Join-Path $ws 'sub')) `
        @('write', (Join-Path $ws 'sub\new.txt')))
Assert-Exit '-r parent stays read-only outside -w child' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', (Join-Path $ws 'sub')) `
        @('write', (Join-Path $ws 'top.txt')))

# Case-insensitive scope matching (path-hash normalization guard).
$ws = New-Workspace
Assert-Exit 'case-insensitive -r scope match' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws.ToUpper()) @('read', (Join-Path $ws 'a.txt')))

# Child-process propagation: the policy survives process hops (probe -> probe).
$ws = New-Workspace
Assert-Exit 'child-process propagation denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('spawn', (Get-Probe), 'write', (Join-Path $ws 'child.txt')))
Assert-Exit 'depth-3 propagation write denied' 10 `
    (Invoke-Sandbox @('-W', $ws) `
        @('spawn', (Get-Probe), 'spawn', (Get-Probe), 'write', (Join-Path $ws 'deep.txt')))

# Multiple disjoint scopes on one invocation each take effect independently; a
# path in none of them stays denied (exercises several branches of the policy
# tree, not just a single nested chain).
$ws = New-Workspace
$d1 = Join-Path $ws 'one'; $d2 = Join-Path $ws 'two'; $d3 = Join-Path $ws 'three'
New-Item -ItemType Directory -Force -Path $d1, $d2, $d3 | Out-Null
'x' | Set-Content (Join-Path $d1 'f.txt'); 'x' | Set-Content (Join-Path $d2 'f.txt')
'x' | Set-Content (Join-Path $d3 'f.txt')
Assert-Exit 'first of two -r scopes readable'  0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $d1, '-r', $d2) @('read', (Join-Path $d1 'f.txt')))
Assert-Exit 'second of two -r scopes readable' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $d1, '-r', $d2) @('read', (Join-Path $d2 'f.txt')))
Assert-Exit 'path in neither -r scope denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $d1, '-r', $d2) @('read', (Join-Path $d3 'f.txt')))

Complete-Harness
