# Reparse-point handling. Bazel's execroot is full of junctions (external/ ->
# repo cache) and, with --windows_enable_symlinks, file symlinks. The engine is
# configured to enforce on the path AS REQUESTED rather than resolving the
# reparse target, so a declared link is allowed and an undeclared one is denied.

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
    -TempDir $TempDir -Suite 'reparse'

# --- Directory junctions (no privilege required) ---------------------------
$ws = New-Workspace
$real = Join-Path $ws 'jreal'
$exec = Join-Path $ws 'jexec'
$link = Join-Path $exec 'link'
New-Item -ItemType Directory -Force -Path $real, $exec | Out-Null
'payload' | Set-Content (Join-Path $real 'f.txt')
& (Get-CmdExe) /c mklink /J "$link" "$real" *> $null

# Reading through a junction declared with -r is allowed (the engine must not
# resolve the junction to its undeclared target).
Assert-Exit 'read through declared junction allowed' 0 `
    (Invoke-Sandbox @('-W', $exec, '-r', $link) @('read', (Join-Path $link 'f.txt')))
# Reading through an UNDECLARED junction inside a denied workdir is blocked.
Assert-Exit 'read through undeclared junction denied' 10 `
    (Invoke-Sandbox @('-W', $exec) @('read', (Join-Path $link 'f.txt')))

# --- File symlinks (require SeCreateSymbolicLinkPrivilege) ------------------
if (-not (Test-SymlinkPrivilege)) {
    Skip-Case 'file symlink enforcement' 'SeCreateSymbolicLinkPrivilege not held'
    Complete-Harness
}

$ws = New-Workspace
$target = Join-Path $ws 'target.txt'
'payload' | Set-Content $target
$linkdir = Join-Path $ws 'lnk'
New-Item -ItemType Directory -Force -Path $linkdir | Out-Null
$flink = Join-Path $linkdir 'flink.txt'
& (Get-CmdExe) /c mklink "$flink" "$target" *> $null
if (-not (Test-Path $flink)) {
    Skip-Case 'file symlink enforcement' 'symlink creation failed at runtime'
    Complete-Harness
}

# Reading through a declared file symlink is allowed - whether the symlink
# itself is the -r scope or its containing directory is.
Assert-Exit 'read declared file symlink (-r on link) allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $flink) @('read', $flink))
Assert-Exit 'read declared file symlink (-r on dir) allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $linkdir) @('read', $flink))
# An undeclared file symlink inside a denied workdir is blocked (the engine does
# not resolve it to its declared/undeclared target).
Assert-Exit 'read undeclared file symlink denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('read', $flink))
# Writing through a declared -w file symlink is allowed.
Assert-Exit 'write declared file symlink (-w on link) allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $flink) @('write', $flink))

# --- Directory symlinks (mklink /D, distinct from a junction) ---------------
# A directory symlink differs from a junction (different reparse tag and, unlike
# a junction, requires the privilege). The engine must treat it the same way:
# enforce on the requested path, not the resolved target.
$ws = New-Workspace
$realdir = Join-Path $ws 'realdir'
New-Item -ItemType Directory -Force -Path $realdir | Out-Null
'payload' | Set-Content (Join-Path $realdir 'f.txt')
$dlink = Join-Path $ws 'dlink'
& (Get-CmdExe) /c mklink /D "$dlink" "$realdir" *> $null
if (Test-Path $dlink) {
    Assert-Exit 'read through declared dir symlink (-r on link) allowed' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', $dlink) @('read', (Join-Path $dlink 'f.txt')))
    Assert-Exit 'read through undeclared dir symlink denied' 10 `
        (Invoke-Sandbox @('-W', $ws) @('read', (Join-Path $dlink 'f.txt')))
    Assert-Exit 'write through declared dir symlink (-w on link) allowed' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $dlink) @('write', (Join-Path $dlink 'g.txt')))
} else {
    Skip-Case 'directory symlink enforcement' 'dir symlink creation failed at runtime'
}

Complete-Harness
