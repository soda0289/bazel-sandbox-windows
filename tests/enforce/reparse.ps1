# Reparse-point handling. Bazel's execroot is full of junctions (external/ ->
# repo cache) and, with --windows_enable_symlinks, file symlinks. Enforcement is
# a hybrid:
#   1. The path AS REQUESTED is checked first, so a link declared with -r/-w is
#      allowed by its own grant without ever resolving the reparse target.
#   2. If the requested path is denied, a handle-resolution fallback resolves the
#      final target (DetourGetFinalPathByHandle) and re-checks THAT against the
#      policy. So an undeclared link is allowed iff its resolved target is itself
#      a DECLARED input (-r/-w granted, as with pnpm intra-store junctions), and
#      denied iff the resolved target lands in a denied region OR is only readable
#      via the whole-filesystem root baseline (not a declared input). This is the
#      mechanism that lets undeclared-but-legitimate junctions work without name-
#      based cones; see docs/sandbox-parity-findings.md (Category A: pnpm junctions).

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
# Target lives INSIDE the -W deny scope so "denied region" cases are meaningful;
# a separate grant subdir exercises the handle-resolution allow path.
$ws = New-Workspace
$exec = Join-Path $ws 'jexec'          # the -W deny scope
$real = Join-Path $exec 'jreal'        # junction target, inside the deny scope
$grant = Join-Path $exec 'jgrant'      # a separately -r-granted target
$link = Join-Path $exec 'link'
$glink = Join-Path $exec 'glink'
New-Item -ItemType Directory -Force -Path $real, $grant | Out-Null
'payload' | Set-Content (Join-Path $real 'f.txt')
'payload' | Set-Content (Join-Path $grant 'f.txt')
& (Get-CmdExe) /c mklink /J "$link" "$real" *> $null
& (Get-CmdExe) /c mklink /J "$glink" "$grant" *> $null

# A junction whose LINK path is declared with -r is allowed by the path-as-
# requested check, without resolving the target.
Assert-Exit 'read through declared junction (-r on link) allowed' 0 `
    (Invoke-Sandbox @('-W', $exec, '-r', $link) @('read', (Join-Path $link 'f.txt')))
# Handle-resolution: an UNDECLARED junction whose resolved target is itself
# -r-granted is allowed (this is the pnpm intra-store junction case).
Assert-Exit 'read through undeclared junction to -r-granted target allowed' 0 `
    (Invoke-Sandbox @('-W', $exec, '-r', $grant) @('read', (Join-Path $glink 'f.txt')))
# Handle-resolution: an undeclared junction whose resolved target sits in a
# denied region is still blocked (the fallback re-checks the real target).
Assert-Exit 'read through undeclared junction to denied target denied' 10 `
    (Invoke-Sandbox @('-W', $exec) @('read', (Join-Path $link 'f.txt')))
# Handle-less stat parity (GetFileInformationByName, libuv's fast fs.stat path).
# The mid-path junction is undeclared, so the literal-path probe is denied; the
# handle-resolution PROBE fallback opens a transient handle that follows the
# junction and re-checks the resolved target. A stat through an undeclared
# junction to an -r-granted target must be ALLOWED (matches the read fallback and
# linux-sandbox, where the forest lets stat follow the link). Without this a tool
# that stats before opening (node/libuv ESM resolution) would see the file as
# absent even though its content is readable. See docs/design/detours-input-filtering.md.
Assert-Exit 'statbyname through undeclared junction to -r-granted target allowed' 0 `
    (Invoke-Sandbox @('-W', $exec, '-r', $grant) @('statbyname', (Join-Path $glink 'f.txt')))
# A stat through an undeclared junction to a denied target stays blocked (the
# probe fallback re-checks the real target, so hermeticity is preserved).
Assert-Exit 'statbyname through undeclared junction to denied target denied' 10 `
    (Invoke-Sandbox @('-W', $exec) @('statbyname', (Join-Path $link 'f.txt')))
# An undeclared junction whose target resolves OUTSIDE every -W deny scope, and is
# therefore readable ONLY via the whole-filesystem root baseline (not a declared
# input), is DENIED. The handle-resolution fallback rescues a link only when its
# resolved target is a declared input (an exact manifest node); a target that would
# merely be allowed by the catch-all root AllowRead scope stays masked. This matches
# hermetic linux-sandbox / RBE, where only declared inputs are present in the input
# root. It is also what prevents the bazel execroot symlink (execroot/_main -> the
# real source tree) from leaking undeclared source files whose in-execroot path is
# denied but which resolve to a root-readable location. (Previously a Category-B gap
# that allowed such reads; now closed. See docs/design/detours-input-filtering.md.)
$ws2 = New-Workspace
$outside = Join-Path $ws2 'outside'
$exec2 = Join-Path $ws2 'exec'
New-Item -ItemType Directory -Force -Path $outside, $exec2 | Out-Null
'payload' | Set-Content (Join-Path $outside 'f.txt')
$olink = Join-Path $exec2 'olink'
& (Get-CmdExe) /c mklink /J "$olink" "$outside" *> $null
Assert-Exit 'read through undeclared junction to root-baseline-only target denied' 10 `
    (Invoke-Sandbox @('-W', $exec2) @('read', (Join-Path $olink 'f.txt')))

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
# An undeclared file symlink is blocked because its resolved target ($target)
# sits inside the -W deny scope with no -r grant (handle-resolution re-check).
Assert-Exit 'read undeclared file symlink (denied target) denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('read', $flink))
# Writing through a declared -w file symlink is allowed.
Assert-Exit 'write declared file symlink (-w on link) allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $flink) @('write', $flink))

# --- Directory symlinks (mklink /D, distinct from a junction) ---------------
# A directory symlink differs from a junction (different reparse tag and, unlike
# a junction, requires the privilege). Enforcement is the same hybrid: the
# requested path is checked first, then handle-resolution re-checks the target.
$ws = New-Workspace
$realdir = Join-Path $ws 'realdir'
New-Item -ItemType Directory -Force -Path $realdir | Out-Null
'payload' | Set-Content (Join-Path $realdir 'f.txt')
$dlink = Join-Path $ws 'dlink'
& (Get-CmdExe) /c mklink /D "$dlink" "$realdir" *> $null
if (Test-Path $dlink) {
    Assert-Exit 'read through declared dir symlink (-r on link) allowed' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', $dlink) @('read', (Join-Path $dlink 'f.txt')))
    # Denied because the resolved target ($realdir) is inside the -W deny scope.
    Assert-Exit 'read through undeclared dir symlink (denied target) denied' 10 `
        (Invoke-Sandbox @('-W', $ws) @('read', (Join-Path $dlink 'f.txt')))
    Assert-Exit 'write through declared dir symlink (-w on link) allowed' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $dlink) @('write', (Join-Path $dlink 'g.txt')))
} else {
    Skip-Case 'directory symlink enforcement' 'dir symlink creation failed at runtime'
}

Complete-Harness
