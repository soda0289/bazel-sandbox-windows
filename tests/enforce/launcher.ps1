# Launcher features Bazel depends on: exact exit-code forwarding, -W working
# directory, -T timeout, @response-file expansion, -l/-L stdout/stderr
# redirection, relative-path scope resolution, and the std-handle repair that a
# Bazel-style launch requires.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Sandbox,
    [Parameter(Mandatory)][string]$Probe,
    [Parameter(Mandatory)][string]$StdioLauncher,
    [string]$TempDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\harness.ps1')
Initialize-Harness -Sandbox $Sandbox -Probe $Probe -StdioLauncher $StdioLauncher `
    -TempDir $TempDir -Suite 'launcher'

$ws = New-Workspace

# Exit-code fidelity: the launcher forwards the child's exact exit code (Bazel
# keys action success/failure off this).
Assert-Exit 'exit code forwarded (7)'   7   (Invoke-Sandbox @('-W', $ws) @('exit', '7'))
Assert-Exit 'exit code forwarded (213)' 213 (Invoke-Sandbox @('-W', $ws) @('exit', '213'))

# -W sets the child's current directory.
Assert-Exit '-W sets child working directory' 0 (Invoke-Sandbox @('-W', $ws) @('cwdis', $ws))

# -T terminates a long-running child (exit 1); a short child under a generous
# timeout completes normally.
Assert-Exit '-T timeout kills long child' 1 (Invoke-Sandbox @('-W', $ws, '-T', '1') @('sleep', '10000'))
Assert-Exit '-T generous timeout lets child finish' 0 (Invoke-Sandbox @('-W', $ws, '-T', '30') @('sleep', '200'))

# -t adds a grace period between the -T timeout and the force-kill. Two observable
# behaviors: (1) with a child that keeps running, the kill is delayed by roughly
# the grace period (vs. an immediate kill without -t); (2) the launcher does not
# block for the full grace period if the child exits during it. Exit is 1 in both
# cases (the timeout fired). Thresholds are coarse to stay deterministic.
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$rc = Invoke-Sandbox @('-W', $ws, '-T', '1', '-t', '3') @('sleep', '30000')
$sw.Stop()
Assert-Exit '-t grace: still force-killed after timeout+grace' 1 $rc
Assert-True '-t grace delayed the kill (>=2.5s elapsed)' ($sw.Elapsed.TotalSeconds -ge 2.5)
Assert-True '-t grace did not wait the child out (<20s elapsed)' ($sw.Elapsed.TotalSeconds -lt 20)

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$rc = Invoke-Sandbox @('-W', $ws, '-T', '1', '-t', '30') @('sleep', '2500')
$sw.Stop()
Assert-Exit '-t grace: child exits during grace, timeout still reported' 1 $rc
Assert-True '-t grace returns early on child exit (<15s elapsed)' ($sw.Elapsed.TotalSeconds -lt 15)

# @response-file expansion: options read from a file are applied (Bazel passes
# arguments this way via params files).
$rsp = Join-Path $ws 'args.rsp'
@('-W', $ws, '-r', $ws) | Set-Content -Encoding Ascii $rsp
Assert-Exit '@response-file applies -r scope' 0 `
    (Invoke-Sandbox @("@$rsp") @('read', (Join-Path $ws 'a.txt')))
@('-W', $ws) | Set-Content -Encoding Ascii $rsp
Assert-Exit '@response-file without -r keeps deny' 10 `
    (Invoke-Sandbox @("@$rsp") @('read', (Join-Path $ws 'a.txt')))

# Relative scope paths resolve against the launcher's current directory.
Push-Location $ws
try {
    Assert-Exit 'relative -r scope resolves to launcher cwd' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', 'a.txt') @('read', (Join-Path $ws 'a.txt')))
} finally { Pop-Location }

# -l / -L route the child's stdout/stderr to the given files (non-Bazel path).
$ws = New-Workspace
$lOut = Join-Path $ws 'l_out.txt'
$lErr = Join-Path $ws 'l_err.txt'
Assert-Exit '-l/-L stdio child succeeded' 0 (Invoke-Sandbox @('-l', $lOut, '-L', $lErr) @('stdio'))
Assert-True '-l/-L captured child stdout+stderr' (
    (Test-Path $lOut) -and ((Get-Content $lOut -Raw) -eq 'o') -and
    (Test-Path $lErr) -and ((Get-Content $lErr -Raw) -eq 'e'))

# Std-handle repair (regression). When Bazel drives the launcher it uses
# STARTF_USESTDHANDLES with inheritable stdout/stderr but no stdin; the launcher
# must repair the missing stdin so the sandboxed child gets three usable
# handles. stdio_launcher reproduces that exact launch.
$scratch = Join-Path $ws 'stdio_out.txt'
$ErrorActionPreference = 'Continue'
& (Get-StdioLauncher) (Get-Sandbox) (Get-Probe) $scratch *> $null
$rc = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-Exit 'std handles valid under Bazel-style launch' 0 $rc

# Cross-bitness guard. The x64 hook DLL cannot be injected into a non-x64 child,
# so the launcher refuses such a target UP FRONT (exit 3) - it reads the target's
# PE machine type and never spawns it, so there is no injection and no blocking
# hard-error dialog. Uses a 32-bit system binary; skipped on hosts without one
# (e.g. non-x64 Windows). The target is not the probe, so invoke the launcher
# directly.
$w32 = Join-Path (Split-Path ([Environment]::SystemDirectory) -Parent) 'SysWOW64\whoami.exe'
if (Test-Path $w32) {
    $ErrorActionPreference = 'Continue'
    & (Get-Sandbox) '-W' $ws '--' $w32 *> $null
    $rcBit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    Assert-Exit 'non-x64 target refused before spawn (exit 3)' 3 $rcBit
} else {
    Skip-Case 'cross-bitness guard' 'no 32-bit system binary (SysWOW64 absent)'
}

# CLI error contract. These target the launcher itself (not the probe), so invoke
# it directly. A nonexistent target exe fails the spawn (exit 2); an empty command
# after -- and an unknown flag are usage errors (exit 1). Bazel relies on these
# being distinct, non-zero, and never hanging.
$ErrorActionPreference = 'Continue'
& (Get-Sandbox) '-W' $ws '--' (Join-Path $ws 'does-not-exist.exe') *> $null
$rcMissing = $LASTEXITCODE
& (Get-Sandbox) '-W' $ws '--' *> $null
$rcNoCmd = $LASTEXITCODE
& (Get-Sandbox) '-Z' '-W' $ws '--' (Get-Probe) 'read' (Get-Probe) *> $null
$rcBadFlag = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-Exit 'nonexistent target exe fails spawn (exit 2)' 2 $rcMissing
Assert-Exit 'no command after -- is a usage error (exit 1)' 1 $rcNoCmd
Assert-Exit 'unknown flag rejected (exit 1)' 1 $rcBadFlag

Complete-Harness
