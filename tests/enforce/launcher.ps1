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

# -D / --trace debugging aids. -D writes launcher diagnostics (UTF-8); --trace
# turns on the DLL's report channel and writes a per-access report. Neither
# changes enforcement: the allowed read still succeeds (exit 0).
$ws = New-Workspace
$dbgFile   = Join-Path $ws 'debug.log'
$traceFile = Join-Path $ws 'trace.txt'
$aTxt      = Join-Path $ws 'a.txt'
Assert-Exit '-D/--trace: allowed read still succeeds' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-D', $dbgFile, '--trace', $traceFile) @('read', $aTxt))
Assert-True '-D wrote a non-empty debug log' `
    ((Test-Path $dbgFile) -and (Get-Item $dbgFile).Length -gt 0)
Assert-True '-D debug log records the child exit code' `
    ((Get-Content $dbgFile -Raw) -match 'child exit code: 0')
Assert-True '--trace wrote a non-empty access report' `
    ((Test-Path $traceFile) -and (Get-Item $traceFile).Length -gt 0)
# The report is UTF-16LE (no BOM); decode explicitly and confirm it recorded the
# access to the file we read.
$traceText = [System.Text.Encoding]::Unicode.GetString([System.IO.File]::ReadAllBytes($traceFile))
Assert-True '--trace report references the read file' ($traceText -match 'a\.txt')

# -S writes child resource-usage statistics as a tools.protos.ExecutionStatistics
# protobuf (linux-sandbox parity). Enforcement is unchanged (allowed read exits 0),
# and the file must be a well-formed message: it starts with the length-delimited
# resource_usage field (tag 0x0A) whose declared length matches the payload.
$ws = New-Workspace
$statsFile = Join-Path $ws 'stats.pb'
$aTxt      = Join-Path $ws 'a.txt'
Assert-Exit '-S: allowed read still succeeds' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-S', $statsFile) @('read', $aTxt))
Assert-True '-S wrote a non-empty stats file' `
    ((Test-Path $statsFile) -and (Get-Item $statsFile).Length -gt 0)
$statsBytes = [System.IO.File]::ReadAllBytes($statsFile)
Assert-True '-S stats start with resource_usage field tag (0x0A)' `
    ($statsBytes.Length -ge 2 -and $statsBytes[0] -eq 0x0A)
# The nested-message length is a single-byte varint here; verify framing is exact.
Assert-True '-S stats nested length matches payload size' `
    ($statsBytes[1] -lt 0x80 -and ($statsBytes.Length - 2) -eq $statsBytes[1])

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

# --- BuildChildCommandLine: child argument round-trip (two Windows regimes) -----
# The launcher rebuilds the child's command-line STRING from its parsed argv,
# matching Bazel's WindowsSubprocessFactory.escapeArgvRest: every tool but cmd.exe
# gets CommandLineToArgvW-style escaping (a space-bearing token stays ONE argument),
# while cmd.exe gets its tail VERBATIM (real quotes preserved, since cmd does not
# understand \"). A regression here corrupts quoted paths (the zlib "copy" bug).
# Response files give byte-exact control of the parsed argv (one token per line),
# so these assertions do not depend on the host shell's own quoting.
$ws = New-Workspace

# Escaped regime: a token containing a space must reach the child intact as a
# single argument, so echoargs prints exactly two lines ("a b", then "c").
$outEsc = Join-Path $ws 'echo_escaped.txt'
$rspEsc = Join-Path $ws 'escaped.rsp'
@('-W', $ws, '-l', $outEsc, '--', (Get-Probe), 'echoargs', 'a b', 'c') |
    Set-Content -Encoding Ascii $rspEsc
$ErrorActionPreference = 'Continue'
& (Get-Sandbox) "@$rspEsc" *> $null
$rcEsc = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-Exit 'escaped regime: echoargs child succeeded' 0 $rcEsc
$escLines = @()
if (Test-Path $outEsc) {
    $escLines = (Get-Content $outEsc) | Where-Object { $_ -ne '' }
}
Assert-True 'escaped regime: space-bearing arg stays ONE token' `
    ($escLines.Count -eq 2 -and $escLines[0] -eq 'a b' -and $escLines[1] -eq 'c')

# Verbatim regime: cmd.exe receives its tail unescaped, so real quotes survive and
# `echo "a b"` prints the quotes literally (no backslash escaping was injected).
$outCmd = Join-Path $ws 'echo_cmd.txt'
$rspCmd = Join-Path $ws 'cmd.rsp'
@('-W', $ws, '-l', $outCmd, '--', 'cmd.exe', '/c', 'echo "a b"') |
    Set-Content -Encoding Ascii $rspCmd
$ErrorActionPreference = 'Continue'
& (Get-Sandbox) "@$rspCmd" *> $null
$rcCmd = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
Assert-Exit 'verbatim regime: cmd.exe child succeeded' 0 $rcCmd
$cmdOut = ''
if (Test-Path $outCmd) { $cmdOut = (Get-Content $outCmd -Raw).Trim() }
Assert-True 'verbatim regime: cmd.exe quotes preserved (no re-escaping)' `
    ($cmdOut -eq '"a b"')

Complete-Harness
