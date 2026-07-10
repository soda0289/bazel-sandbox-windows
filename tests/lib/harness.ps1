# Shared harness for the BazelSandbox enforcement test scripts. Each category
# script under tests/enforce/ dot-sources this file, calls Initialize-Harness
# with the binary paths, runs its cases, and ends with Complete-Harness.
#
# The harness intentionally avoids any external test framework: every case is
# "run the launcher, assert the child's integer exit code". probe exit codes:
#   0  = allowed        20 = other error      40 = bad std handle
#   10 = denied         30 = bad usage        50 = harness error
#
# Fresh-workspace setup/teardown is provided by New-Workspace (a unique seeded
# directory per call, i.e. per-case isolation) plus a single cleanup of the
# whole temp root in Complete-Harness.

Set-StrictMode -Version Latest

# Internal state uses distinct names so dot-sourcing this file cannot clobber a
# category script's own $Sandbox/$Probe/$StdioLauncher parameters (they share
# the script scope).
$script:SbExe = $null
$script:ProbeExe = $null
$script:StdioExe = $null
$script:TempRoot = $null
$script:Passed = 0
$script:Failed = 0
$script:Skipped = 0

function Initialize-Harness {
    param(
        [Parameter(Mandatory)][string]$Sandbox,
        [Parameter(Mandatory)][string]$Probe,
        [string]$StdioLauncher,
        [Parameter(Mandatory)][string]$TempDir,
        [Parameter(Mandatory)][string]$Suite
    )
    $script:SbExe = $Sandbox
    $script:ProbeExe = $Probe
    $script:StdioExe = $StdioLauncher
    $script:TempRoot = $TempDir
    $script:Passed = 0
    $script:Failed = 0
    $script:Skipped = 0
    if (Test-Path $TempDir) { Remove-Item -Recurse -Force $TempDir }
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    Write-Host "== $Suite =="
}

# Expose the discovered binaries to category scripts that need them directly
# (e.g. to pass the probe path as a spawn target).
function Get-Probe { return $script:ProbeExe }
function Set-Probe { param([string]$Path) $script:ProbeExe = $Path }
function Get-Sandbox { return $script:SbExe }
function Get-StdioLauncher { return $script:StdioExe }

# Runs the launcher: BazelSandbox <SandboxArgs> -- <Probe> <ProbeArgs>.
# Returns the child's exit code. A local Continue preference keeps legitimate
# launcher stderr (e.g. the -T timeout message) from surfacing as a terminating
# NativeCommandError under a caller's 'Stop' preference.
function Invoke-Sandbox {
    param([string[]]$SandboxArgs = @(), [string[]]$ProbeArgs = @())
    $ErrorActionPreference = 'Continue'
    $all = @($SandboxArgs) + @('--', $script:ProbeExe) + @($ProbeArgs)
    & $script:SbExe @all *> $null
    return $LASTEXITCODE
}

# Asserts the observed exit code equals the expected one.
function Assert-Exit {
    param([string]$Name, [int]$Expected, [int]$Actual)
    if ($Expected -eq $Actual) {
        Write-Host ("  PASS  {0,-50} (exit {1})" -f $Name, $Actual)
        $script:Passed++
    } else {
        Write-Host ("  FAIL  {0,-50} expected {1}, got {2}" -f $Name, $Expected, $Actual)
        $script:Failed++
    }
}

# Asserts a boolean condition (for non-exit-code checks, e.g. file contents).
function Assert-True {
    param([string]$Name, [bool]$Condition)
    if ($Condition) {
        Write-Host ("  PASS  {0,-50}" -f $Name)
        $script:Passed++
    } else {
        Write-Host ("  FAIL  {0,-50} condition was false" -f $Name)
        $script:Failed++
    }
}

# Records an environment-dependent observation without affecting pass/fail.
function Note-Exit {
    param([string]$Name, [int]$Actual, [string]$Note = '')
    Write-Host ("  NOTE  {0,-50} (exit {1}) {2}" -f $Name, $Actual, $Note)
}

# Records that a case was skipped (e.g. a required OS capability is missing).
function Skip-Case {
    param([string]$Name, [string]$Reason)
    Write-Host ("  SKIP  {0,-50} ({1})" -f $Name, $Reason)
    $script:Skipped++
}

# Creates a unique, freshly seeded workspace directory and returns its path.
# Calling this per case gives before-each isolation; Complete-Harness removes
# the whole temp root afterwards (after-all teardown). The seed layout is:
#   a.txt, src.txt, seed.txt (content), keep.txt (empty), sub/ (empty dir).
function New-Workspace {
    $ws = Join-Path $script:TempRoot ([guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force -Path $ws | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $ws 'sub') | Out-Null
    'x' | Set-Content (Join-Path $ws 'a.txt')
    'x' | Set-Content (Join-Path $ws 'src.txt')
    'seed-data' | Set-Content (Join-Path $ws 'seed.txt')
    '' | Set-Content (Join-Path $ws 'keep.txt')
    return $ws
}

# True if the current token holds SeCreateSymbolicLinkPrivilege (the right that
# lets a non-elevated process create symlinks). Mirrors the check in fusion's
# localdev/check-windows-filesystem-support.ps1.
function Test-SymlinkPrivilege {
    try {
        return [bool](& whoami /priv 2>$null |
            Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege')
    } catch { return $false }
}

# Prints the summary, cleans the temp root, and exits 0 (all passed) or 1.
function Complete-Harness {
    Remove-Item -Recurse -Force $script:TempRoot -ErrorAction SilentlyContinue
    $summary = "$script:Passed passed, $script:Failed failed, $script:Skipped skipped"
    if ($script:Failed -gt 0) {
        Write-Host "== FAILED: $summary =="
        exit 1
    }
    Write-Host "== OK: $summary =="
    exit 0
}
