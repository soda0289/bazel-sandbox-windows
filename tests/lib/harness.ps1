# Shared harness for the BazelSandbox enforcement test scripts. Each category
# script under tests/enforce/ dot-sources this file, calls Initialize-Harness
# with the binary paths, runs its cases, and ends with Complete-Harness.
#
# The harness intentionally avoids any external test framework: every case is
# "run the launcher, assert the child's integer exit code". probe exit codes:
#   0  = allowed        20 = other error      40 = bad std handle
#   10 = denied         30 = bad usage        50 = harness error
#   11 = not-found (path reported absent; --filter-inputs masks denied reads so)
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

# Resolves a binary path argument. Under Bazel it is given a runfiles
# rlocationpath (e.g. "_main/tests/probe.exe") that must be resolved against the
# runfiles tree the launcher stub exported (RUNFILES_DIR / RUNFILES_MANIFEST_FILE).
# An absolute path that already exists is returned as-is.
function Resolve-PathArg {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    # Absolute path that already exists.
    if (Test-Path -LiteralPath $Path) { return (Resolve-Path -LiteralPath $Path).Path }
    # Bazel runfiles directory layout.
    if ($env:RUNFILES_DIR) {
        $cand = Join-Path $env:RUNFILES_DIR $Path
        if (Test-Path -LiteralPath $cand) { return (Resolve-Path -LiteralPath $cand).Path }
    }
    # Bazel runfiles manifest (used when no symlink tree is materialized).
    if ($env:RUNFILES_MANIFEST_FILE -and (Test-Path $env:RUNFILES_MANIFEST_FILE)) {
        foreach ($line in Get-Content $env:RUNFILES_MANIFEST_FILE) {
            $idx = $line.IndexOf(' ')
            if ($idx -gt 0 -and $line.Substring(0, $idx) -eq $Path) {
                return $line.Substring($idx + 1)
            }
        }
    }
    return $Path
}

function Initialize-Harness {
    param(
        [Parameter(Mandatory)][string]$Sandbox,
        [Parameter(Mandatory)][string]$Probe,
        [string]$StdioLauncher,
        [string]$TempDir,
        [Parameter(Mandatory)][string]$Suite
    )
    $script:SbExe = Resolve-PathArg $Sandbox
    $script:ProbeExe = Resolve-PathArg $Probe
    $script:StdioExe = if ($StdioLauncher) { Resolve-PathArg $StdioLauncher } else { $null }
    # Under `bazel test` no -TempDir is passed; use the test's private scratch dir.
    if ([string]::IsNullOrEmpty($TempDir)) {
        $base = if ($env:TEST_TMPDIR) { $env:TEST_TMPDIR } else { [System.IO.Path]::GetTempPath() }
        $TempDir = Join-Path $base 'sbx'
    }
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

# Absolute path to cmd.exe, resolved from the OS system directory (via the
# GetSystemDirectory API, which is env-independent) rather than via PATH.
# Under `bazel test` the environment is scrubbed: a bare `cmd` that PATH cannot
# resolve makes PowerShell fall back to ShellExecute("cmd"), which - with no
# path and no association - pops a modal "Select an app to run 'cmd'" dialog
# that blocks the test until it times out.
function Get-CmdExe {
    if ($env:ComSpec -and (Test-Path -LiteralPath $env:ComSpec)) { return $env:ComSpec }
    return (Join-Path ([Environment]::SystemDirectory) 'cmd.exe')
}

# Runs the launcher: BazelSandbox <SandboxArgs> -- <Probe> <ProbeArgs>.
# Returns the child's exit code. A local Continue preference keeps legitimate
# launcher stderr (e.g. the -T timeout message) from surfacing as a terminating
# NativeCommandError under a caller's 'Stop' preference.
function Invoke-Sandbox {
    param([string[]]$SandboxArgs = @(), [string[]]$ProbeArgs = @())
    $ErrorActionPreference = 'Continue'
    # The enforcement suites validate the deny+grant machinery, which only applies
    # inside the working dir under HERMETIC mode. The sandbox now defaults to
    # permissive reads (linux-sandbox parity), so these suites force -H to exercise
    # enforcement. Mode-distinction tests use Invoke-SandboxRaw (no implicit -H).
    $all = @('-H') + @($SandboxArgs) + @('--', $script:ProbeExe) + @($ProbeArgs)
    & $script:SbExe @all *> $null
    return $LASTEXITCODE
}

# Like Invoke-Sandbox but passes NO implicit -H, so callers control the read mode
# explicitly. Used by the modes suite to contrast permissive (default) vs -H.
function Invoke-SandboxRaw {
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
# lets a non-elevated process create symlinks). Mirrors a typical local-dev
# Windows filesystem-support check.
function Test-SymlinkPrivilege {
    try {
        return [bool](& (Join-Path ([Environment]::SystemDirectory) 'whoami.exe') /priv 2>$null |
            Select-String -SimpleMatch 'SeCreateSymbolicLinkPrivilege')
    } catch { return $false }
}

# Prints the summary, cleans the temp root, and exits 0 (all passed) or 1.
#
# Uses [Environment]::Exit rather than `exit`: rules_powershell's
# process_wrapper.ps1 invokes this script via the call operator (`& $mainPath`)
# inside a try/finally, and a plain `exit N` from an &-invoked script only sets
# $LASTEXITCODE in the caller - it does NOT become the process exit code, so the
# wrapper always returns 0 and every failing test is reported as PASS. A hard
# CLR process exit forces the real code out through the wrapper. (Cleanup above
# already ran; the wrapper skips its own runfiles cleanup under `bazel test`.)
function Complete-Harness {
    Remove-Item -Recurse -Force $script:TempRoot -ErrorAction SilentlyContinue
    $summary = "$script:Passed passed, $script:Failed failed, $script:Skipped skipped"
    if ($script:Failed -gt 0) {
        Write-Host "== FAILED: $summary =="
        [Environment]::Exit(1)
    }
    Write-Host "== OK: $summary =="
    [Environment]::Exit(0)
}
