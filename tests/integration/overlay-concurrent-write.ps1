<#
.SYNOPSIS
    Regression test: two concurrent sandbox actions writing the SAME fixed-name
    undeclared scratch file into the same in-place execroot must both succeed,
    because each action gets its own process-private write overlay.

.DESCRIPTION
    This reproduces, at the sandbox layer, the historical "goyacc y.output"
    collision. `windows-sandbox` runs in place in one shared, persistent execroot
    (unlike linux-sandbox's per-action throwaway copy). goyacc (and tools like it)
    write a FIXED-NAME undeclared scratch file - `y.output` - into the execroot
    root. Under the old per-action created-set model, two actions racing on that
    same path collided: while action A held its `y.output`, concurrent action B saw
    the file already on disk, absent from B's created-set, and the no-clobber guard
    denied it with ERROR_ACCESS_DENIED ("open y.output: Access is denied").

    The write-overlay model fixes this structurally: Bazel's
    WindowsSandboxedSpawnRunner creates a unique per-action temp dir and derives the
    overlay backing store from it (overlayDir = <action-temp>/overlay), so every
    action redirects its undeclared writes into a PRIVATE overlay. Two actions
    writing the same fixed path can no longer collide, and the real execroot is
    never mutated. This test asserts exactly that, deterministically (it forces the
    two invocations to overlap), without needing the full goyacc/gazelle repo.

    Unlike sandbox-strategy-smoke.ps1, this drives BazelSandbox.exe DIRECTLY and
    does NOT need a patched Bazel or network access.

.PARAMETER Sandbox
    Path to BazelSandbox.exe (with DetoursServices.dll beside it). Defaults to the
    repo's bazel-bin\BazelSandbox.exe.

.PARAMETER KeepArtifacts
    Keep the temp execroot/overlays instead of cleaning them up.

.EXAMPLE
    pwsh tests/integration/overlay-concurrent-write.ps1

.NOTES
    Exit codes: 0 = all assertions passed, 1 = an assertion failed,
    2 = missing prerequisite (sandbox binary / dll).
#>
[CmdletBinding()]
param(
    [string]$Sandbox,
    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:Passed = 0
$script:Failed = 0
function Pass { param([string]$Name) Write-Host ("  PASS  {0}" -f $Name); $script:Passed++ }
function Fail {
    param([string]$Name, [string]$Detail = '')
    Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " - $Detail" } else { '' }))
    $script:Failed++
}

# --- Resolve binaries -------------------------------------------------------
if ([string]::IsNullOrEmpty($Sandbox)) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $Sandbox = Join-Path $repoRoot 'bazel-bin\BazelSandbox.exe'
}
if (-not (Test-Path -LiteralPath $Sandbox)) {
    Write-Error "BazelSandbox.exe not found: $Sandbox (build //:BazelSandbox first)"; exit 2
}
$Sandbox = (Resolve-Path -LiteralPath $Sandbox).Path
$dll = Join-Path (Split-Path -Parent $Sandbox) 'DetoursServices.dll'
if (-not (Test-Path -LiteralPath $dll)) {
    Write-Error "DetoursServices.dll not found beside the sandbox: $dll"; exit 2
}

Write-Host "== overlay concurrent-write regression (goyacc y.output) =="
Write-Host "   sandbox: $Sandbox"

# --- Build a throwaway execroot with two per-action overlays ----------------
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("overlay_concurrent_" + [guid]::NewGuid().ToString('N'))
$exec = Join-Path $root 'execroot'
$ovA  = Join-Path $root 'overlayA'
$ovB  = Join-Path $root 'overlayB'
New-Item -ItemType Directory -Force -Path $exec, $ovA, $ovB | Out-Null
# A declared input so each action has a legitimate -r read, like a real grammar.
Set-Content -LiteralPath (Join-Path $exec 'grammar.y') -Value '%%'

# The child creates the FIXED-NAME undeclared scratch file y.output in its cwd
# (the execroot root), holds it open a few seconds to force the two actions to
# overlap, then exits 0 - exactly goyacc's write-and-hold pattern.
$childCmd = 'echo scratch> y.output & ping -n 5 127.0.0.1 >nul & exit 0'

function Start-Action {
    param([string]$Overlay, [string]$OutLog, [string]$ErrLog)
    # -D retains the overlay backing store on exit (cleanup is skipped when a debug
    # path is set), letting us positively confirm the redirected write landed there.
    $dbg = "$OutLog.dbg"
    $sbxArgs = @(
        '-W', $exec,
        '-r', (Join-Path $exec 'grammar.y'),
        '--filter-inputs',
        '--write-overlay',
        '--overlay-dir', $Overlay,
        '-D', $dbg,
        '-l', $OutLog,
        '-L', $ErrLog,
        '--', 'cmd.exe', '/c', $childCmd
    )
    Start-Process -FilePath $Sandbox -ArgumentList $sbxArgs -PassThru -NoNewWindow
}

$aOut = Join-Path $root 'A.out'; $aErr = Join-Path $root 'A.err'
$bOut = Join-Path $root 'B.out'; $bErr = Join-Path $root 'B.err'

Write-Host "-- launching two concurrent actions writing the same y.output"
$pA = Start-Action $ovA $aOut $aErr
$pB = Start-Action $ovB $bOut $bErr
$pA.WaitForExit(); $pB.WaitForExit()
$rcA = $pA.ExitCode; $rcB = $pB.ExitCode
Write-Host "   action A exit=$rcA  action B exit=$rcB"

# --- Assertions -------------------------------------------------------------
if ($rcA -eq 0) { Pass 'action A succeeded (exit 0)' } else { Fail 'action A succeeded (exit 0)' "exit $rcA" }
if ($rcB -eq 0) { Pass 'action B succeeded (exit 0)' } else { Fail 'action B succeeded (exit 0)' "exit $rcB" }

# The historical failure surfaced as ERROR_ACCESS_DENIED from the no-clobber guard.
foreach ($pair in @(@($aErr, 'A'), @($bErr, 'B'))) {
    $errFile = $pair[0]; $tag = $pair[1]
    $txt = if (Test-Path -LiteralPath $errFile) { Get-Content -Raw -LiteralPath $errFile } else { '' }
    if ($txt -and ($txt -match 'Access is denied')) {
        Fail "action $tag write not denied" 'saw "Access is denied" (the old collision)'
    } else {
        Pass "action $tag write not denied"
    }
}

# The real execroot must be untouched - the write went to the overlay, not disk.
if (Test-Path -LiteralPath (Join-Path $exec 'y.output')) {
    Fail 'real execroot not mutated' 'y.output leaked into the real execroot'
} else {
    Pass 'real execroot not mutated'
}

# Each action's write must have landed in ITS OWN overlay backing store.
$aYo = Get-ChildItem -Path $ovA -Recurse -Filter 'y.output' -ErrorAction SilentlyContinue
$bYo = Get-ChildItem -Path $ovB -Recurse -Filter 'y.output' -ErrorAction SilentlyContinue
if ($aYo) { Pass 'overlay A captured its own y.output' } else { Fail 'overlay A captured its own y.output' }
if ($bYo) { Pass 'overlay B captured its own y.output' } else { Fail 'overlay B captured its own y.output' }

# --- Report -----------------------------------------------------------------
Write-Host ""
Write-Host ("== {0} passed, {1} failed ==" -f $script:Passed, $script:Failed)
if ($KeepArtifacts) {
    Write-Host "   artifacts kept at $root"
} else {
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
}
if ($script:Failed -gt 0) { exit 1 } else { exit 0 }
