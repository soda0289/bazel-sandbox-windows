<#
.SYNOPSIS
    Opt-in end-to-end test for the windows-sandbox default mode ("Mode 2",
    --filter-inputs) driven through a real Bazel build.

.DESCRIPTION
    This is intentionally NOT part of `bazel test //tests:all`. Unlike the
    probe-based enforcement suites (which exercise the sandbox binary directly at
    each Windows API surface), this test validates the *integration* layer that the
    probe tests structurally cannot: that Bazel's `windows-sandbox` strategy really
    passes `--filter-inputs`, that declared inputs resolve through the filter, and
    that a real action observes an undeclared input as ABSENT (NOT_FOUND), matching
    linux-sandbox's symlink forest rather than returning ACCESS_DENIED.

    It requires:
      * a PATCHED Bazel binary - built from a Bazel checkout with
        files/bazel-windows-sandbox.patch applied (e.g. `bazel build //src:bazel-dev`,
        then use bazel-bin/src/bazel-dev, copied to a .exe). The stock Bazel does not
        wire the windows-sandbox flags this test relies on.
      * network + corporate certificate trust for Bazel module resolution. The
        default -HostJvmArgs trusts the Windows root store (Zscaler etc.); override
        or clear it if your environment resolves modules differently.

    The test builds a tiny workspace with two genrules:
      good : reads a DECLARED input (a.txt)      -> must SUCCEED under the sandbox
      bad  : reads an UNDECLARED sibling (b.txt)  -> must FAIL with "cannot find the
                                                      file", not "Access is denied"
    A baseline run of `bad` under --spawn_strategy=local confirms b.txt is actually
    reachable, so the sandboxed failure is genuinely the filter hiding it.

.PARAMETER Bazel
    Path to the patched Bazel executable to drive the build.

.PARAMETER Sandbox
    Path to BazelSandbox.exe (with DetoursServices.dll beside it). Defaults to the
    repo's bazel-bin\BazelSandbox.exe.

.PARAMETER OutputUserRoot
    Bazel --output_user_root for the throwaway build. Defaults to a temp dir.

.PARAMETER HostJvmArgs
    Passed as --host_jvm_args. Defaults to trusting the Windows root cert store so
    module resolution works behind a corporate proxy. Pass '' to omit.

.PARAMETER KeepArtifacts
    Keep the temp workspace and output root instead of cleaning them up.

.EXAMPLE
    pwsh tests/e2e/mode2.ps1 -Bazel C:\path\to\patched-bazel.exe

.NOTES
    Exit codes: 0 = all assertions passed, 1 = a assertion failed,
    2 = missing prerequisite (bazel/sandbox/dll), 3 = environment could not resolve
    Bazel modules (network/cert) so the test was skipped.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bazel,
    [string]$Sandbox,
    [string]$OutputUserRoot = (Join-Path ([System.IO.Path]::GetTempPath()) 'sbx_e2e_out'),
    [string]$HostJvmArgs = '-Djavax.net.ssl.trustStoreType=WINDOWS-ROOT',
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
if (-not (Test-Path -LiteralPath $Bazel)) { Write-Error "Bazel not found: $Bazel"; exit 2 }
$Bazel = (Resolve-Path -LiteralPath $Bazel).Path

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

Write-Host "== windows-sandbox Mode 2 e2e =="
Write-Host "   bazel:   $Bazel"
Write-Host "   sandbox: $Sandbox"

# --- Build the throwaway workspace ------------------------------------------
$ws = Join-Path ([System.IO.Path]::GetTempPath()) ("sbx_e2e_ws_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $ws | Out-Null
Set-Content -LiteralPath (Join-Path $ws 'MODULE.bazel') 'module(name = "sbx_e2e", version = "0.0.1")'
Set-Content -LiteralPath (Join-Path $ws 'a.txt') 'declared-input-content'
Set-Content -LiteralPath (Join-Path $ws 'b.txt') 'UNDECLARED-secret-content'
@'
# good declares a.txt as an input; bad reads b.txt WITHOUT declaring it.
# baseline is a distinct action (own output) that also reads the undeclared b.txt,
# used only to prove b.txt is reachable under --spawn_strategy=local. It must be a
# SEPARATE target from bad: a successful build of the identical action would
# populate Bazel's action cache (whose key does not include the undeclared b.txt)
# and the later sandboxed run would get a cache hit instead of re-executing.
genrule(
    name = "good",
    srcs = ["a.txt"],
    outs = ["good.out"],
    cmd_bat = "type a.txt > $@",
)

genrule(
    name = "bad",
    srcs = ["a.txt"],
    outs = ["bad.out"],
    cmd_bat = "type b.txt > $@",
)

genrule(
    name = "baseline",
    srcs = ["a.txt"],
    outs = ["baseline.out"],
    cmd_bat = "type b.txt > $@",
)
'@ | Set-Content -LiteralPath (Join-Path $ws 'BUILD.bazel')

# --- Helpers ----------------------------------------------------------------
$startup = @("--output_user_root=$OutputUserRoot")
if ($HostJvmArgs) { $startup += "--host_jvm_args=$HostJvmArgs" }
$sbxFlags = @(
    '--spawn_strategy=windows-sandbox',
    '--experimental_use_windows_sandbox=yes',
    "--experimental_windows_sandbox_path=$Sandbox"
)

function Invoke-Bazel {
    param([string[]]$BuildArgs)
    Push-Location $ws
    try {
        $out = & $Bazel @startup @BuildArgs 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out }
    } finally { Pop-Location }
}

$exitCode = 1
try {
    # 1) Baseline: `baseline` (own action) under local must succeed, proving b.txt is
    #    reachable. It is a SEPARATE target from `bad` so its cache entry cannot be
    #    reused by the sandboxed `bad` run. If this fails on module resolution, the
    #    environment lacks network/cert - bail with guidance rather than a
    #    misleading test failure.
    Write-Host "-- baseline: //:baseline under --spawn_strategy=local (expect success)"
    $base = Invoke-Bazel @('build', '//:baseline', '--spawn_strategy=local')
    if ($base.Code -ne 0) {
        if ($base.Output -match 'registry|TLS error|PKIX|certification path') {
            Write-Host "  ENV   module resolution failed (network/cert). See -HostJvmArgs. Skipping."
            Write-Host $base.Output
            exit 3
        }
        Fail 'baseline //:baseline builds under local' "exit $($base.Code)"
        Write-Host $base.Output
    } else {
        Pass 'baseline //:baseline builds under local (b.txt reachable)'
    }

    # 2) good (declared input) under the sandbox must succeed.
    Write-Host "-- //:good under windows-sandbox (expect success)"
    $good = Invoke-Bazel (@('build', '//:good') + $sbxFlags)
    if ($good.Code -eq 0 -and $good.Output -match 'windows-sandbox') {
        Pass 'declared input builds under windows-sandbox'
    } elseif ($good.Code -eq 0) {
        Fail 'declared input builds under windows-sandbox' 'built, but no windows-sandbox process reported'
    } else {
        Fail 'declared input builds under windows-sandbox' "exit $($good.Code)"
        Write-Host $good.Output
    }

    # 3) bad (undeclared read) under the sandbox must FAIL with NOT_FOUND, not denied.
    Write-Host "-- //:bad under windows-sandbox (expect failure with NOT_FOUND)"
    $bad = Invoke-Bazel (@('build', '//:bad') + $sbxFlags)
    if ($bad.Code -eq 0) {
        Fail 'undeclared input hidden under windows-sandbox' 'build unexpectedly succeeded'
        Write-Host $bad.Output
    } elseif ($bad.Output -match 'cannot find the file') {
        Pass 'undeclared input reported NOT_FOUND (linux-sandbox parity)'
    } elseif ($bad.Output -match 'Access is denied') {
        Fail 'undeclared input reported NOT_FOUND (linux-sandbox parity)' 'got ACCESS_DENIED instead of NOT_FOUND'
    } else {
        Fail 'undeclared input reported NOT_FOUND (linux-sandbox parity)' 'build failed but with an unexpected error'
        Write-Host $bad.Output
    }

    $summary = "$script:Passed passed, $script:Failed failed"
    if ($script:Failed -gt 0) { Write-Host "== FAILED: $summary =="; $exitCode = 1 }
    else { Write-Host "== OK: $summary =="; $exitCode = 0 }
}
finally {
    # Shut the throwaway Bazel server down so the output root can be removed.
    & $Bazel "--output_user_root=$OutputUserRoot" shutdown 2>&1 | Out-Null
    if (-not $KeepArtifacts) {
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $OutputUserRoot -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "   (kept: workspace $ws, output root $OutputUserRoot)"
    }
}

exit $exitCode
