<#
.SYNOPSIS
    Differential real-repo smoke test for the windows-sandbox strategy.

.DESCRIPTION
    Builds a set of targets in a real (large, open-source) Bazel repo TWICE - once
    under `--spawn_strategy=local` and once under `--spawn_strategy=windows-sandbox`
    - and DIFFS the per-target results. The whole point of the project is parity
    with hermetic linux-sandbox / RBE, so the interesting signal is not "did it
    build" but "does the sandbox result MATCH the non-sandbox result":

        pass local + fail sandbox   -> SANDBOX REGRESSION (actionable; this is a bug)
        fail local + fail sandbox   -> pre-existing Windows/toolchain breakage (not us)
        pass local + pass sandbox   -> good
        fail local + pass sandbox   -> unexpected; reported for inspection

    Per-target status comes from Bazel's Build Event Protocol JSON
    (`--build_event_json_file`), so the comparison is robust for a whole `//...`
    build with `--keep_going`.

    IMPORTANT - separate output bases. The two runs use DIFFERENT
    `--output_user_root`s. Spawn strategy is NOT part of Bazel's action cache key,
    so if both runs shared an output base the sandbox run would get action-cache
    hits from the local run and never actually execute under the sandbox. Separate
    bases force real sandbox execution. They share one `--repository_cache` so
    module/repo fetches are not paid twice.

    Prerequisites are the same as tests/e2e/mode2.ps1:
      * a PATCHED Bazel binary (integration/bazel-windows-sandbox.patch applied) that
        wires the windows-sandbox flags (see integration/README.md);
      * network + corporate cert trust for module resolution (see -HostJvmArgs);
      * git on PATH (only when cloning; not needed with -RepoPath).

    This is opt-in and NOT part of `bazel test //tests:all`.

.PARAMETER Bazel
    Path to the patched Bazel executable.

.PARAMETER Preset
    Name of a curated repo entry in tests/e2e/smoke-repos.psd1 (e.g. 'rules_js').
    Provides RepoUrl/Ref/Subdir/Targets. Any of those can be overridden by the
    explicit parameters below.

.PARAMETER RepoUrl
    Git URL to clone (ignored when -RepoPath is given).

.PARAMETER Ref
    Git ref/branch/tag/commit to check out after cloning (default: repo default).

.PARAMETER RepoPath
    Path to an ALREADY-checked-out repo working tree. Skips cloning. The tree is
    used read-only for source, but Bazel will create bazel-* symlinks in it.

.PARAMETER Subdir
    Sub-directory of the repo that is the actual Bazel workspace root, i.e. the
    dir holding MODULE.bazel/WORKSPACE (e.g. 'examples' for rules_js/rules_ts).
    Must NOT be a package inside the workspace: '//...' is workspace-root-relative,
    so Bazel walks up to the workspace root regardless. Default: repo root.

.PARAMETER Targets
    One or more target patterns to build (default: '//...').

.PARAMETER Sandbox
    Path to BazelSandbox.exe (DetoursServices.dll beside it). Defaults to this
    repo's bazel-bin\BazelSandbox.exe.

.PARAMETER RepositoryCache
    Shared --repository_cache dir (default: a stable temp dir, reused across runs).

.PARAMETER WorkRoot
    Base temp dir for the clone + the two output bases (default: a temp dir).

.PARAMETER HostJvmArgs
    Passed as --host_jvm_args. Defaults to trusting the Windows root cert store so
    module resolution works behind a corporate proxy. Pass '' to omit.

.PARAMETER ExtraBuildArgs
    Extra args appended to BOTH builds (e.g. '--config=windows', '-c','opt').

.PARAMETER WindowsSymlinks
    Pass --windows_enable_symlinks (startup option) to BOTH builds so runfiles
    trees are materialized with real symlinks instead of copies (matches
    linux-sandbox / RBE). Requires SeCreateSymbolicLinkPrivilege. Default: $true.

.PARAMETER EnableRunfiles
    Pass --enable_runfiles=yes to BOTH builds so a real runfiles tree is
    materialized for every target (Windows default 'auto' is manifest-only).
    Matches linux-sandbox / RBE and is required by rules_js's launcher. Default: $true.

.PARAMETER KeepArtifacts
    Keep the clone and output bases instead of cleaning them up.

.EXAMPLE
    pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe -Preset rules_js

.EXAMPLE
    pwsh tests/e2e/smoke.ps1 -Bazel C:\tmp\bazel-dev.exe `
        -RepoUrl https://github.com/aspect-build/rules_js -Subdir e2e/js_image_docker `
        -Targets //... -KeepArtifacts

.NOTES
    Exit codes: 0 = no sandbox regressions, 1 = one or more sandbox regressions,
    2 = missing prerequisite, 3 = environment could not resolve modules / clone.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bazel,
    [string]$Preset,
    [string]$RepoUrl,
    [string]$Ref,
    [string]$RepoPath,
    [string]$Subdir = '',
    [string[]]$Targets,
    [string]$Sandbox,
    [string]$RepositoryCache = (Join-Path ([System.IO.Path]::GetTempPath()) 'sbx_smoke_repocache'),
    [string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) ('sbx_smoke_' + [guid]::NewGuid().ToString('N').Substring(0, 8))),
    [string]$HostJvmArgs = '-Djavax.net.ssl.trustStoreType=WINDOWS-ROOT',
    [string[]]$ExtraBuildArgs = @(),
    [bool]$WindowsSymlinks = $true,
    [bool]$EnableRunfiles = $true,
    [bool]$Submodules = $false,
    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Info { param([string]$m) Write-Host $m }
function Warn { param([string]$m) Write-Host "  WARN  $m" -ForegroundColor Yellow }

# --- Resolve preset ---------------------------------------------------------
if ($Preset) {
    $presetsFile = Join-Path $PSScriptRoot 'smoke-repos.psd1'
    if (-not (Test-Path -LiteralPath $presetsFile)) { Write-Error "presets file not found: $presetsFile"; exit 2 }
    $presets = Import-PowerShellDataFile -LiteralPath $presetsFile
    if (-not $presets.ContainsKey($Preset)) {
        Write-Error "unknown preset '$Preset'. Known: $($presets.Keys -join ', ')"; exit 2
    }
    $p = $presets[$Preset]
    if (-not $RepoUrl -and $p.ContainsKey('RepoUrl')) { $RepoUrl = $p.RepoUrl }
    if (-not $Ref     -and $p.ContainsKey('Ref'))     { $Ref     = $p.Ref }
    if (-not $Subdir  -and $p.ContainsKey('Subdir'))  { $Subdir  = $p.Subdir }
    if (-not $PSBoundParameters.ContainsKey('Submodules') -and $p.ContainsKey('Submodules')) { $Submodules = $p.Submodules }
    if (-not $Targets -and $p.ContainsKey('Targets')) { $Targets = @($p.Targets) }
    if ((-not $ExtraBuildArgs -or $ExtraBuildArgs.Count -eq 0) -and $p.ContainsKey('ExtraBuildArgs')) {
        $ExtraBuildArgs = @($p.ExtraBuildArgs)
    }
}
if (-not $Targets -or $Targets.Count -eq 0) { $Targets = @('//...') }

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

New-Item -ItemType Directory -Force -Path $WorkRoot | Out-Null
New-Item -ItemType Directory -Force -Path $RepositoryCache | Out-Null

# --- Obtain the repo --------------------------------------------------------
if ($RepoPath) {
    if (-not (Test-Path -LiteralPath $RepoPath)) { Write-Error "RepoPath not found: $RepoPath"; exit 2 }
    $checkout = (Resolve-Path -LiteralPath $RepoPath).Path
    Info "== smoke: using existing checkout $checkout"
} else {
    if (-not $RepoUrl) { Write-Error "need -RepoUrl, -RepoPath, or -Preset"; exit 2 }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Error "git not on PATH (needed to clone)"; exit 2 }
    $checkout = Join-Path $WorkRoot 'repo'
    Info "== smoke: cloning $RepoUrl$(if ($Ref) { " @ $Ref" }) -> $checkout"
    # Shallow clone for speed; fetch the specific ref if given. Some repos (e.g.
    # gitiles) keep in-tree bzlmod modules as git submodules (local_path_override),
    # so -Submodules / a preset 'Submodules=$true' recurses them (shallow).
    $subArgs = if ($Submodules) { @('--recurse-submodules', '--shallow-submodules') } else { @() }
    if ($Ref) {
        git clone --depth 1 @subArgs --branch $Ref $RepoUrl $checkout 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            # Ref may be a raw commit; fall back to full clone + checkout.
            git clone @subArgs $RepoUrl $checkout 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Error "git clone failed"; exit 3 }
            git -C $checkout checkout $Ref 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Error "git checkout $Ref failed"; exit 3 }
            if ($Submodules) { git -C $checkout submodule update --init --recursive --depth 1 2>&1 | Out-Null }
        }
    } else {
        git clone --depth 1 @subArgs $RepoUrl $checkout 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Error "git clone failed"; exit 3 }
    }
}

$wsDir = if ($Subdir) { Join-Path $checkout $Subdir } else { $checkout }
if (-not (Test-Path -LiteralPath $wsDir)) { Write-Error "workspace subdir not found: $wsDir"; exit 2 }
$wsDir = (Resolve-Path -LiteralPath $wsDir).Path

Info "   bazel:    $Bazel"
Info "   sandbox:  $Sandbox"
Info "   workspace:$wsDir"
Info "   targets:  $($Targets -join ' ')"
Info "   symlinks: $(if($WindowsSymlinks){'--windows_enable_symlinks (runfiles = symlinks)'}else{'off (runfiles = copies)'})"
Info "   runfiles: $(if($EnableRunfiles){'--enable_runfiles=yes (materialize tree)'}else{'auto (manifest-only on Windows)'})"

# --- Build drivers ----------------------------------------------------------
# IMPORTANT: the two output-base directory names MUST be the same length.
# Bazel builds actions in-place under <output_base>\<hash>\execroot\_main\..., so
# the base name is a constant prefix on every action path. rules_js npm packages
# nest very deeply (e.g. .aspect_rules_js\<pkg>\node_modules\@scope\<pkg>), and
# bsdtar extracts with `--directory <dir>` which performs a chdir into that dir.
# Windows' SetCurrentDirectory is hard-capped at MAX_PATH (259 usable chars) and
# ignores longPathAware / \\?\, so if one base name is even a couple of chars
# longer it can push that dir across 259 and make tar fail with "could not chdir"
# in ONLY that base -- a false-positive "regression" unrelated to sandboxing.
# Keep the names equal-length (and short) so both bases hit the limit identically.
$localBase = Join-Path $WorkRoot 'ob_loc'
$sbxBase   = Join-Path $WorkRoot 'ob_sbx'
$localBep  = Join-Path $WorkRoot 'local.bep.json'
$sbxBep    = Join-Path $WorkRoot 'sandbox.bep.json'

function Invoke-BazelBuild {
    param([string]$OutputBase, [string[]]$StrategyArgs, [string]$BepFile)
    $startup = @("--output_user_root=$OutputBase")
    if ($HostJvmArgs) { $startup += "--host_jvm_args=$HostJvmArgs" }
    # --windows_enable_symlinks is a STARTUP option (needs a fresh server, which we
    # get for free since each phase uses its own --output_user_root). With it OFF
    # (Bazel default) runfiles trees on Windows are materialized by COPYING files;
    # with it ON (and SeCreateSymbolicLinkPrivilege granted) file entries become
    # real symlinks - matching linux-sandbox / RBE. Applied to BOTH phases so the
    # differential stays apples-to-apples.
    if ($WindowsSymlinks) { $startup += '--windows_enable_symlinks' }
    # --enable_runfiles=yes forces Bazel to materialize a real runfiles TREE for
    # every target (default on Windows is 'auto' = manifest-only, no tree). The
    # hermetic reference (linux-sandbox / RBE) always builds trees, and some rules
    # (notably rules_js's js_binary launcher) only resolve entry points correctly
    # when the tree exists - otherwise they fall back to an undeclared cross-config
    # path that the sandbox (rightly) denies. Cheap now that symlinks are on.
    # Applied to BOTH phases so the differential stays apples-to-apples.
    $runfilesArg = if ($EnableRunfiles) { @('--enable_runfiles=yes') } else { @() }
    $buildArgs = @('build') + $Targets + $StrategyArgs + @(
        '--keep_going',
        '--verbose_failures',
        "--repository_cache=$RepositoryCache",
        "--build_event_json_file=$BepFile",
        '--color=no',
        '--curses=no'
    ) + $runfilesArg + $ExtraBuildArgs
    Push-Location $wsDir
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $out = & $Bazel @startup @buildArgs 2>&1 | Out-String
        $sw.Stop()
        # Persist the full phase output next to the BEP so a regression can be
        # diagnosed WITHOUT re-running the (often very long) build. --verbose_failures
        # above makes this include the failing action's command line and stderr.
        $logFile = [regex]::Replace($BepFile, '\.bep\.json$', '.build.log')
        if ($logFile -eq $BepFile) { $logFile = "$BepFile.build.log" }
        Set-Content -LiteralPath $logFile -Value $out -Encoding utf8
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $out; ElapsedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1); LogFile = $logFile }
    } finally { Pop-Location }
}

# Parse per-target success from a BEP JSON-lines file.
# Returns a hashtable: label -> $true (success) / $false (failure).
function Read-BepTargetStatus {
    param([string]$BepFile)
    $status = @{}
    if (-not (Test-Path -LiteralPath $BepFile)) { return $status }
    foreach ($line in [System.IO.File]::ReadLines($BepFile)) {
        if (-not $line) { continue }
        try { $ev = $line | ConvertFrom-Json } catch { continue }
        # targetCompleted events carry the per-target outcome.
        if ($ev.PSObject.Properties.Name -contains 'id' -and
            $ev.id.PSObject.Properties.Name -contains 'targetCompleted') {
            $label = $ev.id.targetCompleted.label
            if (-not $label) { continue }
            $ok = $false
            if ($ev.PSObject.Properties.Name -contains 'completed' -and
                $ev.completed.PSObject.Properties.Name -contains 'success') {
                $ok = [bool]$ev.completed.success
            }
            # If a later event flips a label, keep the worst (failure) outcome.
            if ($status.ContainsKey($label)) { $status[$label] = $status[$label] -and $ok }
            else { $status[$label] = $ok }
        }
        # Some failures arrive as an 'aborted' targetCompleted with no success field.
        elseif ($ev.PSObject.Properties.Name -contains 'aborted' -and
                $ev.PSObject.Properties.Name -contains 'id' -and
                $ev.id.PSObject.Properties.Name -contains 'targetCompleted') {
            $label = $ev.id.targetCompleted.label
            if ($label) { $status[$label] = $false }
        }
    }
    return $status
}

$exitCode = 1
$keepForDebug = $false
try {
    Info ''
    Info "-- [1/2] local build (--spawn_strategy=local)"
    $local = Invoke-BazelBuild -OutputBase $localBase -StrategyArgs @('--spawn_strategy=local') -BepFile $localBep
    Info "   local exit: $($local.Code)  (elapsed: $($local.ElapsedSec)s)"
    $localStatus = Read-BepTargetStatus -BepFile $localBep

    # A genuine environment failure (no network / cert distrust / can't fetch the
    # module graph) produces NO configured targets at all. A non-zero exit WITH
    # target-completion events just means some targets failed under --keep_going,
    # which is exactly what this differential test is designed to measure - do not
    # abort on it. Only bail when nothing built AND the output looks like a
    # module-graph/TLS failure.
    if ($localStatus.Count -eq 0 -and
        ($local.Output -match 'PKIX|TLS|certification path|SSLHandshake|trustAnchors|Error downloading|the registry|Failed to fetch|Unknown module')) {
        Warn "module graph could not be resolved (network/cert). See -HostJvmArgs."
        Info $local.Output
        exit 3
    }

    Info "-- [2/2] sandbox build (--spawn_strategy=windows-sandbox,local)"
    # NOTE the ",local" fallback. Bazel advances to the next strategy in the list
    # only when a strategy REFUSES a spawn (cannot execute that action type), never
    # when it executes and the action FAILS. So every sandboxable action still runs
    # genuinely under windows-sandbox (this is a fresh output base, so there are no
    # action-cache hits from the local run to short-circuit it), while action types
    # windows-sandbox cannot handle at all (CopyFile, worker/persistent, and targets
    # that explicitly request local execution) fall back to local instead of
    # producing spurious "cannot be executed with any of the available strategies"
    # failures that would masquerade as sandbox regressions. This mirrors how a real
    # user runs the strategy.
    $sbxStrategy = @(
        '--spawn_strategy=windows-sandbox,local',
        '--experimental_use_windows_sandbox=yes',
        "--experimental_windows_sandbox_path=$Sandbox"
    )
    $sbx = Invoke-BazelBuild -OutputBase $sbxBase -StrategyArgs $sbxStrategy -BepFile $sbxBep
    Info "   sandbox exit: $($sbx.Code)  (elapsed: $($sbx.ElapsedSec)s)"
    if ($sbx.Output -notmatch 'windows-sandbox') {
        Warn "no 'windows-sandbox' text seen in sandbox build output - strategy may not have engaged."
    }

    # --- Diff -------------------------------------------------------------
    $sbxStatus   = Read-BepTargetStatus -BepFile $sbxBep

    $labels = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($k in $localStatus.Keys) { [void]$labels.Add($k) }
    foreach ($k in $sbxStatus.Keys)   { [void]$labels.Add($k) }

    $regressions = New-Object System.Collections.Generic.List[string]
    $bothFail    = New-Object System.Collections.Generic.List[string]
    $sbxOnlyPass = New-Object System.Collections.Generic.List[string]
    $bothPass    = 0

    foreach ($label in ($labels | Sort-Object)) {
        $lok = $localStatus.ContainsKey($label) -and $localStatus[$label]
        $sok = $sbxStatus.ContainsKey($label)   -and $sbxStatus[$label]
        if ($lok -and $sok)      { $bothPass++ }
        elseif ($lok -and -not $sok) { $regressions.Add($label) }
        elseif (-not $lok -and -not $sok) { $bothFail.Add($label) }
        else { $sbxOnlyPass.Add($label) }
    }

    Info ''
    Info "== differential result =="
    Info ("   both pass:            {0}" -f $bothPass)
    Info ("   both fail (not ours): {0}" -f $bothFail.Count)
    Info ("   sandbox-only pass:    {0}" -f $sbxOnlyPass.Count)
    Info ("   SANDBOX REGRESSIONS:  {0}" -f $regressions.Count)

    # --- Timing / overhead -------------------------------------------------
    # Wall-clock for each full build phase. Both phases use SEPARATE, cold output
    # bases (spawn strategy is not part of the action-cache key), so this compares
    # a cold local build vs a cold sandbox build of the same target set - i.e. the
    # end-to-end cost a user pays for turning the sandbox on. It is NOT a
    # per-action microbenchmark (fetch/analysis/local-fallback actions are included
    # in both), so treat the ratio as a coarse upper bound on sandbox overhead.
    Info ''
    Info "== timing (cold build, separate output bases) =="
    Info ("   local build:    {0}s" -f $local.ElapsedSec)
    Info ("   sandbox build:  {0}s" -f $sbx.ElapsedSec)
    if ($local.ElapsedSec -gt 0) {
        $ratio = [math]::Round($sbx.ElapsedSec / $local.ElapsedSec, 2)
        $deltaSec = [math]::Round($sbx.ElapsedSec - $local.ElapsedSec, 1)
        $pct = [math]::Round((($sbx.ElapsedSec / $local.ElapsedSec) - 1) * 100, 0)
        Info ("   sandbox / local: {0}x  (+{1}s, +{2}%)" -f $ratio, $deltaSec, $pct)
    }

    if ($bothFail.Count -gt 0) {
        Info ''
        Info "-- pre-existing failures (fail local AND sandbox; NOT sandbox bugs):"
        foreach ($l in $bothFail) { Info "     $l" }
    }
    if ($sbxOnlyPass.Count -gt 0) {
        Info ''
        Info "-- sandbox-only passes (fail local, pass sandbox; inspect):"
        foreach ($l in $sbxOnlyPass) { Info "     $l" }
    }
    if ($regressions.Count -gt 0) {
        Info ''
        Info "-- SANDBOX REGRESSIONS (pass local, FAIL sandbox; ACTIONABLE):" 
        foreach ($l in $regressions) { Info "     $l" }
        # Surface the actual failure inline (from the captured --verbose_failures
        # output) so the diagnosis does not require a second, long re-run. We print
        # the first failing action block; the full phase log is kept on disk below.
        Info ''
        Info "-- sandbox failure detail (from --verbose_failures; full log: $($sbx.LogFile)):"
        $sbxLines = $sbx.Output -split "`r?`n"
        $firstErr = ($sbxLines | Select-String -Pattern '^ERROR:' | Select-Object -First 1).LineNumber
        if ($firstErr) {
            $start = [math]::Max(0, $firstErr - 2)
            $sbxLines[$start..([math]::Min($sbxLines.Count - 1, $start + 40))] | ForEach-Object { Info "     $_" }
        } else {
            $sbxLines | Select-Object -Last 30 | ForEach-Object { Info "     $_" }
        }
        Info ''
        Info "   Re-run one under the sandbox with --verbose_failures for details, e.g.:"
        Info "     $Bazel --output_user_root=$sbxBase build <label> $($sbxStrategy -join ' ') --verbose_failures"
        Info "== FAILED: $($regressions.Count) sandbox regression(s) =="
        $exitCode = 1
        # A regression is exactly when the artifacts (BEP + build logs + output bases)
        # are worth keeping for diagnosis, so preserve them even without -KeepArtifacts.
        $keepForDebug = $true
    } else {
        Info ''
        Info "== OK: no sandbox regressions =="
        $exitCode = 0
    }

    if ($labels.Count -eq 0) {
        Warn "no target-completion events parsed from BEP - did the build configure any targets?"
        Info $sbx.Output
        $exitCode = 3
    }
}
finally {
    & $Bazel "--output_user_root=$localBase" shutdown 2>&1 | Out-Null
    & $Bazel "--output_user_root=$sbxBase"   shutdown 2>&1 | Out-Null
    if (-not $KeepArtifacts -and -not $keepForDebug) {
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Info ''
        $why = if ($KeepArtifacts) { '-KeepArtifacts' } else { 'sandbox regression(s) - kept for diagnosis' }
        Info "   (kept: $WorkRoot  [clone + BEP + build logs + output bases]  reason: $why)"
    }
}

exit $exitCode
