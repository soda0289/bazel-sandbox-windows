# KNOWN LIMITATIONS of the vendored engine, characterized so a future rewrite
# that fixes one will make the corresponding assertion change loudly. None is an
# under-deny that silently defeats a declared deny via a normal long path; they
# are edge cases. Environment-dependent outcomes are reported as NOTE
# observations rather than asserted.

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
    -TempDir $TempDir -Suite 'limitations'

# Directory enumeration (FindFirstFile/FindNextFile) is NOT enforced: a denied
# workdir can still be listed. File opens are still enforced; only the listing
# is visible. Potential info-leak surface.
$ws = New-Workspace
Assert-Exit 'KNOWN-GAP: enumerate in denied workdir allowed' 0 `
    (Invoke-Sandbox @('-W', $ws) @('enumerate', $ws))

# 8.3 short names are hashed in long form and not cross-matched, so an exact -b
# block can be evaded via the short name. The exact manifestation varies by
# volume (short-name generation may be disabled), so the short-name outcomes are
# observed, not asserted; only the deterministic long-name control is asserted.
$ws = New-Workspace
$longFile = Join-Path $ws 'longfilename.txt'
'y' | Set-Content $longFile
$shortFile = & (Get-CmdExe) /c "for %A in (`"$longFile`") do @echo %~sA"
if ($shortFile -and ($shortFile -match '~') -and (Test-Path $shortFile)) {
    Assert-Exit 'exact -b blocks long-name write' 10 `
        (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', $longFile) @('write', $longFile))
    Note-Exit 'KNOWN-GAP: 8.3 short-name vs exact -b' `
        (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', $longFile) @('write', $shortFile)) '(0 = bypass)'

    $longSub = Join-Path $ws 'longsubdir'
    New-Item -ItemType Directory -Force -Path $longSub | Out-Null
    'z' | Set-Content (Join-Path $longSub 'f.txt')
    $shortSub = & (Get-CmdExe) /c "for %A in (`"$longSub`") do @echo %~sA"
    if ($shortSub -and ($shortSub -match '~')) {
        Note-Exit 'KNOWN-GAP: 8.3 short-name vs subtree deny' `
            (Invoke-Sandbox @('-W', $ws) @('read', (Join-Path $shortSub 'f.txt'))) '(0 = bypass)'
    }
} else {
    Skip-Case 'KNOWN-GAP: 8.3 short-name cases' 'no 8.3 name on volume'
}

# Long paths (> MAX_PATH). A non-long-path-aware child that passes a raw >260
# path (no \\?\) has it truncated by its own Win32 layer before the engine sees
# it, so a legitimate -r access is over-denied; the \\?\ form works correctly
# (allow and deny both hold). This is a child-side issue, not the launcher's.
$ws = New-Workspace
$deep = $ws
1..20 | ForEach-Object { $deep = Join-Path $deep ('longsegmentname_' + $_) }
$deepOk = $false
try {
    [System.IO.Directory]::CreateDirectory('\\?\' + $deep) | Out-Null
    [System.IO.File]::WriteAllText('\\?\' + (Join-Path $deep 'd.txt'), 'x')
    $deepOk = $true
} catch { }
if ($deepOk -and $deep.Length -gt 260) {
    $deepFile = Join-Path $deep 'd.txt'
    # A non-long-path-aware child truncates the raw >260 path at MAX_PATH before
    # the engine sees it, so the -r grant (keyed on the full path) never matches.
    # The exact failure the child then surfaces - ACCESS_DENIED (10) if the engine
    # denies the truncated path, or FILE_NOT_FOUND (11) if the mangled path is
    # simply absent - depends on the CRT's truncation behavior and is not
    # something the engine controls. Recorded, not gated. The \\?\ and
    # long-path-aware cases below are the ones that assert real engine behavior.
    Note-Exit 'KNOWN-GAP: raw >260 -r over-restricts (child-side truncation)' `
        (Invoke-Sandbox @('-W', $ws, '-r', $deep) @('read', $deepFile)) `
        '(10=denied or 11=not-found; both reflect the truncation, not a grant)'
    Assert-Exit '\\?\ >260 -r allows correctly' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', ('\\?\' + $deep)) @('read', ('\\?\' + $deepFile)))
    Assert-Exit '\\?\ >260 deny still holds' 10 `
        (Invoke-Sandbox @('-W', $ws) @('read', ('\\?\' + $deepFile)))

    # Contrast: the over-deny above is a CHILD-side limitation, not the engine's.
    # A long-path-aware child (probe_lpa, built with longPathAware in its manifest)
    # passes the same raw >260 path (no \\?\) straight through to the engine, so a
    # declared -r is honored and an undeclared access is still denied. This proves
    # long-path-aware API calls are supported end to end. Requires the system
    # policy LongPathsEnabled=1; skipped otherwise or if the binary is absent.
    $probeLpa = Join-Path (Split-Path (Get-Probe) -Parent) 'probe_lpa.exe'
    $lpEnabled = 0
    try {
        $lpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' `
            -Name LongPathsEnabled -ErrorAction Stop).LongPathsEnabled
    } catch { }
    if ((Test-Path $probeLpa) -and ($lpEnabled -eq 1)) {
        $savedProbe = Get-Probe
        try {
            Set-Probe $probeLpa
            Assert-Exit 'long-path-aware child: raw >260 -r allowed' 0 `
                (Invoke-Sandbox @('-W', $ws, '-r', $deep) @('read', $deepFile))
            Assert-Exit 'long-path-aware child: raw >260 deny still holds' 10 `
                (Invoke-Sandbox @('-W', $ws) @('read', $deepFile))
        } finally { Set-Probe $savedProbe }
    } else {
        Skip-Case 'long-path-aware child cases' 'probe_lpa missing or LongPathsEnabled=0'
    }
} else {
    Skip-Case 'KNOWN-GAP: long-path cases' '>260 path not creatable here'
}

# Case-insensitive matching is ASCII-only. The engine upper-cases path fragments
# with _towupper_l(invariant), which folds a-z but NOT non-ASCII letters, so a
# non-ASCII path is matched case-SENSITIVELY. (This mirrors BuildXL's own Windows
# code, which also uses _towupper_l - dropping the macOS-only utf8proc changed
# nothing here.) The ASCII control confirms folding works; the non-ASCII cases
# pin both directions, including the security-relevant under-deny where a -b
# block is bypassed by a differently-cased non-ASCII path.
$ws = New-Workspace
$ascii = Join-Path $ws 'asciidir'
New-Item -ItemType Directory -Force -Path $ascii | Out-Null
'a' | Set-Content (Join-Path $ascii 'f.txt')
Assert-Exit 'ASCII case folds: upper -r scope allows lower access' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ascii.ToUpperInvariant()) @('read', (Join-Path $ascii 'f.txt')))

$acc = Join-Path $ws ('caf' + [char]0x00E9)   # café (é = U+00E9)
New-Item -ItemType Directory -Force -Path $acc | Out-Null
$accFile = Join-Path $acc 'f.txt'
'a' | Set-Content $accFile
# Over-deny: an upper-cased non-ASCII -r scope does NOT match the lower-cased
# access, so a legitimate read is denied.
Assert-Exit 'KNOWN-GAP: non-ASCII case not folded (over-deny)' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $acc.ToUpperInvariant()) @('read', $accFile))
# Under-deny: an upper-cased non-ASCII -b block is bypassed by the lower-cased
# access (0 = the block leaked). Analogous to the 8.3 short-name gap.
Assert-Exit 'KNOWN-GAP: non-ASCII -b bypassed by case (under-deny)' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-b', $acc.ToUpperInvariant()) @('read', $accFile))

# Reparse-point escape. The engine is configured with IgnoreReparsePoints +
# IgnoreFullReparsePointResolving, so it enforces on the path AS REQUESTED and
# does NOT resolve a junction/symlink to its target. Consequence: a reparse point
# that lives inside an ALLOWED scope but points OUTSIDE every scope lets the
# access reach the outside target, even though a direct access to that target is
# denied. This is exactly what BuildXL's full reparse-point resolution (which we
# do not enable) is designed to prevent. Uses a junction (no privilege needed),
# so it is fully deterministic.
$ws = New-Workspace
$inside = Join-Path $ws 'inside'
$outside = Join-Path $ws 'outside'
New-Item -ItemType Directory -Force -Path $inside, $outside | Out-Null
'orig' | Set-Content (Join-Path $outside 'o.txt')
$esc = Join-Path $inside 'esc'
& (Get-CmdExe) /c mklink /J "$esc" "$outside" *> $null
if (Test-Path $esc) {
    # Control: a direct write to the outside target (in neither -r nor -w) is denied.
    Assert-Exit 'direct write to out-of-scope target denied' 10 `
        (Invoke-Sandbox @('-W', $ws, '-r', $inside, '-w', $inside) `
            @('write', (Join-Path $outside 'o.txt')))
    # Gap: the same target reached THROUGH a junction inside the -w scope is
    # allowed (0 = the write escaped confinement to an undeclared location).
    Assert-Exit 'KNOWN-GAP: junction in -w escapes to out-of-scope target' 0 `
        (Invoke-Sandbox @('-W', $ws, '-r', $inside, '-w', $inside) `
            @('write', (Join-Path $esc 'o.txt')))
} else {
    Skip-Case 'KNOWN-GAP: reparse-point escape' 'junction creation failed'
}

Complete-Harness