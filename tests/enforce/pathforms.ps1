# Path-form canonicalization. The engine canonicalizes every access before
# matching policy, so a file in a denied scope must stay denied however its path
# is spelled. These guard against a future rewrite reintroducing a
# canonicalization gap.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Sandbox,
    [Parameter(Mandatory)][string]$Probe,
    [string]$StdioLauncher,
    [Parameter(Mandatory)][string]$TempDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\lib\harness.ps1')
Initialize-Harness -Sandbox $Sandbox -Probe $Probe -StdioLauncher $StdioLauncher `
    -TempDir $TempDir -Suite 'pathforms'

$ws = New-Workspace
$denied = Join-Path $ws 'a.txt'

$fwd    = $denied -replace '\\', '/'                        # forward slashes
$dot    = (Join-Path $ws '.') + '\a.txt'                    # . component
$dotdot = (Join-Path (Join-Path $ws 'sub') '..') + '\a.txt' # .. component
$q      = '\\?\' + $denied                                  # \\?\ prefix
$upper  = $denied.ToUpper()                                 # upper case
$ads    = $denied + '::$DATA'                               # default data stream

# Every spelling of a file in the denied workdir stays denied.
Assert-Exit 'deny not bypassed by forward slashes' 10 (Invoke-Sandbox @('-W', $ws) @('read', $fwd))
Assert-Exit 'deny not bypassed by . component'      10 (Invoke-Sandbox @('-W', $ws) @('read', $dot))
Assert-Exit 'deny not bypassed by .. component'     10 (Invoke-Sandbox @('-W', $ws) @('read', $dotdot))
Assert-Exit 'deny not bypassed by \\?\ prefix'      10 (Invoke-Sandbox @('-W', $ws) @('read', $q))
Assert-Exit 'deny not bypassed by upper case'       10 (Invoke-Sandbox @('-W', $ws) @('read', $upper))
Assert-Exit 'deny not bypassed by ADS ::$DATA'      10 (Invoke-Sandbox @('-W', $ws) @('read', $ads))

# The NUL device is not a real file and must not be sandboxed.
Assert-Exit 'NUL device not sandboxed' 0 (Invoke-Sandbox @('-W', $ws) @('read', 'NUL'))

# Non-ASCII (Unicode) path handling. Windows paths are UTF-16 end to end (the
# launcher, manifest, and engine all use wchar_t), so a non-ASCII path must be
# enforced exactly like an ASCII one when the case matches. (Case-INsensitive
# matching of non-ASCII is a separate, characterized gap - see limitations.ps1.)
$ws = New-Workspace
$uniDir = Join-Path $ws ('caf' + [char]0x00E9 + '_' + [char]0x044F + '_' + [char]0x6587)  # é я 文
New-Item -ItemType Directory -Force -Path $uniDir | Out-Null
$uniFile = Join-Path $uniDir 'data.txt'
'payload' | Set-Content $uniFile
Assert-Exit 'non-ASCII path allowed when declared (-r)' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $uniDir) @('read', $uniFile))
Assert-Exit 'non-ASCII path denied when undeclared' 10 `
    (Invoke-Sandbox @('-W', $ws) @('read', $uniFile))
Assert-Exit 'non-ASCII exact -b block holds' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-b', $uniFile) @('read', $uniFile))

Complete-Harness
