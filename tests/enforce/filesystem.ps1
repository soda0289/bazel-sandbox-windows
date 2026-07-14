# Filesystem operation enforcement across the intercepted API surface: mutations
# (delete/mkdir/rename/rename-by-handle/copy/rmdir/hardlink), attribute and ANSI
# variants, GetTempFileName, the native NtCreateFile path, and the absent-file
# read-only-vs-writable distinction.

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
    -TempDir $TempDir -Suite 'filesystem'

# --- delete / mkdir / rmdir -------------------------------------------------
$ws = New-Workspace
Assert-Exit 'delete in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('delete', (Join-Path $ws 'a.txt')))
$ws = New-Workspace
Assert-Exit 'delete in -w workdir allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('delete', (Join-Path $ws 'a.txt')))

$ws = New-Workspace
Assert-Exit 'mkdir in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('mkdir', (Join-Path $ws 'newdir')))
$ws = New-Workspace
Assert-Exit 'mkdir in -w workdir allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('mkdir', (Join-Path $ws 'newdir')))

$ws = New-Workspace
Assert-Exit 'rmdir in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('rmdir', (Join-Path $ws 'sub')))
$ws = New-Workspace
Assert-Exit 'rmdir in -w workdir allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('rmdir', (Join-Path $ws 'sub')))

# --- rename (Win32 and handle-based) ---------------------------------------
$ws = New-Workspace
Assert-Exit 'rename within -w workdir allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) `
        @('rename', (Join-Path $ws 'src.txt'), (Join-Path $ws 'dst.txt')))
$ws = New-Workspace
Assert-Exit 'rename to -b-blocked dest denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', (Join-Path $ws 'dst.txt')) `
        @('rename', (Join-Path $ws 'src.txt'), (Join-Path $ws 'dst.txt')))

# Handle-based rename (SetFileInformationByHandle + FILE_RENAME_INFO) is the
# path Bazel's own filesystem uses; it must enforce like a plain rename.
$ws = New-Workspace
Assert-Exit 'handle-rename within -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) `
        @('renameh', (Join-Path $ws 'src.txt'), (Join-Path $ws 'dsth.txt')))
$ws = New-Workspace
Assert-Exit 'handle-rename to -b-blocked dest denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', (Join-Path $ws 'dsth.txt')) `
        @('renameh', (Join-Path $ws 'src.txt'), (Join-Path $ws 'dsth.txt')))

# --- copy / hardlink --------------------------------------------------------
$ws = New-Workspace
Assert-Exit 'copy to -b-blocked dest denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', (Join-Path $ws 'cpy.txt')) `
        @('copy', (Join-Path $ws 'src.txt'), (Join-Path $ws 'cpy.txt')))
$ws = New-Workspace
Assert-Exit 'copy to -w dest allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws) `
        @('copy', (Join-Path $ws 'src.txt'), (Join-Path $ws 'cpy.txt')))

# probe usage is: hardlink <newlink> <existing>.
$ws = New-Workspace
Assert-Exit 'hardlink within -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws) `
        @('hardlink', (Join-Path $ws 'hl.txt'), (Join-Path $ws 'src.txt')))

# --- alternate deletion / mutation mechanisms -------------------------------
# Beyond DeleteFileW, modern runtimes delete through other APIs the engine hooks
# separately. Each must enforce like a plain write: denied under a read-only -r
# scope, allowed under -w. A rewrite that forgets one of these would silently let
# a read-only scope be mutated, so pin them here.

# Handle-based delete (SetFileInformationByHandle + FILE_DISPOSITION_INFO) - the
# path .NET's File.Delete uses.
$ws = New-Workspace
Assert-Exit 'handle-delete under -r denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('deleteh', (Join-Path $ws 'a.txt')))
$ws = New-Workspace
Assert-Exit 'handle-delete under -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('deleteh', (Join-Path $ws 'a.txt')))

# Delete-on-close (CreateFile with FILE_FLAG_DELETE_ON_CLOSE) - a common temp
# idiom; the delete intent rides on the DELETE-access open.
$ws = New-Workspace
Assert-Exit 'delete-on-close under -r denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('delonclose', (Join-Path $ws 'a.txt')))
$ws = New-Workspace
Assert-Exit 'delete-on-close under -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('delonclose', (Join-Path $ws 'a.txt')))

# Atomic replace (ReplaceFileW) - editors/tools use it for safe saves.
$ws = New-Workspace
Assert-Exit 'replace to -b-blocked target denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws, '-b', (Join-Path $ws 'keep.txt')) `
        @('replace', (Join-Path $ws 'keep.txt'), (Join-Path $ws 'src.txt')))
$ws = New-Workspace
Assert-Exit 'replace within -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws, '-w', $ws) `
        @('replace', (Join-Path $ws 'keep.txt'), (Join-Path $ws 'src.txt')))

# Directory rename (MoveFileExW on a directory, not a file) is enforced like any
# other mutation: allowed under -w, denied under a read-only -r scope.
$ws = New-Workspace
Assert-Exit 'directory rename within -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('rename', (Join-Path $ws 'sub'), (Join-Path $ws 'subx')))
$ws = New-Workspace
Assert-Exit 'directory rename under -r denied' 10 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('rename', (Join-Path $ws 'sub'), (Join-Path $ws 'subx')))

# --- attribute queries, ANSI variants, native NtCreateFile -----------------
$ws = New-Workspace
Assert-Exit 'stat in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('stat', (Join-Path $ws 'a.txt')))
Assert-Exit 'stat under -r allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('stat', (Join-Path $ws 'a.txt')))
Assert-Exit 'statA in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('stata', (Join-Path $ws 'a.txt')))
Assert-Exit 'readA in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('reada', (Join-Path $ws 'a.txt')))
Assert-Exit 'readA under -r allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('reada', (Join-Path $ws 'a.txt')))

# The native NtCreateFile syscall (bypassing the Win32 wrapper) is enforced
# identically - the engine hooks the Nt* layer, not just kernel32.
Assert-Exit 'native NtCreateFile in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('ntread', (Join-Path $ws 'a.txt')))
Assert-Exit 'native NtCreateFile under -r allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('ntread', (Join-Path $ws 'a.txt')))

# --- GetTempFileName --------------------------------------------------------
$ws = New-Workspace
Assert-Exit 'GetTempFileName in -w allowed' 0 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('tempfile', $ws))
Assert-Exit 'GetTempFileName in denied workdir denied' 10 `
    (Invoke-Sandbox @('-W', $ws) @('tempfile', $ws))

# --- absent-file probing ----------------------------------------------------
# Opening a NON-existent file for read reports FILE_NOT_FOUND (other error, 20)
# under BOTH read-only and writable scopes, because the read scopes carry
# Policy_AllowReadIfNonExistent. This matches the linux default sandbox (and
# local execution), where probing an optional input that is absent yields ENOENT
# rather than a spurious ACCESS_DENIED. Build tools that probe for optional
# inputs (node module resolution, OpenSSL config, etc.) rely on this.
$ws = New-Workspace
Assert-Exit 'read absent file under -r reports not-found' 20 `
    (Invoke-Sandbox @('-W', $ws, '-r', $ws) @('read', (Join-Path $ws 'nope.txt')))
Assert-Exit 'read absent file under -w reports not-found' 20 `
    (Invoke-Sandbox @('-W', $ws, '-w', $ws) @('read', (Join-Path $ws 'nope.txt')))

Complete-Harness
