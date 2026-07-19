<#
.SYNOPSIS
    Opt-in end-to-end test of the write-overlay VFS (--write-overlay) against a
    broad matrix of REAL tools: native Windows shells + utilities, PowerShell
    (7 and Windows 5.1), Microsoft/uutils coreutils, msys2 GNU coreutils, and the
    common language toolchains (python, node, java/javac, dotnet).

.DESCRIPTION
    This is intentionally NOT part of `bazel test //tests:all`. The committed
    enforcement suites under tests/enforce/ drive only the synthetic `probe`
    binary, which cannot reproduce the OS-API patterns real tools exercise:
    libuv's NT readdir, python's os.scandir loop, the JVM class loader's
    per-component path canonicalization, Rust std::fs::copy's CopyFileExW, the
    .NET runtime's File.Copy, GNU vs uutils cp, etc. Every one of these families
    has shaken out a genuine overlay bug the probe suite missed - among them:

      * python os.scandir  -> a stale last-error (WinError 203) leaked from the
        overlay enum-snapshot builder, turning end-of-enumeration into an OSError.
      * java class loading  -> in-cone classpath entries canonicalized into the
        backing store (FindFirstFile returned the BACKING dir's name for the cone
        root), breaking class resolution.
      * CopyFile / CopyFileEx  -> the kernel copy opened the source and wrote the
        destination itself, so the overlay never saw those opens: an overlay-only
        source was NOT_FOUND and the destination LEAKED onto the real execroot
        (hit by uutils cp / Rust std::fs::copy, native `copy`, node fs.copyFileSync,
        .NET File.Copy).

    Real tools live at machine-specific absolute paths and are not hermetic, so
    this script discovers each dynamically and SKIPS any that are absent rather
    than failing. Run it manually (or in a CI lane that installs the tools).

    Each case runs a small file/directory workflow - create a dir, write a file,
    LIST the dir, COPY the file, READ the copy back, (some also SEARCH) - inside a
    SINGLE sandbox invocation (the backing store is process-private and per
    invocation, so a write and its read-back must share one invocation). Success
    is asserted three ways:
      1. the read-back marker appears in the output (overlay read-after-write);
      2. the listing shows the created file (overlay enumeration splice);
      3. the real execroot is byte-for-byte unchanged (every write was redirected
         into the backing store and nothing leaked onto disk).

.PARAMETER Sandbox
    Path to BazelSandbox.exe (with DetoursServices.dll beside it). Defaults to the
    repo's bazel-bin\BazelSandbox.exe.

.PARAMETER KeepArtifacts
    Keep the per-case temp workspaces instead of cleaning them up.

.EXAMPLE
    pwsh tests/e2e/realtools.ps1

.NOTES
    Exit codes: 0 = all discovered tools passed, 1 = a case failed,
    2 = missing prerequisite (sandbox/dll), 3 = no real tools were found (skipped).
#>
[CmdletBinding()]
param(
    [string]$Sandbox,
    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$script:Passed  = 0
$script:Failed  = 0
$script:Skipped = 0

function Pass { param([string]$Name) Write-Host ("  PASS  {0}" -f $Name); $script:Passed++ }
function Fail {
    param([string]$Name, [string]$Detail = '')
    Write-Host ("  FAIL  {0}{1}" -f $Name, $(if ($Detail) { " - $Detail" } else { '' }))
    $script:Failed++
}
function Skip { param([string]$Name, [string]$Why) Write-Host ("  SKIP  {0} - {1}" -f $Name, $Why); $script:Skipped++ }

# --- Resolve the sandbox binary --------------------------------------------
if ([string]::IsNullOrEmpty($Sandbox)) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $Sandbox = Join-Path $repoRoot 'bazel-bin\BazelSandbox.exe'
}
if (-not (Test-Path -LiteralPath $Sandbox)) {
    Write-Error "BazelSandbox.exe not found: $Sandbox (build //:BazelSandbox first)"; exit 2
}
$script:Sandbox = (Resolve-Path -LiteralPath $Sandbox).Path
$dll = Join-Path (Split-Path -Parent $script:Sandbox) 'DetoursServices.dll'
if (-not (Test-Path -LiteralPath $dll)) {
    Write-Error "DetoursServices.dll not found beside the sandbox: $dll"; exit 2
}

# --- Tool discovery ---------------------------------------------------------
function Resolve-Tool {
    param([string]$Name, [string[]]$Fallbacks = @())
    $c = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
         Where-Object { $_.Path } | Select-Object -First 1
    if ($c) { return $c.Path }
    foreach ($f in $Fallbacks) {
        if ($f -and (Test-Path -LiteralPath $f)) { return (Resolve-Path -LiteralPath $f).Path }
    }
    return $null
}
# Return a tool bin directory only if it actually holds the named applets.
function Resolve-AppletDir {
    param([string[]]$Dirs, [string[]]$Applets)
    foreach ($d in $Dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $ok = $true
        foreach ($a in $Applets) { if (-not (Test-Path -LiteralPath (Join-Path $d $a))) { $ok = $false; break } }
        if ($ok) { return (Resolve-Path -LiteralPath $d).Path }
    }
    return $null
}

$sys = Join-Path $env:SystemRoot 'System32'
$script:cmdExe  = Resolve-Tool 'cmd'        @((Join-Path $sys 'cmd.exe'))
$script:pwshExe = Resolve-Tool 'pwsh'       @()
$script:wpsExe  = Resolve-Tool 'powershell' @((Join-Path $sys 'WindowsPowerShell\v1.0\powershell.exe'))
$script:nodeExe = Resolve-Tool 'node'       @('C:\Program Files\nodejs\node.exe')
$script:pyExe   = Resolve-Tool 'python'     @('C:\Python314\python.exe')
$script:dotnet  = Resolve-Tool 'dotnet'     @('C:\Program Files\dotnet\dotnet.exe')
$script:tarExe  = Resolve-Tool 'tar'        @((Join-Path $sys 'tar.exe'))
$script:xcopy   = Resolve-Tool 'xcopy'      @((Join-Path $sys 'xcopy.exe'))
$script:curlExe = Resolve-Tool 'curl'       @((Join-Path $sys 'curl.exe'))

# Microsoft/uutils coreutils and msys2 GNU coreutils (individual applets).
$script:uuBin = Resolve-AppletDir @('C:\Program Files\coreutils\bin') @('ls.exe', 'cp.exe', 'cat.exe', 'mkdir.exe')
$script:gnuBin = Resolve-AppletDir @('C:\msys64\usr\bin', 'C:\msys2\usr\bin') @('ls.exe', 'cp.exe', 'cat.exe', 'grep.exe')

# javac + a version-MATCHED java from the same JDK bin dir (mixing a JDK17 javac
# with a JRE8 java yields UnsupportedClassVersion false failures).
$script:javacExe = Resolve-Tool 'javac' @(
    'C:\Program Files\OpenJDK\jdk-17.0.2\bin\javac.exe',
    'C:\Program Files\Microsoft\jdk-17.0.2\bin\javac.exe')
$script:javaExe = $null
if ($script:javacExe) {
    $cand = Join-Path (Split-Path -Parent $script:javacExe) 'java.exe'
    if (Test-Path -LiteralPath $cand) { $script:javaExe = $cand }
}

# --- Scratch + helpers ------------------------------------------------------
# Chained multi-command lines can't be passed as one `cmd /c "<line>"` argv
# element: PowerShell + the sandbox's command-line reconstruction backslash-escape
# the embedded quotes (cmd then sees \"tool.exe\" and fails). Write the line to a
# throwaway .bat OUTSIDE the -W cone (so it never perturbs the clean snapshot) and
# invoke `cmd /c <bat>` instead - a single unquoted path argument.
$script:ScratchDir = Join-Path ([System.IO.Path]::GetTempPath()) ('rtscr_' + [guid]::NewGuid().ToString('N').Substring(0, 10))
New-Item -ItemType Directory -Force -Path $script:ScratchDir | Out-Null
function BatCmd {
    param([string]$Line)
    $bat = Join-Path $script:ScratchDir ('c_' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.bat')
    Set-Content -LiteralPath $bat -Value ("@echo off`r`n" + $Line) -Encoding ASCII
    return @($script:cmdExe, '/c', $bat)
}
function Quote { param([string]$s) '"' + $s + '"' }

# Build a tiny .NET console helper ONCE (offline; ~7s) so the dotnet case only pays
# for `dotnet exec` under the sandbox. Exercises Directory.CreateDirectory,
# Directory.GetFiles (list), File.Copy (CopyFileEx) and File.ReadAllText.
$script:DotnetDll = $null
$script:DotnetProj = $null
if ($script:dotnet) {
    $script:DotnetProj = Join-Path $script:ScratchDir 'dnapp'
    New-Item -ItemType Directory -Force -Path $script:DotnetProj | Out-Null
    @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <AssemblyName>ovapp</AssemblyName>
  </PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath (Join-Path $script:DotnetProj 'app.csproj') -Encoding ASCII
    @'
using System;using System.IO;
class P{static void Main(string[] a){
 var d=Path.Combine(a[0],"wd"); Directory.CreateDirectory(d);
 var i=Path.Combine(d,"in.txt"); File.WriteAllText(i,"OVDOTNET");
 var lst=string.Join(",",Directory.GetFiles(d));
 var o=Path.Combine(d,"out.txt"); File.Copy(i,o);
 Console.Write("LIST="+lst+" READ="+File.ReadAllText(o));
}}
'@ | Set-Content -LiteralPath (Join-Path $script:DotnetProj 'Program.cs') -Encoding ASCII
    Push-Location $script:DotnetProj
    & $script:dotnet build -c Release -v q --nologo *> (Join-Path $script:ScratchDir 'dnbuild.log')
    Pop-Location
    $found = Get-ChildItem $script:DotnetProj -Recurse -Filter 'ovapp.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $script:DotnetDll = $found.FullName }
}

function New-Ws {
    $ws = Join-Path ([System.IO.Path]::GetTempPath()) ('rtws_' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force -Path $ws | Out-Null
    return $ws
}
function Snap {
    param([string]$Dir)
    ,(@(Get-ChildItem -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }) | Sort-Object)
}
function Invoke-Overlay {
    param([string]$Ws, [string[]]$ToolCmd)
    $out = Join-Path $script:ScratchDir ('o_' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.log')
    $sbArgs = @('--write-overlay', '-W', $Ws, '--') + $ToolCmd
    & $script:Sandbox @sbArgs *> $out
    $code = $LASTEXITCODE
    $text = ''
    if (Test-Path -LiteralPath $out) {
        $text = (Get-Content -Raw -LiteralPath $out -ErrorAction SilentlyContinue)
        if ($null -eq $text) { $text = '' }
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
    }
    return @{ Code = $code; Out = $text }
}

# PowerShell body shared by pwsh (7) and Windows PowerShell (5.1). %%WS%% is the
# execroot; %%MARK%% the read-back marker. Written to be ConstrainedLanguage-safe
# (cmdlets + primitive-type operators only).
$psBody = @'
$d = Join-Path '%%WS%%' 'wd'
New-Item -ItemType Directory -Force $d | Out-Null
Set-Content -LiteralPath (Join-Path $d 'in.txt') -Value '%%MARK%%'
'LIST=' + ((Get-ChildItem $d).Name -join ',')
Copy-Item -LiteralPath (Join-Path $d 'in.txt') -Destination (Join-Path $d 'out.txt')
'READ=' + (Get-Content -Raw -LiteralPath (Join-Path $d 'out.txt'))
'@

# --- Cases ------------------------------------------------------------------
# Each case: Name, Exe (gating tool path; $null => skip), optional NeedCmd/NeedJavac,
# Seed (places inputs in $ws), Cmd (returns tool arg array), Marker (read-back proof),
# optional ListMarker (must appear -> proves the created file was enumerated).
$cases = @(
    @{  Name = 'native cmd (dir/copy/findstr)'; Exe = $script:cmdExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $d = Join-Path $ws 'wd'
            BatCmd (@(
                ('mkdir {0}' -f (Quote $d)),
                ('echo OVCMD> {0}' -f (Quote (Join-Path $d 'in.txt'))),
                ('dir /b {0}' -f (Quote $d)),
                ('copy /y {0} {1} >nul' -f (Quote (Join-Path $d 'in.txt')), (Quote (Join-Path $d 'out.txt'))),
                ('type {0}' -f (Quote (Join-Path $d 'out.txt'))),
                ('findstr OVCMD {0}' -f (Quote (Join-Path $d 'out.txt')))
            ) -join "`r`n") }
        Marker = 'OVCMD'; ListMarker = 'in.txt' },

    @{  Name = 'pwsh 7 (gci/Copy-Item)'; Exe = $script:pwshExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $sc = $psBody.Replace('%%WS%%', $ws).Replace('%%MARK%%', 'OVPWSH')
            @($script:pwshExe, '-NoProfile', '-NonInteractive', '-Command', $sc) }
        Marker = 'READ=OVPWSH'; ListMarker = 'in.txt' },

    @{  Name = 'windows powershell 5.1 (gci/Copy-Item)'; Exe = $script:wpsExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $sc = $psBody.Replace('%%WS%%', $ws).Replace('%%MARK%%', 'OVWPS')
            @($script:wpsExe, '-NoProfile', '-NonInteractive', '-Command', $sc) }
        Marker = 'READ=OVWPS'; ListMarker = 'in.txt' },

    @{  Name = 'ms coreutils / uutils (ls/cp/cat)'; Exe = $script:uuBin
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $d = Join-Path $ws 'wd'
            BatCmd (@(
                ('{0} {1}' -f (Quote (Join-Path $script:uuBin 'mkdir.exe')), (Quote $d)),
                ('echo OVUU> {0}' -f (Quote (Join-Path $d 'in.txt'))),
                ('{0} {1}' -f (Quote (Join-Path $script:uuBin 'ls.exe')), (Quote $d)),
                ('{0} {1} {2}' -f (Quote (Join-Path $script:uuBin 'cp.exe')), (Quote (Join-Path $d 'in.txt')), (Quote (Join-Path $d 'out.txt'))),
                ('{0} {1}' -f (Quote (Join-Path $script:uuBin 'cat.exe')), (Quote (Join-Path $d 'out.txt')))
            ) -join "`r`n") }
        Marker = 'OVUU'; ListMarker = 'in.txt'
        NeedCmd = $true },

    @{  Name = 'msys2 gnu coreutils (ls/cp/cat/grep)'; Exe = $script:gnuBin
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $d = Join-Path $ws 'wd'; $fd = $d -replace '\\', '/'
            BatCmd (@(
                ('{0} {1}' -f (Quote (Join-Path $script:gnuBin 'mkdir.exe')), (Quote $fd)),
                ('echo OVMSYS> {0}' -f (Quote (Join-Path $d 'in.txt'))),
                ('{0} {1}' -f (Quote (Join-Path $script:gnuBin 'ls.exe')), (Quote $fd)),
                ('{0} {1} {2}' -f (Quote (Join-Path $script:gnuBin 'cp.exe')), (Quote ($fd + '/in.txt')), (Quote ($fd + '/out.txt'))),
                ('{0} {1}' -f (Quote (Join-Path $script:gnuBin 'cat.exe')), (Quote ($fd + '/out.txt'))),
                ('{0} OVMSYS {1}' -f (Quote (Join-Path $script:gnuBin 'grep.exe')), (Quote ($fd + '/out.txt')))
            ) -join "`r`n") }
        Marker = 'OVMSYS'; ListMarker = 'in.txt'
        NeedCmd = $true },

    @{  Name = 'node (mkdir/readdir/copyFile)'; Exe = $script:nodeExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $js = "const fs=require('fs'),p=require('path');const d=p.join(process.argv[1],'wd');" +
                  "fs.mkdirSync(d);const i=p.join(d,'in.txt');fs.writeFileSync(i,'OVNODE');" +
                  "const list=fs.readdirSync(d).sort().join(',');const o=p.join(d,'out.txt');" +
                  "fs.copyFileSync(i,o);process.stdout.write('LIST='+list+' READ='+fs.readFileSync(o,'utf8'));"
            @($script:nodeExe, '-e', $js, $ws) }
        Marker = 'READ=OVNODE'; ListMarker = 'in.txt' },

    @{  Name = 'python (mkdir/scandir/shutil.copy)'; Exe = $script:pyExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $py = "import os,sys,shutil`n" +
                  "d=os.path.join(sys.argv[1],'wd');os.mkdir(d)`n" +
                  "i=os.path.join(d,'in.txt');open(i,'w').write('OVPY')`n" +
                  "lst=','.join(sorted(e.name for e in os.scandir(d)))`n" +
                  "o=os.path.join(d,'out.txt');shutil.copy(i,o)`n" +
                  "print('LIST='+lst+' READ='+open(o).read())`n"
            @($script:pyExe, '-c', $py, $ws) }
        Marker = 'READ=OVPY'; ListMarker = 'in.txt' },

    @{  Name = 'java (load class from in-cone -cp)'; Exe = $script:javaExe
        Seed = { param($ws)
            'public class T { public static void main(String[] a){ System.out.println("T-OK"); } }' |
                Set-Content -LiteralPath (Join-Path $ws 'T.java') -Encoding ASCII
            & $script:javacExe -d $ws (Join-Path $ws 'T.java') 2>&1 | Out-Null }
        Cmd  = { param($ws) @($script:javaExe, '-cp', $ws, 'T') }
        Marker = 'T-OK'
        NeedJavac = $true },

    @{  Name = 'javac (compile into overlay) + java run'; Exe = $script:javaExe
        Seed = { param($ws)
            'public class U { public static void main(String[] a){ System.out.println("U-OK"); } }' |
                Set-Content -LiteralPath (Join-Path $ws 'U.java') -Encoding ASCII }
        Cmd  = { param($ws)
            $line = ('{0} -d {1} {2} && {3} -cp {1} U' -f `
                (Quote $script:javacExe), (Quote $ws), (Quote (Join-Path $ws 'U.java')), (Quote $script:javaExe))
            BatCmd $line }
        Marker = 'U-OK'
        NeedJavac = $true; NeedCmd = $true },

    @{  Name = 'dotnet (CreateDirectory/GetFiles/File.Copy)'; Exe = $script:DotnetDll
        Seed = { param($ws) }
        Cmd  = { param($ws) @($script:dotnet, 'exec', $script:DotnetDll, $ws) }
        Marker = 'READ=OVDOTNET'; ListMarker = 'in.txt' },

    @{  Name = 'tar (create+extract in cone)'; Exe = $script:tarExe
        Seed = { param($ws)
            New-Item -ItemType Directory -Force -Path (Join-Path $ws 'src') | Out-Null
            'OVTAR' | Set-Content -LiteralPath (Join-Path $ws 'src\hello.txt') -Encoding ASCII }
        Cmd  = { param($ws)
            $arc = Join-Path $ws 'a.tar'; $ext = Join-Path $ws 'ext'
            $line = ('{0} -cf {1} -C {2} src && mkdir {3} && {0} -xf {1} -C {3} && type {4}' -f `
                (Quote $script:tarExe), (Quote $arc), (Quote $ws), (Quote $ext),
                (Quote (Join-Path $ext 'src\hello.txt')))
            BatCmd $line }
        Marker = 'OVTAR'
        NeedCmd = $true },

    @{  Name = 'xcopy (tree copy in cone)'; Exe = $script:xcopy
        Seed = { param($ws)
            New-Item -ItemType Directory -Force -Path (Join-Path $ws 's') | Out-Null
            'OVXCOPY' | Set-Content -LiteralPath (Join-Path $ws 's\f.txt') -Encoding ASCII }
        Cmd  = { param($ws)
            $line = ('{0} {1} {2} /E /I /Y >nul & type {3}' -f `
                (Quote $script:xcopy), (Quote (Join-Path $ws 's')),
                (Quote ((Join-Path $ws 'd') + '\')), (Quote (Join-Path $ws 'd\f.txt')))
            BatCmd $line }
        Marker = 'OVXCOPY'
        NeedCmd = $true },

    @{  Name = 'curl (file:// into cone)'; Exe = $script:curlExe
        Seed = { param($ws)
            'OVCURL' | Set-Content -LiteralPath (Join-Path $ws 'srcfile.txt') -Encoding ASCII }
        Cmd  = { param($ws)
            $url = 'file:///' + ((Join-Path $ws 'srcfile.txt') -replace '\\', '/')
            $got = Join-Path $ws 'got.txt'
            $line = ('{0} -s -o {1} {2} & type {1}' -f (Quote $script:curlExe), (Quote $got), (Quote $url))
            BatCmd $line }
        Marker = 'OVCURL'
        NeedCmd = $true },

    @{  Name = 'native mklink /H (hardlink in cone)'; Exe = $script:cmdExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $tgt = Join-Path $ws 'tgt.txt'; $lnk = Join-Path $ws 'lnk.txt'
            # The tool WRITES the target first so it lands in the overlay; the hardlink
            # then stays same-volume (both in the backing store). A leak would put the
            # link on the real execroot (cross-volume) and/or dirty the snapshot.
            BatCmd (@(
                ('echo OVHL>{0}' -f (Quote $tgt)),
                ('mklink /H {0} {1} >nul' -f (Quote $lnk), (Quote $tgt)),
                ('dir /b {0}' -f (Quote $ws)),
                ('type {0}' -f (Quote $lnk))
            ) -join "`r`n") }
        Marker = 'OVHL'; ListMarker = 'lnk.txt'
        NeedCmd = $true },

    @{  Name = 'native rmdir (mkdir+rmdir in cone)'; Exe = $script:cmdExe
        Seed = { param($ws) }
        Cmd  = { param($ws)
            $sub = Join-Path $ws 'scratchd'
            # mkdir redirects the dir into the backing store; rmdir must then remove it
            # (symmetric). Without the RemoveDirectory redirect the virtual path has no
            # real dir and rmdir fails -> the marker echo would not run.
            BatCmd (@(
                ('mkdir {0}' -f (Quote $sub)),
                ('rmdir {0}' -f (Quote $sub)),
                'echo RMDIR-OVOK'
            ) -join "`r`n") }
        Marker = 'RMDIR-OVOK'
        NeedCmd = $true }
)

Write-Host ("Sandbox: {0}" -f $script:Sandbox)
Write-Host '--- write-overlay real-tool e2e ---'

foreach ($c in $cases) {
    $needJavac = $c.ContainsKey('NeedJavac') -and $c.NeedJavac
    $needCmd   = $c.ContainsKey('NeedCmd')   -and $c.NeedCmd
    $listMark  = if ($c.ContainsKey('ListMarker')) { $c.ListMarker } else { $null }
    if (-not $c.Exe)                           { Skip $c.Name 'tool not found'; continue }
    if ($needJavac -and -not $script:javacExe) { Skip $c.Name 'javac not found'; continue }
    if ($needCmd   -and -not $script:cmdExe)   { Skip $c.Name 'cmd not found'; continue }

    $ws = New-Ws
    try {
        & $c.Seed $ws
        $before = Snap $ws
        $r = Invoke-Overlay -Ws $ws -ToolCmd (& $c.Cmd $ws)
        $after = Snap $ws

        $hasMarker = ($null -ne $r.Out) -and $r.Out.Contains($c.Marker)
        $hasList   = (-not $listMark) -or (($null -ne $r.Out) -and $r.Out.Contains($listMark))
        $clean = (($before -join '|') -eq ($after -join '|'))

        if ($hasMarker -and $hasList -and $clean) {
            Pass $c.Name
        } else {
            $detail = @()
            if (-not $hasMarker) { $detail += ("marker '{0}' absent (exit {1})" -f $c.Marker, $r.Code) }
            if (-not $hasList)   { $detail += ("listing missing '{0}'" -f $listMark) }
            if (-not $clean) {
                $leaked = @(Compare-Object $before $after | Where-Object { $_.SideIndicator -eq '=>' } |
                            ForEach-Object { $_.InputObject })
                $detail += ('real execroot changed: ' + ($leaked -join ', '))
            }
            Fail $c.Name ($detail -join '; ')
        }
    }
    finally {
        if (-not $KeepArtifacts) { Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Write-Host ('--- {0} passed, {1} failed, {2} skipped ---' -f $script:Passed, $script:Failed, $script:Skipped)

if (-not $KeepArtifacts) { Remove-Item -LiteralPath $script:ScratchDir -Recurse -Force -ErrorAction SilentlyContinue }

if ($script:Failed -gt 0) { exit 1 }
if ($script:Passed -eq 0) { Write-Host 'No real tools were available to test.'; exit 3 }
exit 0
