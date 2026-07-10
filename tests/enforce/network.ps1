# Network sandboxing via -N (loopback only) and -n (no network). The probe
# 'connect' op returns 0 when the sandbox permits the attempt (even if the
# connection is refused, since nothing is listening) and 10 when the sandbox
# blocks it. Port 9 (discard) on loopback is refused instantly, so no real
# network or listener is required; external blocks are denied by our hooks
# before any I/O, so they never touch the network.

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
    -TempDir $TempDir -Suite 'network'

Assert-Exit 'default allows loopback connect' 0 `
    (Invoke-Sandbox @() @('connect', '127.0.0.1', '9'))

Assert-Exit '-N allows loopback connect' 0 `
    (Invoke-Sandbox @('-N') @('connect', '127.0.0.1', '9'))
Assert-Exit '-N blocks external connect' 10 `
    (Invoke-Sandbox @('-N') @('connect', '8.8.8.8', '53'))

Assert-Exit '-n blocks loopback connect' 10 `
    (Invoke-Sandbox @('-n') @('connect', '127.0.0.1', '9'))
Assert-Exit '-n blocks external connect' 10 `
    (Invoke-Sandbox @('-n') @('connect', '8.8.8.8', '53'))

# Network policy propagates to grandchildren (probe spawns probe).
Assert-Exit '-N network policy propagates to child' 10 `
    (Invoke-Sandbox @('-N') @('spawn', (Get-Probe), 'connect', '8.8.8.8', '53'))

# File enforcement still works alongside a network policy.
Assert-Exit '-n still allows reading the tool' 0 `
    (Invoke-Sandbox @('-n') @('read', (Get-Probe)))

Complete-Harness
