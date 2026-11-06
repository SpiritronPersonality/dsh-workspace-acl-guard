# Minimal reproduction helper for dsh-workspace-acl-guard.
#
# Captures a directory's security descriptor (DACL + integrity label) before and
# after a DSH `workspace-write` session, and prints the difference.
#
# It NEVER writes an ACL: it only reads, prints, and tells you which commands to
# run yourself if you want to undo the change.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File docs\REPRODUCE.ps1 -Path "C:\Users\me\Desktop"
#   powershell -ExecutionPolicy Bypass -File docs\REPRODUCE.ps1 -Path "C:\work" -Out "C:\tmp\repro"

[CmdletBinding()]
param(
    [string]$Path = "$env:USERPROFILE\Desktop",
    [string]$Out = "$env:TEMP\acl-repro"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Path does not exist: $Path"
}

$probe = Join-Path (Split-Path -Parent $PSScriptRoot) 'assets\acl-probe.ps1'
if (-not (Test-Path -LiteralPath $probe)) {
    throw "Probe script not found next to this repository: $probe"
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Capture([string]$Tag) {
    $json = ConvertTo-Json -InputObject @($Path) -Compress
    $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $file = Join-Path $Out "probe-$Tag.json"
    $arguments = @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $probe, '-PathsBase64', $base64
    )
    $process = Start-Process powershell.exe -ArgumentList $arguments `
        -RedirectStandardOutput $file -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Probe exited with $($process.ExitCode); see $file"
    }
    return (Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Show-Record([string]$Title, $Record) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
    Write-Host ("path       : {0}" -f $Record.path)
    Write-Host ("owner      : {0} (self={1})" -f $Record.owner, $Record.ownerIsSelf)
    Write-Host ("writeDAC   : {0}   writeOwner: {1}" -f $Record.writeDac, $Record.writeOwner)
    Write-Host ("label      : {0}   protected : {1}" -f $Record.label, $Record.protected)
    Write-Host ("role       : {0}" -f $Record.role)
    Write-Host ("SDDL       : {0}" -f $Record.sddl)
}

function Get-AceSet([string]$Sddl) {
    if ([string]::IsNullOrEmpty($Sddl)) { return @() }
    return @([regex]::Matches($Sddl, '\([^)]+\)') | ForEach-Object { $_.Value })
}

Write-Host "Baseline capture for: $Path"
$before = Capture 'before'
Show-Record 'BEFORE' $before

Write-Host ""
Write-Host "Now do the reproduction:" -ForegroundColor Yellow
Write-Host "  1. open DSH, set the workspace to: $Path"
Write-Host "  2. run one write / rename command in that session"
Write-Host "  3. close the session"
Write-Host ""
Read-Host "Press Enter to capture the AFTER state"

$after = Capture 'after'
Show-Record 'AFTER' $after

$beforeAces = Get-AceSet $before.sddl
$afterAces = Get-AceSet $after.sddl
$added = @($afterAces | Where-Object { $beforeAces -notcontains $_ })
$removed = @($beforeAces | Where-Object { $afterAces -notcontains $_ })

Write-Host ""
Write-Host "== DIFF ==" -ForegroundColor Cyan
Write-Host ("SDDL changed : {0}" -f ($before.sddl -ne $after.sddl))
if ($added.Count -eq 0 -and $removed.Count -eq 0) {
    Write-Host "No ACE difference detected."
} else {
    foreach ($ace in $added) { Write-Host ("+ {0}" -f $ace) -ForegroundColor Red }
    foreach ($ace in $removed) { Write-Host ("- {0}" -f $ace) -ForegroundColor Green }
}

$capabilities = @([regex]::Matches([string]$after.sddl, 'S-1-4-\d+-\d+') |
    ForEach-Object { $_.Value } | Select-Object -Unique)

if ($capabilities.Count -gt 0) {
    Write-Host ""
    Write-Host "Capability SIDs found after the run:" -ForegroundColor Yellow
    foreach ($sid in $capabilities) { Write-Host "  $sid" }

    Write-Host ""
    Write-Host "Cleanup (NOT executed by this script):" -ForegroundColor Yellow
    Write-Host "  icacls `"$Path`" /remove:d Everyone"
    foreach ($sid in $capabilities) {
        Write-Host "  icacls `"$Path`" /remove:g *$sid"
    }
    Write-Host "  icacls `"$Path`" /inheritance:e"
    Write-Host "  (then rebuild the icon cache or restart Explorer)"
}

Write-Host ""
Write-Host "Evidence kept in: $Out"
Write-Host "This script wrote no ACL."
