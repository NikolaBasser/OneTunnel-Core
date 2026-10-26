param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSHA256,
    [Parameter(Mandatory=$true)][string]$ResultPath,
    [ValidateRange(20,30)][int]$DurationSeconds=25
)
$ErrorActionPreference='Stop'
# Reuse the reviewed marker orchestration; permit mode remains explicit and cannot block traffic.
& (Join-Path $PSScriptRoot 'Run-MarkerProof.ps1') @PSBoundParameters -PermitOnly
