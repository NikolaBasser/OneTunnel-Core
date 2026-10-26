param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$isAdmin) {
    $self = Join-Path $PSScriptRoot 'Start-Recovery.ps1'
    $child=Start-Process powershell.exe -Verb RunAs -WindowStyle Normal -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $self + '"'),'-Elevated') -Wait -PassThru
    exit $child.ExitCode
}
$binary = Join-Path $PSScriptRoot 'OneTunnel.Recover.exe'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
    $binary = Join-Path $PSScriptRoot 'arm64\OneTunnel.Recover.exe'
}
$logRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'OneTunnel-Recovery'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$logPath = Join-Path $logRoot ('recovery-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.txt')
$exitCode=0
try {
    Write-Host 'OneTunnel offline emergency recovery'
    Write-Host 'This removes OneTunnel traffic protection and stops OneTunnelCore.'
    & $binary --scan 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) { throw 'WFP inventory failed; no removal attempted.' }
    & $binary --recover-all --stop-service 2>&1 | Tee-Object -FilePath $logPath -Append
    if ($LASTEXITCODE -ne 0) { throw 'Recovery failed. Review the log; no global firewall reset was performed.' }
    Write-Host 'Completed. The utility did not use the internet or modify VPN profiles.'
} catch {
    $exitCode=1
    $_.Exception.Message | Tee-Object -FilePath $logPath -Append | Write-Host
} finally {
    Write-Host ('Log: ' + $logPath)
    Read-Host 'Press Enter to close' | Out-Null
}
exit $exitCode
