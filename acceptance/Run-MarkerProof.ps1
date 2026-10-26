param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSHA256,
    [Parameter(Mandatory=$true)][string]$ResultPath,
    [ValidateRange(20,30)][int]$DurationSeconds=25,
    [switch]$PermitOnly
)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (!([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this marker proof from an elevated administrator session.' }
if (![IO.Path]::IsPathRooted($ResultPath)) { throw 'ResultPath must be absolute.' }
$resultFull=[IO.Path]::GetFullPath($ResultPath)
$resultParent=[IO.Path]::GetDirectoryName($resultFull)
if (!(Test-Path -LiteralPath $resultParent -PathType Container)) { throw 'Result directory must already exist.' }
if (Test-Path -LiteralPath $resultFull) { throw 'Refusing to overwrite prior evidence.' }
$sealedBase=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'OneTunnelAcceptance'
if ($resultFull.StartsWith($sealedBase+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'ResultPath must be outside sealed run roots.' }
$source=(Resolve-Path -LiteralPath $Executable).ProviderPath
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSHA256) { throw 'Source binary hash mismatch.' }
if (!('OneTunnelMarkerProof.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace OneTunnelMarkerProof {
 public static class Native {
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool TerminateProcess(SafeProcessHandle process, uint code);
 }
}
'@
}
$results=New-Object Collections.Generic.List[object]
$overall='failed'
$resultStream=[IO.File]::Open($resultFull,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
function Save-Evidence {
    $scope='marker-only; no WFP filters, adapters, routes, DNS, services or registry changes'
    if ($PermitOnly) { $scope='permit-only; four scoped loopback permits; no deny, adapters, routes, DNS, services or registry changes' }
    $text=[pscustomobject]@{Version=1;UTC=[DateTime]::UtcNow.ToString('o');Scope=$scope;ExecutableSHA256=$ExpectedSHA256;Outcome=$overall;Cases=@($results.ToArray())} | ConvertTo-Json -Depth 8
    $bytes=[Text.Encoding]::UTF8.GetBytes($text)
    $resultStream.Position=0
    $resultStream.SetLength(0)
    $resultStream.Write($bytes,0,$bytes.Length)
    $resultStream.Flush($true)
}
function Read-Json([string]$Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json }
function Get-PrincipalSid([string]$Name) {
    if ($Name -like 'S-1-*') { return ([Security.Principal.SecurityIdentifier]$Name).Value }
    return ([Security.Principal.NTAccount]::new($Name)).Translate([Security.Principal.SecurityIdentifier]).Value
}
function Assert-ExactTask($Run) {
    $task=Get-ScheduledTask -TaskName $Run.Task
    $expectedExe=Join-Path $Run.Root 'OneTunnel.Acceptance.exe'
    $expectedArgs='--mode fallback --plan "'+(Join-Path $Run.Root 'plan.json')+'"'
    if ((Get-PrincipalSid $task.Principal.UserId) -ne 'S-1-5-18' -or @($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $expectedExe -or $task.Actions[0].Arguments -ne $expectedArgs) { throw 'Exact run task identity mismatch.' }
    return $task
}
function Assert-ProcessGone([int]$ProcessId,[long]$CreationTicks,[string]$ExpectedImage) {
    $until=[DateTime]::UtcNow.AddSeconds(3)
    while ([DateTime]::UtcNow -lt $until) {
        try { $observed=Get-Process -Id $ProcessId -ErrorAction Stop }
        catch {
	    if ($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenId*' -and $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return }
            throw
        }
        if ($observed.HasExited) { return }
        $observedImage=$observed.Path
        $observedTicks=$observed.StartTime.ToUniversalTime().Ticks
        if ([string]::IsNullOrWhiteSpace($observedImage) -or $observedTicks -le 0) { throw 'Process identity unavailable; termination proof is inconclusive.' }
        if ($observedTicks -ne $CreationTicks -or $observedImage -ne $ExpectedImage) { return }
        Start-Sleep -Milliseconds 100
    }
    throw 'Expected run process remains alive.'
}
function Inspect-ExactRun($Run,$Plan,[bool]$ExpectedPresent) {
    $image=Join-Path $Run.Root 'OneTunnel.Acceptance.exe'
    $inspection=& $image --mode inspect --plan (Join-Path $Run.Root 'plan.json')
    if ($LASTEXITCODE -ne 0) { throw 'Read-only exact-run WFP inspection failed; fallback remains armed.' }
    $view=($inspection -join [Environment]::NewLine) | ConvertFrom-Json
    if ($view.RunID -ne $Run.RunId -or $view.Provider -ne $Plan.Provider -or $view.ExpectedFingerprint -ne $Plan.Fingerprint -or $view.Present -ne $ExpectedPresent) { throw 'Exact-run WFP inventory scope/presence mismatch.' }
    if ($ExpectedPresent -and (!$view.Recoverable -or $view.RootFingerprint -ne $Plan.Fingerprint -or $view.Filters -ne 4 -or $view.Sublayers -ne 1)) { throw 'Permit-only WFP inventory shape/fingerprint mismatch; fallback remains armed.' }
    if (!$ExpectedPresent -and ($view.Filters -ne 0 -or $view.Sublayers -ne 0)) { throw 'Unexpected residual exact-run objects.' }
    return $view
}
try {
    $cases=@('fallback-only','inspection-failure','guardian-killed')
    if ($PermitOnly) { $cases=@('inspection-failure','guardian-killed') }
    foreach ($caseName in $cases) {
        $arguments=@{Executable=$source;ExpectedSHA256=$ExpectedSHA256;DurationSeconds=$DurationSeconds;Deploy=$true}
        if ($PermitOnly) { $arguments.PermitOnly=$true }
        if ($caseName -ne 'fallback-only') { $arguments.LaunchGuardian=$true }
        if ($caseName -eq 'inspection-failure') { $arguments.InspectionFault=$true }
        $output=& (Join-Path $PSScriptRoot 'Deploy-MarkerCanary.ps1') @arguments
        $run=($output -join [Environment]::NewLine) | ConvertFrom-Json
        $record=[ordered]@{Case=$caseName;RunId=$run.RunId;Root=$run.Root;Task=$run.Task;Deadline=$run.Deadline;Outcome='started';TaskDisabled=$false}
        $results.Add($record)
        Save-Evidence
        $task=Assert-ExactTask $run
        $plan=Read-Json (Join-Path $run.Root 'plan.json')
        $expectedMode='marker'; if ($PermitOnly) { $expectedMode='permit' }
        if ($plan.WorkerMode -ne $expectedMode) { throw 'Protected worker mode mismatch.' }
        $proof=Read-Json (Join-Path $run.Root 'fallback-ready.json')
        $proofAge=([DateTime]::UtcNow-([DateTimeOffset]::Parse($proof.UTC)).UtcDateTime).TotalSeconds
        if ($proof.RunID -ne $run.RunId -or $proof.SHA256 -ne $ExpectedSHA256 -or $proof.BootID -ne $plan.BootID -or $proof.Principal -ne 'S-1-5-18' -or $proofAge -lt 0 -or $proofAge -gt 3) { throw 'Fresh SYSTEM fallback acknowledgement missing.' }
        $guardProcess=$null
        $guardTicks=0L
        $workerProcessId=0
        $workerTicks=0L
        $expectedImage=Join-Path $run.Root 'OneTunnel.Acceptance.exe'
        $heartbeatPath=Join-Path $run.Root 'worker-heartbeat.json'
        if ($caseName -ne 'fallback-only') {
            $guardProcess=Get-Process -Id ([int]$run.GuardianPid)
            $guardTicks=$guardProcess.StartTime.ToUniversalTime().Ticks
            if ($guardProcess.Path -ne $expectedImage) { throw 'Guardian image identity mismatch.' }
            $heartbeatDeadline=[DateTime]::UtcNow.AddSeconds(5)
            while (!(Test-Path -LiteralPath $heartbeatPath) -and [DateTime]::UtcNow -lt $heartbeatDeadline) { Start-Sleep -Milliseconds 100 }
            if (!(Test-Path -LiteralPath $heartbeatPath)) { throw 'Contained worker heartbeat not observed.' }
            $heartbeat=Read-Json $heartbeatPath
            $workerProcessId=[int]$heartbeat.PID
            $workerProcess=Get-Process -Id $workerProcessId
            $workerTicks=$workerProcess.StartTime.ToUniversalTime().Ticks
            if ($workerProcess.Path -ne $expectedImage) { throw 'Worker image identity mismatch.' }
        }
        if ($PermitOnly) {
            $created=Read-Json (Join-Path $run.Root 'permit-created.json')
            if ($created.RunID -ne $run.RunId -or $created.Provider -ne $plan.Provider -or $created.Fingerprint -ne $plan.Fingerprint -or $created.Filters -ne 4 -or $created.Sublayers -ne 1) { throw 'One-shot permit installation evidence mismatch.' }
            $null=Inspect-ExactRun $run $plan $true
            $record.PermitObjectsVerifiedBeforeDeadline=$true
        }
        if ($caseName -eq 'guardian-killed') {
            # Capture the native handle before identity comparison; terminate that handle, never a recycled PID.
            $safeHandle=$guardProcess.SafeHandle
            $guardProcess.Refresh()
            if ($guardProcess.HasExited -or $guardProcess.StartTime.ToUniversalTime().Ticks -ne $guardTicks -or $guardProcess.Path -ne $expectedImage) { throw 'Guardian identity unavailable/changed; fallback stays armed and no process is killed.' }
            if (![OneTunnelMarkerProof.Native]::TerminateProcess($safeHandle,91)) { throw 'Exact guardian-handle termination failed; fallback remains armed.' }
            $record.GuardianKilled=$true
            Assert-ProcessGone $workerProcessId $workerTicks $expectedImage
            if ([DateTime]::UtcNow -ge ([DateTimeOffset]::Parse($run.Deadline)).UtcDateTime) { throw 'Worker death observed after deadline; kill-on-job-close proof is inconclusive.' }
            $record.JobCloseStoppedWorkerBeforeDeadline=$true
            if ($PermitOnly) {
                $null=Inspect-ExactRun $run $plan $true
                if ([DateTime]::UtcNow -ge ([DateTimeOffset]::Parse($run.Deadline)).UtcDateTime) { throw 'Persistent-permit observation reached deadline; proof is inconclusive.' }
                $record.PermitsPersistedAfterGuardianDeath=$true
            }
        }
        $recoveredPath=Join-Path $run.Root 'recovered.json'
        $waitUntil=([DateTimeOffset]::Parse($run.Deadline)).UtcDateTime.AddSeconds(15)
        while (!(Test-Path -LiteralPath $recoveredPath) -and [DateTime]::UtcNow -lt $waitUntil) { Start-Sleep -Milliseconds 100 }
        if (!(Test-Path -LiteralPath $recoveredPath)) { throw 'Bounded scoped recovery proof missing; task deliberately remains armed.' }
        $recovered=Read-Json $recoveredPath
        if ($recovered.RunID -ne $run.RunId -or $recovered.Provider -ne $plan.Provider -or ([DateTimeOffset]::Parse($recovered.UTC)).UtcDateTime -lt ([DateTimeOffset]::Parse($plan.Created)).UtcDateTime) { throw 'Recovered evidence does not identify this run.' }
        if ($PermitOnly) {
            if ($recovered.WorkerMode -ne 'permit') { throw 'Recovery evidence worker mode mismatch.' }
            $null=Inspect-ExactRun $run $plan $false
            $record.PermitObjectsVerifiedAbsent=$true
        }
        # Re-run the trusted, exact-scope expected-fingerprint transaction. It verifies absence/fresh matching ownership without SCM.
        & $expectedImage --mode recover --plan (Join-Path $run.Root 'plan.json')
        if ($LASTEXITCODE -ne 0) { throw 'Fresh exact-scope idempotent recovery verification failed; task remains armed.' }
        if ($caseName -ne 'fallback-only') {
            Assert-ProcessGone ([int]$run.GuardianPid) $guardTicks $expectedImage
            Assert-ProcessGone $workerProcessId $workerTicks $expectedImage
            $lastHeartbeat=Get-Item -LiteralPath $heartbeatPath
            $lastTicks=$lastHeartbeat.LastWriteTimeUtc.Ticks
            Start-Sleep -Milliseconds 500
            if ((Get-Item -LiteralPath $heartbeatPath).LastWriteTimeUtc.Ticks -ne $lastTicks) { throw 'Worker heartbeat continued after recovery.' }
        }
        if ($caseName -eq 'inspection-failure') {
            $events=Get-Content -LiteralPath (Join-Path $run.Root 'events.jsonl') | ForEach-Object { $_ | ConvertFrom-Json }
            if (!($events | Where-Object Kind -eq 'injected-worker-identity-unavailable')) { throw 'Inspection-failure canary did not exercise its fault marker.' }
        }
        $task=Assert-ExactTask $run
        Disable-ScheduledTask -TaskName $run.Task | Out-Null
        $task=Assert-ExactTask $run
        if ($task.State -ne 'Disabled') { throw 'Exact verified-clean task was not disabled.' }
        $record.Outcome='passed'
        $record.TaskDisabled=$true
        $record.RecoveredUTC=$recovered.UTC
        Save-Evidence
    }
    $overall='passed'
} catch {
    $results.Add([pscustomobject]@{Case='orchestration';Outcome='failed';Error=$_.Exception.Message})
    throw
} finally {
    try { Save-Evidence } finally { $resultStream.Dispose() }
}
