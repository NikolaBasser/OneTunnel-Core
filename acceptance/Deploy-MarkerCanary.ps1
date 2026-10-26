param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedSHA256,
    [ValidateRange(15,120)][int]$DurationSeconds=60,
    [switch]$InspectionFault,
	[switch]$PermitOnly,
    [switch]$LaunchGuardian,
    [switch]$Deploy
)
$ErrorActionPreference='Stop'
function Get-PrincipalSid([string]$Name) {
    if ($Name -like 'S-1-*') { return ([Security.Principal.SecurityIdentifier]$Name).Value }
    return ([Security.Principal.NTAccount]::new($Name)).Translate([Security.Principal.SecurityIdentifier]).Value
}
if (!$Deploy) { throw 'No changes made. Explicit -Deploy is required. Only marker or explicitly selected permit-only worker is supported.' }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]$identity
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated administrator session.' }
$source=(Resolve-Path -LiteralPath $Executable).ProviderPath
if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse executable refused.' }
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSHA256) { throw 'Source executable hash mismatch.' }
$programData=[Environment]::GetFolderPath('CommonApplicationData')
$base=Join-Path $programData 'OneTunnelAcceptance'
$sddl='O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
function New-PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) { throw ('Refusing preexisting run directory: '+$Path) }
    New-Item -ItemType Directory -Path $Path | Out-Null
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $Path -AclObject $acl
    if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse directory refused.' }
}
if (!(Test-Path -LiteralPath $base)) { New-PrivateDirectory $base }
if ((Get-Item -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse recovery base refused.' }
$runId=[Guid]::NewGuid().ToString('N')
$root=Join-Path $base $runId
New-PrivateDirectory $root
$target=Join-Path $root 'OneTunnel.Acceptance.exe'
Copy-Item -LiteralPath $source -Destination $target
$fileAcl=New-Object Security.AccessControl.FileSecurity
$fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
Set-Acl -LiteralPath $target -AclObject $fileAcl
if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $ExpectedSHA256) { throw 'Protected executable hash mismatch.' }
$plan=Join-Path $root 'plan.json'
$workerMode='marker';if($PermitOnly){$workerMode='permit'}
& $target --mode init --plan $plan --duration $DurationSeconds --worker-mode $workerMode
if ($LASTEXITCODE -ne 0) { throw 'Protected plan initialization refused; no task or worker started.' }
$settings=Get-Content -LiteralPath $plan -Raw | ConvertFrom-Json
$taskName='OneTunnel-Acceptance-'+$runId
$escapedExe=[Security.SecurityElement]::Escape($target)
$escapedArgs=[Security.SecurityElement]::Escape('--mode fallback --plan "'+$plan+'"')
$deadline=([DateTimeOffset]::Parse($settings.Deadline)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
$xml=@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <Triggers>
  <TimeTrigger><Repetition><Interval>PT1M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>$deadline</StartBoundary><Enabled>true</Enabled></TimeTrigger>
  <BootTrigger><Enabled>true</Enabled></BootTrigger>
 </Triggers>
 <Principals><Principal id="System"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><WakeToRun>true</WakeToRun><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings>
 <Actions Context="System"><Exec><Command>$escapedExe</Command><Arguments>$escapedArgs</Arguments><WorkingDirectory>$root</WorkingDirectory></Exec></Actions>
</Task>
"@
function Assert-TaskXml([string]$Text) {
    $document=New-Object Xml.XmlDocument
    $document.XmlResolver=$null
    $document.LoadXml($Text)
    $namespaces=New-Object Xml.XmlNamespaceManager($document.NameTable)
    $namespaces.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task')
    $expected=@{
        '/t:Task/t:Principals/t:Principal/t:UserId'='S-1-5-18'
        '/t:Task/t:Principals/t:Principal/t:RunLevel'='HighestAvailable'
        '/t:Task/t:Triggers/t:BootTrigger/t:Enabled'='true'
        '/t:Task/t:Triggers/t:TimeTrigger/t:Enabled'='true'
        '/t:Task/t:Triggers/t:TimeTrigger/t:Repetition/t:Interval'='PT1M'
        '/t:Task/t:Triggers/t:TimeTrigger/t:StartBoundary'=$deadline
        '/t:Task/t:Settings/t:StartWhenAvailable'='true'
        '/t:Task/t:Settings/t:RunOnlyIfNetworkAvailable'='false'
        '/t:Task/t:Settings/t:DisallowStartIfOnBatteries'='false'
        '/t:Task/t:Settings/t:StopIfGoingOnBatteries'='false'
        '/t:Task/t:Settings/t:ExecutionTimeLimit'='PT5M'
        '/t:Task/t:Actions/t:Exec/t:Command'=$target
        '/t:Task/t:Actions/t:Exec/t:Arguments'=('--mode fallback --plan "'+$plan+'"')
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $nodes=$document.SelectNodes($entry.Key,$namespaces)
        # Task Scheduler omits these documented schema defaults on export.
        if ($nodes.Count -eq 0 -and $entry.Key -in @('/t:Task/t:Triggers/t:BootTrigger/t:Enabled','/t:Task/t:Triggers/t:TimeTrigger/t:Enabled','/t:Task/t:Settings/t:RunOnlyIfNetworkAvailable')) { continue }
        if ($nodes.Count -eq 1 -and $entry.Key -eq '/t:Task/t:Triggers/t:TimeTrigger/t:StartBoundary' -and ([DateTimeOffset]::Parse($nodes[0].InnerText)).UtcDateTime -eq ([DateTimeOffset]::Parse($entry.Value)).UtcDateTime) { continue }
        if ($nodes.Count -ne 1 -or $nodes[0].InnerText -ne $entry.Value) { throw ('Recovery task XML mismatch: '+$entry.Key) }
    }
    if ($document.SelectNodes('/t:Task/t:Actions/*',$namespaces).Count -ne 1 -or $document.SelectNodes('/t:Task/t:Triggers/*',$namespaces).Count -ne 2) { throw 'Unexpected recovery task actions/triggers.' }
}
Assert-TaskXml $xml
Register-ScheduledTask -TaskName $taskName -Xml $xml -User 'SYSTEM' | Out-Null
$registered=Get-ScheduledTask -TaskName $taskName
if ((Get-PrincipalSid $registered.Principal.UserId) -ne 'S-1-5-18' -or @($registered.Actions).Count -ne 1 -or $registered.Actions[0].Execute -ne $target -or $registered.Actions[0].Arguments -ne ('--mode fallback --plan "'+$plan+'"')) { throw 'Registered task identity mismatch; do not launch a worker.' }
$registeredXml=Export-ScheduledTask -TaskName $taskName
Assert-TaskXml $registeredXml
$registeredXml | Set-Content -LiteralPath (Join-Path $root 'registered-task.xml')
Start-ScheduledTask -TaskName $taskName
$ready=Join-Path $root 'fallback-ready.json'
$waitUntil=[DateTime]::UtcNow.AddSeconds(10)
while (!(Test-Path -LiteralPath $ready) -and [DateTime]::UtcNow -lt $waitUntil) { Start-Sleep -Milliseconds 100 }
if (!(Test-Path -LiteralPath $ready)) { throw 'SYSTEM fallback did not acknowledge. Task remains registered; no guardian/worker started.' }
if ($LaunchGuardian) {
    $mode='guard'; if ($InspectionFault) { $mode='guard-inspection-fault' }
    $process=Start-Process -FilePath $target -ArgumentList @('--mode',$mode,'--plan',('"'+$plan+'"')) -WindowStyle Hidden -PassThru
    [pscustomobject]@{RunId=$runId;Root=$root;Task=$taskName;GuardianPid=$process.Id;Deadline=$settings.Deadline;Mode=$workerMode} | ConvertTo-Json
} else {
    [pscustomobject]@{RunId=$runId;Root=$root;Task=$taskName;Deadline=$settings.Deadline;Mode='fallback-only; no worker launched'} | ConvertTo-Json
}
# Keep the task registered until an operator reviews fresh scoped recovery evidence.
# No automatic task deletion, production service stop, adapter, route, registry or blocking policy exists here.
