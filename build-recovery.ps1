param([Parameter(Mandatory=$true)][string]$Output, [string]$GoExecutable='go', [switch]$Offline)
$ErrorActionPreference='Stop'
$source=[IO.Path]::GetFullPath($PSScriptRoot)
$target=[IO.Path]::GetFullPath($Output)
if ($target -eq $source -or $source.StartsWith($target.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Output must not contain the source directory.' }
if ((Test-Path -LiteralPath $target) -and @(Get-ChildItem -LiteralPath $target -Force).Count) { throw 'Output must be new or empty.' }
$ancestor=$target
while(!(Test-Path -LiteralPath $ancestor)){$ancestor=Split-Path -Parent $ancestor}
$entry=Get-Item -LiteralPath $ancestor -Force
while($null -ne $entry){if($entry.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Output must not traverse reparse points.'};$entry=$entry.Parent}
$go=(Get-Command $GoExecutable -ErrorAction Stop).Source
$saved=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN','GOPROXY','GOSUMDB')){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
Push-Location $source
try {
    $env:GOOS='windows'; $env:CGO_ENABLED='0'; $env:GOTOOLCHAIN='local'
    if($Offline){$env:GOPROXY='off';$env:GOSUMDB='off'}
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach($architecture in @('amd64','arm64')) {
        $env:GOARCH=$architecture
        $directory=$target
        if($architecture -eq 'arm64'){$directory=Join-Path $target 'arm64';New-Item -ItemType Directory -Path $directory | Out-Null}
        & $go build -mod=readonly -trimpath '-ldflags=-s -w' -o (Join-Path $directory 'OneTunnel.Recover.exe') ./cmd/onetunnel-recover
        if($LASTEXITCODE){throw "Recovery build failed: $architecture"}
    }
    Copy-Item -LiteralPath (Join-Path $source 'recovery/Start-Recovery.cmd'),(Join-Path $source 'recovery/Start-Recovery.ps1'),(Join-Path $source 'recovery/RECOVERY.txt'),(Join-Path $source 'recovery/AUDIT.txt') -Destination $target
    $goroot=& $go env GOROOT
    Copy-Item -LiteralPath (Join-Path $goroot 'LICENSE') -Destination (Join-Path $target 'LICENSE.go.txt')
    foreach($module in @('github.com/Microsoft/go-winio','golang.org/x/net','golang.org/x/sys','golang.org/x/text')) {
        $directory=& $go list -mod=readonly -m -f '{{.Dir}}' $module
        if($LASTEXITCODE -or !$directory){throw "Cannot locate license: $module"}
        $name=$module.Replace('/','-')
        Copy-Item -LiteralPath (Join-Path $directory 'LICENSE') -Destination (Join-Path $target ('LICENSE.'+$name+'.txt'))
    }
    & $go version -m (Join-Path $target 'OneTunnel.Recover.exe') | Set-Content -LiteralPath (Join-Path $target 'BUILD-INFO.txt')
    Get-ChildItem -LiteralPath $target -Recurse -File | ForEach-Object { $hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; $hash+'  '+$_.FullName.Substring($target.Length+1) } | Set-Content -LiteralPath (Join-Path $target 'SHA256SUMS.txt')
    Compress-Archive -LiteralPath $target -DestinationPath ($target+'.zip')
    Write-Output $target
} finally {
    Pop-Location
    foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
}
