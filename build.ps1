param(
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$GoExecutable = 'go',
    [string]$OS = 'windows',
    [string]$Architecture = 'amd64'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($OS -cne 'windows' -or $Architecture -cne 'amd64') { throw 'Complete embedded bundles currently require Windows amd64 (Cronet native dependency).' }
$source = [IO.Path]::GetFullPath($PSScriptRoot)
$target = [IO.Path]::GetFullPath($Output)
if ($target -eq $source -or $source.StartsWith($target.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Bundle output must not contain the source directory.' }
if (Test-Path -LiteralPath $target) {
    if (!(Test-Path -LiteralPath $target -PathType Container) -or @(Get-ChildItem -LiteralPath $target -Force).Count) { throw 'Bundle output must be a new or empty directory.' }
}
$ancestorPath = $target
while (!(Test-Path -LiteralPath $ancestorPath)) { $ancestorPath = Split-Path -Parent $ancestorPath }
$ancestor = Get-Item -LiteralPath $ancestorPath -Force
while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Bundle output must not traverse reparse points.' }
    $ancestor = $ancestor.Parent
}
$go = (Get-Command $GoExecutable -ErrorAction Stop).Source
$revision = & git -C $source rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') { throw 'A source Git revision is required.' }
$changes = @(& git -C $source status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source dirty state.' }
$dirty = $changes.Count -gt 0
$version = '0.5.0'
$tags = 'embeddedxray,embeddedsingbox,embeddedtun,embeddedawg,with_quic,with_gvisor,with_naive_outbound,with_purego'
$flags = '-s -w -X onetunnel/core/internal/buildinfo.Version=' + $version + ' -X onetunnel/core/internal/buildinfo.Revision=' + $revision + ' -X onetunnel/core/internal/buildinfo.Dirty=' + $dirty.ToString().ToLowerInvariant()
$saved = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOTOOLCHAIN')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $source
try {
    $env:GOOS = $OS; $env:GOARCH = $Architecture; $env:CGO_ENABLED = '0'; $env:GOTOOLCHAIN = 'local'
    $goVersion = & $go version
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch '^go version go1\.27\.3 ') { throw 'Go 1.27.3 is required; prepare the toolchain explicitly.' }
    $service = Join-Path $target 'service'
    New-Item -ItemType Directory -Path $service -Force | Out-Null
    & $go build -mod=readonly -trimpath -tags $tags -ldflags $flags -o (Join-Path $service 'OneTunnel.Service.exe') ./cmd/onetunnel-service
    if ($LASTEXITCODE -ne 0) { throw 'Go service build failed.' }
    & $go build -mod=readonly -trimpath -ldflags $flags -o (Join-Path $target 'OneTunnel.Profiles.exe') ./cmd/onetunnel-profiles
    if ($LASTEXITCODE -ne 0) { throw 'Go profile host build failed.' }
    $buildInfo = @(& $go version -m (Join-Path $service 'OneTunnel.Service.exe'))
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read Go build metadata.' }
    $buildInfo[0] = $buildInfo[0].Replace((Join-Path $service 'OneTunnel.Service.exe'), 'OneTunnel.Service.exe')
    $buildInfo | Set-Content (Join-Path $service 'go-build-info.txt') -Encoding UTF8
    function Module-Directory([string]$Name) {
        $directory = & $go list -m -mod=readonly -f '{{.Dir}}' $Name
        if ($LASTEXITCODE -ne 0 -or !$directory -or !(Test-Path -LiteralPath $directory -PathType Container)) { throw "Dependency unavailable: $Name" }
        return $directory
    }
    $cronet = Module-Directory 'github.com/sagernet/cronet-go/lib/windows_amd64'
    $cronetDll = Join-Path $cronet 'libcronet.dll'
    if ((Get-FileHash -LiteralPath $cronetDll -Algorithm SHA256).Hash -ne '3217C6260FBCA5F16072E0B79735742F40109A63BB0FF88FD6B96DD6B54A2928') { throw 'Cronet checksum mismatch.' }
    Copy-Item -LiteralPath $cronetDll -Destination (Join-Path $service 'libcronet.dll')
    Copy-Item -LiteralPath (Join-Path $cronet 'LICENSE') -Destination (Join-Path $service 'LICENSE.cronet.txt')
    Copy-Item -LiteralPath (Join-Path $source 'licenses/LICENSE.wintun.txt') -Destination (Join-Path $service 'LICENSE.embedded-wintun.txt')
    Copy-Item -LiteralPath (Join-Path (Module-Directory 'github.com/xtls/xray-core') 'LICENSE') -Destination (Join-Path $service 'LICENSE.embedded-xray.txt')
    Copy-Item -LiteralPath (Join-Path (Module-Directory 'github.com/sagernet/sing-box') 'LICENSE') -Destination (Join-Path $service 'LICENSE.embedded-sing-box.txt')
    Copy-Item -LiteralPath (Join-Path (Module-Directory 'github.com/rivo/uniseg') 'LICENSE.txt') -Destination (Join-Path $target 'LICENSE.uniseg.txt')
    $goroot = & $go env GOROOT
    if ($LASTEXITCODE -ne 0 -or !$goroot) { throw 'Cannot locate Go toolchain license.' }
    Copy-Item -LiteralPath (Join-Path $goroot 'LICENSE') -Destination (Join-Path $service 'LICENSE.go.txt')
    $modules = @(& $go list -mod=readonly -tags $tags -deps -f '{{with .Module}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}' ./cmd/onetunnel-service ./cmd/onetunnel-profiles)
    if ($LASTEXITCODE -ne 0) { throw 'Dependency notice enumeration failed.' }
    $notices = @()
    foreach ($entry in @($modules | Where-Object { $_ -match '\|' } | Sort-Object -Unique)) {
        $parts = $entry -split '\|',3
        if ($parts[0] -eq 'onetunnel/core') { continue }
        $folder = ($parts[0] + '@' + $parts[1]) -replace '[^A-Za-z0-9._@-]','_'
        $moduleTarget = Join-Path $service ('third-party/' + $folder)
        New-Item -ItemType Directory -Path $moduleTarget -Force | Out-Null
        $licenses = @(Get-ChildItem -LiteralPath $parts[2] -File | Where-Object { $_.Name -match '^(LICENSE|COPYING|NOTICE|COPYRIGHT)(\..*)?$' })
        foreach ($license in $licenses) { Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $moduleTarget $license.Name) }
        $notices += @{Module=$parts[0];Version=$parts[1];Directory=('third-party/'+$folder);Notices=@($licenses | ForEach-Object { $_.Name })}
    }
    ConvertTo-Json -InputObject @($notices) -Depth 5 | Set-Content (Join-Path $service 'embedded-dependencies.json') -Encoding UTF8
    foreach ($entry in @(@('github.com/Microsoft/go-winio','LICENSE.go-winio.txt'),@('golang.org/x/sys','LICENSE.x-sys.txt'),@('golang.org/x/net','LICENSE.x-net.txt'),@('golang.org/x/text','LICENSE.x-text.txt'))) {
        Copy-Item -LiteralPath (Join-Path (Module-Directory $entry[0]) 'LICENSE') -Destination (Join-Path $service $entry[1])
    }
    @{Runtime='go';Version=$version;ApiVersion=1;SourceRevision=$revision;Dirty=$dirty;OS=$OS;Architecture=$Architecture;AdapterRequired=$false;EmbeddedXray=$true;EmbeddedSingBox=$true;EmbeddedTun=$true;EmbeddedAWG=$true;EmbeddedScope='embedded-native-and-proxy';EmbeddedInternalNtp=$true;EmbeddedNaive=$true} | ConvertTo-Json | Set-Content (Join-Path $service 'go-runtime.json') -Encoding UTF8
    $files = @(Get-ChildItem -LiteralPath $target -Recurse -File | Sort-Object FullName | ForEach-Object {
        @{Path=$_.FullName.Substring($target.TrimEnd('\','/').Length+1).Replace('\','/');Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    @{SchemaVersion=1;Version=$version;ApiVersion=1;OS=$OS;Architecture=$Architecture;SourceRevision=$revision;Dirty=$dirty;Files=$files} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $target 'core-bundle.json') -Encoding UTF8
    Write-Output $target
} finally {
    Pop-Location
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
