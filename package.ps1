param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'dist'))
$ErrorActionPreference='Stop'
$exe=Join-Path $PSScriptRoot 'artifacts\SpotiRoute.exe'
if(-not (Test-Path -LiteralPath $exe)){throw 'Run build.ps1 first.'}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$names=@('SpotiRoute.exe','README.md','LICENSE')
Copy-Item -LiteralPath $exe -Destination (Join-Path $OutputDirectory 'SpotiRoute.exe')
foreach($name in @('README.md','LICENSE')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $OutputDirectory $name)}
$zip=Join-Path $OutputDirectory 'SpotiRoute-0.1.0-win.zip'
Compress-Archive -LiteralPath @($names|ForEach-Object{Join-Path $OutputDirectory $_}) -DestinationPath $zip -Force
$hashes=foreach($name in @('SpotiRoute.exe','SpotiRoute-0.1.0-win.zip')){(Get-FileHash -LiteralPath (Join-Path $OutputDirectory $name) -Algorithm SHA256).Hash+'  '+$name}
[IO.File]::WriteAllLines((Join-Path $OutputDirectory 'SHA256SUMS.txt'),$hashes,(New-Object Text.UTF8Encoding($false)))
Write-Output $zip
