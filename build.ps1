param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts'))
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not (Test-Path -LiteralPath $compiler)){$compiler=Join-Path $env:SystemRoot 'Microsoft.NET\Framework\v4.0.30319\csc.exe'}
if(-not (Test-Path -LiteralPath $compiler)){throw 'The .NET Framework C# compiler is required.'}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$payload=Join-Path $PSScriptRoot 'scripts'
$names=@('Guard.Core.ps1','Update-SpotifyHosts.ps1','Manage-SpotifyGuard.ps1','Install-SpotifyGuard.ps1','config.json')
$hashes=[ordered]@{}
foreach($name in $names){$hashes[$name]=(Get-FileHash -LiteralPath (Join-Path $payload $name) -Algorithm SHA256).Hash}
$json=([ordered]@{Schema=1;Hashes=$hashes}|ConvertTo-Json -Depth 4).Replace("`r`n","`n")
[IO.File]::WriteAllText((Join-Path $payload 'manifest.json'),$json,(New-Object Text.UTF8Encoding($false)))
$exe=Join-Path $OutputDirectory 'SpotiRoute.exe'
$compileArgs=@('/nologo','/target:winexe','/platform:anycpu','/optimize+','/utf8output',('/out:'+$exe),('/win32manifest:'+(Join-Path $PSScriptRoot 'src\app.manifest')),'/r:System.dll','/r:System.Core.dll','/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll','/r:Microsoft.CSharp.dll')
foreach($name in ($names+@('manifest.json'))){$compileArgs+=('/resource:'+(Join-Path $payload $name)+',SpotiRoute.Payload.'+$name)}
$compileArgs+=(Join-Path $PSScriptRoot 'src\SpotiRoute.cs')
& $compiler @compileArgs
if($LASTEXITCODE -ne 0){throw 'C# build failed.'}
(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash+'  SpotiRoute.exe' | Set-Content -LiteralPath (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ASCII
Write-Output $exe
