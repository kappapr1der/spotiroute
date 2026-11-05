param([string]$OutputPath=(Join-Path $PSScriptRoot 'SpotiRoute-AccessPoint-Diagnostics.json'),[switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$report=[ordered]@{Schema=1;Tool='SpotiRoute access point protocol diagnostics';ToolVersion='1.0';StartedUtc=[DateTime]::UtcNow.ToString('o');ReadOnly=$true;AuthenticationAttempted=$false;AccountDataRead=$false;Error=$null;ResolverChecks=@();AccessPoints=@()}
$hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsHash=$null
$targets=New-Object 'Collections.Generic.List[string]'
function Read-Value {param($Object,[string]$Name,$Default) $p=$Object.PSObject.Properties[$Name];if($p){return $p.Value};return $Default}
function Quote-Argument {param([string]$Value) return '"'+$Value.Replace('"','\"')+'"'}
function Resolve-AccessPoints {
    param([string]$Relay='')
    $body=Join-Path $PSScriptRoot ('resolver-'+[Guid]::NewGuid().ToString('N')+'.tmp')
    $result=[ordered]@{Route=if($Relay){'Astra relay candidate'}else{'current DNS/hosts'};Http=0;TlsVerified=$false;Error=$null;Targets=@()}
    $args=@('--disable','--noproxy','*','--ipv4','--proto','=https','--connect-timeout','6','--max-time','8','--max-filesize','65536','--silent','--show-error','--output',$body,'--write-out','%{json}','--user-agent','SpotiRoute-AccessPoint-Diagnostics/1.0')
    if($Relay){$args+=@('--resolve',('apresolve.spotify.com:443:'+$Relay))}
    $args+='https://apresolve.spotify.com/?type=accesspoint&type=dealer&type=spclient'
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName=Join-Path $env:SystemRoot 'System32\curl.exe'
    $process.StartInfo.Arguments=(@($args|ForEach-Object{Quote-Argument $_}) -join ' ')
    $process.StartInfo.UseShellExecute=$false;$process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true;$process.StartInfo.RedirectStandardError=$true
    try {
        [void]$process.Start()
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(12000)){$process.Kill();$process.WaitForExit();throw 'resolver time limit'}
        $meta=$stdout.GetAwaiter().GetResult()|ConvertFrom-Json
        [void]$stderr.GetAwaiter().GetResult()
        $result.Http=[int](Read-Value $meta 'http_code' 0)
        $result.TlsVerified=$process.ExitCode -eq 0 -and [int](Read-Value $meta 'ssl_verify_result' -1) -eq 0 -and [double](Read-Value $meta 'time_appconnect' 0) -gt 0
        if($process.ExitCode -ne 0){$result.Error=[string](Read-Value $meta 'errormsg' 'resolver request failed')}
        if($result.TlsVerified -and $result.Http -eq 200) {
            $data=[IO.File]::ReadAllText($body)|ConvertFrom-Json
            $result.Targets=@($data.accesspoint|Where-Object{$_ -is [string] -and $_ -cmatch '\A[a-z0-9-]+\.(?:ap\.)?spotify\.com:(443|4070|80)\z'}|Select-Object -Unique -First 6)
        }
    }catch{$result.Error='Resolver probe failed: '+$_.Exception.GetType().Name}
    finally{$process.Dispose();if([IO.File]::Exists($body)){[IO.File]::Delete($body)}}
    return [pscustomobject]$result
}
try {
    $source=Join-Path $PSScriptRoot 'AccessPointProbe.cs'
    if($PSVersionTable.PSEdition -eq 'Core'){Add-Type -Path $source}else{Add-Type -Path $source -ReferencedAssemblies 'System.dll','System.Core.dll','System.Numerics.dll'}
    if($SelfTest) {
        $count=[SpotiRoute.Diagnostics.AccessPointProbe]::SelfTest()
        $report.SelfTest=@{Success=$true;Cases=$count;NetworkUsed=$false}
    }else{
        if([IO.File]::Exists($hostsPath)){$hostsHash=(Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash}
        $curl=Join-Path $env:SystemRoot 'System32\curl.exe'
        $banner=@(& $curl --disable --version)
        if($LASTEXITCODE -ne 0 -or $banner.Count -eq 0 -or $banner[0] -notmatch '^curl (\d+\.\d+\.\d+)\b' -or [version]$Matches[1] -lt [version]'7.70.0'){throw 'System curl 7.70 or newer required'}
        $report.CurlVersion=[string]$banner[0]
        $report.SpotifyProcessCount=@(Get-Process -Name Spotify -ErrorAction SilentlyContinue).Count
        $report.NetworkProcesses=@(Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.ProcessName -in @('winws','winws2')}|Group-Object ProcessName|ForEach-Object{@{Name=$_.Name;Count=$_.Count}})
        foreach($relay in @('','217.60.179.6')){
            Write-Output 'Reading public access point addresses...'
            $result=Resolve-AccessPoints $relay
            $report.ResolverChecks+=,$result
            foreach($target in @($result.Targets)){if(-not $targets.Contains($target) -and $targets.Count -lt 6){$targets.Add($target)}}
        }
        if(-not $targets.Contains('ap.spotify.com:443')){$targets.Add('ap.spotify.com:443')}
        $report.Selection='First six unique AP resolver targets plus the standard ap.spotify.com:443 fallback; public IPv4 only.'
        foreach($target in $targets){
            $parts=$target -split ':',2
            Write-Output ('Checking Spotify protocol: '+$target)
            $report.AccessPoints+=,[SpotiRoute.Diagnostics.AccessPointProbe]::Probe($parts[0],[int]$parts[1],8000)
        }
        $report.SpotifyProcessCountAtEnd=@(Get-Process -Name Spotify -ErrorAction SilentlyContinue).Count
    }
}catch{$report.Error=$_.Exception.GetType().Name}
finally{
    if($hostsHash){$report.HostsUnchanged=((Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash -eq $hostsHash)}
    $report.FinishedUtc=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report|ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))
}
Write-Output ('Saved report: '+[IO.Path]::GetFullPath($OutputPath))
if($report.Error){exit 1}