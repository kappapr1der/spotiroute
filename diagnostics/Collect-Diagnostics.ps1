param([string]$OutputPath=(Join-Path $PSScriptRoot 'SpotiRoute-Diagnostics.json'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$report=[ordered]@{Schema=1;Tool='SpotiRoute connection diagnostics';StartedUtc=[DateTime]::UtcNow.ToString('o');ReadOnly=$true;Error=$null;Checks=@()}
$temp=Join-Path $PSScriptRoot ('temp-'+[Guid]::NewGuid().ToString('N'))
$curl=Join-Path $env:SystemRoot 'System32\curl.exe'
$live=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsBefore=$null
function Read-Field {param($Object,[string]$Name,$Default) $p=$Object.PSObject.Properties[$Name];if($p){return $p.Value};return $Default}
function Quote-Argument {param([string]$Value) return '"'+$Value.Replace('"','\"')+'"'}
function Invoke-Probe {
    param([string]$Label,[string]$Domain,[string]$Address,[switch]$Tls12)
    $body=Join-Path $temp ([Guid]::NewGuid().ToString('N')+'.body')
    $arguments=@('--disable','--noproxy','*','--ipv4','--proto','=https','--connect-timeout','12','--max-time','18','--max-filesize','524288','--silent','--show-error','--verbose','--output',$body,'--write-out','%{json}','--resolve',($Domain+':443:'+$Address),'--user-agent','SpotiRoute-Diagnostics/1.0')
    if($Tls12){$arguments+=@('--tlsv1.2','--tls-max','1.2')}
    $arguments+=('https://'+$Domain+'/image/ab67616d00001e028b2c42026277efc3e058855b')
    $r=[ordered]@{Label=$Label;Domain=$Domain;Address=$Address;Tls12Only=$Tls12.IsPresent;TcpConnected=$false;TlsCompleted=$false;JpegVerified=$false;Stage='probe_error';Error=$null}
    $process=New-Object Diagnostics.Process
    $process.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $process.StartInfo.FileName=$curl
    $process.StartInfo.Arguments=(@($arguments|ForEach-Object{Quote-Argument $_}) -join ' ')
    $process.StartInfo.UseShellExecute=$false
    $process.StartInfo.CreateNoWindow=$true
    $process.StartInfo.RedirectStandardOutput=$true
    $process.StartInfo.RedirectStandardError=$true
    try {
        [void]$process.Start()
        $stdoutTask=$process.StandardOutput.ReadToEndAsync()
        $stderrTask=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(24000)){$process.Kill();$process.WaitForExit();throw 'curl process exceeded its timeout'}
        $stdout=$stdoutTask.GetAwaiter().GetResult()
        $stderr=$stderrTask.GetAwaiter().GetResult()
        $r.ExitCode=$process.ExitCode
        $meta=$stdout | ConvertFrom-Json
        $r.Http=[int](Read-Field $meta 'http_code' 0)
        $r.RemoteAddress=[string](Read-Field $meta 'remote_ip' '')
        $r.TcpSeconds=[double](Read-Field $meta 'time_connect' 0)
        $r.TlsSeconds=[double](Read-Field $meta 'time_appconnect' 0)
        $r.TotalSeconds=[double](Read-Field $meta 'time_total' 0)
        $r.TlsVerifyResult=[int](Read-Field $meta 'ssl_verify_result' -1)
        $r.ContentType=[string](Read-Field $meta 'content_type' '')
        $r.HttpVersion=[string](Read-Field $meta 'http_version' '')
        $r.TcpConnected=$r.TcpSeconds -gt 0
        $r.TlsCompleted=$r.TlsSeconds -gt 0
        $bytes=if([IO.File]::Exists($body)){[IO.File]::ReadAllBytes($body)}else{[byte[]]@()}
        $r.JpegVerified=$r.ExitCode -eq 0 -and $r.TlsVerifyResult -eq 0 -and $r.Http -eq 200 -and $r.ContentType -match '^image/jpeg(?:;|$)' -and $bytes.Length -ge 1024 -and $bytes[0] -eq 255 -and $bytes[1] -eq 216 -and $bytes[2] -eq 255
        $r.Stage=if($r.JpegVerified){'verified_image'}elseif(-not $r.TlsCompleted){'https_connect_not_completed'}else{'http_or_image_failed'}
        $r.Trace=@($stderr -split '\r?\n' | Where-Object {$_ -match '^\*.*(Trying |Connected|schannel:|ALPN:|SSL connection|connect to|timed out)'} | Select-Object -First 15)
        $tcp=New-Object Net.Sockets.TcpClient
        $watch=[Diagnostics.Stopwatch]::StartNew()
        try { $pending=$tcp.BeginConnect($Address,443,$null,$null);if(-not $pending.AsyncWaitHandle.WaitOne(3000)){throw 'timeout'};$tcp.EndConnect($pending);$r.IndependentTcpReachable=$true } catch {$r.IndependentTcpReachable=$false} finally {$tcp.Close();$r.IndependentTcpSeconds=$watch.Elapsed.TotalSeconds}
        if($r.ExitCode -ne 0){$clean=([string](Read-Field $meta 'errormsg' 'curl transfer failed')).Replace($PSScriptRoot,'<diagnostics>').Replace($env:USERPROFILE,'<profile>');$r.Error=$clean.Substring(0,[Math]::Min(500,$clean.Length))}
    } catch {$r.Error='Probe or metadata parsing failed: '+$_.Exception.GetType().Name}
    finally {$process.Dispose();if([IO.File]::Exists($body)){[IO.File]::Delete($body)}}
    return [pscustomobject]$r
}
try {
    [void][IO.Directory]::CreateDirectory($temp)
    if([IO.File]::Exists($live)){$hostsBefore=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash}
    if(-not [IO.File]::Exists($curl)){throw 'System curl.exe is missing'}
    $banner=@(& $curl --disable --version)
    if($LASTEXITCODE -ne 0 -or $banner.Count -eq 0 -or $banner[0] -notmatch '^curl (\d+\.\d+\.\d+)\b' -or [version]$Matches[1] -lt [version]'7.70.0'){throw 'System curl 7.70 or newer is required'}
    $report.CurlVersion=[string]$banner[0]
    $report.WindowsVersion=[Environment]::OSVersion.Version.ToString()
    $report.PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    $knownNames=@('winws','winws2','goodbyedpi','openvpn','wireguard','amnezia','amnezia_vpn','nekoray','nekobox','sing-box','xray','clash','mihomo','v2ray','outline')
    $report.NetworkProcesses=@(Get-Process -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName.ToLowerInvariant() -in $knownNames} | Group-Object ProcessName | ForEach-Object {@{Name=$_.Name;Count=$_.Count}})
    try {
        $proxy=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $report.WindowsProxyEnabled=[bool](Read-Field $proxy 'ProxyEnable' 0)
        $report.ProxyAutoConfigPresent=-not [string]::IsNullOrWhiteSpace([string](Read-Field $proxy 'AutoConfigURL' ''))
    } catch {$report.ProxySettingsReadable=$false}
    $report.ChecksBypassHttpProxy=$true
    Write-Output '[1/4] Akamai control'
    $report.Checks+=Invoke-Probe 'akamai_control' 'image-cdn-ak.spotifycdn.com' '23.215.2.166'
    Write-Output '[2/4] i.scdn.co on Fastly (longer timeout)'
    $report.Checks+=Invoke-Probe 'fastly_i_default' 'i.scdn.co' '199.232.210.250'
    Write-Output '[3/4] Other Spotify hostname on the same Fastly IP'
    $report.Checks+=Invoke-Probe 'fastly_alias_default' 'image-cdn-fa.spotifycdn.com' '199.232.210.250'
    Write-Output '[4/4] i.scdn.co with TLS 1.2'
    $report.Checks+=Invoke-Probe 'fastly_i_tls12' 'i.scdn.co' '199.232.210.250' -Tls12
} catch {$report.Error=$_.Exception.Message.Replace($PSScriptRoot,'<diagnostics>').Replace($env:USERPROFILE,'<profile>')}
finally {
    if($hostsBefore){$report.HostsUnchanged=((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $hostsBefore)}
    $report.FinishedUtc=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)))
    if([IO.Directory]::Exists($temp)){[IO.Directory]::Delete($temp,$false)}
}
Write-Output ('Saved report: '+[IO.Path]::GetFullPath($OutputPath))
if($report.Error){exit 1}