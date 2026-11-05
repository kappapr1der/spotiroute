param([string]$OutputPath=(Join-Path $PSScriptRoot 'SpotiRoute-Desktop-Diagnostics.json'),[switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
function Get-ProxySummary {
    param([string]$Text,[string]$Kind)
    $m=[regex]::Matches($Text,'(?m)^\s*network\.proxy\.mode\s*=\s*(\d+)\s*$')
    $modes=@($m|ForEach-Object{[int]$_.Groups[1].Value})
    $addresses=[regex]::Matches($Text,'(?m)^\s*network\.proxy\.addr\s*=([^\r\n]*)')
    $configured=$false
    foreach($address in $addresses){$value=$address.Groups[1].Value.Trim().Trim('"');if($value -and $value -notmatch '^@(http|https|socks4|socks5)$'){$configured=$true}}
    return [pscustomobject]@{Kind=$Kind;ProxyModes=$modes;ExplicitProxyConfigured=$configured}
}
if($SelfTest){
    $samples=@("autologin.blob=PRIVATE_SECRET`nnetwork.proxy.mode=1`nnetwork.proxy.addr=`"@http`"", "network.proxy.mode=2`nnetwork.proxy.addr=`"secret-user:secret-pass@proxy.example:8080@http`"", 'autologin.username=private-user')
    $r=@($samples|ForEach-Object{Get-ProxySummary $_ 'fixture'})
    $json=$r|ConvertTo-Json -Depth 5
    if($r[0].ProxyModes[0] -ne 1 -or $r[0].ExplicitProxyConfigured -or $r[1].ProxyModes[0] -ne 2 -or -not $r[1].ExplicitProxyConfigured -or @($r[2].ProxyModes).Count -ne 0 -or $json -match 'PRIVATE_SECRET|secret-user|secret-pass|proxy.example|private-user'){throw 'Proxy summary privacy self-test failed'}
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),'{"success":true,"proxy_summary_cases":3,"private_values_excluded":true}',(New-Object Text.UTF8Encoding($false)))
    exit 0
}
function Read-Field {param($Object,[string]$Name,$Default) if($null -eq $Object){return $Default};$p=$Object.PSObject.Properties[$Name];if($p){return $p.Value};return $Default}
function Quote-Argument {param([string]$Value) return '"'+$Value.Replace('"','\"')+'"'}
$report=[ordered]@{Schema=1;Tool='SpotiRoute desktop sign-in diagnostics';StartedUtc=[DateTime]::UtcNow.ToString('o');ReadOnly=$true;Error=$null;HttpChecks=@();AccessPointTcp=@();SpotifyProxy=@()}
$curl=Join-Path $env:SystemRoot 'System32\curl.exe'
$temp=Join-Path $PSScriptRoot ('temp-'+[Guid]::NewGuid().ToString('N'))
$live=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:ApTargets=@();$prefHashes=@{};$hostsBefore=$null
function Invoke-HttpCheck {
    param([string]$Domain,[string]$Path,[string]$Address='')
    $file=Join-Path $temp ([Guid]::NewGuid().ToString('N')+'.body')
    $arguments=@('--disable','--noproxy','*','--ipv4','--proto','=https','--connect-timeout','8','--max-time','12','--max-filesize','524288','--silent','--show-error','--output',$file,'--write-out','%{json}','--user-agent','SpotiRoute-Desktop-Diagnostics/1.0')
    if($Address){$arguments+=@('--resolve',($Domain+':443:'+$Address))}
    $arguments+=('https://'+$Domain+$Path)
    $r=[ordered]@{Domain=$Domain;Route=if($Address){'Astra relay candidate'}else{'current DNS/hosts'};AuthenticationTested=$false;Error=$null}
    $p=New-Object Diagnostics.Process
    $p.StartInfo=New-Object Diagnostics.ProcessStartInfo
    $p.StartInfo.FileName=$curl;$p.StartInfo.Arguments=(@($arguments|ForEach-Object{Quote-Argument $_}) -join ' ')
    $p.StartInfo.UseShellExecute=$false;$p.StartInfo.CreateNoWindow=$true
    $p.StartInfo.RedirectStandardOutput=$true;$p.StartInfo.RedirectStandardError=$true
    try {
        [void]$p.Start();$outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit(18000)){$p.Kill();$p.WaitForExit();throw 'curl time limit exceeded'}
        $stdout=$outTask.GetAwaiter().GetResult();$stderr=$errTask.GetAwaiter().GetResult()
        $meta=$stdout|ConvertFrom-Json
        $r.Exit=$p.ExitCode;$r.Http=[int](Read-Field $meta 'http_code' 0);$r.TlsVerifyResult=[int](Read-Field $meta 'ssl_verify_result' -1)
        $r.Seconds=[double](Read-Field $meta 'time_total' 0)
        $r.TlsCompleted=([double](Read-Field $meta 'time_appconnect' 0)) -gt 0
        $r.TransportReached=$r.Exit -eq 0 -and $r.TlsVerifyResult -eq 0 -and $r.Http -gt 0
        if($r.Exit -ne 0){$r.Error=[string](Read-Field $meta 'errormsg' 'curl request failed')}
        if($Domain -eq 'apresolve.spotify.com' -and $r.TransportReached -and $r.Http -eq 200){
            try {
                $data=[IO.File]::ReadAllText($file)|ConvertFrom-Json
                $targets=@($data.accesspoint|Where-Object{$_ -match '^([a-z0-9-]+\.(?:ap\.)?spotify\.com):(443|4070)$'}|Select-Object -First 2)
                $r.AccessPoints=$targets;$r.DealerNames=@($data.dealer);$r.SpclientNames=@($data.spclient)
                if(-not $Address -or $script:ApTargets.Count -eq 0){$script:ApTargets=$targets}
            } catch {$r.ResolverJsonValid=$false}
        }
    } catch {$r.Error='Probe failure: '+$_.Exception.GetType().Name}
    finally {$p.Dispose();if([IO.File]::Exists($file)){[IO.File]::Delete($file)}}
    return [pscustomobject]$r
}
try {
    [void][IO.Directory]::CreateDirectory($temp)
    if([IO.File]::Exists($live)){$hostsBefore=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash}
    if(-not [IO.File]::Exists($curl)){throw 'System curl.exe is missing'}
    $banner=@(& $curl --disable --version)
    if($LASTEXITCODE -ne 0 -or $banner.Count -eq 0 -or $banner[0] -notmatch '^curl (\d+\.\d+\.\d+)\b' -or [version]$Matches[1] -lt [version]'7.70.0'){throw 'System curl 7.70 or newer required'}
    $report.CurlVersion=[string]$banner[0];$report.WindowsVersion=[Environment]::OSVersion.Version.ToString()
    $spotify=@(Get-Process -Name Spotify -ErrorAction SilentlyContinue)
    $report.SpotifyProcessCount=$spotify.Count
    $versions=@()
    foreach($process in $spotify){try{if($process.Path){$versions+=[Diagnostics.FileVersionInfo]::GetVersionInfo($process.Path).FileVersion}}catch{}}
    $report.SpotifyVersions=@($versions|Select-Object -Unique)
    $prefs=@(@{Path=(Join-Path $env:APPDATA 'Spotify\prefs');Kind='classic'})
    $packages=Join-Path $env:LOCALAPPDATA 'Packages'
    if([IO.Directory]::Exists($packages)){
        foreach($folder in @(Get-ChildItem -LiteralPath $packages -Directory -Filter 'SpotifyAB.SpotifyMusic_*' -ErrorAction SilentlyContinue)){
            foreach($relative in @('LocalState\Spotify\prefs','LocalCache\Spotify\prefs','LocalCache\Roaming\Spotify\prefs','RoamingState\Spotify\prefs')){$prefs+=@{Path=(Join-Path $folder.FullName $relative);Kind=('store:'+($relative -replace '\\','/'))}}
        }
    }
    foreach($candidate in $prefs){
        if([IO.File]::Exists($candidate.Path) -and (Get-Item -LiteralPath $candidate.Path).Length -le 2097152){
            $prefHashes[$candidate.Path]=(Get-FileHash -LiteralPath $candidate.Path -Algorithm SHA256).Hash
            $report.SpotifyProxy+=Get-ProxySummary ([IO.File]::ReadAllText($candidate.Path)) $candidate.Kind
        }
    }
    $report.PrefsFound=@($report.SpotifyProxy).Count -gt 0
    $status='C:\ProgramData\SpotifyNetworkGuard\data\status.json'
    if([IO.File]::Exists($status)){
        try {$s=[IO.File]::ReadAllText($status)|ConvertFrom-Json;$report.Guard=@{Healthy=[bool]$s.Healthy;FinishedUtc=$s.FinishedUtc;Result=$s.Result}}catch{$report.GuardReadable=$false}
    }
    $known=@('winws','winws2','goodbyedpi','openvpn','wireguard','sing-box','xray','clash','mihomo','v2ray')
    $report.NetworkProcesses=@(Get-Process -ErrorAction SilentlyContinue|Where-Object{$_.ProcessName.ToLowerInvariant() -in $known}|Group-Object ProcessName|ForEach-Object{@{Name=$_.Name;Count=$_.Count}})
    $counter=0
    foreach($target in @(@('apresolve.spotify.com','/?type=accesspoint&type=dealer&type=spclient'),@('login5.spotify.com','/v3/login'),@('clienttoken.spotify.com','/v1/clienttoken'),@('accounts.spotify.com','/'))){
        foreach($address in @('','217.60.179.6')){$counter++;Write-Output ('['+$counter+'/8] '+$target[0]);$report.HttpChecks+=Invoke-HttpCheck $target[0] $target[1] $address}
    }
    foreach($target in $script:ApTargets){
        if($target -match '^([a-z0-9-]+\.(?:ap\.)?spotify\.com):(443|4070)$'){
            $server=$Matches[1];$port=[int]$Matches[2];$tcp=New-Object Net.Sockets.TcpClient;$timer=[Diagnostics.Stopwatch]::StartNew()
            $item=@{Server=$server;Port=$port;Connected=$false}
            try {$pending=$tcp.BeginConnect($server,$port,$null,$null);if(-not $pending.AsyncWaitHandle.WaitOne(3000)){throw 'timeout'};$tcp.EndConnect($pending);$item.Connected=$true}catch{$item.Error='TCP connection unavailable'}finally{$tcp.Close();$item.Seconds=$timer.Elapsed.TotalSeconds}
            $report.AccessPointTcp+=,$item
        }
    }
} catch {$report.Error=$_.Exception.GetType().Name}
finally {
    if($hostsBefore){$report.HostsUnchanged=((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $hostsBefore)}
    $preserved=$true;foreach($prefPath in $prefHashes.Keys){if((Get-FileHash -LiteralPath $prefPath -Algorithm SHA256).Hash -ne $prefHashes[$prefPath]){$preserved=$false}}
    $report.PreferenceFilesUnchanged=$preserved;$report.FinishedUtc=[DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($report|ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))
    if([IO.Directory]::Exists($temp)){[IO.Directory]::Delete($temp,$false)}
}
Write-Output ('Saved report: '+[IO.Path]::GetFullPath($OutputPath))
if($report.Error){exit 1}