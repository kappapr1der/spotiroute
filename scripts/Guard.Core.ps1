Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:GuardDomains = @('i.scdn.co','image-cdn-ak.spotifycdn.com','api.spotify.com','dealer.spotify.com','spclient.wg.spotify.com','gew1-spclient.spotify.com','gew1-dealer.spotify.com')
$script:GatewayDomains = @('api.spotify.com','dealer.spotify.com','spclient.wg.spotify.com','gew1-spclient.spotify.com','gew1-dealer.spotify.com')
$script:BeginMarker = '# >>> SpotifyNetworkGuard managed begin >>>'
$script:EndMarker = '# <<< SpotifyNetworkGuard managed end <<<'
$script:Utf8 = New-Object Text.UTF8Encoding($false)
$script:ByteEncoding = [Text.Encoding]::GetEncoding(28591)

function ConvertTo-GuardHashtable {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Collections.IDictionary]) {
        $r=@{}; foreach($key in $Value.Keys){$r[$key]=ConvertTo-GuardHashtable $Value[$key]}; return ,$r
    }
    if ($Value -is [Management.Automation.PSCustomObject]) {
        $r=@{}; foreach($p in $Value.PSObject.Properties){$r[$p.Name]=ConvertTo-GuardHashtable $p.Value}; return ,$r
    }
    if ($Value -is [Collections.IEnumerable] -and $Value -isnot [string]) {
        $items=@(); foreach($item in $Value){$items+=,(ConvertTo-GuardHashtable $item)}; return ,$items
    }
    return $Value
}
function Read-GuardJson {
    param([string]$Path)
    if(-not [IO.File]::Exists($Path)){return $null}
    return ConvertTo-GuardHashtable ([IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) | ConvertFrom-Json)
}
function Write-GuardJson {
    param([string]$Path,$Value)
    $text=$Value | ConvertTo-Json -Depth 16
    $temp=$Path+'.new-'+[Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($temp,$text,$script:Utf8)
        if([IO.File]::Exists($Path)){$previous=$Path+'.previous';if([IO.File]::Exists($previous)){[IO.File]::Delete($previous)};[IO.File]::Replace($temp,$Path,$previous)}else{[IO.File]::Move($temp,$Path)}
    } finally {if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
}
function Get-GuardHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()} finally {$sha.Dispose()}
}
function Test-GuardPublicIPv4 {
    param([string]$Address)
    $parsed=$null
    if(-not [Net.IPAddress]::TryParse($Address,[ref]$parsed)){return $false}
    if($parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $parsed.ToString() -ne $Address){return $false}
    $b=$parsed.GetAddressBytes()
    if($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224){return $false}
    if($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127){return $false}
    if($b[0] -eq 169 -and $b[1] -eq 254){return $false}
    if($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31){return $false}
    if($b[0] -eq 192 -and (($b[1] -eq 168) -or ($b[1] -eq 0 -and ($b[2] -eq 0 -or $b[2] -eq 2)))){return $false}
    if($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19 -or ($b[1] -eq 51 -and $b[2] -eq 100))){return $false}
    if($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113){return $false}
    return $true
}
function Get-GuardHostRows {
    param([string]$Text)
    $rows=@()
    foreach($line in [regex]::Split($Text,'\r\n|\n|\r')){
        $body=($line -split '#',2)[0].Trim()
        if(-not $body){continue}
        $parts=@($body -split '\s+')
        if($parts.Count -lt 2){continue}
        for($i=1;$i -lt $parts.Count;$i++){
            $rows+=,@{Address=$parts[0];Domain=$parts[$i].TrimEnd('.').ToLowerInvariant()}
        }
    }
    return $rows
}
function Get-GuardUnrelatedSignature {
    param([string]$Text)
    $keys=@(Get-GuardHostRows $Text | Where-Object {$_.Domain -notin $script:GuardDomains} | ForEach-Object {$_.Address+' '+$_.Domain} | Sort-Object)
    return [string]::Join([char]10,[string[]]$keys)
}
function Assert-GuardMapping {
    param([Collections.IDictionary]$Mapping)
    if($Mapping.Count -ne $script:GuardDomains.Count){throw 'The map must contain exactly seven Spotify names.'}
    foreach($domain in $Mapping.Keys){
        if($domain -notin $script:GuardDomains -or -not (Test-GuardPublicIPv4 ([string]$Mapping[$domain]))){throw ('Invalid mapping: '+$domain)}
    }
}
function Get-GuardObservedMapping {
    param([string]$Text)
    $r=@{}
    foreach($domain in $script:GuardDomains){
        $ips=@(Get-GuardHostRows $Text | Where-Object {$_.Domain -eq $domain} | ForEach-Object {$_.Address} | Select-Object -Unique)
        if($ips.Count -eq 1 -and (Test-GuardPublicIPv4 $ips[0])){$r[$domain]=$ips[0]}
    }
    return ,$r
}
function Set-GuardHostsText {
    param([string]$Text,[Collections.IDictionary]$Mapping,[switch]$Flat)
    Assert-GuardMapping $Mapping
    $beginCount=[regex]::Matches($Text,'(?m)^'+[regex]::Escape($script:BeginMarker)+'\r?$').Count
    $endCount=[regex]::Matches($Text,'(?m)^'+[regex]::Escape($script:EndMarker)+'\r?$').Count
    if($beginCount -gt 1 -or $endCount -gt 1 -or $beginCount -ne $endCount){throw 'Ambiguous or damaged SpotifyNetworkGuard markers; hosts was not changed.'}
    $parts=[regex]::Split($Text,'(\r\n|\n|\r)')
    $kept=New-Object Text.StringBuilder
    $inside=$false
    for($i=0;$i -lt $parts.Length;$i+=2){
        $line=$parts[$i];$newline=if($i+1 -lt $parts.Length){$parts[$i+1]}else{''}
        if($line -eq $script:BeginMarker){if($inside){throw 'Nested marker'};$inside=$true;continue}
        if($line -eq $script:EndMarker){if(-not $inside){throw 'End marker before begin'};$inside=$false;continue}
        if($inside){
            $rows=@(Get-GuardHostRows $line)
            if(@($rows | Where-Object {$_.Domain -notin $script:GuardDomains}).Count -gt 0){throw 'Unrelated hostname inside managed block; refusing to remove it.'}
            continue
        }
        $rows=@(Get-GuardHostRows $line)
        $owned=@($rows | Where-Object {$_.Domain -in $script:GuardDomains})
        if($owned.Count -gt 0){
            if(@($rows | Where-Object {$_.Domain -notin $script:GuardDomains}).Count -gt 0){throw 'Mixed Spotify/unrelated aliases need individual review.'}
            continue
        }
        [void]$kept.Append($line);[void]$kept.Append($newline)
    }
    if($inside){throw 'Unclosed marker'}
    $base=$kept.ToString()
    $newline=if($Text.Contains([string][char]13+[char]10)){[string][char]13+[char]10}else{[string][char]10}
    # Canonical trailing boundary makes repeat runs byte-identical.
    $base=$base.TrimEnd([char[]]@([char]10,[char]13))+$newline+$newline
    if(-not $Flat){$base+=$script:BeginMarker+$newline}
    foreach($domain in $script:GuardDomains){$base+=[string]$Mapping[$domain]+' '+$domain+$newline}
    if(-not $Flat){$base+=$script:EndMarker+$newline}
    if((Get-GuardUnrelatedSignature $Text) -cne (Get-GuardUnrelatedSignature $base)){throw 'Unrelated hosts invariant failed.'}
    return $base
}
function Read-GuardDohJson {
    param([string]$Text,[string]$Domain)
    $d=ConvertTo-GuardHashtable ($Text | ConvertFrom-Json)
    if(-not $d.ContainsKey('Status') -or [int]$d.Status -ne 0){throw 'DNS error response'}
    $question=@($d.Question)
    if($question.Count -ne 1 -or ([string]$question[0].name).TrimEnd('.').ToLowerInvariant() -ne $Domain.ToLowerInvariant() -or [int]$question[0].type -ne 1){throw 'DNS question mismatch'}
    $allowed=@{};$current=$Domain.TrimEnd('.').ToLowerInvariant()
    for($hop=0;$hop -lt 10;$hop++){
        if($allowed.ContainsKey($current)){throw 'DNS CNAME loop'}
        $allowed[$current]=$true
        $cname=@($d.Answer | Where-Object {[int]$_.type -eq 5 -and ([string]$_.name).TrimEnd('.').ToLowerInvariant() -eq $current})
        if($cname.Count -eq 0){break}
        if($cname.Count -ne 1){throw 'Ambiguous CNAME'}
        $current=([string]$cname[0].data).TrimEnd('.').ToLowerInvariant()
    }
    $ips=@()
    foreach($answer in @($d.Answer)){
        if([int]$answer.type -eq 1 -and $allowed.ContainsKey(([string]$answer.name).TrimEnd('.').ToLowerInvariant()) -and (Test-GuardPublicIPv4 ([string]$answer.data))){$ips+=[string]$answer.data}
    }
    return @($ips | Select-Object -Unique)
}
function Get-GuardPublishedGateways {
    param([string]$Text)
    if($Text.Length -gt 1048576){throw 'Provider source too large'}
    $anchors=@('chatgpt.com','ntc.party','gql.twitch.tv')
    $rows=@(Get-GuardHostRows $Text)
    $counts=@{}
    foreach($anchor in $anchors){
        foreach($ip in @($rows | Where-Object {$_.Domain -eq $anchor -and (Test-GuardPublicIPv4 $_.Address)} | ForEach-Object {$_.Address} | Select-Object -Unique)){
            if(-not $counts.ContainsKey($ip)){$counts[$ip]=0};$counts[$ip]++
        }
    }
    return @($counts.Keys | Where-Object {$counts[$_] -ge 2} | Sort-Object)
}
function Get-GuardRemainingSeconds {
    $left=[int][Math]::Floor($script:MaxRunSeconds-$script:RunClock.Elapsed.TotalSeconds)
    if($left -lt 1){throw 'Run time budget exhausted'}
    return $left
}
function Merge-GuardCandidates {
    param([string[]]$Fresh,[string[]]$Cached,[string]$Fallback,[int]$Limit=12)
    # A hosts entry may replace InitialMapping during setup. Keep the packaged
    # fallback available even when all DNS answers are unreachable on this network.
    return @((@($Fallback)+@($Fresh)+@($Cached)) | Where-Object {Test-GuardPublicIPv4 $_} | Select-Object -Unique | Select-Object -First $Limit)
}
function Assert-GuardCurlVersion {
    param([string]$Banner)
    if($Banner -notmatch '^curl (\d+\.\d+\.\d+)\b' -or [version]$Matches[1] -lt [version]'7.70.0'){
        throw 'System curl 7.70 or newer is required for JSON diagnostics. Update Windows; hosts was not changed.'
    }
    return $Matches[1]
}
function Get-GuardBootstrapFailure {
    param($Status)
    $details=@()
    if($Status -and $Status.ContainsKey('HealthBefore')){
        foreach($domain in $script:GuardDomains){
            if($Status.ContainsKey('FailedDomains') -and $domain -notin @($Status.FailedDomains)){continue}
            if(-not $Status.HealthBefore.ContainsKey($domain)){continue}
            $probe=$Status.HealthBefore[$domain]
            if(-not $probe.Ok){
                $http=if($probe.ContainsKey('Http')){[string]$probe.Http}else{'unknown'}
                $details+=($domain+' (HTTP '+$http+'; '+[string]$probe.Reason+')')
            }
        }
    }
    $message='No verified complete route set'
    if($details.Count){$message+=': '+[string]::Join(', ',[string[]]$details)}
    if($Status -and $Status.ContainsKey('Error') -and $Status.Error){$message+='. '+[string]$Status.Error}
    return $message+'. Live hosts was not changed. Details: C:\ProgramData\SpotifyNetworkGuard\data\setup-result.json'
}
function Invoke-GuardRequest {
    param([string]$Url,[string]$Domain='',[string]$Address='',[int]$MaxBytes=524288,[int]$Timeout=5,[string]$Accept='*/*')
    if($Url -notmatch '^https://'){throw 'Only HTTPS requests are allowed'}
    if($Address -and -not (Test-GuardPublicIPv4 $Address)){throw 'Non-public candidate address'}
    $remaining=Get-GuardRemainingSeconds
    $seconds=[Math]::Max(1,[Math]::Min($Timeout,$remaining))
    $temp=Join-Path $script:TempRoot ([Guid]::NewGuid().ToString('N')+'.body')
    $err=$temp+'.err'
    $curlArgs=@('--noproxy','*','--ipv4','--proto','=https','--proto-redir','=https','--connect-timeout',[string][Math]::Min(3,$seconds),'--max-time',[string]$seconds,'--max-filesize',[string]$MaxBytes,'--silent','--show-error','--output',$temp,'--write-out','%{json}','--user-agent','SpotifyNetworkGuard/1.0')
    if($Address){$curlArgs+=@('--resolve',($Domain+':443:'+$Address))}
    $curlArgs+=@('--header',('Accept: '+$Accept))
    $curlArgs+=$Url
    try {
        $oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
        try {$raw=& $script:CurlPath @curlArgs 2> $err;$exitCode=$LASTEXITCODE}finally{$ErrorActionPreference=$oldPreference}
        $meta=ConvertTo-GuardHashtable (($raw -join '') | ConvertFrom-Json)
        $bytes=if([IO.File]::Exists($temp)){[IO.File]::ReadAllBytes($temp)}else{[byte[]]@()}
        $errorText=if([IO.File]::Exists($err)){[IO.File]::ReadAllText($err).Trim()}else{''}
        if($errorText.Length -gt 240){$errorText=$errorText.Substring(0,240)}
        return @{Exit=$exitCode;Http=[int]$meta.http_code;ContentType=[string]$meta.content_type;Tls=[int]$meta.ssl_verify_result;Seconds=[double]$meta.time_total;Bytes=$bytes;Error=$errorText}
    } finally {
        if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}
        if([IO.File]::Exists($err)){[IO.File]::Delete($err)}
    }
}
function Test-GuardJpeg {
    param($Response)
    return ($Response.Exit -eq 0 -and $Response.Tls -eq 0 -and $Response.Http -eq 200 -and $Response.ContentType -match '^image/jpeg(?:;|$)' -and $Response.Bytes.Length -ge 1024 -and $Response.Bytes.Length -le 524288 -and $Response.Bytes[0] -eq 255 -and $Response.Bytes[1] -eq 216 -and $Response.Bytes[2] -eq 255)
}
function Test-GuardRoute {
    param([string]$Domain,[string]$Address,[switch]$Thorough)
    try {
        if($Domain -in @('i.scdn.co','image-cdn-ak.spotifycdn.com')){
            $ids=@('ab67616d00001e028b2c42026277efc3e058855b')
            if($Thorough){$ids+='ab67616d00001e02ff9ca10b55ce82ae553c8228'}
            $hashes=@()
            foreach($id in $ids){
                $r=Invoke-GuardRequest -Url ('https://'+$Domain+'/image/'+$id) -Domain $Domain -Address $Address
                if(-not (Test-GuardJpeg $r)){return @{Ok=$false;Domain=$Domain;Address=$Address;Http=$r.Http;Error=$r.Error;Reason='artwork_probe_failed'}}
                $hashes+=Get-GuardHash $r.Bytes
            }
            if($Thorough -and @($hashes | Select-Object -Unique).Count -ne 2){return @{Ok=$false;Domain=$Domain;Address=$Address;Reason='identical_artwork_responses'}}
            return @{Ok=$true;Domain=$Domain;Address=$Address;Http=200;Reason='jpeg_verified'}
        }
        $path=if($Domain -eq 'api.spotify.com'){'/v1/me'}else{'/'}
        $r=Invoke-GuardRequest -Url ('https://'+$Domain+$path) -Domain $Domain -Address $Address -MaxBytes 32768
        $expected=if($Domain -in @('api.spotify.com','dealer.spotify.com','gew1-dealer.spotify.com')){401}else{404}
        $ok=($r.Exit -eq 0 -and $r.Tls -eq 0 -and $r.Http -eq $expected)
        if($ok -and $Domain -eq 'api.spotify.com'){
            $body=ConvertTo-GuardHashtable ($script:Utf8.GetString($r.Bytes) | ConvertFrom-Json)
            $ok=($body.ContainsKey('error') -and $body.error.ContainsKey('status') -and [int]$body.error.status -eq 401 -and [string]$body.error.message -match 'access token')
        }
        return @{Ok=$ok;Domain=$Domain;Address=$Address;Http=$r.Http;Reason=if($ok){'spotify_endpoint_reachable'}else{'control_probe_failed'};Error=$r.Error}
    } catch {return @{Ok=$false;Domain=$Domain;Address=$Address;Reason='probe_exception';Error=$_.Exception.Message}}
}
function Get-GuardDohCandidates {
    param([string]$Domain)
    $sources=if($Domain -eq 'i.scdn.co'){@('i.scdn.co','image-cdn-fa.spotifycdn.com')}else{@('image-cdn-ak.spotifycdn.com','i.scdn.co')}
    $ips=@()
    foreach($name in $sources){
        foreach($base in @('https://cloudflare-dns.com/dns-query?name=','https://1.1.1.1/dns-query?name=','https://dns.google/resolve?name=')){
            try {
                $queryUrl=$base+[Uri]::EscapeDataString($name)+'&type=A';if($base -like 'https://dns.google/*'){$queryUrl+='&edns_client_subnet=0.0.0.0%2F0'};$r=Invoke-GuardRequest -Url $queryUrl -MaxBytes 65536 -Timeout 4 -Accept 'application/dns-json'
                if($r.Exit -eq 0 -and $r.Http -eq 200 -and $r.Tls -eq 0){$ips+=Read-GuardDohJson -Text ($script:Utf8.GetString($r.Bytes)) -Domain $name}
            } catch {}
        }
    }
    return @($ips | Select-Object -Unique)
}
function Get-GuardGatewayCandidates {
    $urls=@('https://raw.githubusercontent.com/ASTRACAT2022/host-DNS/main/base_hosts.txt','https://api.github.com/repos/ASTRACAT2022/host-DNS/contents/base_hosts.txt?ref=main')
    foreach($url in $urls){
        try {
            $r=Invoke-GuardRequest -Url $url -MaxBytes 1572864 -Timeout 5
            if($r.Exit -ne 0 -or $r.Http -ne 200 -or $r.Tls -ne 0){continue}
            $text=$script:Utf8.GetString($r.Bytes)
            if($url -like 'https://api.github.com/*'){
                $d=ConvertTo-GuardHashtable ($text | ConvertFrom-Json)
                if($d.encoding -ne 'base64' -or [int]$d.size -gt 1048576){continue}
                $text=$script:Utf8.GetString([Convert]::FromBase64String($d.content))
            }
            $ips=@(Get-GuardPublishedGateways $text)
            if($ips.Count -gt 0){return $ips}
        } catch {}
    }
    return @()
}
function Test-GuardGateway {
    param([string]$Address)
    $checks=@()
    foreach($domain in $script:GatewayDomains){
        $check=Test-GuardRoute -Domain $domain -Address $Address
        $checks+=,$check
        if(-not $check.Ok){return @{Ok=$false;Address=$Address;Checks=$checks}}
    }
    return @{Ok=$true;Address=$Address;Checks=$checks}
}
function Select-GuardReplacement {
    param([string]$Current,[bool]$Healthy,[int]$FailureCount,[string[]]$Candidates,[scriptblock]$Validate,[int]$Threshold=2)
    if($Healthy){return @{Address=$Current;Failures=0;Changed=$false;Reason='healthy_current_kept'}}
    $failures=$FailureCount+1
    if($failures -lt $Threshold){return @{Address=$Current;Failures=$failures;Changed=$false;Reason='waiting_for_repeat_failure'}}
    foreach($candidate in @($Candidates | Select-Object -Unique)){
        if($candidate -eq $Current -or -not (Test-GuardPublicIPv4 $candidate)){continue}
        if(& $Validate $candidate){return @{Address=$candidate;Failures=0;Changed=$true;Reason='validated_replacement'}}
    }
    return @{Address=$Current;Failures=$failures;Changed=$false;Reason='no_valid_replacement_old_kept'}
}
function Write-GuardHostsLocked {
    param([string]$Path,[byte[]]$Expected,[byte[]]$Proposed,[string]$BackupRoot)
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $current=New-Object byte[] $stream.Length
        $offset=0;while($offset -lt $current.Length){$read=$stream.Read($current,$offset,$current.Length-$offset);if($read -le 0){throw 'Short hosts read'};$offset+=$read}
        if((Get-GuardHash $current) -ne (Get-GuardHash $Expected)){throw 'Hosts changed concurrently; write skipped.'}
        $name='hosts-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+(Get-GuardHash $Expected).Substring(0,12)+'.bak'
        [IO.File]::WriteAllBytes((Join-Path $BackupRoot $name),$Expected)
        try {
            $stream.Position=0;$stream.Write($Proposed,0,$Proposed.Length);$stream.SetLength($Proposed.Length);$stream.Flush($true)
        } catch {
            $stream.Position=0;$stream.Write($Expected,0,$Expected.Length);$stream.SetLength($Expected.Length);$stream.Flush($true);throw
        }
    } finally {$stream.Dispose()}
}

function Restore-GuardScopedHostsText {
    param([string]$CurrentText,[string]$OriginalText,[Collections.IDictionary]$SafeMapping)
    $canonical=Set-GuardHostsText -Text $CurrentText -Mapping $SafeMapping
    $marker=$canonical.LastIndexOf($script:BeginMarker,[StringComparison]::Ordinal)
    if($marker -lt 0){throw 'Expected generated marker not found'}
    $prefix=$canonical.Substring(0,$marker)
    $newline=if($CurrentText.Contains([string][char]13+[char]10)){[string][char]13+[char]10}else{[string][char]10}
    $selected=@()
    foreach($line in [regex]::Split($OriginalText,'\r\n|\n|\r')){
        $rows=@(Get-GuardHostRows $line)
        $owned=@($rows | Where-Object {$_.Domain -in $script:GuardDomains})
        if($owned.Count -eq 0){continue}
        if(@($rows | Where-Object {$_.Domain -notin $script:GuardDomains}).Count -gt 0){throw 'Original mixed aliases need individual review'}
        $selected+=$line
    }
    $result=$prefix.TrimEnd([char[]]@([char]10,[char]13))+$newline+$newline
    if($selected.Count -gt 0){$result+=([string]::Join($newline,[string[]]$selected))+$newline}
    if((Get-GuardUnrelatedSignature $CurrentText) -cne (Get-GuardUnrelatedSignature $result)){throw 'Scoped restore invariant failed'}
    return $result
}
