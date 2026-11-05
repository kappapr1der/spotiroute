param(
    [switch]$Apply,
    [switch]$ForceDiscovery,
    [string]$DataRoot = ''
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Guard.Core.ps1')
$script:CurlPath=Join-Path $env:SystemRoot 'System32\curl.exe'
$hostPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if(-not $DataRoot){$DataRoot=Join-Path $PSScriptRoot 'data'}
[void][IO.Directory]::CreateDirectory($DataRoot)
$script:TempRoot=Join-Path $DataRoot 'temp'
$backupRoot=Join-Path $DataRoot 'backups'
[void][IO.Directory]::CreateDirectory($script:TempRoot)
[void][IO.Directory]::CreateDirectory($backupRoot)
$config=Read-GuardJson (Join-Path $PSScriptRoot 'config.json')
if(-not $config -or [int]$config.Schema -ne 1){throw 'Invalid guard config'}
Assert-GuardMapping $config.InitialMapping
$script:MaxRunSeconds=[Math]::Min(110,[Math]::Max(30,[int]$config.MaxRunSeconds))
$script:RunClock=[Diagnostics.Stopwatch]::StartNew()
$statePath=Join-Path $DataRoot 'state.json'
$statusPath=Join-Path $DataRoot 'status.json'
$logPath=Join-Path $DataRoot 'events.jsonl'
$lockPath=Join-Path $DataRoot 'run.lock'
$lock=$null;$state=$null
$checks=@{};$healthy=@{}
$candidateChecks=New-Object 'System.Collections.Generic.List[object]'
$status=@{Schema=1;StartedUtc=[DateTime]::UtcNow.ToString('o');Mode=if($Apply){'apply'}else{'check'};Changed=$false;Healthy=$false;Error=$null}
try {
    try {$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch {$status.Result='already_running';$status | ConvertTo-Json -Depth 5;exit 0}
    if($Apply){
        $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Apply requires administrator rights'}
        if([IO.Path]::GetFullPath($hostPath) -ne 'C:\Windows\System32\drivers\etc\hosts'){throw 'Unexpected live hosts path'}
    }
    if(-not [IO.File]::Exists($script:CurlPath)){throw 'System curl.exe is missing; update Windows.'}
    $curlBanner=@(& $script:CurlPath --version)
    if($LASTEXITCODE -ne 0 -or $curlBanner.Count -eq 0){throw 'Cannot determine system curl version.'}
    $status.CurlVersion=Assert-GuardCurlVersion ([string]$curlBanner[0])
    $fallback=if($config.ContainsKey('FallbackMapping')){$config.FallbackMapping}else{$config.InitialMapping}
    Assert-GuardMapping $fallback
    $state=Read-GuardJson $statePath
    if(-not $state){
        $state=@{Schema=1;Mapping=$config.InitialMapping.Clone();Failures=@{};Candidates=@{};OriginAddresses=@($config.OriginAddresses);LastDiscoveryAttemptUtc='';LastResult='';LastSignature=''}
    }
    Assert-GuardMapping $state.Mapping
    $before=[IO.File]::ReadAllBytes($hostPath)
    $text=$script:ByteEncoding.GetString($before)
    $beforeHash=Get-GuardHash $before
    $status.HealthBefore=$checks
    $status.CandidateChecks=$candidateChecks
    foreach($domain in $script:GuardDomains){
        $check=Test-GuardRoute -Domain $domain -Address ([string]$state.Mapping[$domain])
        $checks[$domain]=$check;$healthy[$domain]=[bool]$check.Ok
    }
    $gatewayOk=(@($script:GatewayDomains | Where-Object {-not $healthy[$_]}).Count -eq 0)
    $gatewayIps=@($script:GatewayDomains | ForEach-Object {[string]$state.Mapping[$_]} | Select-Object -Unique)
    if($gatewayIps.Count -ne 1){$gatewayOk=$false;foreach($domain in $script:GatewayDomains){$healthy[$domain]=$false}}
    $due=$ForceDiscovery.IsPresent -or -not $state.LastDiscoveryAttemptUtc
    if(-not $due){
        try{$due=(([DateTime]::UtcNow-[DateTime]::Parse($state.LastDiscoveryAttemptUtc).ToUniversalTime()).TotalMinutes -ge [int]$config.DiscoveryMinutes)}
        catch{$due=$true}
    }
    $groupFailures=if($state.Failures.ContainsKey('gateway')){[int]$state.Failures.gateway}else{0}
    $needGateway=$due -or (-not $gatewayOk -and ($groupFailures+1 -ge [int]$config.FailureThreshold))
    foreach($domain in @('i.scdn.co','image-cdn-ak.spotifycdn.com')){
        $failures=if($state.Failures.ContainsKey($domain)){[int]$state.Failures[$domain]}else{0}
        if($due -or (-not $healthy[$domain] -and ($failures+1 -ge [int]$config.FailureThreshold))){
            $fresh=@(Get-GuardDohCandidates -Domain $domain)
            $cached=if($state.Candidates.ContainsKey($domain)){@($state.Candidates[$domain])}else{@()}
            $state.Candidates[$domain]=@(Merge-GuardCandidates -Fresh $fresh -Cached $cached -Fallback ([string]$fallback[$domain]))
        }
    }
    if($needGateway){
        $fresh=@(Get-GuardGatewayCandidates)
        $cached=if($state.Candidates.ContainsKey('gateway')){@($state.Candidates.gateway)}else{@()}
        $state.Candidates.gateway=@(Merge-GuardCandidates -Fresh $fresh -Cached $cached -Fallback ([string]$fallback['api.spotify.com']) -Limit 6)
        # Ordinary origin addresses must not become relay replacements.
        try{
            $r=Invoke-GuardRequest -Url 'https://cloudflare-dns.com/dns-query?name=api.spotify.com&type=A' -MaxBytes 65536 -Timeout 4
            if($r.Exit -eq 0 -and $r.Http -eq 200 -and $r.Tls -eq 0){
                $origin=@(Read-GuardDohJson -Text ($script:Utf8.GetString($r.Bytes)) -Domain 'api.spotify.com')
                $state.OriginAddresses=@(($origin+@($state.OriginAddresses)) | Select-Object -Unique | Select-Object -First 24)
            }
        }catch{}
    }
    if($due){$state.LastDiscoveryAttemptUtc=[DateTime]::UtcNow.ToString('o')}
    $proposed=$state.Mapping.Clone()
    $decisions=@{}
    foreach($domain in @('i.scdn.co','image-cdn-ak.spotifycdn.com')){
        $failureCount=if($state.Failures.ContainsKey($domain)){[int]$state.Failures[$domain]}else{0}
        $candidates=if($state.Candidates.ContainsKey($domain)){@($state.Candidates[$domain])}else{@()}
        $validate={param($candidate) $probe=Test-GuardRoute -Domain $domain -Address $candidate -Thorough;[void]$candidateChecks.Add($probe);return [bool]$probe.Ok}
        $decision=Select-GuardReplacement -Current ([string]$state.Mapping[$domain]) -Healthy $healthy[$domain] -FailureCount $failureCount -Candidates $candidates -Validate $validate -Threshold ([int]$config.FailureThreshold)
        $decisions[$domain]=$decision
        $state.Failures[$domain]=[int]$decision.Failures
        if($decision.Changed){$proposed[$domain]=$decision.Address;$healthy[$domain]=$true}
    }
    $gatewayCandidates=if($state.Candidates.ContainsKey('gateway')){@($state.Candidates.gateway | Where-Object {$_ -notin @($state.OriginAddresses)})}else{@()}
    $validateGateway={param($candidate) $probe=Test-GuardGateway -Address $candidate;[void]$candidateChecks.Add($probe);return [bool]$probe.Ok}
    $gatewayDecision=Select-GuardReplacement -Current ([string]$state.Mapping['api.spotify.com']) -Healthy $gatewayOk -FailureCount $groupFailures -Candidates $gatewayCandidates -Validate $validateGateway -Threshold ([int]$config.FailureThreshold)
    $decisions.gateway=$gatewayDecision
    $state.Failures.gateway=[int]$gatewayDecision.Failures
    if($gatewayDecision.Changed){
        foreach($domain in $script:GatewayDomains){$proposed[$domain]=$gatewayDecision.Address;$healthy[$domain]=$true}
    }
    $rendered=Set-GuardHostsText -Text $text -Mapping $proposed
    $newBytes=$script:ByteEncoding.GetBytes($rendered)
    $needsWrite=($beforeHash -ne (Get-GuardHash $newBytes))
    $observed=Get-GuardObservedMapping $text
    $unsafeRestore=@($script:GuardDomains | Where-Object {-not $healthy[$_] -and (-not $observed.ContainsKey($_) -or $observed[$_] -ne $proposed[$_])})
    if($unsafeRestore.Count -gt 0){$needsWrite=$false;$status.DeferredUnhealthyRestore=$unsafeRestore}
    $status.Mapping=$proposed
    $status.Decisions=$decisions
    $status.HealthBefore=$checks
    $status.Healthy=(@($script:GuardDomains | Where-Object {-not $healthy[$_]}).Count -eq 0)
    $status.WouldChange=$needsWrite
    $status.BeforeHash=$beforeHash
    if($Apply -and $needsWrite){
        [void](Get-GuardRemainingSeconds)
        Write-GuardHostsLocked -Path $hostPath -Expected $before -Proposed $newBytes -BackupRoot $backupRoot
        $status.Changed=$true
        $status.AfterHash=Get-GuardHash ([IO.File]::ReadAllBytes($hostPath))
        try{Clear-DnsClientCache -ErrorAction Stop}catch{$status.DnsFlushWarning=$_.Exception.Message}
        $state.Mapping=$proposed
    }
    $status.Result=if($status.Healthy){if($status.Changed){'healthy_updated'}else{'healthy'}}else{'degraded_old_addresses_preserved'}
    $state.LastCheckUtc=[DateTime]::UtcNow.ToString('o')
    $state.LastResult=$status.Result
    if($status.Healthy){$state.LastHealthyUtc=$state.LastCheckUtc}
    Write-GuardJson -Path $statePath -Value $state
    # Retain only our own specifically named snapshots; the pre-install backup is separate.
    if($Apply){
        $snapshots=@(Get-ChildItem -LiteralPath $backupRoot -File | Where-Object {$_.Name -match '^hosts-\d{8}T\d{9}-[a-f0-9]{12}\.bak$'} | Sort-Object Name -Descending)
        foreach($snapshot in @($snapshots | Select-Object -Skip 20)){[IO.File]::Delete($snapshot.FullName)}
    }
} catch {
    $status.Error=$_.Exception.Message
    $status.Result='error_no_unverified_replacement'
} finally {
    if($lock){
        $status.FailedDomains=@($script:GuardDomains | Where-Object {-not $healthy.ContainsKey($_) -or -not $healthy[$_]})
        $status.FinishedUtc=[DateTime]::UtcNow.ToString('o')
        $status.DurationSeconds=[Math]::Round($script:RunClock.Elapsed.TotalSeconds,3)
        try {
            $previous=Read-GuardJson $statusPath
            Write-GuardJson -Path $statusPath -Value $status
            $eventNeeded=($status.Changed -or -not $previous -or [string]$previous.Result -ne [string]$status.Result -or [string]$previous.Error -ne [string]$status.Error)
            if($eventNeeded){
                if([IO.File]::Exists($logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1048576){
                    if([IO.File]::Exists($logPath+'.previous')){[IO.File]::Delete($logPath+'.previous')}
                    [IO.File]::Move($logPath,$logPath+'.previous')
                }
                $event=@{AtUtc=$status.FinishedUtc;Result=$status.Result;Changed=$status.Changed;Error=$status.Error}
                if($status.ContainsKey('Mapping')){$event.Mapping=$status.Mapping}
                [IO.File]::AppendAllText($logPath,($event | ConvertTo-Json -Compress -Depth 6)+[Environment]::NewLine,$script:Utf8)
            }
        } catch {}
        $lock.Dispose()
    }
}
$status | ConvertTo-Json -Depth 12
if($status.Error){exit 1}
