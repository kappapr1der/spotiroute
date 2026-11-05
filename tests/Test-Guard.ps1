param([string]$PackageRoot)
$ErrorActionPreference='Stop'
. (Join-Path $PackageRoot 'Guard.Core.ps1')
$script:Passed=0
function Assert-Case {param([bool]$Condition,[string]$Name) if(-not $Condition){throw ('FAIL: '+$Name)};$script:Passed++;Write-Output ('PASS: '+$Name)}
function Assert-Throws {param([scriptblock]$Action,[string]$Name) $thrown=$false;try{& $Action | Out-Null}catch{$thrown=$true};Assert-Case $thrown $Name}
$config=Read-GuardJson (Join-Path $PackageRoot 'config.json')
$map=$config.InitialMapping
Assert-Case (Test-GuardPublicIPv4 '199.232.210.250') 'public IPv4 accepted'
foreach($bad in @('127.0.0.1','10.0.0.1','172.16.2.3','192.168.1.1','169.254.1.1','100.64.0.1','0.0.0.0','224.1.2.3','198.18.0.1','192.0.2.1','203.0.113.2','198.51.100.2','::1','1.2.3','1.2.3.04')){
    Assert-Case (-not (Test-GuardPublicIPv4 $bad)) ('unsafe address rejected: '+$bad)
}
$nl=[string][char]13+[char]10
$inputText='# comment: '+[char]1046+[char]1105+$nl+'192.0.2.5 unrelated.example'+$nl+'217.60.179.6 api.spotify.com'+$nl+'# old inactive api.spotify.com'+$nl
$rendered=Set-GuardHostsText -Text $inputText -Mapping $map
Assert-Case ((Get-GuardUnrelatedSignature $inputText) -ceq (Get-GuardUnrelatedSignature $rendered)) 'unrelated hosts preserved'
Assert-Case ($rendered.Contains('# comment: '+[char]1046+[char]1105)) 'non-ASCII text preserved'
Assert-Case ((Set-GuardHostsText -Text $rendered -Mapping $map) -ceq $rendered) 'repeated rendering is byte-identical'
Assert-Case (@(Get-GuardHostRows $rendered | Where-Object {$_.Domain -in $script:GuardDomains}).Count -eq 7) 'exactly seven unique active names'
$flat=Set-GuardHostsText -Text $rendered -Mapping $map -Flat
Assert-Case (-not $flat.Contains($script:BeginMarker) -and (Get-GuardUnrelatedSignature $flat) -ceq (Get-GuardUnrelatedSignature $inputText)) 'scoped restore retains other entries'
Assert-Throws {Set-GuardHostsText -Text ('1.2.3.4 api.spotify.com unrelated.example'+$nl) -Mapping $map} 'mixed aliases fail closed'
Assert-Throws {Set-GuardHostsText -Text ($script:BeginMarker+$nl) -Mapping $map} 'unclosed marker fails closed'
Assert-Throws {Set-GuardHostsText -Text ($rendered+$script:BeginMarker+$nl+$script:EndMarker+$nl) -Mapping $map} 'duplicate markers fail closed'
Assert-Throws {Set-GuardHostsText -Text ($script:BeginMarker+$nl+'1.2.3.4 unrelated.example'+$nl+$script:EndMarker+$nl) -Mapping $map} 'unrelated data inside owned block is protected'
$dns='{"Status":0,"Question":[{"name":"i.scdn.co","type":1}],"Answer":[{"name":"i.scdn.co","type":5,"data":"edge.example."},{"name":"edge.example.","type":1,"data":"23.215.2.166"},{"name":"unrelated.example","type":1,"data":"8.8.8.8"},{"name":"edge.example.","type":1,"data":"127.0.0.1"}]}'
$ips=@(Read-GuardDohJson -Text $dns -Domain 'i.scdn.co')
Assert-Case ($ips.Count -eq 1 -and $ips[0] -eq '23.215.2.166') 'CNAME chain used; unrelated and private answers ignored'
Assert-Throws {Read-GuardDohJson -Text $dns -Domain 'api.spotify.com'} 'DNS question mismatch rejected'
$loop='{"Status":0,"Question":[{"name":"i.scdn.co","type":1}],"Answer":[{"name":"i.scdn.co","type":5,"data":"x.example"},{"name":"x.example","type":5,"data":"i.scdn.co"}]}'
Assert-Throws {Read-GuardDohJson -Text $loop -Domain 'i.scdn.co'} 'CNAME loops rejected'
$provider='217.60.179.6 chatgpt.com'+$nl+'217.60.179.6 ntc.party'+$nl+'1.2.3.4 other.example'+$nl
$ips=@(Get-GuardPublishedGateways $provider)
Assert-Case ($ips.Count -eq 1 -and $ips[0] -eq '217.60.179.6') 'provider candidate requires matching anchors'
Assert-Case (@(Get-GuardPublishedGateways '1.2.3.4 chatgpt.com').Count -eq 0) 'single unconfirmed anchor rejected'
$r=Select-GuardReplacement -Current '199.232.210.250' -Healthy $true -FailureCount 9 -Candidates @('23.215.2.166') -Validate {throw 'Healthy route must not test replacement'}
Assert-Case (-not $r.Changed -and $r.Address -eq '199.232.210.250' -and $r.Failures -eq 0) 'healthy route never churns on new DNS data'
$r=Select-GuardReplacement -Current '199.232.210.250' -Healthy $false -FailureCount 0 -Candidates @('23.215.2.166') -Validate {$true}
Assert-Case (-not $r.Changed -and $r.Failures -eq 1) 'single transient failure retains old route'
$r=Select-GuardReplacement -Current '199.232.210.250' -Healthy $false -FailureCount 1 -Candidates @('127.0.0.1','23.215.2.166') -Validate {param($candidate) $candidate -eq '23.215.2.166'}
Assert-Case ($r.Changed -and $r.Address -eq '23.215.2.166') 'repeat failure accepts only validated public replacement'
$r=Select-GuardReplacement -Current '199.232.210.250' -Healthy $false -FailureCount 1 -Candidates @('23.215.2.166') -Validate {$false}
Assert-Case (-not $r.Changed -and $r.Address -eq '199.232.210.250') 'total network/candidate failure retains last address'
$jpeg=New-Object byte[] 2048;$jpeg[0]=255;$jpeg[1]=216;$jpeg[2]=255
Assert-Case (Test-GuardJpeg @{Exit=0;Tls=0;Http=200;ContentType='image/jpeg';Bytes=$jpeg}) 'real JPEG response accepted'
Assert-Case (-not (Test-GuardJpeg @{Exit=0;Tls=0;Http=200;ContentType='text/html';Bytes=$jpeg})) 'HTML cannot pass artwork probe'
Assert-Case (-not (Test-GuardJpeg @{Exit=0;Tls=60;Http=200;ContentType='image/jpeg';Bytes=$jpeg})) 'TLS verification failure cannot pass'
Assert-Case (-not (Test-GuardJpeg @{Exit=0;Tls=0;Http=200;ContentType='image/jpeg';Bytes=([Text.Encoding]::ASCII.GetBytes('not an image'))})) 'invalid JPEG body rejected'
$testRoot=Join-Path $PSScriptRoot ('fixture-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
$backupRoot=Join-Path $testRoot 'backups';[void][IO.Directory]::CreateDirectory($backupRoot)
$file=Join-Path $testRoot 'hosts.fixture'
$before=[Text.Encoding]::UTF8.GetBytes($inputText)
$after=[Text.Encoding]::UTF8.GetBytes($rendered)
[IO.File]::WriteAllBytes($file,$before)
Write-GuardHostsLocked -Path $file -Expected $before -Proposed $after -BackupRoot $backupRoot
Assert-Case ((Get-GuardHash ([IO.File]::ReadAllBytes($file))) -eq (Get-GuardHash $after)) 'locked writer commits expected content'
Assert-Case (@(Get-ChildItem -LiteralPath $backupRoot -File).Count -eq 1) 'backup precedes write'
$external=[Text.Encoding]::UTF8.GetBytes('external change')
[IO.File]::WriteAllBytes($file,$external)
Assert-Throws {Write-GuardHostsLocked -Path $file -Expected $after -Proposed $before -BackupRoot $backupRoot} 'concurrent modification prevents overwrite'
Assert-Case ((Get-GuardHash ([IO.File]::ReadAllBytes($file))) -eq (Get-GuardHash $external)) 'concurrent content remains intact'

$jsonPath=Join-Path $testRoot 'atomic.json'
Write-GuardJson -Path $jsonPath -Value @{Value=1}
Write-GuardJson -Path $jsonPath -Value @{Value=2}
Assert-Case ((Read-GuardJson $jsonPath).Value -eq 2 -and (Read-GuardJson ($jsonPath+'.previous')).Value -eq 1) 'atomic JSON replace retains previous state'
Write-GuardJson -Path $jsonPath -Value @{Value=3}
Assert-Case ((Read-GuardJson $jsonPath).Value -eq 3 -and (Read-GuardJson ($jsonPath+'.previous')).Value -eq 2) 'repeated atomic JSON replacement is compatible with PowerShell 5'


$emptyOriginal='# clean machine'+$nl+'192.0.2.5 unrelated.example'+$nl
$restored=Restore-GuardScopedHostsText -CurrentText $rendered -OriginalText $emptyOriginal -SafeMapping $map
Assert-Case (@(Get-GuardHostRows $restored | Where-Object {$_.Domain -in $script:GuardDomains}).Count -eq 0) 'clean-install restore removes updater-created routes'
Assert-Case ((Get-GuardUnrelatedSignature $restored) -ceq (Get-GuardUnrelatedSignature $rendered)) 'clean-install restore preserves unrelated hosts'
$restored=Restore-GuardScopedHostsText -CurrentText $rendered -OriginalText $inputText -SafeMapping $map
Assert-Case (@(Get-GuardHostRows $restored | Where-Object {$_.Domain -in $script:GuardDomains}).Count -eq 1) 'restore retains only originally present routes'

$merged=@(Merge-GuardCandidates -Fresh @('143.20.64.192') -Cached @('143.20.64.192') -Fallback '199.232.210.250')
Assert-Case ($merged.Count -eq 2 -and $merged[0] -eq '199.232.210.250') 'packaged fallback survives stale hosts and unreachable DNS answers'
$decision=Select-GuardReplacement -Current '143.20.64.192' -Healthy $false -FailureCount 0 -Threshold 1 -Candidates $merged -Validate {param($candidate) $candidate -eq '199.232.210.250'}
Assert-Case ($decision.Changed -and $decision.Address -eq '199.232.210.250') 'fresh setup can recover an adopted unreachable hosts address'
$decision=Select-GuardReplacement -Current '143.20.64.192' -Healthy $false -FailureCount 0 -Threshold 1 -Candidates $merged -Validate {$false}
Assert-Case (-not $decision.Changed -and $decision.Address -eq '143.20.64.192') 'packaged fallback still requires successful validation'
$merged=@(Merge-GuardCandidates -Fresh @() -Cached @() -Fallback '199.232.210.250')
Assert-Case ($merged.Count -eq 1 -and $merged[0] -eq '199.232.210.250') 'DNS outage retains a packaged candidate'
$merged=@(Merge-GuardCandidates -Fresh @('8.8.8.8','9.9.9.9','127.0.0.1') -Cached @('8.8.8.8') -Fallback '199.232.210.250' -Limit 2)
Assert-Case ($merged.Count -eq 2 -and $merged[0] -eq '199.232.210.250') 'candidate limit cannot discard packaged fallback'
Assert-Case (@(Merge-GuardCandidates -Fresh @('127.0.0.1') -Cached @() -Fallback '10.0.0.1').Count -eq 0) 'private fallback and DNS answers are rejected'
Assert-Case ((Assert-GuardCurlVersion 'curl 8.21.0 (Windows) libcurl/8.21.0 Schannel') -eq '8.21.0') 'supported native curl accepted'
Assert-Throws {Assert-GuardCurlVersion 'curl 7.55.1 (Windows)'} 'curl without JSON support fails before network probes'
Assert-Throws {Assert-GuardCurlVersion 'not a curl banner'} 'unknown curl version fails explicitly'
$failed=@{Healthy=$false;FailedDomains=@('i.scdn.co');Error=$null;HealthBefore=@{'i.scdn.co'=@{Ok=$false;Http=0;Reason='artwork_probe_failed'};'api.spotify.com'=@{Ok=$true;Http=401;Reason='spotify_endpoint_reachable'}}}
$explanation=Get-GuardBootstrapFailure $failed
Assert-Case ($explanation.Contains('i.scdn.co (HTTP 0; artwork_probe_failed)') -and $explanation.Contains('setup-result.json')) 'bootstrap failure names failed endpoint and persistent report'
Assert-Case (-not $explanation.Contains('api.spotify.com')) 'healthy endpoints are not blamed by setup diagnostics'
$explanation=Get-GuardBootstrapFailure @{Error='Run time budget exhausted';HealthBefore=@{}}
Assert-Case ($explanation.Contains('Run time budget exhausted')) 'early discovery error survives the setup message'
Assert-Case ((Get-GuardBootstrapFailure $null).Contains('Live hosts was not changed')) 'missing probe report has a safe failure explanation'

Write-Output ('ALL PASSED: '+$script:Passed)
