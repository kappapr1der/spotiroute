param([string]$PackageRoot=$PSScriptRoot)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$install='C:\ProgramData\SpotifyNetworkGuard'
$taskName='Spotify Network Guard'
$report=@{Success=$false;StartedUtc=[DateTime]::UtcNow.ToString('o');Error=$null;TaskRegistered=$false}
$reportRootReady=$false
try {
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Installation requires administrator rights'}
    # Never adopt an installation tree an ordinary user can still replace or modify.
    if([IO.Directory]::Exists($install)){
        $trusted=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        $pending=New-Object 'System.Collections.Generic.Queue[string]'
        $pending.Enqueue($install);$checkedPaths=0
        $writeRights=[Security.AccessControl.FileSystemRights]'Write, Delete, ChangePermissions, TakeOwnership, DeleteSubdirectoriesAndFiles'
        while($pending.Count -gt 0){
            $checkPath=$pending.Dequeue();$checkedPaths++
            if($checkedPaths -gt 1000){throw 'Existing installation contains too many entries to adopt'}
            $checkItem=Get-Item -LiteralPath $checkPath -Force
            if(($checkItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Existing installation contains a redirected path'}
            $checkAcl=Get-Acl -LiteralPath $checkPath
            if($checkAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'Existing installation has an untrusted owner'}
            foreach($rule in $checkAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
                if($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeRights) -ne 0 -and $rule.IdentityReference.Value -notin $trusted){throw 'Existing installation is writable by ordinary users'}
            }
            if($checkItem.PSIsContainer){foreach($child in [IO.Directory]::GetFileSystemEntries($checkPath)){$pending.Enqueue($child)}}
        }
        $existingOwner=Get-Content -LiteralPath (Join-Path $install 'owner.json') -Raw | ConvertFrom-Json
        if($existingOwner.Product -ne 'SpotifyNetworkGuard'){throw 'Installation directory belongs to another product'}
    }
    if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){throw 'Task name is already in use'}
    $files=@('Guard.Core.ps1','Update-SpotifyHosts.ps1','Manage-SpotifyGuard.ps1','config.json')
    $manifest=Get-Content -LiteralPath (Join-Path $PackageRoot 'manifest.json') -Raw | ConvertFrom-Json
    foreach($name in $files){
        $expected=[string]$manifest.Hashes.$name
        if(-not $expected -or (Get-FileHash -LiteralPath (Join-Path $PackageRoot $name) -Algorithm SHA256).Hash -ne $expected){throw ('Package checksum mismatch: '+$name)}
    }
    . (Join-Path $PackageRoot 'Guard.Core.ps1')
    $hostPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $before=[IO.File]::ReadAllBytes($hostPath)
    $originalText=$script:ByteEncoding.GetString($before)
    $observed=Get-GuardObservedMapping $originalText
    $config=Read-GuardJson (Join-Path $PackageRoot 'config.json')
    if(-not $config.ContainsKey('FallbackMapping')){$config.FallbackMapping=$config.InitialMapping.Clone()}
    $mapping=$config.InitialMapping.Clone()
    foreach($domain in @('i.scdn.co','image-cdn-ak.spotifycdn.com')){
        if($observed.ContainsKey($domain)){$mapping[$domain]=$observed[$domain]}
    }
    $oldGateways=@($script:GatewayDomains | Where-Object {$observed.ContainsKey($_)} | ForEach-Object {$observed[$_]} | Select-Object -Unique)
    if($oldGateways.Count -eq 1 -and @($script:GatewayDomains | Where-Object {-not $observed.ContainsKey($_)}).Count -eq 0){
        foreach($domain in $script:GatewayDomains){$mapping[$domain]=$oldGateways[0]}
    }
    Assert-GuardMapping $mapping
    [void][IO.Directory]::CreateDirectory($install)
    $item=Get-Item -LiteralPath $install -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Install directory must not be a reparse point'}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $prop=[Security.AccessControl.PropagationFlags]::None
    foreach($entry in @(@('S-1-5-18','FullControl'),@('S-1-5-32-544','FullControl'),@('S-1-5-32-545','ReadAndExecute'))){
        $sid=New-Object Security.Principal.SecurityIdentifier($entry[0])
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]$entry[1],$inherit,$prop,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    Set-Acl -LiteralPath $install -AclObject $acl -ErrorAction Stop
    foreach($name in $files){[IO.File]::WriteAllBytes((Join-Path $install $name),[IO.File]::ReadAllBytes((Join-Path $PackageRoot $name)))}
    $data=Join-Path $install 'data'
    [void][IO.Directory]::CreateDirectory($data)
    [void][IO.Directory]::CreateDirectory((Join-Path $data 'backups'))
    [void][IO.Directory]::CreateDirectory((Join-Path $data 'temp'))
    $reportRootReady=$true
    Write-GuardJson -Path (Join-Path $install 'owner.json') -Value @{Product='SpotifyNetworkGuard';Schema=1;InstallationComplete=$false;InstalledUtc=[DateTime]::UtcNow.ToString('o');Hashes=$manifest.Hashes}
    if(-not [IO.File]::Exists((Join-Path $data 'preinstall-hosts.bak'))){[IO.File]::WriteAllBytes((Join-Path $data 'preinstall-hosts.bak'),$before)}

    Write-GuardJson -Path (Join-Path $data 'preinstall-routes.json') -Value $observed
    $native=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    # Discover and validate everything before the first live write, including on a clean machine.
    $config.InitialMapping=$mapping
    $config.FailureThreshold=1
    Write-GuardJson -Path (Join-Path $install 'config.json') -Value $config
    $bootstrap=Join-Path $data 'bootstrap'
    [void][IO.Directory]::CreateDirectory($bootstrap)
    & $native -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File (Join-Path $install 'Update-SpotifyHosts.ps1') -ForceDiscovery -DataRoot $bootstrap | Out-File -LiteralPath (Join-Path $data 'bootstrap-run.json') -Encoding utf8
    $bootstrapExit=$LASTEXITCODE
    $checked=Read-GuardJson (Join-Path $bootstrap 'status.json')
    $report.Bootstrap=$checked
    if($bootstrapExit -ne 0 -or -not $checked -or -not $checked.Healthy -or $checked.Error){throw (Get-GuardBootstrapFailure $checked)}
    $config.InitialMapping=$checked.Mapping
    $config.FailureThreshold=2
    Write-GuardJson -Path (Join-Path $install 'config.json') -Value $config
    $state=Read-GuardJson (Join-Path $bootstrap 'state.json')
    $state.Mapping=$checked.Mapping;$state.Failures=@{}
    Write-GuardJson -Path (Join-Path $data 'state.json') -Value $state
    & $native -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File (Join-Path $install 'Update-SpotifyHosts.ps1') -Apply | Out-File -LiteralPath (Join-Path $data 'initial-run.json') -Encoding utf8
    if($LASTEXITCODE -ne 0){throw 'Initial elevated application failed; task was not enabled'}
    $status=Read-GuardJson (Join-Path $data 'status.json')
    if(-not $status.Healthy -or $status.Error){throw 'Routes changed during setup; task was not enabled'}
    $actualHashes=$manifest.Hashes
    $actualHashes.'config.json'=(Get-FileHash -LiteralPath (Join-Path $install 'config.json') -Algorithm SHA256).Hash
    Write-GuardJson -Path (Join-Path $install 'owner.json') -Value @{Product='SpotifyNetworkGuard';Schema=1;InstallationComplete=$false;InstalledUtc=[DateTime]::UtcNow.ToString('o');Hashes=$actualHashes}
    $now=[IO.File]::ReadAllBytes($hostPath)
    if((Get-GuardUnrelatedSignature $originalText) -cne (Get-GuardUnrelatedSignature ($script:ByteEncoding.GetString($now)))){throw 'Unrelated hosts changed during installation; task was not enabled'}
    $action=New-ScheduledTaskAction -Execute $native -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\SpotifyNetworkGuard\Update-SpotifyHosts.ps1" -Apply' -WorkingDirectory $install
    $repeat=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 2)
    $boot=New-ScheduledTaskTrigger -AtStartup
    $boot.Delay='PT30S'
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7
    $taskPrincipal=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $definition=New-ScheduledTask -Action $action -Trigger @($repeat,$boot) -Settings $settings -Principal $taskPrincipal -Description 'Checks seven Spotify routes every two minutes. Replaces failed IPs only after validated HTTPS probes; preserves other hosts and never restarts Spotify or Discord.'
    Register-ScheduledTask -TaskName $taskName -InputObject $definition -ErrorAction Stop | Out-Null
    $report.TaskRegistered=$true
    $registered=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $principalId=[string]$registered.Principal.UserId
    if($principalId -match '^S-1-'){$principalSid=$principalId}else{$principalSid=(New-Object Security.Principal.NTAccount($principalId)).Translate([Security.Principal.SecurityIdentifier]).Value}
    if($registered.Actions[0].Execute -ne $native -or $principalSid -ne 'S-1-5-18'){throw 'Registered task does not match the intended principal/action'}

    Export-ScheduledTask -TaskName $taskName | Out-File -LiteralPath (Join-Path $PackageRoot 'task.xml') -Encoding utf8
    $report.FirstSchedulerStartUtc=[DateTime]::UtcNow.ToString('o')
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $owner=Read-GuardJson (Join-Path $install 'owner.json');$owner.InstallationComplete=$true;Write-GuardJson -Path (Join-Path $install 'owner.json') -Value $owner
    $control=Join-Path $data 'control-result.json'
    if([IO.File]::Exists($control)){Write-GuardJson -Path $control -Value @{Action='Install';Success=$true;AtUtc=[DateTime]::UtcNow.ToString('o')}}
    $report.Success=$true
    $report.InstallRoot=$install
    $report.InitialResult=$status.Result
    $report.InitialMapping=$status.Mapping
    $report.UnrelatedHostsPreserved=$true
    $report.SourceHashes=$manifest.Hashes
} catch {
    $report.Error=$_.Exception.Message
    if($report.TaskRegistered){try{Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null}catch{}}
} finally {
    $report.FinishedUtc=[DateTime]::UtcNow.ToString('o')
    if($reportRootReady){try{Write-GuardJson -Path (Join-Path $data 'setup-result.json') -Value $report}catch{}}
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $PackageRoot 'installation.json') -Encoding utf8
}
if(-not $report.Success){exit 1}
