param([ValidateSet('Status','Check','Disable','Enable','Restore','Uninstall')][string]$Action='Status')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$root='C:\ProgramData\SpotifyNetworkGuard'
$taskName='Spotify Network Guard'
if([IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') -ne $root){throw 'Run the installed manager from C:\ProgramData\SpotifyNetworkGuard.'}
. (Join-Path $root 'Guard.Core.ps1')
$data=Join-Path $root 'data'
if($Action -eq 'Status'){
    $status=Read-GuardJson (Join-Path $data 'status.json')
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $info=if($task){Get-ScheduledTaskInfo -TaskName $taskName}else{$null}
    @{Task=if($task){[string]$task.State}else{'not_visible_with_current_permissions'};LastTaskResult=if($info){$info.LastTaskResult}else{$null};Status=$status} | ConvertTo-Json -Depth 12
    exit 0
}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    $native=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    [void](Start-Process -FilePath $native -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','"C:\ProgramData\SpotifyNetworkGuard\Manage-SpotifyGuard.ps1"','-Action',$Action) -PassThru)
    Write-Output 'Administrator helper launched. Check status for the result.'
    exit 0
}
$result=@{Action=$Action;AtUtc=[DateTime]::UtcNow.ToString('o');Success=$false;Error=$null}
try {
    switch($Action){
        'Check' {Start-ScheduledTask -TaskName $taskName -ErrorAction Stop}
        'Disable' {Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null}
        'Enable' {Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null;Start-ScheduledTask -TaskName $taskName -ErrorAction Stop}
        {$_ -in @('Restore','Uninstall')} {
            $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if($task){Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null}
            $wait=[Diagnostics.Stopwatch]::StartNew()
            while($task -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Running'){
                if($wait.Elapsed.TotalSeconds -gt 135){throw 'Current check did not finish; no routes were restored.'}
                Start-Sleep -Milliseconds 400
            }
            $live=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
            $before=[IO.File]::ReadAllBytes($live)
            $config=Read-GuardJson (Join-Path $root 'config.json')
            $currentText=$script:ByteEncoding.GetString($before)
            $originalText=if($Action -eq 'Restore'){$script:ByteEncoding.GetString([IO.File]::ReadAllBytes((Join-Path $data 'preinstall-hosts.bak')))}else{$currentText}
            $newText=Restore-GuardScopedHostsText -CurrentText $currentText -OriginalText $originalText -SafeMapping $config.InitialMapping
            $proposed=$script:ByteEncoding.GetBytes($newText)
            if((Get-GuardHash $before) -ne (Get-GuardHash $proposed)){
                Write-GuardHostsLocked -Path $live -Expected $before -Proposed $proposed -BackupRoot (Join-Path $data 'backups')
                Clear-DnsClientCache -ErrorAction Stop
            }
            if($Action -eq 'Uninstall' -and $task){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop}
            if($Action -eq 'Uninstall'){
                $owner=Read-GuardJson (Join-Path $root 'owner.json');$owner.InstallationComplete=$false
                Write-GuardJson -Path (Join-Path $root 'owner.json') -Value $owner
            }
        }
    }
    $result.Success=$true
} catch {$result.Error=$_.Exception.Message}
Write-GuardJson -Path (Join-Path $data 'control-result.json') -Value $result
$result | ConvertTo-Json
if(-not $result.Success){exit 1}
