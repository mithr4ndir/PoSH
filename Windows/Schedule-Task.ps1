#$repeat = (New-TimeSpan -Hours 6)
#$duration = ([timeSpan]::maxvalue)

######    Trigger once daily.    ######
$trigger = @(
           #$(New-ScheduledTaskTrigger -At 06:30 -Daily),
           $(New-ScheduledTaskTrigger -At 18:30 -Daily)
           )

######    Trigger once repeat indefinitely.    ######
#$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
$action = New-ScheduledTaskAction -execute powershell.exe -argument '-command "&{C:\Repository\bin\Scheduled\scheduled_OSS_stats.ps1}"'
$principal = New-ScheduledTaskPrincipal -UserID corp\svc-gmsa-script$ -LogonType Password
$taskName = "Update-OSS-Dashboard"
$description = "Update OSS Kibana Dashboard"
Register-ScheduledTask -TaskName $taskname -Action $action -description $description -Trigger $trigger -Principal $principal -TaskPath "\Kibana Reports\"
