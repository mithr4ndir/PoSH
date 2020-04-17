$repeat = (New-TimeSpan -Hours 6)
$duration = ([timeSpan]::maxvalue)

######    Trigger once daily.    ######
<#$trigger = @(
           $(New-ScheduledTaskTrigger -At 06:30 -Daily),
           $(New-ScheduledTaskTrigger -At 18:30 -Daily)
           )#>

######    Trigger once repeat indefinitely.    ######
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
$action = New-ScheduledTaskAction -execute powershell.exe -argument '-command "& {c:\repository\bin\set-vmBkupTag.ps1 -vcenter vcenter -cluster SJC1_INFRA -logDir c:\repository\logs -logFile SJC1_INFRA-vmtagging.log -go}"'
$principal = New-ScheduledTaskPrincipal -UserID corp\svc-gmsa-script$ -LogonType Password
$taskName = "VMWare-SJC1_INFRA-Backup Tagging"
$description = "Updates SSSD Groups gid number attribute to a unique value, runs every 12 hours"
Register-ScheduledTask -TaskName $taskname -Action $action -description $description -Trigger $trigger -Principal $principal -TaskPath "\vCenter\"

