$repeat = (New-TimeSpan -Hours 12)
$duration = ([timeSpan]::maxvalue)

######    Trigger once daily.    ######
<#$trigger = @(
           $(New-ScheduledTaskTrigger -At 06:30 -Daily),
           $(New-ScheduledTaskTrigger -At 18:30 -Daily)
           )#>

######    Trigger once repeat indefinitely.    ######
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
$action = New-ScheduledTaskAction -execute powershell.exe -argument '-command "&{C:\Repository\bin\gid.ps1}"'
$principal = New-ScheduledTaskPrincipal -UserID corp\svc-gmsa-script$ -LogonType Password
$taskName = "Update-SSID-Gid"
$description = "Updates SSSD Groups gid number attribute to a unique value, runs every 12 hours"
Register-ScheduledTask -TaskName $taskname -Action $action -description $description -Trigger $trigger -Principal $principal -TaskPath "\Active Directory\"