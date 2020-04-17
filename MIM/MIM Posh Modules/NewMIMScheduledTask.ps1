if (!$UserCredential) { $UserCredential = Get-Credential 'domain\MIMAdmin' }
$ScriptDirectory = 'E:\MIM\Tools'
$Disable = $false

$A = New-ScheduledTaskAction –Execute '%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NonInteractive -NoProfile -File "Start-FIMSync.ps1"' -WorkingDirectory $ScriptDirectory
$T = New-ScheduledTaskTrigger -Once -At (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration ([timespan]::MaxValue)
$P = New-ScheduledTaskPrincipal -UserId $UserCredential.UserName -LogonType S4U -RunLevel Limited
$S = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -WakeToRun -MultipleInstances IgnoreNew -Disable:$Disable
$SchTaskMIMScheduler = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S -Description 'Runs a single MIM sync cycle.'

$A = New-ScheduledTaskAction –Execute '%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NonInteractive -NoProfile -File "Clear-FIMRunHistory.ps1"' -WorkingDirectory $ScriptDirectory
$T = New-ScheduledTaskTrigger -Weekly -At (Get-Date -Hour 20 -Minute 0 -Second 0 -Millisecond 0) -DaysOfWeek Wednesday
$P = New-ScheduledTaskPrincipal -UserId $UserCredential.UserName -LogonType S4U -RunLevel Limited
$S = New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -WakeToRun -MultipleInstances IgnoreNew -Disable:$Disable
$SchTaskMIMClearRunHistory = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S -Description 'Clears the MIM sync Run History.'

$CimSession = New-CimSession -Credential $UserCredential
Register-ScheduledTask -TaskPath 'MIMSync' -TaskName 'MIMSync Scheduler' -InputObject $SchTaskMIMScheduler -CimSession $CimSession
Register-ScheduledTask -TaskPath 'MIMSync' -TaskName 'MIMSync Clear Run History' -InputObject $SchTaskMIMClearRunHistory -CimSession $CimSession
$CimSession | Remove-CimSession
