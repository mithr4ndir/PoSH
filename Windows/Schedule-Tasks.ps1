
# Set Global Variables
$ErrorActionPreference = "Stop"
$principal = New-ScheduledTaskPrincipal -UserID corp\svc-gmsa-script$ -LogonType Password



# Schedule Reporting Scripts
$description = "https://team.Companyxinternal.com/display/IT/Reporting+Groups+Scripts#ReportingGroupsScripts-ScriptDependencies"
$TaskPath = “\Reporting Scripts\”


$TaskName = "scheduled_createDK+3Groups"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
    -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration ([timespan]::MaxValue)
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_UpdateOrCreate_ALL_Report_Groups_FTE_EXT"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 14:00 -Daily
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_UpdateOrCreate_Direct_Report_Groups_FTE_EXT"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 04:00 -Daily
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_UpdateOrCreate_Staff_Report_Groups_FTE_EXT"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 06:00 -Daily
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath



# Schedule Active Directory Scripts
$description = "This scheduled task is maintained by TS-CorpSys."
$TaskPath = “\Active Directory\”


$TaskName = "scheduled_Workstation_AutoMover_Script"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
    -RepetitionInterval (New-TimeSpan -Hours 3) -RepetitionDuration ([timespan]::MaxValue)
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_Workstation_Cleanup_Script"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 00:00 -Weekl -DaysOfWeek Monday
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath -

$TaskName = "scheduled_SendEmail_DSRM_Rotation"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 00:00 -Weekly -DaysOfWeek Monday -WeeksInterval 24
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_SendEmail_Krbtgt_Rotation"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -At 00:00 -Weekly -DaysOfWeek Monday -WeeksInterval 24
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_Server_Update_Groups"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
    -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration ([timespan]::MaxValue)
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath

$TaskName = "scheduled_BOD_Accounts_Status"
$action = New-ScheduledTaskAction -execute powershell.exe `
    -argument "-command `"&{C:\Repository\bin\Scheduled\$TaskName.ps1}`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
    -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration ([timespan]::MaxValue)
Register-ScheduledTask -TaskName $taskName -Trigger $trigger `
    -Action $action -description $description -principal $principal `
    -taskpath $TaskPath
    
