<#
#Create Group for the GMSA service account, this will allow any member of this group to retrieve the password for gMSA account.
New-ADGroup -Name "gMSA_Infra" -SamAccountName "gMSA_Infra" -DisplayName "gMSA_Infra" -Description "Place Nodes that will leverage this svc-gmsa-infra" -GroupScope Universal -GroupCategory Security -Path "OU=gMSA Management,OU=Groups,OU=Restricted,$OUDomainPATH" -Server site1-dc01

#Add all windows nodes to this group so that they are allowed to retrieve password. Keep in mind -members parameter relies on samaccount input value, and since these are systems we are adding to those group, we have to append the $ after the hostname of the computer object.
Add-ADGroupMember -Identity "gMSA_Infra" -Members "site1-infra01$" -Server site1-dc01

#Create gMSA account and add gmsa group which the nodes stored within retrieve the password from the domain.
New-ADServiceAccount -Name "svc-gmsa-infra" -SamAccountName "svc-gmsa-infra" -Displayname "svc-gmsa-infra" -Description "This gMSA account will manage Tasks that will run within site1-infra01.corp.Companyx.com" -DNSHostName svc-gmsa-infra.corp.Companyx.com -PrincipalsAllowedToRetrieveManagedPassword "gMSA_infra"  -Path "OU=gMSA Accounts,$OUPath,DC=corp,DC=Companyx,DC=com" -Server site1-dc01

#Systems added to groups need to be rebooted to reflect new membership principals.

#Test to verify that the computer account can retrieve the password for the gmsa account.
Invoke-Command site1-infra01 -ScriptBlock { Install-ADServiceAccount -Identity "svc-gmsa-infra"; Test-ADServiceAccount svc-gmsa-infra}
#>

#Create Scheduled Tasks = Worked for Win2012r2; you may have issues with 2016
$action = New-ScheduledTaskAction -execute 'C:\Repository\wrappers\auto-populate-802.1xtestcomputersGroup.cmd'
$trigger = New-ScheduledTaskTrigger -Once -At 1:45 -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([timeSpan]::maxvalue)
$principal = New-ScheduledTaskPrincipal -UserID corp\svc-gmsa-script$ -LogonType Password
$task = Register-ScheduledTask -TaskName "Populate 802.1x Test Computers Group" -Action $action -Trigger $trigger -Principal $principal -TaskPath "\Active Directory\"
#$task.Triggers.Repetition.Duration = "P1D" #Repeat for a duration of one day
#$task.Triggers.Repetition.Interval = "PT1H" #Repeat every 6 hours, use PT30m for every 30 minutes if needed
#$task | Set-ScheduledTask

#To Remove scheduled task run...
Unregister-scheduledtask "Populate 802.1x Test Computers Group" -Confirm:$false -TaskPath "\A"

Get-ScheduledTask -TaskPath \ -CimSession site1-scripts01 | ? {$_.taskname -like "*infra*"}


<#
TODO
Make a process out of this...
#>


# Change these three variables to whatever you want
$jobname = "Recurring PowerShell Task"
$script =  "C:\Scripts\Test-ExampleScript.ps1 -Server server1"
$repeat = (New-TimeSpan -Minutes 5)
 
# The script below will run as the specified user (you will be prompted for credentials)
# and is set to be elevated to use the highest privileges.
# In addition, the task will run every 5 minutes or however long specified in $repeat.
$action = New-ScheduledTaskAction –Execute "$pshome\powershell.exe" -Argument  "$script; quit"
$duration = ([timeSpan]::maxvalue)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
 
$msg = "Enter the username and password that will run the task"; 
$credential = $Host.UI.PromptForCredential("Task username and password",$msg,"$env:userdomain\$env:username",$env:userdomain)
$username = $credential.UserName
$password = $credential.GetNetworkCredential().Password
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd
 
Register-ScheduledTask -TaskName $jobname -Action $action -Trigger $trigger -RunLevel Highest -User $username -Password $password -Settings $settings