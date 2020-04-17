<#
.Synopsis
   This script is designed to remove constrained language mode. 
.OUTPUTS
   Outputs of the scripts logic are currently displayed within an active console only.
   $InvokeAppQuery Will show you which servers have the app installed
.NOTES
   Keep in mind that this script uses New-PSSession and Invoke-command modules to carry out config queries and removals.
#>

#DomainDN is an adaptable domain variable, so that you may run this script within prod or dev domains.
$DomainDN = (Get-ADRootDSE).defaultnamingcontext
$memberservers = get-adcomputer -filter {operatingsystem -like "Windows Server*"} -SearchBase "OU=Servers,Ou=Computers,OU=managed,$domaindn" -pro lastlogondate | select dnshostname,lastlogondate
Get-PSSession | Remove-PSSession
$s = New-PSSession -ComputerName $servers.dnshostname

#Session Executions
$PSLMassRemoval = Invoke-command -Session $s -ScriptBlock {
$PSLExist? = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\'
IF ($PSLExist?.__PSLockdownPolicy -match '[0-9]') {Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name __PSLockdownPolicy ; $CheckAgain = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' ; IF ($CheckAgain.__PSLockdownPolicy -match '[0-9]') {Write-host "Failed to remove __PSLockDown from $env:computername" -BackgroundColor Black -ForegroundColor White} Else {Write-host "PSLockdown Removed from $env:computername" -BackgroundColor Green -ForegroundColor Black}}
IF ($PSLExist?.__PSLockdownPolicy -notmatch '[0-9]') {Write-host "Server $env:computername does not have constrained language mode" -BackgroundColor Cyan -ForegroundColor Yellow}
}