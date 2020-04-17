<#
.Synopsis.
   This script is designed to set constrained language mode to full language mode, which is the a non-restriction setting for all powershell type of executions. 
.OUTPUTS.
   Outputs of the scripts logic are currently displayed within an active console only.
.NOTES.
   -What is Powershell language mode? They are several mode types, that if set to constrained language mode, would set every powershell session, on the enforced windows operating system, in a restrictive state in which
   would limit powershells awesome abilities to carry out functions remotely, calling up .net objects and the like. More info can be found within the links provided in .REFERENCED LINKS.

   -Keep in mind that this script uses New-PSSession and Invoke-command modules to carry out config queries and modifications.
   
   -Different config modes of __PSLockdownPolicy...
    0 = Full Language
    1 = Full Language
    2 = Full Language
    3 = Full Language
    4 = Constrained Language Mode
    5 = Constrained Language Mode
    6 = Constrained Language Mode
    7 = Constrained Language Mode
    8 = Full Language

.REFERENCE LINKS.
   https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-5.1&viewFallbackFrom=powershell-Microsoft.PowerShell.Core
#>

#DomainDN is an adaptable domain variable, so that you may run this script within prod or dev domains.
$DomainDN = (Get-ADRootDSE).defaultnamingcontext
$memberservers = get-adcomputer -filter {operatingsystem -like "Windows Server*"} -SearchBase "OU=Servers,Ou=Computers,OU=managed,$domaindn" -pro lastlogondate | select dnshostname,lastlogondate
Get-PSSession | Remove-PSSession
$s = $null
$s = New-PSSession -ComputerName $servers.dnshostname

#Session Executions
$PSLMassRemoval = Invoke-command -Session $s -ScriptBlock {
$PSLExist? = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\'
IF ($PSLExist?.__PSLockdownPolicy -match '[4-7]') {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name __PSLockdownPolicy -Value '0'; $CheckAgain = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' ; IF ($CheckAgain.__PSLockdownPolicy -match '[4-7]') {Write-host "Failed to modify __PSLockDown from $env:computername" -BackgroundColor Black -ForegroundColor White} Else {Write-host "PSLockdown modified from $env:computername" -BackgroundColor Green -ForegroundColor Black}}
IF ($PSLExist?.__PSLockdownPolicy -notmatch '[4-7]') {Write-host "Server $env:computername does not have constrained language mode" -BackgroundColor Cyan -ForegroundColor Yellow}
}