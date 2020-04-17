$DomainDN = (Get-ADRootDSE).defaultnamingcontext
$servers = get-adcomputer -filter {operatingsystem -like "Windows Server*" -and name -notlike "*-dc0*"} -SearchBase "OU=Servers,Ou=Computers,OU=managed,$domaindn" -pro lastlogondate | select dnshostname,lastlogondate
Get-PSSession | Remove-PSSession
$s = New-PSSession -ComputerName $servers.dnshostname

#Session Executions
$PSLMassRemoval = Invoke-command -Session $s -ScriptBlock {
$PSLExist? = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\'
IF ($PSLExist?.__PSLockdownPolicy -match '[0-9]') {Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name __PSLockdownPolicy ; $CheckAgain = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' ; IF ($CheckAgain.__PSLockdownPolicy -match '[0-9]') {Write-host "Failed to remove __PSLockDown from $env:computername" -BackgroundColor Black -ForegroundColor White} Else {Write-host "PSLockdown Removed from $env:computername" -BackgroundColor Green -ForegroundColor Black}}
IF ($PSLExist?.__PSLockdownPolicy -notmatch '[0-9]') {Write-host "Server $env:computername does not have constrained language mode" -BackgroundColor Cyan -ForegroundColor Yellow}
}


#Foreach enumerations
Foreach ($server in $servers) {
$PSLExist? = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' 
IF ($PSLExist?.__PSLockdownPolicy -match '[0-9]') {Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name __PSLockdownPolicy ; $CheckAgain = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' ; IF ($CheckAgain.__PSLockdownPolicy -match '[0-9]') {Write-host "Failed to remove __PSLockDown from $env:computername" -BackgroundColor Black -ForegroundColor White} Else {Write-host "PSLockdown Removed from $env:computername" -BackgroundColor Green -ForegroundColor Black}}
IF ($PSLExist?.__PSLockdownPolicy -notmatch '[0-9]') {Write-host "Server $env:computername does not have constrained language mode" -BackgroundColor Cyan -ForegroundColor Yellow}


}


$DHCP = get-adcomputer -filter {name -like "*dhcp*" -and name -notlike "pgn1-*"} | select name
$newdhcpsesh | Remove-PSSession
$newdhcpsesh = New-PSSession -ComputerName $dhcp.name