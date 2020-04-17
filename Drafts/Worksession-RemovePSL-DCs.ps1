$DomainDN = (Get-ADRootDSE).defaultnamingcontext
$dcs = Get-ADDomainController -filter * | select hostname
Get-PSSession | Remove-PSSession
$s = New-PSSession -ComputerName $dcs.hostname

$PSLMassRemoval = Invoke-command -Session $s -ScriptBlock {
$PSLExist? = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\'
IF ($PSLExist?.__PSLockdownPolicy -match '[0-9]') {Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name __PSLockdownPolicy ; $CheckAgain = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' ; IF ($CheckAgain.__PSLockdownPolicy -match '[0-9]') {Write-host "Failed to remove __PSLockDown from $env:computername" -BackgroundColor Black -ForegroundColor White} Else {Write-host "PSLockdown Removed from $env:computername" -BackgroundColor Green -ForegroundColor Black}}
IF ($PSLExist?.__PSLockdownPolicy -notmatch '[0-9]') {Write-host "Server $env:computername does not have constrained language mode" -BackgroundColor Cyan -ForegroundColor Yellow}
}