Function ConnectTo-Domaincontrollers () {
IF ($sesh -is [Object]) {Write-Output "Closing existing PS sessions"; Remove-PSSession $sesh -ErrorAction SilentlyContinue; Remove-Variable Sesh}
$alldcs = Get-ADDomainController -filter * | select -exp name
$cred=Get-Credential
$sesh = New-PSSession -ComputerName $alldcs -Credential $cred
Write-Output '$Sesh variable established'
}
