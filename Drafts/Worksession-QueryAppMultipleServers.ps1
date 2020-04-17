$Feb24=(Get-Date).AddDays(-11)
$Servers=Get-ADComputer -filter {whencreated -gt $Feb24} -SearchBase "ou=servers,ou=computers,$OUDomainPATH"| select -exp name
$psSession = New-PSSession -ComputerName $Servers
Invoke-Command -Session $psSession -ScriptBlock { Get-WmiObject -Class win32_product | ? {$_.Name -like "*puppet*"} | select Name,Version,InstallDate }

