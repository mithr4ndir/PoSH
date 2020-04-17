$date  = (Get-date).AddDays(-30)
$servers = Get-ADComputer -filter {enabled -eq $true -and lastlogondate -gt $date -and OperatingSystem -like "Windows*Server*"} -SearchBase "OU=Servers,OU=Computers,$OUDomainPATH" | select -ExpandProperty dnshostname

$enter = New-PSSession -ComputerName $servers