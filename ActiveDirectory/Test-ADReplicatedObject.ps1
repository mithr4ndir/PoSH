$domainControllers = Get-ADDomainController -Filter * | select -ExpandProperty name | sort | ? {$_ -notlike "HKG1*"} |  ? {$_ -notlike "NET1*"}

$dcSession = New-PSSession -ComputerName $domainControllers

$VerifyNTDSCorrupt = Invoke-command -session $dcSession -scriptblock {
Get-EventLog -LogName "Directory Service" -Source "NTDS ISAM" -InstanceId 467 -Newest 5 
}



