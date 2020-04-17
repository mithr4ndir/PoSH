$domainControllers = Get-ADDomainController -Filter * | select -ExpandProperty name | sort # | ? {$_ -notlike "HKG1*"} |  ? {$_ -notlike "NET1*"}

$dcSession = New-PSSession -ComputerName $domainControllers
$dcSession += New-PSSession -ComputerName sjo1-dc01,hyd1-dc01


$VerifyNTDSCorrupt = Invoke-command -ComputerName site1-scripts01 -scriptblock {
#Get-Service puppet
#New-EventLog -LogName "Directory Service" -Source "NTDS ISAM"
#Write-EventLog -LogName "Directory Service" -Source "NTDS ISAM" -Message "Hello World" -EventId 467
$date = Get-Date
    $TempObj = Get-EventLog -LogName "Directory Service" -Source "NTDS ISAM" -ErrorAction SilentlyContinue | ? {$_.eventid -like "467"} 
    If (!$TempObj) {Write-Output "$($date.ToUniversalTime()) : No 467 event id entries found for $env:computername"}
    Else {Write-Output "$($date.ToUniversalTime()) : OH NO!!! DB Corruption Detected!"}
}

$dcSession | Remove-PSSession
Remove-Variable $dcSession