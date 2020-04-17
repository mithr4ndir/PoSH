$ars = Get-ADComputer -filter {name -like "*-ars-app*"} | select name
$arsSession = New-PSSession -ComputerName $ars.name
Invoke-Command -Session $arsSession -ScriptBlock {Set-Service ARAdminSvc -StartupType Disabled}

Invoke-Command -Session $arsSession -ScriptBlock {get-service aradminsvc}