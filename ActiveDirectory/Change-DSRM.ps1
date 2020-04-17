#Grab all domain controllers hostname - no table/no headers
$domaincontrollers = Get-ADDomainController -filter * | select -ExpandProperty hostname
#$domaincontrollers = "site2-dc03","site2-dc10","site5-dc02"

#Remove existing powershell sessions for variable newdcsessions if they exist
If (!($newdcsessions -eq $null)) { Remove-PSSession -Session $newdcsessions ; $newdcsessions=$null }

#Load variable with sessions from Domaincontrollers variable
$newdcsessions = New-PSSession $domaincontrollers

#Set DSRM Password to session 
$DsrmMassChange = invoke-command -session $newdcsessions -scriptblock {
    Write-Host Currently processing $env:computername and checking for dsrm-reset -ForegroundColor Green
    ntdsutil "set dsrm password" "Sync from domain account dsrm-reset" quit quit
    Get-ADUser dsrm-reset -pro passwordlastset -server $env:computername | select passwordlastset
    }

