$servers = @(
"site1-wsus02.corp.Companyx.com",
"irn1-rds-pm02.corp.Companyx.com",
"acm1-sql01.corp.Companyx.com",
"site1-verint01.corp.Companyx.com",
"irn1-rds-da01.corp.Companyx.com",
"sfo2-phy-sec01.corp.Companyx.com",
"irn1-rds-da02.corp.Companyx.com",
"irn1-rds-pa01.corp.Companyx.com",
"site2-sync01.corp.Companyx.com",
"irn1-rds-pm01.corp.Companyx.com",
"site4-cai-dhcp01.corp.Companyx.com",
"site4-sccm-dp01.corp.Companyx.com",
"site4-fintech01.corp.Companyx.com",
"site5-sccm-mp01.corp.Companyx.com",
"site4-fintech04.corp.Companyx.com",
"site4-fintech02.corp.Companyx.com",
"site4-fintech03.corp.Companyx.com",
"site1-infra01.corp.Companyx.com",
"mex1-prt-srv01.corp.Companyx.com"
)
$ServersSesh=New-PSSession $servers

$date = (Get-Date).AddDays(-30)
$DC2012 = Get-ADDomainController -Filter {operatingsystem -like "Windows Server*2012*"} |  select -ExpandProperty hostname # | ? {$_ -contains "acm1-dc01.corp.Companyx.com" -or $_ -like "acm1-dc02.corp.Companyx.com" -or $_ -like "irn1-dc01.corp.Companyx.com" -or $_ -like "irn1-dc02.corp.Companyx.com" -or $_ -like "ott1-dc01.corp.Companyx.com" -or $_ -like "sgp2-dc01.corp.Companyx.com" -or $_ -like "hyd1-dc01.corp.Companyx.com"}
$DC2016 = Get-ADDomainController -Filter {operatingsystem -like "Windows Server*2016*"} |  select -ExpandProperty hostname # | ? {$_ -contains "acm1-dc01.corp.Companyx.com" -or $_ -like "acm1-dc02.corp.Companyx.com" -or $_ -like "irn1-dc01.corp.Companyx.com" -or $_ -like "irn1-dc02.corp.Companyx.com" -or $_ -like "ott1-dc01.corp.Companyx.com" -or $_ -like "sgp2-dc01.corp.Companyx.com" -or $_ -like "hyd1-dc01.corp.Companyx.com"}
$MBRServers = Get-ADComputer -Filter {operatingsystem -like "Window*Server*2012*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase "OU=Servers,Ou=Computers,$OUDomainPATH" -Properties operatingsystem,whencreated,lastlogondate | select dnshostname,operatingsystem,whencreated,lastlogondate
$MBRServers = Get-ADComputer -Filter {operatingsystem -like "Window*Server*" -and enabled -eq $true -and lastlogondate -gt $date -and name -notlike "*pkienroll*"} <# -SearchBase "OU=Servers,Ou=Computers,$OUDomainPATH" #> -Properties operatingsystem,whencreated,lastlogondate | select dnshostname,operatingsystem,whencreated,lastlogondate
#$MBRServers = Get-ADComputer -Filter * -SearchBase "OU=Servers,Ou=Computers,$OUDomainPATH" -Properties operatingsystem,whencreated,lastlogondate | ? {$_.dnshostname -like $servers}| select dnshostname,operatingsystem,whencreated,lastlogondate
$MBRServersOther = Get-ADComputer -Filter {operatingsystem -like "Window*Server*" -and enabled -eq $true -and lastlogondate -gt $date} <#-SearchBase "OU=Servers,Ou=Computers,$OUDomainPATH"#> -Properties operatingsystem,whencreated,lastlogondate | select dnshostname,operatingsystem,whencreated,lastlogondate

#Get WSUS Clients
$WSUSClients = Get-WsusComputer -ComputerTargetGroups "All Computers" | sort FullDomainName
#Remove any int.Companyxatc domain entries
$WSUSClients= $WSUSClients | ? {$_.FullDomainName -notlike "*int.Companyx*"}

#Compare what is in wsus and AD
$ServersToFix = Compare-Object $WSUSClients.FullDomainName $MBRServers.dnshostname | sort InputObject | select -ExpandProperty inputobject

#Remove domain suffix
$servershostname = $ServersToFix -replace ".corp.Companyx.com"

#Give me memberof for these computers that are not in corp.Companyx.com
$servershostname| % {Get-ADComputer $_ -pro memberof | select samaccountname,@{name="memberof";expression={$_.memberof -join ","}}}
$servershostname| % {Get-ADComputer $_ -pro memberof | select samaccountname,@{name="memberof";expression={$_.memberof -join ","}}}

$newsesh = New-PSSession $ServersToFix

$here = Invoke-Command -Session $newsesh -ScriptBlock {Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate | select susclientid} 
$here

#Compile errors array into a readable format
$error.clear()
$AllObjs=@()
Foreach ($err in $error) {
$TempObj = New-Object PSObject
$TempObj | Add-Member -Type NoteProperty -Name "ServerName" -Value "$($err.TargetObject.ConnectionInfo.ComputerName)"
$TempObj | Add-Member -Type NoteProperty -Name "Reason" -Value "$($err.CategoryInfo.Reason)"
$TempObj | Add-Member -Type NoteProperty -Name "Details" -Value "$( $err.ErrorDetails.Message)"
$AllObjs += $TempObj
}
$AllObjs | export-csv C:\users\ChrisL\Desktop\errors1.csv -NoTypeInformation

$DCsesh2016 = New-PSSession $DC2016
$MBRsesh2012 = New-PSSession $MBR2012
$MBRsesh2016 = New-PSSession $MBR2016
$MBRsesh2012=$null
$MBRsesh2016=$null
Get-PSSession | Remove-PSSession


Get-ADComputer -Filter {operatingsystem -like "Window*Server*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase "OU=Servers,Ou=Computers,$OUDomainPATH" | measure

Invoke-Command -ComputerName hyd1-dc01 -ScriptBlock {
#Get-Hotfix | Sort InstalledOn
#Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows\
#hostname
"\\site1-file01\SWInstall\WSUS\Reset WSUS Authorization.bat"
}
#2012r2 Security Update Needed KB4056898
$Query2012 = Invoke-Command -Session $DCSesh2012 -ScriptBlock { 
Get-hotfix | ? {$_.hotfixid -like "KB4056898"}
}
$Query2016 = Invoke-Command -Session $DCsesh2016 -ScriptBlock { 
Get-hotfix | ? {$_.hotfixid -like "KB4056890"}
}

$MissingUpdate2012 = Compare-Object $DC2012 $Query2012.pscomputername

$MissingUpdate2016 = Compare-Object $DC2016 $Query2016.pscomputername

#2016 Security update needed
KB4056890
$QueryDC

$comp = get-adcomputer site1-mim-sql01|select -ExpandProperty dnshostname
$sesh = New-PSSession -ComputerName $ServersToFix

$Query=$null
$Query = Invoke-Command -Session $MBRSesh2016 -ScriptBlock {
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate -Name SusClientID | select pscomputername,susclientid
}
$Query = $Query | sort SusClientID | export-csv -NoTypeInformation C:\Users\ChrisL\Desktop\query

#Fix WSUS same client id issues
$FixWSUS = Invoke-Command -Session $newsesh -ScriptBlock{
#$checkCltID=(Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate -Name SusClientID).susclientid
#IF ($checkCltID -eq "1f4820c8-99fc-4b5a-9c2a-82306dadfe5c") {
#Start-Process -File powershell.exe -ArgumentList '-Command "& {stop-Service Wuauserv}"' -PassThru -wait
#IF ((Get-service wuauserv).Status -like "Stopped") {Ren C:\Windows\SoftwareDistribution C:\Windows\SoftwareDistribution.old1}
#Write-Output "$env:COMPUTERNAME"
#Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate #| Remove-ItemProperty -Name SusClientId -force
#Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
#Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate | Remove-ItemProperty -Name SusClientIdValidation -force
#Start-Process -File powershell.exe -ArgumentList '-Command "& {IF ((Get-service wuauserv).Status -like "Stopped")) {start-Service Wuauserv;wuauclt /resetauthorization /detectnow}}"' -PassThru -wait
#Start-Service wuauserv
<#
IF ((Get-service MpsSvc).Status -like "Stopped") {Start-Service -Name MpsSvc} 
IF ((Get-service BITS).Status -like "Stopped") {Start-Service -Name BITS}
IF ((Get-service wuauserv).Status -like "Stopped") {start-Service -Name wuauserv} 
IF ((Get-service appidsvc).Status -like "Stopped") {start-Service -Name appidsvc}
IF ((Get-service cryptsvc).Status -like "Stopped") {start-Service -Name cryptsvc}
#>
<#
Get-Service MpsSvc
Get-service BITS
Get-service wuauserv 
Get-service appidsvc
Get-service cryptsvc
#>
#(Get-service wuauserv).Status
#IF ((Get-service wuauserv).Status -like "Stopped") {start-Service Wuauserv;wuauclt /resetauthorization /detectnow}
#wuauclt /resetauthorization /detectnow
#gpresult /SCOPE computer /r
#gpupdate
#Test-NetConnection site1-wsus01 -Port 8530
}

$servershostname | % {Get-ADComputer $_}

$FixWSUS | FT
#}
$error
$AllObjects=@()
Foreach ($server in $FixWSUS) {
IF ($server.value -eq "Stopped") {
$tempobject = New-PSobject
$tempobject | Add-Member -MemberType NoteProperty -Name FixThese -Value $Server.pscomputername
$AllObjects += $tempobject
}
}

Foreach ($serv in $servers) {
Invoke-Command -ComputerName $serv -ScriptBlock {
wuauclt /resetauthorization /detectnow
}}