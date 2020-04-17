<#
.Synopsis
   This script is designed to install netmon 3.4 to all member servers from the Powershell ISE Console.
.OUTPUTS
   Outputs of the scripts logic are currently displayed within an active console only.
   $InvokeAppQuery Will show you which servers have the app installed
.NOTES
   Keep in mind that this script uses New-PSSession and Invoke-command modules to carry out application queries and install executions. Add-Path script and function is loaded within this script so that there is no dependancy on whether the module exists within the server fleet.
#>

#DomainDN is a adaptable domain variable, so that you may run this script within prod or dev domains.
$DomainDN = (Get-ADDomain).DistinguishedName
#membberservers will include any domain joined servers found within the domain that live within the Servers OU. Lastlogondate is also included for each computer class object, which is good for troubleshooting possible scenarios where a server was unreachable due to it either being stale within the directory
$memberservers = Get-adcomputer -filter {operatingsystem -like "Windows Server*" -and enabled -eq $true} -SearchBase "OU=Backup,OU=Virtualization,OU=Servers,OU=Computers,OU=Managed,$DomainDN" -pro lastlogondate | select dnshostname,lastlogondate

#Define application and parameter variables
#####
$AppBits = "\\site1-file01\SWInstall\Duomst\DuoWindowsLogon64.msi"
$AppLocalBits = "C:\Installs\DuoWindowsLogon64.msi"
$AppFileName = "DuoWindowsLogon64.msi"
$AppParam = ' /qn'
$AppQuery = "Duo Authentication*"
#####

#Create PS Sessions based off of $membersservers
Get-PSSession | Remove-PSSession
$s = New-PSSession -ComputerName $memberservers.dnshostname

#Query Servers for application.
$InvokeAppQuery = $null
$InvokeAppQuery = Invoke-Command -Session $s -ScriptBlock {
    param(
    $rAppQuery = $AppQuery
    )
    Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $rAppQuery}
    Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $rAppQuery}
    } -ArgumentList $AppQuery

#Variable to create a new session of the machines that currently do not have the application installed
$NotInstalled = $null
$NotInstalled = Compare-Object $memberservers.dnshostname $InvokeAppQuery.pscomputername

Write-host "These servers do not have $AppFileName installed..." -BackgroundColor Black -ForegroundColor Red
$NotInstalled.InputObject

#Create new session for servers that do not have app installed.
$newSesh = New-PSSession -ComputerName $NotInstalled.InputObject
$newsesh = $s

#Copy app binaries to all servers to prepare for install; only if the binaries or the folder of where the binaries live do not exist
Write-Host "Starting foreach loop"
Foreach ($server in $newSesh.ComputerName)
{
    Write-host "Processing through $server"
    if (!(Test-Path -path "\\$server\C$\Installs\$AppFileName"))
        {                                            
            Write-host "File not found, does path exist?" -BackgroundColor Black -ForegroundColor Red
            if (!(Test-path -path "\\$server\c$\Installs\"))
                {
                Write-Host "Folder not found creating directory now..." -BackgroundColor Black -ForegroundColor Red
                New-Item "\\$server\c$\Installs\" -Type Directory
                }
            Write-Host "Path Exists, going to copy binaries..." -BackgroundColor Black -ForegroundColor Red
            Copy-Item -Path $AppBits -Destination "\\$server\c$\Installs\" -Force
            Write-host "$AppFileName File Copied"
        }

}
#Print to console servers that need to have app installed.
Write-host "Attempting to install app for ..." -BackgroundColor Black -ForegroundColor Yellow
$newsesh.computername

#Invoke the app install.
$InvokeAppInstall = Invoke-Command -Session $newSesh -ScriptBlock {
    param(
    $rAppLocalBits = $AppLocalBits,
    $rAppParam = $AppParam
    )
    #Unblocks file since it was copied from a network based directory otherwise the app does not install
    Unblock-file  -path $rAppLocalBits
    Write-host "Installing bits for $env:computername"
    start-process -File $rAppLocalBits -ArgumentList $rAppParam -PassThru | Wait-process
    
    } -ArgumentList $AppLocalBits,$AppParam