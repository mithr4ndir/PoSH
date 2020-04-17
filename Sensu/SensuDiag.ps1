<#
.SYNOPSIS
  Name: Diag-Sensu.ps1
  The purpose of this script is to harness Sensu App info on target node to help with problematic nodes.
  
.DESCRIPTION

.PARAMETER InitialDirectory
  
.PARAMETER Add
  A switch parameter that will cause the example function to ADD content.

Add or remove PARAMETERs as required.

.NOTES
    Updated: 02-22-2019        Change comment.
    Release Date: 02-22-2019
   
  Author: Chris L.

.EXAMPLE
  Run the Get-Example script to create the c:\example folder:
  Get-Example -Directory c:\example

.EXAMPLE 
  Run the Get-Example script to create the folder c:\example and
  overwrite any existing folder in that location:
  Get-Example -Directory c:\example -force

See Help about_Comment_Based_Help for more .Keywords

# Comment-based Help tags were introduced in PS 2.0
#requires -version 2
#>
Function Get-SensuInfo() {
[CmdletBinding()]
PARAM ( 
    [string[]]$node
)
#Sensu 
Foreach ($no in $node) {
    Write-Output "$no - Checking Sensu Service" 
    $sensuService=Get-Service sensu-client -ComputerName $no -ErrorAction SilentlyContinue| select Name,StartType,Status
    If ($sensuService -isnot [object]) {
    Write-Output "$no = ## Sensu Service Not Found ##"
    }
    Else {
        ##Sensu App info
        Try {
        $installInfo=ICM -ComputerName $no -ScriptBlock { Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,InstallSource,InstallDate,UninstallString | ? {$_.displayname -like "*Sensu*"} }
        } Catch { Write-Output "$_"}
        ##Sensu Config
        Try {$Config=GC \\$no\c$\opt\sensu\conf.d\rabbitmq.json;$config=$Config | ConvertFrom-Json | select -exp rabbitmq}
        Catch { Write-Output "File not found - $_"}

        ##Sensu Processes
        $Process=Get-WmiObject -class win32_process -ComputerName $no | ? {$_.commandline -like "*sensu*"} | select path,ProcessName,CommandLine 

        ##Test Net Connection
        $TestPort=ICM -ComputerName $no -ScriptBlock {Test-NetConnection "usw2-rabbitmq-prod-vip.corp.Companyx.internal" -Port 5672}
    
        #Get Host info
        $hostinfo=Get-wmiobject win32_operatingsystem -ComputerName $no | select PSComputerName,Caption,OSArchitecture,BuildNumber,LastBootUpTime
        
        $tempObj=New-Object psobject
        $tempObj | Add-Member NoteProperty -Name ServiceState -Value $sensuService
        $tempObj | Add-Member NoteProperty -name InstallInfo -Value $installInfo
        $tempObj | Add-Member NoteProperty -Name Config -Value $Config
        $tempObj | Add-Member NoteProperty -name Process -Value $Process
        $tempObj | Add-Member NoteProperty -Name TestPort -Value $TestPort
        $tempObj | Add-Member NoteProperty -name HostInfo -Value $hostinfo
        return $tempObj
        }
    }
}