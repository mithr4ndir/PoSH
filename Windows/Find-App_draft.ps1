<#
#Name of app to query
$app = 'Active Roles'
#Gather Hostnames
$memberServers = Get-adcomputer -filter {operatingsystem -like "Windows*Server*" -and enabled -eq $true} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" | select -ExpandProperty name
#Open PSSessions with hostnames gathered
$memberSessions = Enter-PSSession -ComputerName $memberServers

#Enumerate each hostname of $memberserver array
Foreach ($member in $memberserver)
{
        #Ping Server, if unsuccessful jump to else
        If (Test-Connection $member -count 2 -Quiet)
            {
                Write-host "$member pingable, gathering data..." -ForegroundColor Yellow -BackgroundColor Black
                $appwmi = $null
                $appwmi = Get-WmiObject -ComputerName $member -Class Win32_Product | Where-Object {$_.Name -match $app}
                
    }
}
#>

<#
.Synopsis
   This script is designed to install netmon 3.4 to all member servers from the Powershell ISE Console.
.OUTPUTS
   Outputs of the scripts logic are currently displayed within an active console only.
   $InvokeAppQuery Will show you which servers have the app installed
.NOTES
   Keep in mind that this script uses New-PSSession and Invoke-command modules to carry out application queries and install executions. Add-Path script and function is loaded within this script so that there is no dependancy on whether the module exists within the server fleet.
#>
    param
    (   
        #DomainDN is a adaptable domain variable, so that you may run this script within prod or dev domains.
        $Domain = (Get-ADDomain).dnsroot,
        $DomainDN = (Get-ADDomain).DistinguishedName,
        $memberservers = (Get-adcomputer -filter {operatingsystem -like "Windows*Server*" -and enabled -eq $true -and name -notlike "site1-scripts01"} -SearchBase "ou=servers,ou=computers,ou=managed,$DomainDN" -pro lastlogondate | select dnshostname,lastlogondate),
        
        #Define application and parameter variables
        $AppBits = "\\site1-file01\SWInstall\Tools\NetMon\NM34_x64.exe",
        $AppLocalBits = "C:\Installs\NM34_x64.exe",
        $AppFileName = "NM34_x64.exe",
        $AppParam = ' /Q',
        $App = "Dell Active Roles ?.?",
        $FailedWinRMArray=@(),
        $FileCopyErrors = 'C:\Repository\logs\netmonfile-errlogs.log',
        [boolean]$Transcripts = $false,
        $TranscriptFile = "C:\Repository\logs\netmonfile-transcripts.log",
        $WinRMRawErrors = $null
    )
$Error.Clear()
If (Test-Path $FileCopyErrors) {del $FileCopyErrors}
If ($Transcripts) {If (Test-path $TranscriptFile) {ri $Transcripts}}
If ($Transcripts) {Start-Transcript $TranscriptFile}

#Create PS Sessions based off of $membersservers
Get-PSSession | Remove-PSSession
$s = $null
$s = New-PSSession -ComputerName $memberservers.dnshostname -ErrorAction SilentlyContinue -ErrorVariable WinRMRawErrors
<#
#Extract erroneous hostnames into a readable format and export into a file
$WinRMRawMsg = $WinRMRawErrors.ErrorDetails | select -ExpandProperty message
$WinRMRawMsgSplit1 = $WinRMRawMsg -split "[][]" | sort
foreach ($item in $WinRMRawMsgSplit1) {if ($item -like "*$domain") {Write-host "$($item):Error establishing WinRM session" -BackgroundColor red;out-file -Append -Encoding ascii -FilePath $FileCopyErrors -InputObject  "$($item):Error establishing WinRM session";$Tempobj=New-Object PSObject;$Tempobj | Add-Member -MemberType NoteProperty -Name Hosts -Value $item;$FailedWinRMArray+=$Tempobj}}
#>
#Check for SMB


#Query Servers for application.
$InvokeAppQuery = $null
<#$InvokeAppQuery = Invoke-Command -Session $s -ScriptBlock {
    param(
    $rApp = $App
    )
    Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $rApp}
    Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $rApp}
    } -ArgumentList $App#>

Invoke-Command -Session $newseshy -ScriptBlock {
    param(
    $rApp = $App
    )
    
    $Query32 = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -match $rApp}
    if ($Query32 -is [object]) {Write-host "Displaying 32bit apps found" -BackgroundColor Yellow;$Query32}
    $Query64 = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -match $rApp} 
    if ($Query64 -is [object]) {Write-host "Displaying 64bit apps found" -BackgroundColor Green;$Query64}
    #$gatherUninstalls = $Query32
    #$gatherUninstalls += $Query64
    #Foreach ($item in $gatherUninstalls) {Write-host "Processing $($item.Displayname)";Write-host "Removing Software $($item.uninstallstring)";Start-process -FilePath "C:\"}
    #Write-host "Removing Software Active Roles";Start-process -FilePath "C:\ProgramData\Package Cache\{25af5230-05e8-467c-b6bd-1dba4fa049ed}\Setup.exe" -ArgumentList " /quiet /uninstall"
    } -ArgumentList $App

if ('Dell Active Roles 7.0' -like $app) {}#>

#New connection for hosts found with install
$newsesh = New-PSSession $InvokeAppQuery.pscomputername

$Test = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $App}
$test1 = $test.uninstallstring.replace(" /modify","")

<#Invoke-Command -Session $newseshy -ScriptBlock {
        param(
        $rapp=$app
        )
        $Test = Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | ? {$_.displayname -like $rApp}
        $test1 = $test.uninstallstring.replace(" /modify","")
        Start-process -FilePath $test1 -ArgumentList " /quiet /uninstall"
 } -ArgumentList $app
 #>
<#
#Variable to create a new session of the machines that currently do not have the application installed
$CompareObj = $null
$CompareObj = Compare-Object $memberservers.dnshostname $InvokeAppQuery.pscomputername -ErrorAction SilentlyContinue
IF ($CompareObj -eq $null) {write-host "Terminating script, no hosts to process" -BackgroundColor Black;Break}

$NotInstalled = $null
$NotInstalled = Compare-Object $FailedWinRMArray.hosts $CompareObj.inputobject

Write-host "These servers do not have $AppFileName installed..." -BackgroundColor Black -ForegroundColor Red
$NotInstalled.InputObject

#Create new session for servers that do not have app installed.
$newSesh | Remove-PSSession -ErrorAction SilentlyContinue
$newsesh = $null
$newSesh = New-PSSession -ComputerName $NotInstalled.InputObject -ErrorAction SilentlyContinue
#>
<#
#Check SMB
$test = Invoke-Command -Session $newSesh -ScriptBlock {portqry -n site1-scripts01 -e 445 -p tcp}
#>
<#
#Copy app binaries to all servers to prepare for install; only if the binaries or the folder of where the binaries live do not exist
Foreach ($server in $newSesh.ComputerName)
    {
        Write-host "Processing through $server"
        if (!(Test-Path -path "\\$server\C$\Installs\$AppFileName"))
            {                                            
                Write-host "File not found, does path exist?" -BackgroundColor Black -ForegroundColor Red
                if (!(Test-path -path "\\$server\c$\Installs\"))
                    {
                    Write-Host "Folder not found creating directory now..." -BackgroundColor Black -ForegroundColor Red
                    New-Item "\\$server\c$\Installs\" -Type Directory -ErrorAction SilentlyContinue
                    }
                Write-Host "Path Exists, going to copy binaries..." -BackgroundColor Black -ForegroundColor Red
                Copy-Item -Path $AppBits -Destination "\\$server\c$\Installs\" -Force -ErrorAction SilentlyContinue
                #Check if copy was successful
                If (Test-path "\\$server\c$\installs\$appfilename") { Write-host "$AppFileName File Copied" -BackgroundColor Green} Else {Write-Host "$AppFileName File NOT Copied" -BackgroundColor Red;out-file -Append -Encoding ascii -FilePath $FileCopyErrors -InputObject "$($server):Error copying binary to $($server), check port 445"}
            }
    }
#>
#Write-Verbose "This is a test"
#Print to console, servers that need to have app installed.
#Write-host "Enumrate install for this list of servers..." -BackgroundColor Black -ForegroundColor Yellow

<#$newSesh.computername | sort

#Invoke the app install.
$InvokeAppInstall = Invoke-Command -Session $newSesh -ScriptBlock {
    param(
    $rAppLocalBits = $AppLocalBits,
    $rAppParam = $AppParam
    )
    #Unblocks file since it was copied from a network based directory otherwise the app does not install
    Unblock-file  -path $rAppLocalBits
    Write-host "Installing bits for $env:computername"
    start-process -File $rAppLocalBits -ArgumentList $rAppParam -PassThru | Wait-process -Timeout 20
    #Removes shortcut
    Remove-Item 'C:\users\public\desktop\Microsoft Network Monitor 3.4.lnk'

    } -ArgumentList $AppLocalBits,$AppParam

Stop-Transcript#>