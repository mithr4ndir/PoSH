#
#   .. Synopsis ..
#
# This script will grab network info, export to C:\installs\, mount a WinOS2016, 
# and automate the process along with post tasks that include setting nic to original IP 
#
#
#

#if ($credential -is [object]) {remove-variable credential;write-host "removed credential variable"}
if ($sessions -is [object]) {Get-PSSession | Remove-PSSession -Confirm:$False; Remove-Variable sessions;write-host "removed sessions variable"}
if ($psdrive -is [object]) {Remove-Variable psdrive; Write-Host "removed psdrive varible"}

#Harness Node
$servers=gc \\site1-scripts01\c$\Repository\input\WindowsInPlaceUpgrade\serversToUpgrade.txt
$sessions=New-PSSession -ComputerName $servers
if ($sessions -isnot [object]) {Write-host "Sessions Variable is not object, stopping script";exit}
# Get VMware resources and connect vcenter if not already connected
Import-Module VMware.VimAutomation.Core
If($connect.IsConnected -ne $true) {$connect=Connect-VIServer site1-vcsa01.corp.Companyx.com}
<#
#Get get snapshots for node
Foreach ($server in $servers) {
    if ($existingSnap -is [object]) {remove-variable existingsnap;write-host "removed existingSnap variable"}
    $existingSnap=Get-Snapshot $server
    #Create snapshots with live memory
    If ($existingSnap -isnot [object]) {New-Snapshot -VM $servers -Name BeforeUpgradeTo2016 -Memory:$true}
    }
    #>
#Get credential to run upgrade with
$credential = Get-Credential
IF ($credential -isnot [object]) {write-host "Exiting script credentials not provided";exit}

If (!($psdrive -is [object])) {
                               $psdrive = @{
                                    Name = "OSUpgrade"
                                    PSProvider = "FileSystem"
                                    Root = "\\site1-file01\SWInstall\Windows"
                                    Credential=$credential
                              }
}
IF ($psdrive -isnot [object]) {Write-host "Exiting script, will not be able to mount drive as PSDrive variable is null";exit}

#Record servers that have been upgraded already and export to csv
$upgradedserverslog="\\site1-file01\SWInstall\Windows\osUpgrade2018\serversUpgraded.csv"
If(!(Test-Path $upgradedserverslog)) {New-Item -Path $upgradedserverslog -ItemType File;Write-Host "Server upgrade log created"}

Invoke-Command -Session $sessions -ScriptBlock {
    param (
    $rUpgradedserverslog=$Upgradedserverslog
    )
    
    #Map drive to allow for access of network resources
    Try {Write-Output "Mounting drive!";$catchPSDriveProcess=Write-Output "Mounting drive!";New-PSDrive @using:PSDrive} 
    Catch {Write-Output "[$env:computername] $(Get-Date) : Failed to mount drive - $($_.exception.message) - EXITING";$catchPSDriveError=Write-Output "Failed to mount drive - $($_.exception.message) - EXITING";Exit}
    
    #Log function
    $LogFolder = "\\site1-file01\SWInstall\Windows\osUpgrade2018\scriptLogs"
    $MyName = "$Env:computername"
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
    Function Write-Log ($Message) {
        $ThisMsg = "[$MyName] $(Get-Date) : $Message"
        $ThisMsg | Out-File $LogFile -Append
        $ThisMsg
    }
    IF ($catchPSDriveProcess -is [object]) {Write-Log "Recording PSDrive result... $catchPSDriveError"}
    IF ($catchPSDriveError -is [object]) {Write-Log "Recording PSDrive result... $catchPSDriveError"}
    
    Write-Log "Starting pre-tasks upgrade process for $env:COMPUTERNAME"
    
    #Create Local Admin Account as failsafe option
    $securefile = "\\site1-file01\SWInstall\Windows\domain\secthing.txt"
    $KeyFile = "\\site1-file01\SWInstall\Windows\domain\random.key"
    $key = Get-Content $KeyFile
    
    $checkAdmin = Get-LocalUser FallBackAdmin -ErrorAction Ignore
    If (!($checkAdmin)) {
        Write-Log "Creating local admin account for failsafe purposes"
        New-LocalUser -Name FallBackAdmin -AccountNeverExpires -PasswordNeverExpires -Password (Get-Content $secureFile | ConvertTo-SecureString -Key $key) `
        -Description "Fallback Account for post migration"
        Add-LocalGroupMember -Group Administrators -Member FallBackAdmin
        }
    Else {
        Write-Log "Not creating local admin account, it already exists."
    }

    #Check to see if there is atleast 15gbs of free space on C otherwise stop the script
    $volumeC=Get-Volume | ? {$_.DriveLetter -like "C"}
    $sizeGB=($volumeC.SizeRemaining/1GB)
    $sizeGBrounded=[math]::Round($sizeGB)
    If ($sizeGBrounded -lt 15) {
        Write-log "Not enough capacity to upgrade, please clear some space"
        $temp = New-Object PSObject
        $temp | Add-Member -MemberType NoteProperty -name Hostname -Value ($env:computername)
        $temp | Add-Member -MemberType NoteProperty -name TimeStarted -Value (Get-date)
        $temp | Add-Member -MemberType NoteProperty -name Notes -Value "Not enough space on drive C - $($sizeGBrounded)"
        $temp | Export-csv -Path $rUpgradedserverslog -NoTypeInformation -Append -Force
        Exit
    }

    #Remove RAS-NIS if exist, otherwise upgrade fails.
    $nisInstall=Get-WindowsFeature rsat-nis
    If ($nisInstall.InstallState -like "Installed") {
        Try {
            Write-Log "RSAT-NIS Found, will uninstall, otherwise upgrade stalls"
            Uninstall-WindowsFeature rsat-nis
        } Catch { Write-Log "Failed to uninstall rsat-nis because of - $($_.exception.message)"}
    }
    
    #Remove Telnet Server if installed
    $telnetServ=Get-WindowsFeature telnet-server
    If ($telnetServ.InstallState -like "Installed") {
        Try {
            Write-Log "TelnetServer Found, will uninstall, otherwise upgrade stalls"
            Uninstall-WindowsFeature telnet-server
        } Catch { Write-Log "Failed to uninstall rsat-nis because of - $($_.exception.message)"}
    }

    #Need to remove SCEP before upgrade, otherwise upgrade fails
    $Scep=Test-Path 'C:\Program Files\Microsoft Security Client\MsMpEng.exe'
    if ($Scep) { 
        Try {
            Write-Log "SCEP found, uninstalling..."
        Start-Process "C:\Program Files\Microsoft Security Client\setup.exe" -ArgumentList "/u /s" -Wait
            }
        Catch {Write-Log "Failed to uninstall SCEP! - $($_.exception.message)"}
    } Else { Write-log "No Scep found"}

    #Stop and disable services
    $puppet=Get-service puppet -ErrorAction Ignore
    IF($puppet) {
        Try {
            Stop-Service $puppet.Name
            Set-Service -Name $puppet.name -StartupType Disabled 
            Write-Log "Stopped Puppet Service successfully!"
        } Catch { Write-Log "Failed to stop $($puppet.name) - $($_.exception.message)"}
        $puppetReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\puppet
        Try {
            If ($puppetReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$puppetReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\puppet -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($puppetReg.DisplayName)"}
    }
    $sensu=Get-Service sensu-client -ErrorAction Ignore
    IF($sensu) {
        Try {
        Stop-Service $sensu.Name
        Set-Service -Name $sensu.name -StartupType Disabled 
        Write-Log "Stopped Carbon Black Service successfully!"
        } Catch { Write-Log "Failed to stop $($sensu.name) - $($_.exception.message)"}
        $sensuReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\sensu-client
        Try {
            If ($sensuReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$sensuReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\sensu-client -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($sensuReg.DisplayName)"}
    }
    $nxlog=Get-Service nxlog -ErrorAction Ignore
    IF($nxlog) {
        Try {
        Stop-Service $nxlog.Name
        Set-Service -Name $nxlog.name -StartupType Disabled 
        Write-Log "Stopped NXLOG Service successfully!"
        } Catch { Write-Log "Failed to stop $($nxlog.name) - $($_.exception.message)"}
        $nxlogReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\nxlog
        Try {
            If ($nxlogReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$nxlogReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\nxlog -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($nxlogReg.DisplayName)"}

    }
    $carbon=Get-Service CarbonBlack -ErrorAction Ignore
    IF($carbon) {
        Try {
        Stop-Service $carbon.Name
        Set-Service -Name $carbon.name -StartupType Disabled 
        Write-Log "Stopped Carbon Black Service successfully!"
        } Catch { Write-Log "Failed to stop $($carbon.name) - $($_.exception.message)"}
        $carbonReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\carbonblack
        Try {
            If ($carbonReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$carbonReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\carbonblack -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($nxlogReg.DisplayName)"}
    }
    $pxp=Get-Service pxp-agent -ErrorAction Ignore
    IF($pxp) {
        Try {
        Stop-Service $pxp.Name
        Set-Service -Name $pxp.name -StartupType Disabled 
        Write-Log "Stopped PXP Puppet Service successfully!"
        } Catch { Write-Log "Failed to stop $($pxp.name) - $($_.exception.message)"}
        $pxpReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\pxp-agent
        Try {
            If ($pxpReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$pxpReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\pxp-agent -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($pxpReg.DisplayName)"}
    }
    $EMET=Get-Service EMET_Service -ErrorAction Ignore
    IF($EMET) {
        Try {
        Stop-Service $EMET.Name
        Set-Service -Name $EMET.name -StartupType Disabled 
        Write-Log "Stopped EMET Service successfully!"
        } Catch { Write-Log "Failed to stop $($EMET.name) - $($_.exception.message)"}
        $emetReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\emet_service
        Try {
            If ($emetReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$emetReg.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\emet_service -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($pxpReg.DisplayName)"}
    }
    $mcollective=Get-Service mcollective -ErrorAction Ignore
    IF($mcollective) {
        Try {
        Stop-Service $mcollective.Name
        Set-Service -Name $mcollective.name -StartupType Disabled 
        Write-Log "Stopped mcollective Service successfully!"
        } Catch { Write-Log "Failed to stop $($mcollective.name) - $($_.exception.message)"}
        $mcollectReg=Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\mcollective
        Try {
            If ($mcollectReg.ImagePath -like "1*") {
                Write-Log "No need to destroy imagepath, already destroyed" 
                }
                Else {
                    Write-Log "Set path prefix value with 1 to stop service from auto starting"
                    $SetNew="1"+$mcollective.ImagePath
                    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\mcollective -Name ImagePath  -Value $SetNew 
                }
        } Catch { Write-Log "Caught an error while trying to destroy imagepath of $($mcollectReg.DisplayName)"}
    }
    $filezilla=Get-Service "filezilla server" -ErrorAction Ignore
    IF($filezilla) {
        Try {
        Stop-Service $filezilla.Name
        Set-Service -Name $filezilla.name -StartupType Disabled 
        Write-Log "Stopped mcollective Service successfully!"
        } Catch { Write-Log "Failed to stop $($filezilla.name) - $($_.exception.message)"}
    }
    #If script was previously run, likely a checkmount variable exist, so we'll deconstruct the existing variable
    If ($checkmount -is [object]) {Remove-Variable checkmount}

    #Create Installs folder if does not exist
    $LocalPath="C:\Installs\"
    If (!(Test-Path $LocalPath)) {New-Item -Path $LocalPath -ItemType Directory -ErrorAction Ignore}
    #Grab network info
    $netInfoFilePath="C:\Installs\NetworkInfo.csv"
    #Copy local set net script to server.
    Copy-Item \\site1-file01\SWInstall\Windows\postUpgrade\set-netAdapter* $LocalPath -Force
    Copy-Item \\site1-file01\SWInstall\Windows\postUpgrade\install-puppet* $LocalPath -Force

    #Create new file if already exist, or create directory.
    Try {
    If (Test-Path $netInfoFilePath) {rm $netInfoFilePath -Force;Write-Log "Found and Deleted old $netInfoFilePath!"}
    Get-NetIPConfiguration | ? {$_.interfacealias -like "*ethernet*"}| Select computername, `
                                    interfacealias, `
                                    interfaceindex, `
                                    interfacedescription, `
                                    @{n="ipv4address";e={$_.ipv4address -join ","}}, `
                                    @{n="ipv4defaultgateway";e={$_.ipv4defaultgateway.nexthop -join ","}}, `
                                    @{n="dnsserver";e={$_.dnsserver.ServerAddresses -join ","}}, `
                                    @{n="ipv4prefixlength";e={(Get-NetIPAddress -InterfaceAlias ($_.interfacealias) |? {$_.addressfamily -eq "IPv4"}).PrefixLength}} -First 1 | Export-csv -Path C:\Installs\NetworkInfo.csv -NoTypeInformation -force
    }
    Catch {
        Write-Log "Error trying to get netipconfig! $($_.exception.message)"
    }
    #WindowsUpgrade Logs
    $logspathHost="\\site1-file01\SWInstall\Windows\osUpgrade2018\hostUpgradeLogs\$env:COMPUTERNAME"
    #Create log path for each host
    IF (!(Test-Path $logspathHost)) {Write-Log "Creating directory $logspathHost";New-Item -Path $logspathHost -ItemType Directory | out-null}
    #Path of Windows 2016 Standard Image
    $ImagePath="\\site1-file01\SWInstall\Windows\SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-3_MLF_X21-30350.ISO"
    #Custom WIM, only one option configured, Desktop mode
    $customWIM="\\site1-file01\SWInstall\Windows\WIM-8_29_2018\install.wim"
    #If ISOs mounted remove them
    IF($checkMount -is [object]) {$Dismount=Dismount-DiskImage -ImagePath $ImagePath; Write-log "Attempted to dismount image"}
    #Unblock files
    Unblock-File -Path $ImagePath
    Unblock-File -Path $customWIM

    #Freshly mount Windows 2016
    Try {
        $Mount=Mount-DiskImage -ImagePath $ImagePath
    }
    Catch {
        Write-Log "Error mounting drive! $($_.exception.message)"
    }
    #Harness drive letter of mounted iso
    Try {
    $imageVolDr=(Get-Volume | ? {$_.FileSystemLabel -like "SSS_X64FREV_EN-US_DV9"} | select -first 1).DriveLetter
    }
    Catch {
        Write-Log "Error finding winOS volume! $($_.exception.message)"
    }
    #Start the process to upgrade unattendly, logs will go to fileshare, ignore any compatiblity warnings, auto upgrade, silently, install from custom wim, execute post job tasks. (remove /quiet for now)
    Try {
    $upgradeProcess=Start-Process -FilePath "$($imageVolDr):\setup.exe" -ArgumentList " /copylogs $logspathHost /compat ignorewarning /auto upgrade /installfrom $customWIM /postoobe C:\installs\set-netAdapter.cmd" -PassThru
    }
    Catch {
        Write-Log "Error trying to start the process! $($_.exception.message)"
    }
        Write-Log "Logging Process ID $($upgradeProcess.ID) for $env:COMPUTERNAME"
    IF ($upgradeProcess.id -ne $null) {
        $temp = New-Object PSObject
        $temp | Add-Member -MemberType NoteProperty -name Hostname -Value ($env:computername)
        $temp | Add-Member -MemberType NoteProperty -name TimeStarted -Value (Get-date)
        $temp | Add-Member -MemberType NoteProperty -name Notes -Value "Started"
        $temp | Export-csv -Path $rUpgradedserverslog -NoTypeInformation -Append -Force
        }
    Else {Write-Log "Process not found therefore not adding server to upgradedserverlog"}
} -ArgumentList Upgradedserverslog

#Check setup process for servers
Start-Sleep -Seconds 30
icm -Session $sessions -ScriptBlock { `
    if($findSetup -is [object]) {
        Remove-Variable findSetup
        }
        $findSetup=get-process -ProcessName setuphost
        while ($findSetup) {get-process *set*;get-date | select -exp datetime ;Start-Sleep -Seconds 30}
        Write-host "$($Env:COMPUTERNAME) - Process no longer exists! Check the upgrade via console!" -BackgroundColor yellow
    } -ErrorAction Ignore