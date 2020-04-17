#
#
# .SYNOPSIS - Script is used to Upgrade Windows OS 2012r2 Server
#
# .DESCRIPTION - There is a process on how and when to use this script please find it here...
#                https://team.Companyxinternal.com/display/IT/OS+Standardization+-+Install+Procedure
#
#

Function Local-Upgrade2016 { 
    $upgradedserverslog="\\site1-file01\SWInstall\Windows\osUpgrade2018\serversUpgraded.csv"

    #Log function
    $LogFolder = "\\site1-file01\SWInstall\Windows\osUpgrade2018\scriptLogs"
    $MyName = "$Env:computername"
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
    Function Write-Log ($Message) {
        $ThisMsg = "[$MyName] $(Get-Date) : $Message"
        $ThisMsg | Out-File $LogFile -Append
        $ThisMsg
    }
        
    Write-Log "Starting pre-tasks upgrade process for $env:COMPUTERNAME"
    
    #Check for PSVersion, if lower than 5.1, upgrade with WMF5.1
    $psCheck=$PSVersionTable.PSVersion.Major
    If ($psCheck -lt 5) {
        Try {
        $wmf51="\\site1-file01\SWInstall\Windows_Updates\Win8.1AndW2K12R2-KB3191564-x64.msu"
        $destFold="C:\Installs\"
        Write-Log "WMF needs updating, starting WMF 5.1 install, restart required afterwards, re-run script afterwards to continue upgrade process"
        if (!(Test-Path -path $destFold -Verbose)) { New-Item $destFold -Type Directory | Out-Null}
        Copy-Item -Path $wmf51 -Destination $destFold -Verbose
        Start-Process -FilePath 'wusa.exe' -ArgumentList "C:\Installs\Win8.1AndW2K12R2-KB3191564-x64.msu /extract:C:\windows\temp\" -Wait -PassThru 
        Start-Process -FilePath 'dism.exe' -ArgumentList "/online /quiet /add-package /PackagePath:C:\Windows\Temp\WindowsBlue-KB3191564-x64.cab" -Wait -PassThru 
        } Catch { Write-Log "Error caught! This is the msg... $($_.message)";Exit }
    }

    #OSCheck
    $osCheck=Get-WmiObject win32_operatingsystem | select -exp Caption
    If ($osCheck -like "*2016*") {
        Write-Log "No need to upgrade; this server is already 2016, exiting..."
        Exit
    }

    #Create Local Admin Account as failsafe option
    $securefile = "\\site1-file01\SWInstall\Windows\domain\secthing.txt"
    $KeyFile = "\\site1-file01\SWInstall\Windows\domain\random.key"
    $key = Get-Content $KeyFile
    
    $checkAdmin = Get-LocalUser FallBackAdmin -ErrorAction Ignore
    If (!($checkAdmin)) {
        Write-Log "Creating local admin account for failsafe purposes"
        New-LocalUser -Name FallBackAdmin -AccountNeverExpires -PasswordNeverExpires -Password (Get-Content $secureFile | ConvertTo-SecureString -Key $key) | Out-null `
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
        Write-log "Not enough capacity to upgrade, please clear some space, need 15gbs free"
        $temp = New-Object PSObject
        $temp | Add-Member -MemberType NoteProperty -name Hostname -Value ($env:computername)
        $temp | Add-Member -MemberType NoteProperty -name TimeStarted -Value (Get-date)
        $temp | Add-Member -MemberType NoteProperty -name Notes -Value "Not enough space on drive C - $($sizeGBrounded)"
        $temp | Export-csv -Path $Upgradedserverslog -NoTypeInformation -Append -Force
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
    }
    $sensu=Get-Service sensu-client -ErrorAction Ignore
    IF($sensu) {
        Try {
        Stop-Service $sensu.Name
        Set-Service -Name $sensu.name -StartupType Disabled 
        Write-Log "Stopped Carbon Black Service successfully!"
        } Catch { Write-Log "Failed to stop $($sensu.name) - $($_.exception.message)"}
    }
    $nxlog=Get-Service nxlog -ErrorAction Ignore
    IF($nxlog) {
        Try {
        Stop-Service $nxlog.Name
        Set-Service -Name $nxlog.name -StartupType Disabled 
        Write-Log "Stopped NXLOG Service successfully!"
        } Catch { Write-Log "Failed to stop $($nxlog.name) - $($_.exception.message)"}
    }
    $carbon=Get-Service CarbonBlack -ErrorAction Ignore
    IF($carbon) {
        Try {
        Stop-Service $carbon.Name
        Set-Service -Name $carbon.name -StartupType Disabled 
        Write-Log "Stopped Carbon Black Service successfully!"
        } Catch { Write-Log "Failed to stop $($carbon.name) - $($_.exception.message)"}
    }
    $pxp=Get-Service pxp-agent -ErrorAction Ignore
    IF($pxp) {
        Try {
        Stop-Service $pxp.Name
        Set-Service -Name $pxp.name -StartupType Disabled 
        Write-Log "Stopped PXP Puppet Service successfully!"
        } Catch { Write-Log "Failed to stop $($pxp.name) - $($_.exception.message)"}
    }
    $EMET=Get-Service EMET_Service -ErrorAction Ignore
    IF($EMET) {
        Try {
        Stop-Service $EMET.Name
        Set-Service -Name $EMET.name -StartupType Disabled 
        Write-Log "Stopped EMET Service successfully!"
        } Catch { Write-Log "Failed to stop $($EMET.name) - $($_.exception.message)"}
    }
    $mcollective=Get-Service mcollective -ErrorAction Ignore
    IF($mcollective) {
        Try {
        Stop-Service $mcollective.Name
        Set-Service -Name $mcollective.name -StartupType Disabled 
        Write-Log "Stopped mcollective Service successfully!"
        } Catch { Write-Log "Failed to stop $($mcollective.name) - $($_.exception.message)"}
    }

    #Remove RAS-NIS if exist, otherwise upgrade fails.
    $nisInstall=Get-WindowsFeature rsat-nis
    If ($nisInstall.InstallState -like "Installed") {
        Try {
            write-log "RSAT-NIS Found, will uninstall, otherwise upgrade stalls"
            Uninstall-WindowsFeature rsat-nis
        } Catch { write-log "Failed to uninstall rsat-nis because of - $($_.exception.message)"}
    }
    #Remove Telnet Server if installed
    $telnetServ=Get-WindowsFeature telnet-server
    If ($telnetServ.InstallState -like "Installed") {
        Try {
            write-log "TelnetServer Found, will uninstall, otherwise upgrade stalls"
            Uninstall-WindowsFeature telnet-server
        } Catch { write-log "Failed to uninstall rsat-nis because of - $($_.exception.message)"}
    }
    $filezilla=Get-Service "filezilla server" -ErrorAction Ignore
    IF($filezilla) {
        Try {
        Stop-Service $filezilla.Name
        Set-Service -Name $filezilla.name -StartupType Disabled 
        Write-Log "Stopped mcollective Service successfully!"
        } Catch { Write-Log "Failed to stop $($filezilla.name) - $($_.exception.message)"}
    }

    #Create Installs folder if does not exist
    $LocalPath="C:\Installs\"
    If (!(Test-Path $LocalPath)) {New-Item -Path $LocalPath -ItemType Directory}
    #Grab network info
    $netInfoFilePath="C:\Installs\NetworkInfo.csv"
    #Copy local set net script to server.
    Copy-Item \\site1-file01\SWInstall\Windows\postUpgrade\set-netAdapter* $LocalPath -Force
    Copy-Item \\site1-file01\SWInstall\Windows\postUpgrade\install-puppet* $LocalPath -Force

    #Create new file if already exist, or create directory.
    Try {
    If (Test-Path $netInfoFilePath) {rm $netInfoFilePath -Force;write-log "Found and Deleted old $netInfoFilePath!"}
                                Get-NetIPConfiguration | ? {$_.NetProfile.Name -like "*corp.Companyx.com*"}| Select computername, `
                                    interfacealias, `
                                    interfaceindex, `
                                    interfacedescription, `
                                    @{n="MacAddress";e={$_.NetAdapter.MacAddress}},
                                    @{n="ipv4address";e={$_.ipv4address -join ","}}, `
                                    @{n="ipv4defaultgateway";e={$_.ipv4defaultgateway.nexthop -join ","}}, `
                                    @{n="dnsserver";e={$_.dnsserver.ServerAddresses -join ","}}, `
                                    @{n="ipv4prefixlength";e={(Get-NetIPAddress -InterfaceAlias ($_.interfacealias) |? {$_.addressfamily -eq "IPv4"}).PrefixLength}} -First 1 | Export-csv -Path C:\Installs\NetworkInfo.csv -NoTypeInformation -force
    }
    Catch {
        write-log "Error trying to get netipconfig! $($_.exception.message)"
    }
    #WindowsUpgrade Logs
    $logspathHost="\\site1-file01\SWInstall\Windows\osUpgrade2018\hostUpgradeLogs\$env:COMPUTERNAME"
    #Create log path for each host
    IF (!(Test-Path $logspathHost)) {write-log "Creating directory $logspathHost";New-Item -Path $logspathHost -ItemType Directory | out-null}
    #Path of Windows 2016 Standard Image
    $ImagePath="\\site1-file01\SWInstall\Windows\SW_DVD9_Win_Svr_STD_Core_and_DataCtr_Core_2016_64Bit_English_-3_MLF_X21-30350.ISO"
    #Custom WIM, only one option configured, Desktop mode
    $customWIM="\\site1-file01\SWInstall\Windows\WIM-8_29_2018\install.wim"
    #If ISOs mounted remove them
    IF($checkMount -is [object]) {$Dismount=Dismount-DiskImage -ImagePath $ImagePath; write-log "Attempted to dismount image"}
    #Unblock Files
    Unblock-File -Path $ImagePath
    Unblock-File -Path $customWIM
    #Freshly mount Windows 2016
    Try {
        $Mount=Mount-DiskImage -ImagePath $ImagePath
    }
    Catch {
        write-log "Error mounting drive! $($_.exception.message)"
    }
    #Harness drive letter of mounted iso
    Try {
    $imageVolDr=(Get-Volume | ? {$_.FileSystemLabel -like "SSS_X64FREV_EN-US_DV9"} | select -first 1).DriveLetter
    }
    Catch {
        write-log "Error finding winOS volume! $($_.exception.message)"
    }
    #Start the process to upgrade unattendly, logs will go to fileshare, ignore any compatiblity warnings, auto upgrade, silently, install from custom wim, execute post job tasks. (remove /quiet for now)
    Try {
    $upgradeProcess=Start-Process -FilePath "$($imageVolDr):\setup.exe" -ArgumentList " /copylogs $logspathHost /compat ignorewarning /auto upgrade /installfrom $customWIM /postoobe C:\installs\set-netAdapter.cmd" -PassThru
    }
    Catch {
    write-log "Error trying to start the process! $($_.exception.message)";Exit
    }
    write-log "Logging Process ID $($upgradeProcess.ID) for $env:COMPUTERNAME"
    IF ($upgradeProcess.id -ne $null) {
    $temp = New-Object PSObject
    $temp | Add-Member -MemberType NoteProperty -name Hostname -Value ($env:computername)
    $temp | Add-Member -MemberType NoteProperty -name TimeStarted -Value (Get-date)
    $temp | Add-Member -MemberType NoteProperty -name Notes -Value "Script ran to upgrade - Change performed by "
    $temp | Export-csv -Path $Upgradedserverslog -NoTypeInformation -Append
    }
    Else {write-log "Process not found therefore not adding server to upgradedserverlog"}

}
Local-Upgrade2016