$servers=gc C:\Repository\input\CAClientUpgradeHosts.txt
$sessions=New-PSSession $servers
$Source="\\site1-file01\SWInstall\Dell\Change Auditor\Dell Change Auditor 7.0.1\Installation\x64\Quest Change Auditor Client (x64).msi"

#Log function
    $LogFolder = "C:\Repository\logs\CAUpgrade"
    $MyName = "$Env:computername"
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
    Function Write-Log ($Message) {
        $ThisMsg = "[$MyName] $(Get-Date) : $Message"
        $ThisMsg | Out-File $LogFile -Append
        $ThisMsg
    }
Foreach ($server in $servers) {
$Destination="\\$server\C$\Installs\"
Write-Log "Processing $server..."
if (!(Test-Path \\$server\C$\Installs)) {New-Item -Path \\$server\C$ -Name Installs -ItemType Directory | Out-null}
Write-Log "Attempting to copy binaries to $server"
if (!(Test-Path "\\$server\c$\Installs\Quest Change Auditor Client (x64).msi")) {Copy-Item $Source $Destination -Force}
}

ICM -Session $sessions -ScriptBlock {

    If($check -is [Object]) {Remove-Variable Check; Write-Host "$Env:computername : Removed Cached Entry of Check Variable"}
    $check=Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ? {$_.displayname -like "*Change Auditor Client*"}
    if ($check.VersionMajor -le 7)
    {
        Write-Host "$Env:computername : Uninstalling CA Client" -BackgroundColor Yellow
        $unInstallString = "MsiExec.exe /X{52B1CEF7-1772-4E53-A9B3-F5D52915A635} /quiet /qn /norestart"
        $newProc=([WMICLASS]"\\$env:COMPUTERNAME\root\cimv2:win32_Process").Create($unInstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host "$Env:computername : New process uninstall created - $($newProc.ProcessId)" } 
        else { Write-Host "$Env:computername : Process create failed with $($newProc.ReturnValue)"}
        Write-Host "$Env:computername : Putting to sleep for 15 seconds"
        Sleep 15
        Write-Host "$Env:computername : Starting to install CA 7.0 client"
        $InstallString='MsiExec.exe /i "C:\Installs\Quest Change Auditor Client (x64).msi" /quiet /qn /norestart'
        $newProc=([WMICLASS]"\\$env:COMPUTERNAME\root\cimv2:win32_Process").Create($InstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host "$Env:computername : New process install created - $($newProc.ProcessId)" } 
        else { Write-Host "$Env:computername :  Process create failed with $($newProc.ReturnValue)"}
        Write-Host "$Env:computername : Sleeping for 20 seconds..."
        Sleep 20
        Write-Host "$Env:computername : Checking for successful installation..."
        If($check -is [Object]) {Remove-Variable Check; Write-Host "$Env:computername : Removed Cached Entry of Check Variable"}
        $check=Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ? {$_.displayname -like "*Change Auditor Client*"}
        If ($check.versionmajor -ge 7) { Write-Host "$Env:computername : Version is higher than 7, new client successfully installed!" -BackgroundColor Green} Else {Write-Host "$Env:computername : Not higher than 7! Something went wrong with the installation!" -BackgroundColor Yellow}
    }
    Elseif ($check -isnot [Object]) {Write-Host "$Env:computername : Change Auditor does not exist" -BackgroundColor Red}
    if ($check.VersionMajor -ge 7) {Write-host "$Env:Computername : Recent Change Auditor Client installed" -BackgroundColor Green}
}