$servers="site1-ChrisL01.corp.Companyx.com"
$sessions=New-PSSession $servers
$Source="\\site1-file01\SWInstall\Dell\Change Auditor\Dell Change Auditor 7.0.1\Installation\x64\Quest Change Auditor Client (x64).msi"
$Destination="C:\Installs\"

Foreach ($server in $servers) {
Write-Host "Processing $server..."
if (!(Test-Path \\$server\C$\Installs)) {New-Item -Path \\$server\C$ -Name Installs -ItemType Directory | Out-null}
Write-Host "Attempting to copy binaries to $server"
if (!(Test-Path "\\$server\c$\Installs\Quest Change Auditor Client (x64).msi")) {Copy-Item $Source $Destination -Force}
}

ICM -Session $sessions -ScriptBlock {
    If($check -is [Object]) {Remove-Variable Check; Write-host "Removed Cached Entry of Check Variable"}
    $check=Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | ? {$_.displayname -like "Dell Change Auditor Client*"}
    if ($check -is [Object])
    {
        Write-host "Uninstalling CA Client from $env:COMPUTERNAME" -BackgroundColor Yellow
        $unInstallString = "MsiExec.exe /X{52B1CEF7-1772-4E53-A9B3-F5D52915A635} /quiet /qn /norestart"
        $newProc=([WMICLASS]"\\$env:COMPUTERNAME\root\cimv2:win32_Process").Create($unInstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $env:COMPUTERNAME $newProc.ProcessId } 
        else { write-host $env:COMPUTERNAME Process create failed with $newProc.ReturnValue}
        Putting to Sleep
        Sleep 15
        Write-host "Starting to install CA 7.0 client for $env:COMPUTERNAME"
        $InstallString='MsiExec.exe /i "C:\Installs\Quest Change Auditor Client (x64).msi" /quiet /qn /norestart'
        $newProc=([WMICLASS]"\\$env:COMPUTERNAME\root\cimv2:win32_Process").Create($InstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $env:COMPUTERNAME $newProc.ProcessId } 
        else { write-host $env:COMPUTERNAME Process create failed with $newProc.ReturnValue}
        Write-host
    }
    Else {Write-host "Change Auditor does not exist for $env:COMPUTERNAME" -BackgroundColor Green}
}
