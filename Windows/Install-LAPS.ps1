$LAPSRequired = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {$_.LAPS -eq $false}).DNSName

$InstallString = "MsiExec.exe /i C:\Bits\LAPS.x64.msi /quiet /qn /norestart"

$LAPSRequired | % `
{
    $srv= $_
    Write-Host "Processing $srv..."
    Write-Host "    Copy installation files to $srv"
    if (!(Test-Path \\$srv\C$\Bits)) {New-Item -Path \\$srv\C$ -Name Bits -ItemType Directory}
    if (!(Test-Path \\$srv\c$\Bits\LAPS.x64.msi)) {Copy-Item \\site1-file01\SWInstall\LAPS\LAPS.x64.msi \\$srv\c$\Bits\ -Force}

        "Install LAPS to $srv"
        $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($InstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $srv $newProc.ProcessId } 
        else { write-host $srv Process create failed with $newProc.ReturnValue}
}

