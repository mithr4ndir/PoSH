#$DuoRequired = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {(($_.Duo -eq $false) -or ($_.Duo -eq '2.0.0.71')) -and (($_.Name -notmatch '-fintech') -and ($_.Name -notmatch '-RDS'))}).DNSName
$DuoRequired = "site3-vmmgmt01"
$InstallString = "MsiExec.exe /i C:\Bits\DuoWindowsLogon64.msi IKEY=`"KEY`" SKEY=`"KEY1`" HOST=`"APIADDRESS`" AUTOPUSH=`"#1`" FAILOPEN=`"#1`" SMARTCARD=`"#0`" RDPONLY=`"#0`" /quiet /qn /norestart"
$UninstallString = "MsiExec.exe /X{AF828DB1-476C-4EDD-BFF1-44456828764F} /quiet /qn /norestart"

$DuoRequired | % `
{
    $srv= $_
    Write-Host "Processing $srv..."
    Write-Host "    Copy installation files to $srv"
    if (!(Test-Path \\$srv\C$\Bits)) {New-Item -Path \\$srv\C$ -Name Bits -ItemType Directory}
    if (!(Test-Path \\$srv\c$\Bits\DuoWindowsLogon64.msi)) {Copy-Item \\site1-file01\SWInstall\Duomst\DuoWindowsLogon64.msi \\$srv\c$\Bits -Force}

    # check Duo version
    if ((Get-CimInstance -ComputerName $srv -ClassName win32_product | ? {$_.Name -eq 'Duo Authentication for Windows Logon x64'}).Version -match '2.0.0')
    {
        "Uninstall Duo on $srv"
        $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($UninstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $srv $newProc.ProcessId } 
        else { write-host $srv Process create failed with $newProc.ReturnValue}
    sleep 10
    }
        "Install Duo to $srv"
        $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($InstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $srv $newProc.ProcessId } 
        else { write-host $srv Process create failed with $newProc.ReturnValue}
}

