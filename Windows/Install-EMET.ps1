$EMETRequired = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {$_.EMET -eq 'false'}).DNSName

$InstallString = "MsiExec.exe /i C:\EMETSetup.msi /quiet /qn /norestart"

$EMETRequired | % `
{
    $srv= $_
    Write-Host "Processing $srv..."
    Write-Host "    Copy installation files to $srv"
    if (!(Test-Path \\$srv\c$\EMETSetup.msi)) {Copy-Item \\site1-file01\SWInstall\EMET\EMETSetup.msi \\$srv\c$ -Force}

        "Install EMET to $srv"
        $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($InstallString)
        If ($newProc.ReturnValue -eq 0) { Write-Host $srv $newProc.ProcessId } 
        else { write-host $srv Process create failed with $newProc.ReturnValue}
    #Write-Host 'Remove installation file'
    #Remove-Item \\$srv\c$\EMETSetup.msi
}

<#
$EMETRequired | % `
{
    $srv= $_
    $e= try {Get-Service EMET_Service -ComputerName $srv } catch {}
    if ($e)
    {
    #Write-Host 'Remove installation file'
    Remove-Item \\$srv\c$\EMETSetup.msi
    }
    else {"$srv"}
}
#>