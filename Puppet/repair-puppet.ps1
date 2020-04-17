$repairListFile = "\\site1-scripts01\c$\repository\input\nodesneedfixin.txt"
$PuppetRequired = gc $repairListFile
$UninstallString = "MsiExec.exe /X{6CF825F0-9F34-452B-920C-0AF2D8A19CAF} /qn /norestart"

$PuppetRequired | % `
{
    $srv= $_
    write-output "Processing $srv..." -BackgroundColor Green
    if (!(Test-Path \\$srv\C$\Bits)) {New-Item -Path \\$srv\C$ -Name Bits -ItemType Directory}
    if (!(Test-Path \\$srv\c$\Bits\install-puppetagent.ps1)) {Copy-Item \\site1-file01\swinstall\Puppet\agent\install-puppetAgent* \\$srv\c$\Bits -Force;write-output "    Copy installation files to $srv"}

    # check puppet service
    write-output "Checking for puppet service on $srv..."
    if (!(get-service -ComputerName $srv -Name puppet -erroraction ignore))
    {
        "Uninstall Puppet on $srv"
        $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($UninstallString)
        If ($newProc.ReturnValue -eq 0) { write-output $srv $newProc.ProcessId } 
        else { write-output $srv Process create failed with $newProc.ReturnValue}
    Start-sleep -Seconds 10
        "Attempting to install Puppet to $srv"
        $result=icm $srv { start-process powershell.exe -ArgumentList ' -command "&{c:\Bits\install-puppetagent.ps1}"' -PassThru -ErrorAction ignore | Wait-Process -Timeout 20 -ErrorAction Ignore}
    }
    Else {write-output "Service already exists - nothing to do"}
    Start-sleep -Seconds 30
    $CheckPuppetSvc=Get-Service puppet | select status,name,displayname,starttype
    If ($CheckPuppetSvc.starttype -ne "Automatic") {write-output "Puppet service not set to automatic, now setting to automatic for $env:computername!";Set-Service puppet -StartupType Automatic}
    If ($CheckPuppetSvc.status -ne "Running") {write-output "Puppet not running, starting now for $env:computername";Start-Service puppet}
    $CheckpxpSvc=Get-Service pxp-agent | select status,name,displayname,starttype
    If ($CheckpxpSvc.starttype -ne "Automatic") {write-output "pxp service not set to automatic, now setting to automatic for $env:computername!";Set-Service pxp-agent -StartupType Automatic}
    If ($CheckpxpSvc.status -ne "Running") {write-output "pxp not running, starting now for $env:computername";Start-Service pxp-agent}
    Puppet agent -t --no-use_cached_catalog
}
