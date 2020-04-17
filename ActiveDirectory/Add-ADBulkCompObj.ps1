#
#
#    This Script will create AD Computer objects with the useraccountcontrol bit of 4096 (Trusted Workstation). Please only use this script to create these objects for non windows systems, such as android or iosx tablets.
#
#    Created By: Chris L
#
#
#    Input file should consist of only hostnames seperated by returns, no headers are required. 
#    Also provide the path of the input file on line 22, where the $hostname variable is being declared (should be txt format).
#    -Example Input file...
#        Hostname1
#        hostname2
#
#    Three logs are created after the script is executed. 
#    -First log will show what which object was processed, 
#    -second is to provide a total report of which systems were inputted successfully, 
#    -third is for all errors generated during the script
#
#
#

$hostnames = gc "C:\Repository\input\Custom-comp-hostnames.txt"
#$hostnames = "MM-C07TX2S0G1HVtest"
$date=Get-Date -Format MM-dd-yyyy_HH-mm-ss
$logpath = "C:\Repository\output\Add-ADCompObjectsLog$date.txt"
$Report = "C:\Repository\output\Add-ADCompOjectsReport$date.csv"
$errors = "C:\Repository\output\Add-ADCompOjectsErrors$date.txt"
IF (Test-Path $logpath) {ri $logpath}
IF (Test-Path $Report) {ri $Report}
$countAdded=0
$countNotAdded=0
$HostnamesStatus=@()
$Error.Clear()

Write-output "------------------------------------------------------------------------------------------------"
Write-output "------------------------------------------------------------------------------------------------" | Out-File -FilePath $logpath -Appen
Foreach ($comp in $hostnames) {
Try {
        Write-Output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Processing $comp"
        Write-Output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Processing $comp" | Out-File -FilePath $logpath -Append
        New-ADComputer -Name $comp -DisplayName $comp -SAMAccountName $comp -Enabled $true -Path "OU=AV-Devices,OU=Workstations,OU=Computers,$OUDomainPATH" -Server site1-dc01 -PasswordNotRequired $false
        $Tempobj = New-Object PSObject
        $Tempobj | Add-Member -MemberType NoteProperty -Name Hostname -Value $comp
        $Tempobj | Add-Member -MemberType NoteProperty -Name Status -Value "Added Successfully"
        $HostnamesStatus+=$Tempobj
        $countAdded++
    }
Catch {
    Write-Output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Error Processing $comp"
    Write-Output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Error Processing $comp" | Out-File -FilePath $logpath -Append 
    $Tempobj = New-Object PSObject
    $Tempobj | Add-Member -MemberType NoteProperty -Name Hostname -Value $comp
    $Tempobj | Add-Member -MemberType NoteProperty -Name Status -Value "Not Added Successfully"
    $HostnamesStatus+=$Tempobj
    $countNotAdded++
    }
}

Write-output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Hosts Created in AD : $countAdded"
Write-output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Hosts Not Created in AD : $countNotAdded"
Write-output "------------------------------------------------------------------------------------------------"
Write-output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Hosts Created in AD : $countAdded" | Out-File -FilePath $logpath -Append
Write-output "$(Get-Date -Format MM-dd-yyyy_HH:mm:ss) - Hosts Not Created in AD : $countNotAdded" | Out-File -FilePath $logpath -Append
Write-output "------------------------------------------------------------------------------------------------" | Out-File -FilePath $logpath -Append
$HostnamesStatus | Export-csv -Path $Report -NoTypeInformation -Force -Encoding ASCII
$error | Out-File -FilePath $errors

Start-Process Notepad -ArgumentList $Report
Start-process notepad -ArgumentList $logpath
Start-process Notepad -ArgumentList $errors