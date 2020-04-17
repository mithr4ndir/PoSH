#$computername = Get-ADComputer -Filter 'name -like "kto-dmzapp-*"' | select -ExpandProperty name
#$computername = gc C:\Repository\input\MemberServers.txt
$computername = "site1-gads01.corp.Companyx.com"
$msufile = "\\site1-file01\SWInstall\Windows_Updates\Win8.1AndW2K12R2-KB3191564-x64.msu"

foreach ($computer in $computername)
{
Write-host "Copying bits to $computer"
$destinationFolder = "\\$computer\C$\Installs\"
    if (!(Test-Path -path $destinationFolder -Verbose)) {
        New-Item $destinationFolder -Type Directory -Verbose
        Write-host "Copied file successfully to $server"
        }
        Try {
        Copy-Item -Path $msufile -Destination $destinationFolder -Verbose
        }
        Catch {Write-host "Error copying file for $server"}
}
Invoke-Command -ComputerName $computer -Verbose -ScriptBlock {
Write-Host "Attempting to install WMF 5.1 for $env:COMPUTERNAME"
Start-Process -FilePath 'wusa.exe' -ArgumentList "C:\Installs\Win8.1AndW2K12R2-KB3191564-x64.msu /extract:C:\temp\" -Wait -PassThru -Verb runas
Start-Process -FilePath 'dism.exe' -ArgumentList "/online /add-package"
}