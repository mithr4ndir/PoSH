$Error.Clear()
#$2012DCs = Get-ADComputer -SearchBase 'OU=Domain Controllers,DC=corp,DC=Companyx,DC=com' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server 2012*"} -Properties operatingsystem

$computer = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {$_.SCEP -eq 'false' -and $_.Name -match '-dc'}).DNSName

$computer | % `
{
    $srv= $_
    Write-Host "Processing $srv..."
    Write-Host "    Copy installation files to $srv"
    if (!(Test-Path \\$srv\c$\Windows\ScepInstall\scepinstall.exe)) {Copy-Item \\site1-file01\SWInstall\SCCM\ScepInstall \\$srv\c$\Windows\ -Recurse -Force}
    $ScriptBlc = {
        try {$ScepVer=(Get-ChildItem 'C:\Program Files\Microsoft Security Client\MsMpEng.exe' -ErrorAction Stop).VersionInfo.ProductVersion} catch {$ScepVer=$null}
        if ($ScepVer)
        {
            if ($ScepVer -notlike "4.10.*")
            {
                Write-host "    Uninstalling old SCEP of version $ScepVer, please wait..."
                Start-Process C:\Windows\ScepInstall\scepinstall.exe -ArgumentList "/u /s" -Wait
                Write-host "     Installing newer version of SCEP with base policy, please wait..."
                Start-Process C:\Windows\ScepInstall\scepinstall.exe -ArgumentList "/s /q /policy C:\Windows\ScepInstall\SCEP_Base.xml" -Wait
            }
            else {Write-host "    SCEP of version 4.10.xxx already exist on $env:COMPUTERNAME"}
    
        }
        else 
        {
            Write-host "    Installing SCEP, please wait..."
            Start-Process C:\Windows\ScepInstall\scepinstall.exe -ArgumentList "/s /q /policy C:\Windows\ScepInstall\SCEP_Base.xml" -Wait
        }
    }
    
    Invoke-Command -ComputerName $srv -ScriptBlock $ScriptBlc
    
    Write-host "    Install role policies of DNS & DC"
    $Session = New-PSSession $srv
    Invoke-Command -Session $session -ScriptBlock {Start-Process "C:\Program Files\Microsoft Security Client\ConfigSecurityPolicy.exe" -ArgumentList "C:\Windows\ScepInstall\SCEP_DNS.xml C:\Windows\ScepInstall\SCEP_DC.xml"}
}

sleep 15
Remove-PSSession $Session
# To check exclusions paths
# Invoke-Command -ComputerName site2-DC01 -ScriptBlock {(Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions\Paths').Property}