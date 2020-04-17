$Error.Clear()
$S2012vrs = Get-ADComputer -SearchBase '$OUDomainPATH' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server 2012*" -and servicePrincipalName -notlike "MSClusterVirtualServer*"} -Properties operatingsystem
$computer = $S2012vrs.Name

$computer | % `
{
    $srv= $_
    Write-Host "Processing $srv..."
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
}

#Write-host "    Install additional role policies"
$DhcpSrv = $computer | ? {$_ -match "-dhcp"}
$IISSrv = $computer | ? {($_ -match "-csrpt") -or ($_ -like "*-*web*")}

if ($DhcpSrv)
{
    Write-host "    Install DHCP role policy"
    $DhcpSrvSession = New-PSSession $DhcpSrv
    Invoke-Command -Session $DhcpSrvSession -ScriptBlock {Start-Process "C:\Program Files\Microsoft Security Client\ConfigSecurityPolicy.exe" -ArgumentList "C:\Windows\ScepInstall\SCEP_DHCP.xml"}
    Remove-PSSession $DhcpSrvSession
}

if ($IISSrv)
{
    Write-host "    Install IIS role policy"
    $IISSrvSession = New-PSSession $IISSrv
    Invoke-Command -Session $IISSrvSession -ScriptBlock {Start-Process "C:\Program Files\Microsoft Security Client\ConfigSecurityPolicy.exe" -ArgumentList "C:\Windows\ScepInstall\SCEP_IIS.xml"}
    Remove-PSSession $IISSrvSession
}

# To check exclusions paths
# Invoke-Command -ComputerName site2-CSWEB01 -ScriptBlock {(Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions\Paths').Property}