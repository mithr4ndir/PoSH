$Svrs = Get-ADComputer -SearchBase '$OUDomainPATH' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server*" -and servicePrincipalName -notlike "MSClusterVirtualServer*"} -Properties Created,CanonicalName,IPv4Address,MemberOf,PasswordLastSet,DNSHostName
$DCs = Get-ADComputer -SearchBase 'OU=Domain Controllers,DC=corp,DC=Companyx,DC=com' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server*" -and servicePrincipalName -notlike "MSClusterVirtualServer*"} -Properties Created,CanonicalName,IPv4Address,MemberOf,PasswordLastSet,DNSHostName
$Svrs = $Svrs + $DCs
$Servers = $Svrs.DNSHostName

$ScriptSCEP = {
New-Object psobject -Property @{LastAppliedPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft Security Client' -Name LastSuccessfullyAppliedPolicy).LastSuccessfullyAppliedPolicy;
    DisableLocalAdminMerge = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware' -Name DisableLocalAdminMerge).DisableLocalAdminMerge;
    ExcludedExtentions = Try {(Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions\Extensions' -ErrorAction Stop).Property} catch {};
    ExcludedPaths = Try {(Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions\Paths' -ErrorAction Stop).Property.Count} catch {};
    ExcludedProcesses = Try {(Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\Exclusions\Processes' -ErrorAction Stop).Property -join "; "} catch{};
    Version = Try {(Get-ChildItem 'C:\Program Files\Microsoft Security Client\MsMpEng.exe' -ErrorAction Stop).VersionInfo.ProductVersion} catch {"Not Found"}
    }
}


Invoke-Command -ComputerName site2-CSWEB01,site1-dc05, site1-admin02 -ScriptBlock $ScriptSCEP 
