Function Set-ADDiagnostics {
[cmdletbinding()]
param(
[ValidateSet("Enable","Disable","Get")][Parameter(Mandatory=$True)]$Action,
[string[]][Parameter(Mandatory=$True)]$Computer,
[credential]$credential=(Get-Credential -Message "Enter DAD Credentials")
)
If ($Action -eq "Enable"){
$checkDiagPath=Get-Item -Path HKLM:System\Currentcontrolset\services\ntds\Diagnostics
    If ($checkDiagPath -is [object]){
    $checkDiagSetting=Get-ItemProperty -Path HKLM:System\Currentcontrolset\services\ntds\Diagnostics -Name "16 LDAP Interface Events"
        IF($checkDiagSetting.'16 LDAP Interface Events' -eq 5)
    }
    Else {Write-Output "Diagnostics path not found, you must target a domain controller";exit}
}


Set-ItemProperty 


icm -ComputerName site1-dc07 {
Get-Item -Path HKLM:System\Currentcontrolset\services\ntds\Diagnostics 
#Get-Item -Path HKLM:System\Currentcontrolset\services\ntds\Parameters 
#Get-ItemProperty -Path HKLM:System\Currentcontrolset\services\ntds\Diagnostics -Name "16 LDAP Interface Events" 
Get-ItemProperty -Path HKLM:System\Currentcontrolset\services\ntds\Parameters
Set-ItemProperty -Path HKLM:System\Currentcontrolset\services\ntds\Parameters -Name
} -Credential $cred

Set-RegDWord -ComputerName $Computer -Hive LocalMachine -Key 'System\CurrentControlSet\Services\NTDS\Diagnostics' -Value '15 Field Engineering' -data 5
Set-RegDWord -ComputerName $Computer -Hive LocalMachine -Key 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Value 'Expensive Search Results Threshold' -data 0
Set-RegDWord -ComputerName $Computer -Hive LocalMachine -Key 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Value 'Inefficient Search Results Threshold' -data 0
Set-RegDWord -ComputerName $Computer -Hive LocalMachine -Key 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Value 'Search Time Threshold (msecs)' -data 100

}