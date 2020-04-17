$dhcpservers = Get-DhcpServerInDC | select -ExpandProperty dnsname

$dhcpserversSessions = New-PSSession -ComputerName $dhcpservers

$invoke = Invoke-Command -Session $dhcpserversSessions -ScriptBlock {
$logfilesize = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DhcpServer\Parameters -Name DHCPLogFilesMaxSize).DhcpLogFilesMaxSize
If ($logfilesize -ne "950") {
    Write-Host "$env:computername has it set to $logfilesize"
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DhcpServer\Parameters -Name DHCPLogFilesMaxSize -Value 950
    $newlogfilesize = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DhcpServer\Parameters -Name DHCPLogFilesMaxSize).DhcpLogFilesMaxSize
    Write-host "$env:computername has now been set to $newlogfilesize"
    }
}

