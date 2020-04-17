$DHCP = Get-DhcpServerInDC | select -ExpandProperty dnsname | sort

Get-PSSession | Remove-PSSession

$DHCPSesh = New-PSSession -ComputerName $dhcp

Invoke-Command -Session $DHCPSesh -ScriptBlock {Get-ChildItem Env:__PS*}



