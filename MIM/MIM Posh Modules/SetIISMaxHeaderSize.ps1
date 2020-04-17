
Set-ItemProperty HKLM:\System\CurrentControlSet\Services\HTTP\Parameters -Name MaxFieldLength -Type DWord -Value 65534
Set-ItemProperty HKLM:\System\CurrentControlSet\Services\HTTP\Parameters -Name MaxRequestBytes -Type DWord -Value 65534
iisreset
