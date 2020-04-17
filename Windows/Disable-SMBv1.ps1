$smb1enabled = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {$_.smb1enabled -eq $true}).DNSName

Invoke-Command -ComputerName $smb1enabled -ScriptBlock {Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart}
Set-SmbServerConfiguration -CimSession $smb1enabled -EnableSMB1Protocol $false -Force