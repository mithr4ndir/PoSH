#$servers=Import-Csv C:\Users\ChrisL\Desktop\hostnamesofbadpuppet.csv | sort fqdn -Unique
$date = (Get-date).AddDays(-30)
$servers=Get-ADComputer -filter {lastlogondate -gt $date -and enabled -eq $true -and operatingsystem -like "*windows*server*" -and name -notlike "*-dc*" -and name -notlike "*-iiq*" -and name -notlike "*pki*"} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" | select dnshostname | sort dnshostname
Get-PSSession | Remove-PSSession -ErrorAction SilentlyContinue
$ConnServers=@()
$ConnServers=New-PSSession -ComputerName $servers.dnshostname
Get-PSSession

$data=icm -Session $ConnServers -ScriptBlock {
#Write-Output "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) - $hostname"
#Adapted from https://gist.github.com/altrive/5329377
#Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>
function Test-PendingReboot
{
 if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) {Write-Output "Component Based Servicing - RebootPending Found!";return $true  }
 if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) {Write-Output "WindowsUpdate - RebootRequired Found!";return $true  }
 if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) {Write-Output "PendingFileRenameOperations found in SessionManager!";return $true }
 try { 
   $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
   $status = $util.DetermineIfRebootPending()
   if(($status -ne $null) -and $status.RebootPending){
     return $true
   }
 }catch{}
 
 return $false
}
Test-PendingReboot
}