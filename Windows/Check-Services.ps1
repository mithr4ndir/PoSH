$servers = Get-ADDomainController -filter * | select -ExpandProperty hostname
$sessionServers = New-PSSession -ComputerName $servers
$sessionServers += New-PSSession -computername $error.TargetObject.ConnectionInfo.ComputerName
$sessionServers += New-PSSession -ComputerName sjo1-dc01.corp.Companyx.com


$error.TargetObject.ConnectionInfo.ComputerName


Remove-PSSession -Session $sessionServers
Remove-Variable sessionServers
$command = Invoke-Command -Session $sessionServers -ScriptBlock `
{
    Get-ChildItem C:\Windows\NTDS\ntds.dit | `
    select name,@{name="Length";expression={$_.length /1Gb}}
}
