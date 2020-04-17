$servers = Get-ADDomainController -filter * | select -ExpandProperty hostname
$sessionServers = New-PSSession -ComputerName $servers





Remove-PSSession -Session $sessionServers
Remove-Variable sessionServers
$command = Invoke-Command -Session $sessionServers -ScriptBlock `
{
    Get-ChildItem C:\Windows\NTDS\ntds.dit | `
    select name,@{name="Length";expression={$_.length /1Gb}}
}
