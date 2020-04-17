$affected = gc C:\users\ChrisL\Desktop\affectedservers.txt
$Result =@()
Foreach ($server in $affected)
{
$Result += Invoke-Command $server -ScriptBlock {
Get-Item Env:\__PSLockdownPolicy | Remove-Item 
}
}