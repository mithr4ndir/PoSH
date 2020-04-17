$fintech = get-adcomputer -filter {name -like "*fintech*"} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" | select name

$finsesh = New-PSSession -ComputerName $fintech.name

$Finseshstuff = Invoke-command -Session $finsesh -ScriptBlock {
Get-WinEvent -ListLog System,Application,Microsoft-Windows-RemoteDesktopServices-*,Microsoft-Windows-TerminalServices-* -ErrorAction SilentlyContinue  | Get-WinEvent -ErrorAction SilentlyContinue| Where { $_.id -like '1132'} | select -first 1
}