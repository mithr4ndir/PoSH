$domainc = Get-ADDomainController -filter * | select -ExpandProperty hostname | sort

$newdc = New-PSSession -ComputerName $domainc 

$query = Invoke-Command -Session $newdc -ScriptBlock {dir C:\windows\ntds\ntds.dit | select name,pscomputername,@{name="length";expression={$_.length / 1GB}}}