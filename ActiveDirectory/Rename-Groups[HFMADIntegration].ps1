$list=import-csv C:\Users\ChrisL\desktop\newnamesHyperion.csv
$allcheck=@()
Foreach ($item in $list) {
$queryDN = Get-ADGroup $item.oldname
Set-ADGroup -Identity $queryDN.DistinguishedName -SamAccountName $item.newname -DisplayName $item.newname
Rename-ADObject -Identity $queryDN.DistinguishedName -NewName $item.newname
$check = get-adgroup $item.newname -pro samaccountname,cn,distinguishedname,name,canonicalname,displayname |select distinguishedname,canonicalname,name,displayname,samaccountname,cn
$allcheck+=$check
}