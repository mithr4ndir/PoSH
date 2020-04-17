$list=Get-adgroup -filter * -SearchBase "OU=Oracle,OU=Groups,$OUDomainPATH"
$allcheck=@()
Foreach ($item in $list) { 
    IF ($item.samaccountname -like "*Access*") {
    $Newname=$item.samaccountname -replace "Access","Role"
    Set-ADGroup -Identity $item.ObjectGUID -SamAccountName $Newname -DisplayName $Newname
    Rename-ADObject -Identity $item.ObjectGUID -NewName $Newname
    }
    IF ($item.samaccountname -like "*Role*") {
    $Newname=$item.samaccountname -replace "Role","Access"
    Set-ADGroup -Identity $item.ObjectGUID -SamAccountName $Newname -DisplayName $Newname
    Rename-ADObject -Identity $item.ObjectGUID -NewName $Newname
    }
$check = get-adgroup $Newname -pro samaccountname,cn,distinguishedname,name,canonicalname,displayname |select distinguishedname,canonicalname,name,displayname,samaccountname,cn
$allcheck+=$check
}