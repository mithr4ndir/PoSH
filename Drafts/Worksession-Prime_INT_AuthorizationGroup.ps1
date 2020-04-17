$intatc = get-aduser -filter {enabled -eq $true} -SearchBase "OU=Users,OU=ATC Users,DC=int,DC=Companyxatc,DC=com" -server int.Companyxatc.com | select samaccountname,givenname,surname
$Companyxtagged = get-aduser -filter {enabled -eq $true -and Companyx-tags -like "ATG"} -SearchBase "ou=users,$OUDomainPATH" -pro Companyx-tags | select samaccountname,givenname,surname
$Companyxuntagged = get-aduser -filter {enabled -eq $true} -SearchBase "ou=users,$OUDomainPATH" -pro Companyx-tags| ? Companyx-tags -NotContains "atg"|select samaccountname,givenname,surname



#Only in PRIME
compare-object $intatc $Companyxtagged | ? sideindicator -like "=>" | measure

#Only in INT
compare-object $intatc $Companyxtagged | ? sideindicator -like "<=" | measure

#Found in both environments, which users are not tagged as ATG that are in INT
$P_And_Int = compare-object $intatc $Companyxuntagged -Property samaccountname -IncludeEqual | ? sideindicator -like "==" | select -ExpandProperty samaccountname

$AllPIData=@()
Foreach ($PI in $P_And_Int) {
$TempADInfo = Get-ADUser $PI -pro * | select samaccountname,mail,@{name="Companyx-tags";expression={$_.'Companyx-tags' -join ";"}},whencreated,lastlogondate,employeenumber,Companyx-job-family,Companyxjobprofile,Companyx-job-family-group,surname,givenname
$TempObj = New-Object psobject
$TempObj | Add-Member -MemberType NoteProperty -Name givenname -Value $tempadinfo.givenname
$TempObj | Add-Member -MemberType NoteProperty -Name surname -Value $TempADInfo.surname
$TempObj | Add-Member -MemberType NoteProperty -Name samaccountname -Value $tempadinfo.samaccountname
$TempObj | Add-Member -MemberType NoteProperty -Name mail -Value $TempADInfo.mail
$TempObj | Add-Member -MemberType NoteProperty -Name Companyx-tags -Value $TempADInfo.'Companyx-tags'
$TempObj | Add-Member -MemberType NoteProperty -Name whencreated -Value $TempADInfo.whencreated
$TempObj | Add-Member -MemberType NoteProperty -Name lastlogondate -Value $TempADInfo.lastlogondate
$TempObj | Add-Member -MemberType NoteProperty -Name employeenumber -Value $TempADInfo.employeenumber
$TempObj | Add-Member -MemberType NoteProperty -Name Companyx-job-family -Value $TempADInfo.'Companyx-job-family'
$TempObj | Add-Member -MemberType NoteProperty -Name Companyx-job-family-group -Value $TempADInfo.'Companyx-job-family-group'
$TempObj | Add-Member -MemberType NoteProperty -Name Companyxjobprofile -Value $TempADInfo.Companyxjobprofile
$AllPIData += $TempObj
}
#ATG Tagged Data
$AllPINOTATG=@()
$AllPIATG=@()
Foreach ($all in $AllPIData) {
#Find users not marked as ATG in PRIME
If ($all.'Companyx-tags' -notcontains "ATG")
{
$TempObj1 = New-Object psobject
$TempObj1 | Add-Member -Type NoteProperty -Name CompanyxTags -Value $all.'Companyx-tags'
$TempObj1 | Add-Member -Type NoteProperty -Name samaccountname -Value $all.samaccountname
$AllPINOTATG += $TempObj1
}
#Find users marked as ATG in PRIME
If ($all.'Companyx-tags' -contains "ATG") {
$TempObj2 = New-Object psobject
$TempObj2 | Add-Member -Type NoteProperty -Name CompanyxTags -Value $all.'Companyx-tags'
$TempObj2 | Add-Member -Type NoteProperty -Name samaccountname -Value $all.samaccountname
$AllPIATG += $TempObj2
}
}


#Gather INT AD User information
$AllIntData=@()
Foreach ($int in $intatc) {
$TempAD = Get-aduser $int -pro lastlogondate,whencreated -Server int.Companyxatc.com | select samaccountname,lastlogondate,whencreated
$TempObj = New-Object PSObject
$TempObj | Add-Member -MemberType NoteProperty -Name samaccountname -Value $tempad.samaccountname
$TempObj | Add-Member -MemberType NoteProperty -name lastlogondate -value $tempad.lastlogondate
$TempObj | Add-Member -MemberType NoteProperty -name Whencreated -value $tempad.whencreated
$AllIntData += $TempObj
}
$allintdate | ogv

#Obtain list of people that are found in both realms 












