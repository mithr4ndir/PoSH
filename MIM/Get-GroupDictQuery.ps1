Param(
    [string] $InputFile,
    [string] $OutputFile
)

if ($InputFle) {
    $Groups = Get-Content $InputFile
} else {
    $groups = get-qadgroup * -Dynamic $true -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist| select samaccountname,edsadgconditionslist
}



#$groups = get-qadgroup * -Dynamic $true -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist| select samaccountname,edsadgconditionslist
#$groups = get-qadgroup heaven-users -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist | select -expandproperty edsadgconditionslist
#$group = get-qadgroup atg_staff -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist | select name,edsadgconditionslist
$array=@()
$error.clear()


#if (!$Cred) { $Cred = Get-Credential domain\account }
$paramFIMService = @{}
$paramFIMService["Uri"] = "http://server1:5725"
if ($Cred) { $paramFIMService["Credential"] = $Cred } 


Foreach ($group in $groups)
{
$conditions = $group.edsadgconditionslist.split("[").replace('\3d','=').replace('\28','(').replace('\29',')')
    Foreach ($condition in $conditions)
    {
        If  ($condition -like "0x1*")
            {
            $0x1 = $condition.split(";")
            $ouGUID = $0x1[1]
            $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
            $LDAPSplit = $0x1.split("]")
            $LDAPQuery = $LDAPSplit[2]

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include LDAP query"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value $LDAPQuery
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
            $array += $objTemp
            }
        
        If  ($condition -like "0x2*")
            {
            $0x2 = $condition.split(";")
            $ouGUID = $0x2[1]
            $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
            $LDAPSplit = $0x2.split("]")
            $LDAPQuery = $LDAPSplit[2]

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude LDAP query"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value $LDAPQuery
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
            $array += $objTemp

            }
        If  ($condition -like "0x3*")
            {
            $0x3 = $condition.split(";")
            $userGUID = $0x3[1]
            $userRule = Get-ADObject $userguid -Properties samaccountname

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include User Explicitly"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(distinguishedname=$($userRule.DistinguishedName))"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $UserRule.Distinguishedname
            $array += $objTemp
            }
        
        If  ($condition -like "0x4*")
            {
            $0x4 = $condition.split(";")
            $userGUID = $0x4[1]
            $UserRule = Get-ADObject $userguid -Properties samaccountname

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude User Explicitly"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!(distinguishedname=$($userRule.DistinguishedName)))"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $UserRule.Distinguishedname
            $array += $objTemp

            }
        If  ($condition -like "0x5*")
            {
            $0x5 = $condition.split(";")
            $groupGUID = $0x5[1]
            $groupRule = Get-ADObject $groupGUID -Properties samaccountname -ErrorAction Stop

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include Members of Group"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(memberof=$($groupRule.DistinguishedName))"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $groupRule.distinguishedname
            $array += $objTemp
            }
                

        
        If  ($condition -like "0x6*")
            {
            $0x6 = $condition.split(";")
            $groupGUID = $0x6[1]
            $groupRule = Get-ADObject $groupGUID -Properties samaccountname

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude Members of Group"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!(memberof=$($groupRule.DistinguishedName)))"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $groupRule.distinguishedname
            $array += $objTemp
            }
    }
}


$Obj = $array | ? {$_.RuleType -like "*LDAP query" -or $_.RuleType -like "*Members of Group"} | ? {$_.RuleQuery -like "*memberof*"} | ? {$_.RuleQuery -notlike "*OU=Computers,*"} | select -ExpandProperty RuleQuery
#$Obj = $array | ? {$_.RuleType -eq "Include LDAP query"} | ? {$_.RuleQuery -like "*memberof*"} | select -ExpandProperty RuleQuery
$TheDict = @{}

Select-String '\(memberof=CN=([\w\s\d-_]*)[\w\s\d,-_]*\)' -input $obj -AllMatches | Foreach {
    for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
        $ThisMatch = $_.matches[$MatchNum]
        $ThisMatch = $ThisMatch.ToString().Split("=")[2].Split(",")[0]
        $ThisObjID = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $ThisMatch @paramFIMService
        $ThisObjID = $ThisObjID | ConvertFrom-FIMResourceToObject
        $ThisObjID = $ThisObjID.ObjectID.ToString().Replace("urn:uuid:","")
        $TheDict[$ThisMatch] = $ThisObjID
        #echo "$ThisMatch,$ThisObj"
    }
}

<#Foreach ($Group in $Obj) {
#Foreach ($Group in $Groups) {
    $ThisObjID = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group @paramFIMService
    $ThisObjID = $ThisObjID | ConvertFrom-FIMResourceToObject
    $ThisObjID = $ThisObjID.ObjectID.ToString().Replace("urn:uuid:","")
    $TheDict[$Group] = $ThisObjID
}#>

<#If ($OutputFile) {
    foreach ($Key in $TheDict.Keys) { echo "$Key,$($TheDict[$Key])" >> $OutputFile }
} Else {#>
    foreach ($Key in $TheDict.Keys) { echo "$Key,$($TheDict[$Key])" }
#}