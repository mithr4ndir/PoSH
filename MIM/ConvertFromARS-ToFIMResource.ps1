Import-Module FIMService

Function ConvertFromARSFormat($DGConditionlist) {
$array=@()

$conditions = $DGConditionlist.split("[")
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
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(&(distinguishedname=$($userRule.DistinguishedName)))"
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
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(&(memberof=$($groupRule.DistinguishedName)))"
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
$array
}

$group = get-qadgroup w-test2 -Dynamic $true -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist 

$ConditionsList = ConvertFromARSFormat $group.edsadgconditionslist
#TODO Logic for conditionslist to xpath

#if (!$Cred) { $Cred = Get-Credential domain\account }
$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
if ($Cred) { $paramFIMService["Credential"] = $Cred } 

$FimGroup = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $group.SamAccountName @paramFIMService
$FimGroupdata = $FimGroup | ConvertFrom-FIMResourceToObject
#$Fimrefgroup = Get-FIMResource -XPathFilters '/Group[AccountName="w-test"]' @paramFIMService | ConvertFrom-FIMResourceToObject
#TODO: Split FIMrefgroup to remove urn:uuid:

#$xpath = '/Person[ObjectID = /Group[AccountName != "All_Disabled_Users"]/ComputedMember AND contains(City, "San Francisco") AND contains(supervisoryOrganization, "Technology Services")]'
$xpath = "/Person[(not(Disabled = True)) and (starts-with(City, '%San Francisco')) and (starts-with(supervisoryOrganization, '%Technology Services')) and (ObjectID = /Group[ObjectID = '5a0cf4c7-667d-49ba-90ec-8e794e7e861d']/ComputedMember)]"
#$xpath = '/Person[(not(Disabled = True)) and (((contains(city,"San Francisco")) and ((contains(supervisoryOrganization,"Technology Services")))) or (ObjectID = /Group[ObjectID = "5a0cf4c7-667d-49ba-90ec-8e794e7e861d"]/ComputedMember))]'
    

$FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpath

$Importchanges = @(
New-FIMImportChange "Filter" $FIMFilter
New-FIMImportChange "MembershipLocked" $true
New-FIMImportChange "MembershipAddWorkflow" "None"
#New-FIMImportChange "ExplicitMember" $FimGroupdata.ExplicitMember -ImportOperation Delete
)

$FimGroup | Set-FIMResource -ImportChanges $Importchanges @paramFIMService


