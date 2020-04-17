$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"


#Xpath filter which provides conditions of only enabled users and people with specific costcenter.
$xpathfinal = "/Person[(not(Disabled = True)) and (starts-with(departmentNumber,'%$($grp.costcenter)'))]"

#Fim filter pretext needed for when importing xpath filters, a -f switch along with $xpathfinal variable are placed at the end of the next line to concatenate the full filter.
$FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpathFinal

#Find group place in variable
$fimgrp = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues workplace-cost-center @paramFIMService 
#Convert fimgrp variable into an array with data of the group


#If owner approval is set, set it to none, we need to do this so that we can make changes to the group without requiring approval
If ($fimgrpdata.MembershipAddWorkflow -like "Owner Approval") {$fimgrp | Set-FIMResource -ImportChanges @( New-FIMImportChange "MembershipAddWorkflow" "None") @paramFIMService}

#If owner is not set, set the owner to L2-adm, otherwise we can not modify the group.
If (!$fimgrpdata.Owner)  {$FimGrp | Set-FIMResource -ImportChanges @(
                                                New-FIMImportChange "Owner" $OwnerOID -ImportOperation Add
                                                New-FIMImportChange "DisplayedOwner" $OwnerOID -ImportOperation Replace
                                            ) @paramFIMService}
#Remove static members; needed before we are able to convert the static group into a dynamic group, otherwise it will fail at time of conversion.
If ($fimgrpdata.ExplicitMember)  {$FimGrp | Set-FIMResource -ImportChanges @(
                                                New-FIMImportChange "ExplicitMember" $FimGrpdata.ExplicitMember -ImportOperation Delete
                                            ) @paramFIMService}
#Compile proposed changes; add filter, add email and lock the membership.
$Importchanges = @(
    New-FIMImportChange "Email" ($grp.samaccountname + "@company.com")
    New-FIMImportChange "Filter" $FIMFilter
    New-FIMImportChange "MembershipLocked" $true
                )
#Configure the group object with the proposed changes above.
$fimgrp | Set-FIMResource -ImportChanges $Importchanges @paramFIMService 
