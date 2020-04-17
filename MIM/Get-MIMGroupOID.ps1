$ARSDynamicGrps = Get-QADGroup -Dynamic $true -Proxy -Service server1 | select -ExpandProperty samaccountname
$FIMService=@{}
$FIMService["Uri"] = "http://server1:5725"
$MIMOIDArray=@()

foreach ($Group in $ARSDynamicGrps) {
    $MIMQuery = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group @FIMService | ConvertFrom-FIMResourceToObject
    $OIDObj = New-Object PSObject
    $OIDObj | Add-Member -MemberType NoteProperty -Name GrpSamAccountName -Value $Group
    $OIDObj | Add-Member -MemberType NoteProperty -Name GrpMIMOID -Value $MIMQuery.ObjectID
    $MIMOIDArray += $OIDObj
}

$MIMOIDArray | export-csv -NoTypeInformation C:\Repository\output\AllDynGrps_MIMOIDs.csv


#After making changes to web portal's UI(includes search scopes, rcdcs, links, nav bar links, etc...), we need to flush cache
Recycle-FIMAppPool MIMAppPool -WMIComputerName site1-portal01

#Get all groups with Membershiplocked defined.
$groups = Get-FIMResource -ObjectType Group -AttributeName MembershipLocked -AttributeValues $true @paramFIMService 
#Get Xpath translation
New-FIMXPath -ObjectType Group -AttributeName MembershipLocked -AttributeValues $true


#Find groups with membership locked and explicitmembers added within the criteria group, there should not be explicit members within criteria groups.
$groups = Get-FIMResource -XPathFilters '/Group[MembershipLocked="True" and ExplicitMember=/*]' @paramFIMService

$listImportObjects = New-Object System.Collections.Generic.List[Microsoft.ResourceManagement.Automation.ObjectModel.ImportObject]

#Delete explicitmember values from criteria based groups
Foreach ($group in $groups) {
    $groupdata = $group | ConvertFrom-FIMResourceToObject
    Write-Output "Processing $($groupdata.AccountName)"
    $ImportObject = New-FIMImportObject -ObjectIdentifiers $group.ResourceManagementObject.ObjectIdentifier -ObjectType $group.ResourceManagementObject.ObjectType -ImportState Put -ImportChanges (New-FIMImportChange ExplicitMember $groupdata.ExplicitMember -ImportOperation Delete)
    $listImportObjects.Add($ImportObject)
    #$group | Set-FIMResource -ImportChanges (New-FIMImportChange ExplicitMember $groupdata.ExplicitMember -ImportOperation Delete) @paramFIMService 
}

$failed = $listImportObjects | Import-FIMResource @paramFIMService


#$xpathquery = Get-FIMResource -XPathFilters '/Group[ObjectID="9a547b68-419c-45fe-a7c3-f451c1152bc2"]/ComputedMember[DisplayName="MeisamVosoughpourYazdchi"]' @paramFIMService


#Copy FIM Resource
Copy-FIMResource -AttributeName DisplayName -AttributeValues "General workflow: Filter attribute validation for non-administrators " -OverrideAttributes @{DisplayName="~Group General workflow-Filter attribute validation: ~All Active People: None Admins"} @paramFIMService