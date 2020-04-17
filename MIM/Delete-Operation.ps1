$paramFIMService = @{}
$paramFIMService["Uri"] = "http://server1:5725"
$groups = gc '\\server1\c$\Repository\input\mail-mim-cleanup.txt'


Foreach ($group in $groups) {
Get-adgroup $group -pro mail | select samaccountname,mail
}


$Changes = @(New-FIMImportChange -AttributeName Email -AttributeValues "" -ImportOperation Replace)
Foreach ($group in $groups) {
Set-FIMResource -AttributeName AccountName -AttributeValues $group -ImportChanges $Changes @paramFIMService #-WhatIf
}

$Tempobj = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues cas-eats-dispatchlogic @paramFIMService | ConvertFrom-FIMResourceToObject

$Changes = @(New-FIMImportChange -AttributeName Email -AttributeValues "" -ImportOperation Replace)


$Fimgroup = Get-FIMResource -AttributeName AccountName -AttributeValues "atg-az-vo1" @paramFIMService | ConvertFrom-FIMResourceToObject
$Fimgroup.ExplicitMember | measure
$adgroup = get-adgroup atg-az-vo1 -pro members | select -ExpandProperty members | measure



nico-FTE-STAFF 
tpham-FTE-STAFF
four-FTE-STAFF 


xin.ge-FTE-S...
pooja-FTE-STAFF
pooja-EXT-STAFF
xin.ge-EXT-S...




#Set-FIMResource -AttributeValues cas-eats-acceptancelogic -ImportChanges @(New-FIMImportChange -AttributeName E-mail -AttributeValues "Test" -ImportOperation Replace) @paramFIMService