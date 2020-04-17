$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"

#Not needed for when testing xpath queries, but nice to have here just incase we want to upload something to the mim portal
$FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpathfinal

#Examples of querying person properties
$xpathfinal = '/Person[((not(Disabled = True))) and (((((starts-with(departmentNumber,"%cc51002"))) and ((starts-with(City,"%San Francisco"))))) or ((((starts-with(departmentNumber,"%cc70804"))) and ((starts-with(City,"%San Francisco"))))) or ((((starts-with(departmentNumber,"%cc50706"))) and ((starts-with(City,"%San Francisco"))))))]'
$xpathfinal = "/Person[(not(starts-with(AccountName,'%')))]"
$xpathfinal = "/Person[(AccountName = 'ashaik4')]"
$xpathfinal = "/Person[not(starts-with(Email,'%'))]"

#This is the REAL way to look for null objects
$xpathfinal = "/Person[(not(EmployeeType = '%')]"

#Without NOT STARTSWITH EMployeetype BPO
$xpathfinal = @"
/Person[((not(((Disabled = True)))) and (((((starts-with(Email,"%@company.com"))) or ((starts-with(Email,"%@ext.Companyx.com"))) or ((starts-with(Email,"%@xchangeleasing.com"))) or ((starts-with(Email,"%@Companyxatc.com"))) or ((starts-with(Email,"%@xchangeleasing.in"))) or ((starts-with(Email,"%@lioncityrentals.com.sg")))))))]
"@

#Without original bucketed NOTS
$xpathfinal = @"
/Person[((not(((Disabled = True)))) and (not(((starts-with(EmployeeType,"%BPO"))))) and (((((starts-with(Email,"%@company.com"))) or ((starts-with(Email,"%@ext.Companyx.com"))) or ((starts-with(Email,"%@xchangeleasing.com"))) or ((starts-with(Email,"%@Companyxatc.com"))) or ((starts-with(Email,"%@xchangeleasing.in"))) or ((starts-with(Email,"%@lioncityrentals.com.sg")))))))]
"@

#When handling negating wildcards This below returns 2, which reflects whats in AD
$xpathfinal = '/Person[((not(Disabled = True)) and (not(starts-with(EmployeeType,"%"))) and ((starts-with(Country,"%Vietnam%"))))]'

#This is not the same as ^, this below, returns 37, which does not reflect whats in AD
$xpathfinal = '/Person[((not(Disabled = True)) and (not(starts-with(EmployeeType,"%Invalid%"))) and ((starts-with(Country,"%Vietnam%"))))]'
$xpathfinal = '/Person[((not(Disabled = True)) and (EmployeeType != "%") and ((starts-with(Country,"%Vietnam%"))))]'
$xpathfinal = '/Person[EmployeeType = "Employee"]'

Get-FIMResource -XPathFilters $xpathfinal @paramFIMService | ConvertFrom-FIMResourceToObject

echo $xpathfinal

Copy-FIMResource -AttributeName "ObjectID" -AttributeValues "6878df1d-302e-4609-9759-23a9b1739d9f" @paramFIMService -OverrideAttributes @{DisplayName="~Distribution list management: Users can read selected attributes of group resources"} #| ConvertFrom-FIMResourceToObject

Get-FIMResource -XPathFilters '/ObjectID[Group]' @paramFIMService | ConvertFrom-FIMResourceToObject

Get-FIMResource -XPathFilters '/Group[MembershipLocked = True]' @paramFIMService | ConvertFrom-FIMResourceToObject


$DynamicGroups=Get-FIMResource -AttributeName MembershipLocked -AttributeValues "True" @paramFIMService | ConvertFrom-FIMResourceToObject



Get-FIMResource -XPathFilters "/Person[not(AccountName = '%')]" @paramFIMService 
