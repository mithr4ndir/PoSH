$Groups = Get-Content .\Test5DGroupsSam.txt

$FimGrObjArray=@()
$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"

Foreach ($group in $groups) {
$FimGroupData = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group @paramFIMService
$FimGroupObject = $FimGroupData | ConvertFrom-FIMResourceToObject
$FimGrObjArray += $FimGroupObject
}
$FimGrObjArray


$data = Get-FIMResource -ObjectType Group -AttributeName MembershipLocked -AttributeValues True @paramFIMService   | ConvertFrom-FIMResourceToObject 


employeetype-none = 0381bcbe-e13a-40da-b7bb-76a874b28620
emea-ext-locations = 04614fbe-f64b-4230-9c99-092858e80fec
emea-ext-static = 1b00488a-8493-4047-ad2a-8af71ae895fc



