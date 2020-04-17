$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"

$mimCritGroups = Get-FIMResource -XPathFilters '/Group[MembershipLocked="true"]' @paramFIMService | ConvertFrom-FIMResourceToObject