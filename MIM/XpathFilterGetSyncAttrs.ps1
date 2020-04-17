$paramFIMService = @{}
$paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"

Get-FIMResource -XPathFilters '/SynchronizationRule' @paramFIMService | ConvertFrom-FIMResourceToObject | select user 
    
Get-FIMResource -XPathFilters '/ObjectTypeDescription' @paramFIMService | ConvertFrom-FIMResourceToObject | ft Name,DisplayName,Description
Get-FIMResource -XPathFilters '/BindingDescription[BoundObjectType = /ObjectTypeDescription[Name="Person"]]/BoundAttributeType' @paramFIMService | ConvertFrom-FIMResourceToObject | select DataType,DisplayName,Multivalued,Name,Description,StringRegex | export-csv .\output\MIMService-Person-Attr.csv -NoTypeInformation