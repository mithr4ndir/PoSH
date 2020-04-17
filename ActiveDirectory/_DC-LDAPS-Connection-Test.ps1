#$dc = [System.DirectoryServices.ActiveDirectory.Domain]::getCurrentDomain().DomainControllers | Select -First 1
$LDAPS = [ADSI]"LDAP://site1-dc07.corp.Companyx.com:636"
try {
   $Connection = [adsi]($LDAPS)
} Catch {
}
If ($Connection.Path) {
   Write-Host "Active Directory server correctly configured for SSL, test connection to $($LDAPS.Path) completed."
} Else {
   Write-Host "Active Directory server not configured for SSL, test connection to LDAP://$($dc.name):636 did not work."
}