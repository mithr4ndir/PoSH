$Groups=dir 'AD:\,OU=server1' | ? {$_.objectclass -like "OrganizationalUnit"}
$grouparray=@()
$groupLabeled=@()
foreach ($ou in $groups){
    $grouparray+=Get-adgroup -filter * -SearchBase $ou.distinguishedname -Properties labeleduri
}
foreach ($lab in $grouparray){
IF ($lab.labeleduri -like "*") {$groupLabeled+=$lab}
}

$contentionGrps = Compare-Object $groupLabeled.Samaccountname $mimCritGroups.AccountName -IncludeEqual | ? {$_.sideindicator -eq "=="}

$historicLabeleduri=@()
Foreach ($grp in $contentionGrps.InputObject) {
    #$historicLabeleduri+=Get-ADGroup $grp -pro labeleduri,Companyx-dynamic-processing-priority | select samaccountname,labeleduri,Companyx-dynamic-processing-priority
    #Set-adgroup $grp -clear labeleduri,Companyx-dynamic-processing-priority
    Get-adgroup $grp -pro labeleduri,Companyx-dynamic-processing-priority
}
#$historicLabeleduri|Export-Csv -NoTypeInformation -Path $env:USERPROFILE\desktop\historicLabeleduri.csv
 
Write-Output "There are this many groups under Managed/Groups/ $($groups.Count)"

$groupsOneLevel=Get-adgroup -filter * -SearchBase "OU=Groups,$OUDomainPATH" -SearchScope OneLevel 