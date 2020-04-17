#
#    ...SYNOPSIS...
#    Since we have moved the ReportingScripts OU into the GoogleSync/RubyTroubleshoot OU, there was
#    a need to rectify breakage of reporting groups' hardcoded DNs for dynamic groups.
#    The purpose for this script is to modify ARS Dynamic groups with conditions of "Include Queries"; those of which are querying for users' 
#    memberof attribute of the hardcoded DN paths of groups (the groups being reporting groups).
#    
#
#  Find only the groups that have accountnamehistory generated with dynamic group conditionslist values of group DNs that of which are "*ReportingGroups,*"; 
# accountnamehistory is an AD attribute that is filled by ARS with a collective of information which include conditions/queries.
#  EDSADGConditionsList is an attribute that lives within the ARS Schema only, 

$ReportGroupConditions = get-adgroup -filter {accountnamehistory -like "*ReportingGroups,*"} -pro accountnamehistory | select -ExpandProperty samaccountname | Get-QADGroup -Proxy -Service site1-ars-app01 -IncludedProperties edsadgconditionslist | select samaccountname,edsadgconditionslist
#  Backup attribute data just incase
$ReportGroupConditions | export-csv -NoTypeInformation C:\users\ChrisL\desktop\ReportinGroupsBasedConditionsBackup2.csv
#start C:\Users\ChrisL\Desktop\work.csv

#  Counters
$countChanges=0
$countChangesNOTMADE=0

#  Process each item and replace values that will ultimately reflect the new path.
#  PLEASE TAKE NOTICE - ARS has some sort of escaping mechanism that it uses, when filling in conditions list, where all ='s symbols are \3d, we need to include this in the new value
Foreach ($sam in $ReportGroupConditions) 
{
    If($sam.edsadgconditionslist -like "*ReportingGroups,OU\3dGoogleSync,*"){
    $EditConditions = $sam.edsadgconditionslist -replace "ReportingGroups,","ReportingGroups,OU\3dRubyTroubleshoot,"
    Set-QADGroup -Identity $sam.samaccountname -ObjectAttributes @{edsadgconditionslist="$($EditConditions)"}
    $countchanges++
    }
    Else {$countChangesNOTMADE++}
}

#  Check for what processed.
Write-host "$countChanges changes attempted"
Write-host "$countChangesNOTMADE changes NOT attempted"
