<#
    ...SYNOPSIS
        Simple Script to add members to a group via a string feed

    ...USAGE EXPLANATION
        Feed in a text file with no spaces, followed by a return for each samaccountname name provided (You will need samaccountnames for this to work)

    ...ERROR REPORTING
        Simple error reporting built into this tool
 #>

$Samaccountname = gc "C:\Users\ChrisL\Desktop\Samaccountname.txt"
$countErr=0
$countAdded=0
$arrayErr=@()
$arrayAdded=@()
Foreach ($stuff in $Samaccountname) {
    Try   {
          Add-ADGroupMember "ADP-Restricted-Users-FlexForce Ext NoLogin-Full Control" -Members $stuff
          $CountAdded++
          $arrayAdded+=$stuff

          }

    Catch {
          $countErr++
          $arrayErr+=$stuff
          }

}
IF ($countErr -gt 0) {"`r";Write-host "$countErr users were not processed due to errors check it out..." -ForegroundColor Red;$arrayErr + "`r"}
IF ($countAdded -gt 0) {Write-host "$countAdded users were successfully processed check it out..." -ForegroundColor Green;$arrayAdded} 