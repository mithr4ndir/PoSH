<#

    .CREATED BY 
        Chris Ladino

    .NOTES  
        Requirement from EngSec to restrict DAD accounts workstation logon access to Domain Controllers. 
        This script will allow you to update all DAD profiles' userWorkstation attribute to reflect all the current domain controllers in the environment
        MUST Run from a domain controller within an elevated powershell window

    .JIRA
        https://jira.Companyxinternal.com/browse/TSINFRA-7857

    .SYNTAX 
        .\Update-DADLogonWorkstation        # Basic Syntax Structure
        .\Update-DADLogonWorkstation -logs  # Generate additional logging to the console and also create a log file to the desktop

#>
[cmdletbinding()]
param(
    [switch]$logs
)

Function Update-DADLogonWorkstation {

If ($logs) {
    $Date = Get-Date -Format MMddyyyy
    $LogFile="$env:USERPROFILE\Desktop\Update_DADLogonWorkstationLogs_$Date.txt"
    If (Test-Path $LogFile) {Remove-Item $LogFile}
}

[int]$countChangesNotNeeded=0
[int]$countChangesMade=0
[int]$countErrors=0
$dads=(Get-ADUser -Filter {samAccountName -like "*-dad" -and enabled -eq $true} -Properties userworkstations,logonworkstations | select samaccountname,userworkstations,logonworkstations | sort samaccountname)
$dcs=(Get-ADDomainController -filter * | select name | sort name)
$alldcs=$dcs.name -join ","
$alldcs = $alldcs + ",use1-dc01,use1-dc02,site1-SCRIPTS01,site1-ChrisL01,site1-PRAKASH01,site1-ADMIN01,site2-ADMIN01,site4-ADMIN01,site5-ADMIN01,IRN1-ADMIN01,site1-ADMIN02,site1-ADMIN03,site1-ADMIN04,site1-ADMIN05"

Foreach ($user in $dads) {
    IF ($user.userworkstations -eq $null) {
          #Additional logging = Write-output "No userWorkstation data for $($User.samaccountname), updating list now..." -BackgroundColor Yellow
          Try { 
               Set-ADUser $user.samaccountname -Replace @{userWorkstations=$alldcs}
               If($logs) {Write-output "Changes Made for $($user.samaccountname)"}
               $countChangesMade++
          }
          Catch {
          If($logs) {Write-output "Error while trying to update $($user.samaccountname): $($Error[0].Exception)"}
          $countErrors++
          }
    
    }
    Else {
          $CheckIfNeededToUpdate = Compare-Object $alldcs $user.userWorkstations
          If ($CheckIfNeededToUpdate -eq $null) {
                If($logs) {
                Write-output "$($user.samaccountname) has all DCs already, no change needed"
                Write-output "$($user.samaccountname) has all DCs already, no change needed" | Out-File -FilePath $LogFile -Append
                
                }
              $countChangesNotNeeded++
          }
          Else {
                #Additional logging = Write-output "Inconsistent list for $($User.samaccountname), updating list now..." -BackgroundColor Yellow
                Try { 
                     Set-ADUser $user.samaccountname -Replace @{userWorkstations=$alldcs}
                        If($logs) {
                        Write-output "Changes Made for $($user.samaccountname)"
                        Write-output "Changes Made for $($user.samaccountname)"| Out-File -FilePath $LogFile -Append
                        }
                     $countChangesMade++
                  }
                  Catch {
                         If($logs) {
                         Write-output "Error while trying to update $($user.samaccountname): $($Error[0].Exception)"
                         Write-output "Error while trying to update $($user.samaccountname): $($Error[0].Exception)" | Out-File -FilePath $LogFile -Append
                         }
                         $countErrors++
                  }
          
          }
    }
}

Write-output "`n`nChanges Made : $countChangesMade"
Write-output "Changes Attempted : $countErrors"
Write-output "Changes Not Needed : $countChangesNotNeeded"

    If ($logs) {
    Write-output "-----------------------------------------------------------"| Out-File -FilePath $LogFile -Append
    Write-output "`n`nChanges Made : $countChangesMade"| Out-File -FilePath $LogFile -Append
    Write-output "Changes Attempted : $countErrors"| Out-File -FilePath $LogFile -Append
    Write-output "Changes Not Needed : $countChangesNotNeeded"| Out-File -FilePath $LogFile -Append
    }

$RefreshDads=Get-ADUser -filter {samAccountName -like "*-dad" -and enabled -eq $true} -pro userworkstations,logonworkstations | select samaccountname,userworkstations,logonworkstations | sort samaccountname
Write-Output "`nCurrent DAD userWorkstation Attribute Data for all active DAD accounts..."
$RefreshDads

    If($logs) {
    Write-output "-----------------------------------------------------------"| Out-File -FilePath $LogFile -Append
    Write-Output "`nEntire list of DCs updated to dad accounts..." | Out-File -FilePath $LogFile -Append
    $alldcs | Out-File -FilePath $LogFile -Append
    $RefreshDads | Out-File -FilePath $LogFile -Append
    Write-Output "`n`nA log file was saved on your desktop"
    }
}

Update-DADLogonWorkstation
