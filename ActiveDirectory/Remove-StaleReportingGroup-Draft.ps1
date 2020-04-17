<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>

#Setting variables for date/time,counters, and arrays used within the scripts
$StartDate=(Get-date -Format MM-dd-yyyy)
$StartTime=(Get-date -Format HH.mm.ss)
$CountIFdisabled=0
$CountIFenabled=0
$CountIFerrors=0
$CountIFdeleted=0
$GroupSamAcct=@()
$AllRPGrpsToBeDeleted=@()

#Obtain all reporting groups found within the Reporting groups OU
$AllReportinGroups = Get-ADGroup -Filter * -SearchBase "OU=ReportingGroups,OU=RubyTroubleshoot,OU=GoogleSync,OU=Groups,$OUDomainPATH" | select -ExpandProperty samaccountname

#Lets obtain just the samaccountname portion of the reporting group name; we achieve this by creating a new array with the truncated version of the groupname
Foreach ($item in $AllReportinGroups) {$tempobj = New-Object PSObject; $tempobj|Add-Member -MemberType NoteProperty -Name "Sams" -Value $item.Substring(0, $item.Indexof('-')); $GroupSamAcct += $tempobj }

#This next line will give us, sorted, unique values
$GroupSamUniq = $GroupSamAcct| sort sams |select sams -Unique

#Let there be logs!
$transcript=$true
$transcriptlog="C:\Repository\output\Remove-StaleReportinGroups-$($StartDate)_$($StartTime)-Transcripts.log"
If ($transcript) {Start-Transcript $transcriptlog}
$logging=$true
$logs="C:\Repository\output\Remove-StaleReportingGroups-$($StartDate)_$($StartTime)-logs.log"
$deletedgroups=""

#Let us create variables that this script will use, to model after the naming convention structure in which was embedded with the reporting scripts when creating new groups (for example ChrisL-fte-staff, ChrisL-ext-directs)
$AllStaffStructure='-all-staff'
$AllDirectStructure='-all-directs'
$FTEStaffStructure='-fte-staff'
$EXTStaffStructure='-ext-staff'
$FTEDirectsStructure='-fte-directs'
$EXTDirectsStructure='-ext-directs'

#This will start processing each user to determine which groups to delete if disabled or not found, otherwise if enabled, we leave them alone.
Foreach ($user in $GroupSamUniq) {
    Try {
        $userquery = Get-aduser $user.Sams
        IF ($userquery.enabled -eq $false)
            {
            Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- $($userquery.samaccountname) is disabled - removing all reportings groups"
            $CountIFDisabled++
            Try {
                #Create temp naming structure for each wave
                $TempGrpAllStaffObj=$userquery.samaccountname+$AllStaffStructure
                $TempGrpAllDirectsObj=$userquery.samaccountname+$AllDirectStructure
                $TempGrpFTEStaffObj=$userquery.samaccountname+$FTEStaffStructure
                $TempGrpEXTStaffObj=$userquery.samaccountname+$EXTStaffStructure
                $TempGrpFTEDirectsObj=$userquery.samaccountname+$FTEDirectsStructure
                $TempGrpEXTDirectsObj=$userquery.samaccountname+$EXTDirectsStructure
                #Attempt to find groups
                $GroupsFound=Get-ADGroup -Filter {samaccountname -like $TempGrpAllStaffObj -or samaccountname -like $TempGrpAllDirectsObj -or samaccountname -like $TempGrpFTEStaffObj -or samaccountname -like $TempGrpEXTStaffObj -or samaccountname -like $TempGrpFTEDirectsObj -or samaccountname -like $TempGrpEXTDirectsObj} -pro description
                #Keep a collection of all groups to be deleted.
                $AllRPGrpsToBeDeleted += $GroupsFound
                IF ($GroupsFound -is [object])
                    {
                    Write-Host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups Found for - $($userquery.samaccountname) - Attempting to delete..."
                    IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + '---- Could not find this user - ' + $userquery.samaccountName | Out-file $logs -Append}
                    $GroupsFound | Remove-ADGroup -Confirm:$false -WhatIf
                    $FindDeletedGroups=Get-ADGroup -Filter {samaccountname -like $TempGrpAllStaffObj -or samaccountname -like $TempGrpAllDirectsObj -or samaccountname -like $TempGrpFTEStaffObj -or samaccountname -like $TempGrpEXTStaffObj -or samaccountname -like $TempGrpFTEDirectsObj -or samaccountname -like $TempGrpEXTDirectsObj}
                    IF ($FindDeletedGroups -is [object])
                        {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups still exist after attemping to delete them for this account - $($userquery.samaccountname) - Find out what is going on"
                        IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + '----  Groups still exist after attemping to delete them for this account - ' + $userquery.samaccountName + ' - Find out what is going on' | Out-file $logs -Append}
                        }
                    Else {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups deleted successfully for - $($userquery.samaccountname)"
                         IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + 'Groups deleted successfully for - ' + $userquery.samaccountName | Out-file $logs -Append}
                         $CountIFdeleted++
                         }
                    }
                }
            Catch {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Error occurred trying to find groups for - $($userquery.samaccountName) - $($_.Exception.Message)" -BackgroundColor Red}
            }
        Else {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- $($userquery.samaccountname) still enabled";$CountIFEnabled++}
        }
    Catch {
          IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + '---- Could not find this user - ' + $userquery.samaccountName + ' - ' + $_.Exception.Message | Out-file $logs -Append}
          Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Could not find this user - $($userquery.samaccountName) - $($_.Exception.Message)" -BackgroundColor Red
          $CountIFerrors++
            Try {
                #Create temp naming structure for each wave
                $TempGrpAllStaffObj=$userquery.samaccountname+$AllStaffStructure
                $TempGrpAllDirectsObj=$userquery.samaccountname+$AllDirectStructure
                $TempGrpFTEStaffObj=$userquery.samaccountname+$FTEStaffStructure
                $TempGrpEXTStaffObj=$userquery.samaccountname+$EXTStaffStructure
                $TempGrpFTEDirectsObj=$userquery.samaccountname+$FTEDirectsStructure
                $TempGrpEXTDirectsObj=$userquery.samaccountname+$EXTDirectsStructure
                #Attempt to find groups
                $GroupsFound=Get-ADGroup -Filter {samaccountname -like $TempGrpAllStaffObj -or samaccountname -like $TempGrpAllDirectsObj -or samaccountname -like $TempGrpFTEStaffObj -or samaccountname -like $TempGrpEXTStaffObj -or samaccountname -like $TempGrpFTEDirectsObj -or samaccountname -like $TempGrpEXTDirectsObj} -pro description
                #Keep a collection of all groups to be deleted.
                $AllRPGrpsToBeDeleted += $GroupsFound
                IF ($GroupsFound -is [object])
                    {
                    Write-Host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups Found for - $($userquery.samaccountname) - Attempting to delete..."
                    IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + '---- Could not find this user - ' + $userquery.samaccountName | Out-file $logs -Append}
                    $GroupsFound | Remove-ADGroup -Confirm:$false -WhatIf
                    $FindDeletedGroups=Get-ADGroup -Filter {samaccountname -like $TempGrpAllStaffObj -or samaccountname -like $TempGrpAllDirectsObj -or samaccountname -like $TempGrpFTEStaffObj -or samaccountname -like $TempGrpEXTStaffObj -or samaccountname -like $TempGrpFTEDirectsObj -or samaccountname -like $TempGrpEXTDirectsObj}
                    IF ($FindDeletedGroups -is [object])
                        {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups still exist after attemping to delete them for this account - $($userquery.samaccountname) - Find out what is going on"
                        IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + '----  Groups still exist after attemping to delete them for this account - ' + $userquery.samaccountName + ' - Find out what is going on' | Out-file $logs -Append}
                        }
                    Else {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Groups deleted successfully for - $($userquery.samaccountname)"
                         IF($logging){(Get-Date -Format MM-dd-yyyy) + '_' + (Get-Date -Format HH.mm.ss) + 'Groups deleted successfully for - ' + $userquery.samaccountName | Out-file $logs -Append}
                         $CountIFdeleted++
                         }
                    }
                }
            Catch {Write-host "$(Get-Date -Format MM-dd-yyyy)_$(Get-Date -Format HH.mm.ss)---- Error occurred trying to find groups for - $($userquery.samaccountName) - $($_.Exception.Message)" -BackgroundColor Red}
          }
        
    
}
If ($transcript) {Stop-Transcript}
If ($logging) {
               $tempobj1 = New-Object PSObject
               $tempobj1 | Add-Member -MemberType NoteProperty -name Disabled -Value $CountIFdisabled
               $tempobj1 | Add-Member -MemberType NoteProperty -name Enabled -Value $CountIFenabled
               $tempobj1 | Add-Member -MemberType NoteProperty -name NotFound -Value $CountIFerrors
               $tempobj1 | Add-Member -MemberType NoteProperty -name Deleted -Value $CountIFDeleted
               $tempobj1 | out-file $logs -append
              }