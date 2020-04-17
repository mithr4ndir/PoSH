#Script to find all dynamic groups with static members

param(
[switch]$Report,
[switch]$Auto,
[string[]]$InputGrp
)
$LogFolder = "C:\Repository\logs"
$MyName = $MyInvocation.MyCommand.Name
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
$transcriptfile = "$LogFolder\$MyName`_$(Get-date -Format filedatetime)_transcript.log"
$ExplicitMemFile = "$LogFolder\$MyName`_$(Get-date -Format filedatetime)_ExplicitMemberGroup.csv"
$countExpMem=0
$allExplicitMem=@()
Start-Transcript -Path $transcriptfile | Out-Null

#Log Module
Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg | Out-File $LogFile -Append
    $ThisMsg
}

IF(!$Auto -and !($InputGrp -is [object]) -and !$Report) {
    Write-Log "Error! You must atleast enter one of the following parameters before executing this script, -Report, -Auto, or -InputGrp!"
    Stop-Transcript | Out-Null
    Break
}

#Must be one or the other paramater cannot be both
IF ($InputGrp -and $Auto) {
    Write-Log "Error! You must not use both parameters -InputGrp or -Auto, please choose one!"
    Stop-Transcript | Out-Null
    Break
}

#Cannot use both switches with report
IF ($Report -and !$Auto -and $InputGrp -isnot [Object]) {
    Write-Log "Error! Need to use atleast -AUTO or -InputGrp with -Report!"
    Stop-Transcript | Out-Null
    Break
}

#Connect to MIM Service
$paramFIMService = @{}
$paramFIMService["Uri"] = "http://server1:5725"

#Obtain all dynamic group info into vartiable
If ($Auto) {$DynamicGroups=Get-FIMResource -AttributeName MembershipLocked -AttributeValues "True" @paramFIMService | ConvertFrom-FIMResourceToObject}

#Process each manually inputted group
If ($InputGrp -is [object]) {
    $DynamicGroups=@()
    Foreach ($iGrp in $InputGrp) {
        Try {
            $tempObj = Get-FIMResource -AttributeName AccountName -AttributeValues $iGrp @paramFIMService | ConvertFrom-FIMResourceToObject
        }
        Catch {
            Write-Log "_Error Trying to process $iGrp - $($_.exception.message)"
        }
        $DynamicGroups += $tempObj
    }
}

# Genereate Report of Dynamic groups into Out-GridView
If ($Report) {
    $allObjs=@()
    Foreach ($grp in $DynamicGroups) {
        Write-Progress "Processing $($grp.AccountName)"
        $tempObj = New-Object PSObject
        $tempObj | Add-Member -MemberType NoteProperty -Name GroupName -Value $grp.AccountName 
        $tempObj | Add-Member -MemberType NoteProperty -Name WorkFlow -Value $grp.MembershipAddWorkflow
        $tempObj | Add-Member -MemberType NoteProperty -Name ExplicitMember -Value $grp.ExplicitMember
        $tempObj | Add-Member -MemberType NoteProperty -Name MembershipLocked -Value $grp.MembershipLocked
        $tempObj | Add-Member -MemberType NoteProperty -Name CostCenter -Value $grp.costcenter
        $tempObj | Add-Member -MemberType NoteProperty -Name Email -Value $grp.Email
        $tempObj | Add-Member -MemberType NoteProperty -Name Filter -Value $grp.Filter
        $tempObj | Add-Member -MemberType NoteProperty -Name ADOrgUnit -Value $grp.ADOrganizationalUnit
        $allObjs += $tempObj
    }
$allObjs | ogv
$allobjs | Export-Csv $ExplicitMemFile -NoTypeInformation
Break
}
Write-Log "$(($DynamicGroups|measure).count) - Total dynamic groups found!"
#Grab Owner Object ID from GM group, which is L2-ADM account, this is used just as a place holder.
$OwnerOID = Get-FIMResource -AttributeName AccountName -AttributeValues "gm" @paramFIMService | ConvertFrom-FIMResourceToObject
$OwnerOID = ($OwnerOID | select -ExpandProperty Owner).split(":")[2]

#Iterate throughout each group
Foreach ($grp in $DynamicGroups) {
Write-Log "_Processing $($grp.AccountName)..."
$grpURI = Get-FIMResource -AttributeName AccountName -AttributeValues $grp.AccountName @paramFIMService
#If owner approval is set, set it to none, we need to do this so that we can make changes to the group without requiring approval
If ($grp.MembershipAddWorkflow -like "Owner Approval") { 
                                    Try {
                                        Write-Log "__Owner Approval workflow found, setting to None!"
                                        $grpURI | Set-FIMResource -ImportChanges @( New-FIMImportChange "MembershipAddWorkflow" "None") @paramFIMService 
                                    }
                                    Catch {
                                        Write-Log "__Failed to remove MembershipAddWorkFlow the error msg is - $($_.exception.message)"
                                    }

                                }

#If owner is not set, set the owner to L2-adm, otherwise we can not modify the group.
If (!$grp.Owner)  {
                    Try {
                        Write-Log "__No owner found, setting owner to be L2-adm..."
                        $grpURI | Set-FIMResource -ImportChanges @( New-FIMImportChange "Owner" $OwnerOID -ImportOperation Add; New-FIMImportChange "DisplayedOwner" $OwnerOID -ImportOperation Replace) @paramFIMService
                    }
                    Catch {
                        Write-log "__Failed to add owner, the error msg is - $($_.exception.message)"
                    }
                  }
#Remove static members; needed before we are able to convert the static group into a dynamic group, otherwise it will fail at time of conversion.
If ($grp.ExplicitMember)  {
                            Write-Log "__Explicit Members found for $($grp.AccountName) - $($grp.explicitMember.count) Total members"
                            Write-Log "-----------------------------------------------"
                            Write-Log "$($grp.explicitmember)"
                            Write-Log "-----------------------------------------------"
                            $countExpMem++
                            $tempObj2 = New-Object PSObject
                            $tempObj2 | Add-Member -MemberType NoteProperty -Name Groups -Value "$($grp.AccountName)"
                            $tempObj2 | Add-Member -MemberType NoteProperty -Name Explicitmembers -Value "$($grp.ExplicitMember)"
                            $tempObj2 | Add-Member -MemberType NoteProperty -Name Count -Value "$($grp.ExplicitMember.count)"
                            $allExplicitMem += $tempObj2
                            Try {
                                #$temp = Get-FIMResource -AttributeName AccountName -AttributeValues $grp.AccountName @paramFIMService
                                Write-Log "__Attempting to remove Members!"
                                #$Grp | Set-FIMResource -ImportChanges @(New-FIMImportChange -AttributeName "MembershipLocked" -AttributeValues $false) @paramFIMService
                                $grpURI | Set-FIMResource -ImportChanges @(New-FIMImportChange -AttributeName "ExplicitMember" $grp.ExplicitMember -ImportOperation Delete) @paramFIMService
                                #$Grp.AccountName | Set-FIMResource -ImportChanges @(New-FIMImportChange -AttributeName "MembershipLocked" -AttributeValues $true) @paramFIMService                                
                                Write-Log "___Safely removed all members!"
                                }
                            Catch {
                                Write-log "___Failed to remove members from group the error msg is - $($_.exception.message)"
                            }                 
                          }
Else {
        Write-Log "___No Explicit Members to remove!"
    }
}
$allExplicitMem | Export-Csv $ExplicitMemFile -NoTypeInformation
Stop-Transcript | Out-Null