<#
.SYNOPSIS
    Name: Set-uGroup
    Set common uGroup -- an AD group configured for the corp.Companyx.com domain -- attributes like Pullo and MIM Filters

.NOTES

#requires -version 2
#>


Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose) { Write-Host $Message }
    $Message >> $LogFile
}


Function Set-MIMFilter {
    Param (
        [String]$Group,
        [String]$Filter
    )
    # Set the FIM service URI and authentication data
    #if (!$Cred) { $Cred = Get-Credential domain\account }
    $paramFIMService = @{}
    $paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
    if ($Cred) { $paramFIMService["Credential"] = $Cred } 
    
    <#if ($MIMFilter) {
        $XpathFinal = "/Person[$MIMFilter]" 
        Write-Log "about to apply $xpathfinal"
    }#>

    # Cast the XPATH query into a FIM dialect filter
    $MIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $Filter
    Write-Log "FIM Filter: $MIMFilter"

    Write-Log "Importing FIM resource object for $Group."
    $ThisGroup = Get-ADGroup -Identity $Group

    $FimGroup = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $ThisGroup.SamAccountName @paramFIMService 2>&1 | tee-object $LogFile -Append
    $FimGroupData = $FimGroup | ConvertFrom-FIMResourceToObject 2>&1 | tee-object $LogFile -Append
    # THIS SHOULD TAKE A BACKUP AND RESTORE IT WHEN NOT SUCCESSFUL !!!


    # If there are any explicit members in the group, they need to be removed in order to make it dynamic
    if ($FimGroupData.ExplicitMember) {
        $FimGroup | Set-FIMResource -ImportChanges @(New-FIMImportChange "ExplicitMember" $FimGroupdata.ExplicitMember -ImportOperation Delete) @paramFIMService <#-ErrorAction "Stop"#> 2>&1 | tee-object $LogFile -Append
        Write-Log "Completed attempted deletion of Explicit Members from $($ThisGroup.SamAccountName)"
    }
    if ($FimGroupData.Owner) {
        $Importchanges = @(
            New-FIMImportChange "Filter" $MIMFilter
            New-FIMImportChange "MembershipLocked" $true
            New-FIMImportChange "MembershipAddWorkflow" "None"
        )
    } else {
        $Importchanges = @(
            New-FIMImportChange "Filter" $MIMFilter
            New-FIMImportChange "MembershipLocked" $true
            New-FIMImportChange "MembershipAddWorkflow" "None"
            New-FIMImportChange "Owner" "9fc51e31-7ff8-4568-8910-7e030f4909d5" -ImportOperation Add
            New-FIMImportChange "DisplayedOwner" "9fc51e31-7ff8-4568-8910-7e030f4909d5"
        )
    }

    try {
        $FimGroup |
            Set-FIMResource -ImportChanges $Importchanges @paramFIMService 2>&1 | tee-object $LogFile -Append
    } finally {
        Write-Log "Error -- Failed to import changes for group $Name : $($_.Exception.Message)"
    }
    
    Write-Log "Attempted to import changes to FIM based on group conditions."
    Write-Log "Completed attempted migration of $($ThisGroup.SamAccountName)."
}


Function Usage {
    echo "`n.\Set-uGroup Usage:"
    echo "`tSet-uGroup.ps1 -Name group-name [ -SetReferenceGroup reference-group | -AddReferenceGroup reference-group ]"
    echo "`tset-uGroup.ps1 -Name group-name [ -SetMembers user-list | -AddMembers user-list ]"
    echo "`tset-uGroup.ps1 -Name group-name [ -PulloFilter basic-ldap-filter [ -StaticGroup static-group ] ] "
}

Function Set-uGroup {
    Param(
        [String]$Name,
        [String[]]$AddMembers,
        [String[]]$SetMembers,
        [String]$AddReferenceGroup,
        [String]$SetReferenceGroup,
        [String]$PulloFilter,
        [String]$MIMFilter,
        [String]$StaticGroup,
        [Switch]$Verbose,
        [Switch]$Force
    )
    Begin {
    # Dot Source any required Function Libraries
        # . "C:\Scripts\Functions.ps1"

    # Set local variables
        $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

        $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
        $LogFolder = "C:\Temp\uManage_Logs" # Log file directory
        $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify
        
        $Intro = "$MyName" # Program introduction
        $Decor = "="*$Intro.Length # Decoration string
    
        $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage
        
        Write-Log $Decoration
        Write-Log $Intro
        Write-Log $Decoration
        
        Write-Log "$MyName logging to $Logfile..."

        try {
            $AD = (Get-ADRootDSE).DefaultNamingContext
            if (!$Path) { $Path = "OU=Groups,OU=Managed," + $AD }
        } catch {
            Write-Log "Error -- Failed to retrieve Domain Naming Context : $($_.Exception.Message)"
            break
        }
    } Process {
        if ($Name) {
            try {
                $DistinguishedName = (Get-AdGroup $Name | Select -ExpandProperty DistinguishedName)
                Write-Log "Got DN for Group $Name -- $DistinguishedName"
            } catch {
                Write-Log "Error -- Failed to get Distinguished Name for group $Name : $($_.Exception.Message)"
            }

            if ($AddMembers -xor $SetMembers) {
                if ($SetMembers) {
                    $Members = $SetMembers
                    try {
                        $CurrentMembers = (Get-ADGroup -Identity $DistinguishedName -Properties Members | select -ExpandProperty Members)
                        If ($CurrentMembers) {
                            Remove-ADGroupMember -Identity $DistinguishedName `
                                -Members $CurrentMembers `
                                -Confirm:$false
                        } 
                    } catch {
                        Write-Log "Error -- Group $Name member clearing failed : $($_.Exception.Message)"
                    }
                } else {
                    $Members = $AddMembers
                }
                try {
                    Add-ADGroupMember -Identity (Get-ADGroup $Name | select -ExpandProperty DistinguishedName) `
                        -Members $Members
                } catch {
                    Write-Log "Error -- Group $Name member addition failed : $($_.Exception.Message)"
                }

            } elseif ($AddReferenceGroup -xor $SetReferenceGroup) {
                if ($SetReferenceGroup) {
                    try {
                        Remove-ADGroupMember -Identity $DistinguishedName `
                            -Members (Get-ADGroup -Identity $DistinguishedName -Properties Members | select -ExpandProperty Members)
                    } catch {
                        Write-Log "Error -- Group $Name addition failed : $($_.Exception.Message)"
                    }
                }
                try {
                    Add-ADGroupMember -Identity (Get-ADGroup $Name | select -ExpandProperty DistinguishedName) `
                        -Members (get-adgroup $ReferenceGroup -Properties member | select -ExpandProperty member)
                } catch {
                    Write-Log "Error -- Group $Name member addition failed : $($_.Exception.Message)"
                }

            } elseif ($PulloFilter -xor $MIMFilter) {
                if ($PulloFilter) {
                    if ($StaticGroup) {
                        try {
                            $StaticGroupDN = (Get-AdGroup $StaticGroup).DistinguishedName
                            Write-Log "Got DN for Group $StaticGroup -- $StaticGroupDN"                            
                        } catch {
                            Write-Log "Error -- Failed to get Distinguished Name for static group $StaticGroup : $($_.Exception.Message)"
                        }
                        $FullFilter = "ldap:///ou=Users,$OUDomainPATH??one?(|(&(memberof=$StaticGroupDN)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))(&$PulloFilter(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))))"
                    } else {
                        $FullFilter = "ldap:///ou=Users,$OUDomainPATH??one?(&$PulloFilter(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"        
                    }
                    try {
                        Write-Log "Applying Pullo Filter to group $Name : $FullFilter"
                        Set-ADGroup `
                            -Identity $DistinguishedName `
                            -Replace @{labeledURI=$FullFilter;"Companyx-dynamic-processing-priority"=600}
                        Write-Log "Set Pullo Filter for group $Name"                            
                    } catch {
                        Write-Log "Error -- Failed to set labeledURI for group $Name : $($_.Exception.Message)"
                    }
                } elseif ($MIMFilter) {
                    If (Set-MIMFilter -Group $Name -Filter $MIMFilter) {
                        Set-ADGroup `
                            -Identity $DistinguishedName `
                            -Replace @{"Companyx-dynamic-processing-priority"=500}
                    }
                }
            } else {
                Usage
            }
        } else {
            Usage
        }
    } End {
        $LogFile = $null
    }
}


Export-ModuleMember -Function Set-uGroup


