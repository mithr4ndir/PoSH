<#
.SYNOPSIS
    Name: New-uGroup
    Creates a uGroup -- an AD group configured for the corp.Companyx.com domain

.NOTES

#requires -version 2
#>


Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg >> $LogFile
    If ($Verbose) { Write-Host $ThisMsg }
}

Function Usage {
    "Usage :`n`tNew-uGroup.ps1 -Name group-name [ -DisplayName group-name ] [ -Manager group-manager ]`n`t`t[ -Description description ] [ -ReferenceGroup reference-group ] [ -MailEnabled ] [ -Path OU ] [ -Verbose ]"
}

Function New-uGroup {
    Param(
        [string[]]$Name,
        [string[]]$DisplayName,
        [switch]$MailEnabled,
        [string]$Manager,
        [string]$Description,
        [string]$ReferenceGroup,
        [string]$Path,
        [switch]$Verbose
    )


    Begin {
    # Dot Source any required Function Libraries
        # . "C:\Scripts\Functions.ps1"

    # Set Error Action
        $ErrorActionPreference = "Continue"

    # Set any global variables
        $LogFolder = "C:\Temp\uManage_Logs" # Log file directory
        $MyName = $MyInvocation.MyCommand.Name
        $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify

        $Intro = "$MyName"
        $Decoration = "="*$Intro.Length
        
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
            For ($i = 0 ; $i -lt $Name.Count ; $i++) {
                if (!$DisplayName) {
                    $ThisDisplayName = $Name[$i]
                } elseif ($DisplayName.Count -gt 1) {
                    $ThisDisplayName = $DisplayName[$i]
                } else {
                    $ThisDisplayName = $DisplayName[0]
                }

                if (!$Description) {
                    $ThisDescription = ""
                } elseif ($Description.Count -gt 1) {
                    $ThisDescription = $Description[$i]
                } else {
                    $ThisDescription = $Description[0]
                }

                Function Find-ADGroup {
                    Param ($Name,$DisplayName)
                    if ($MailEnabled) {
                        $Results = Get-ADGroup -LDAPFilter "(|(name=$($Name[$i]))(displayName=$ThisDisplayName)(mail=$($Name[$i])@company.com))"
                    } else {
                        $Results = Get-ADGroup -LDAPFilter "(|(name=$($Name[$i]))(displayName=$ThisDisplayName))"
                    }
                    return $Results
                }

                try {
                    if ($MailEnabled -and $Manager) {
                        New-ADGroup -Name ($Name[$i]) `
	                        -Description $Description `
	                        -ManagedBy (get-aduser $Manager | select -ExpandProperty DistinguishedName) `
	                        -DisplayName $ThisDisplayName `
	                        -GroupScope Universal `
	                        -GroupCategory Security `
                            -OtherAttributes @{ Mail = "$Name@company.com" }
                    } elseif ($Manager) {
                        New-ADGroup -Name ($Name[$i]) `
	                        -Description $Description `
	                        -ManagedBy (get-aduser $Manager | select -ExpandProperty DistinguishedName) `
	                        -DisplayName $ThisDisplayName `
	                        -GroupScope Universal `
	                        -GroupCategory Security
                    } else {
                        New-ADGroup -Name ($Name[$i]) `
	                        -Description $Description `
	                        -DisplayName $ThisDisplayName `
	                        -GroupScope Universal `
	                        -GroupCategory Security
                    }
                    Write-Log "Group $($Name[$i]) provisioned"
                } catch {
                    Write-Log "Error -- Group $($Name[$i]) provisioning failed : $($_.Exception.Message)"
                }

                try {
                    if ($ReferenceGroup) {
                        Add-ADGroupMember -Identity (Get-ADGroup $($Name[$i]) | select -ExpandProperty DistinguishedName) `
                            -Members (get-adgroup $ReferenceGroup -Properties member | select -ExpandProperty member)
                    }
                } catch {
                    Write-Log "Error -- Group $($Name[$i]) reference group member addition failed : $($_.Exception.Message)"
                }

                try { # move the group to the groups ou
                    sleep 5
                    Move-ADObject -Identity (Get-ADGroup $Name[$i] | select -ExpandProperty DistinguishedName) `
                        -TargetPath $Path
                    if (!(Find-ADGroup -Name $Name[$i] -DisplayName $DisplayName)) { # If the group is not found, wait 5 seconds and try again to move it
                        sleep 5
                        Move-ADObject -Identity (Get-ADGroup $Name[$i] | select -ExpandProperty DistinguishedName) `
                            -TargetPath $Path
                    }
                    Write-Log "Group $($Name[$i]) moved to $Path"
                } catch {
                    Write-Log "Error -- Group $($Name[$i]) move to $Path failed : $($_.Exception.Message)"
                }

                try {
                    $Results = (Find-ADGroup -Name $Name[$i] -DisplayName $DisplayName)
                    if ($Results.Count -lt 1) { # if the group is not found
                        Write-Log "Error provisioning $($Name[$i]), Group not found"
                    } elseif ($Results.Count -gt 1) {
                        Write-Log "Error provisioning $($Name[$i]) : Duplicate groups found for $($Name[$i]) :`n$Results"
                    }
                } catch {
                    Write-Log "Error -- Group $($Name[$i]) check failed : $($_.Exception.Message)"
                }
            }
        } else {
            Usage
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution, now exiting..."
        }
        $LogFile = $null
    }
}

Export-ModuleMember -Function New-uGroup


