<#
.SYNOPSIS
    Name: Convert-ArsToLdap
    Converts a uGroup legacy ARS dynamic group condition object to a single 

.NOTES

#requires -version 2
#>


Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose) { Write-Host $Message }
    $Message >> $LogFile
}

Function Build-LdapFilter ($AndBucket, $OrBucket) {
    # Initialize the final xpath filter for pullo and encapsulate the whole thing in "(...)"
    $ldapFinal = "("
    
    # If there are multiple condition types to parse, we encapsulate them in an "&(...)"
    if (($AndBucket) -and ($OrBucket)) { $ldapFinal += "&(" }
    
    # Construct the "and" bucket for the filter and wrap it in an "&(...)"   
    if ($AndBucket.Count -gt 1) { $ldapFinal += "&(" }
    foreach ($Condition in $AndBucket) { $ldapFinal += "$Condition" }
    if ($AndBucket.Count -gt 1) { $ldapFinal += ")" }
    
    # Construct the "and" bucket for the filter and wrap it in an "|(...)"
    if ($OrBucket.Count -gt 1) { $ldapFinal += "(|(" }
    foreach ($Condition in $OrBucket) { $ldapFinal += "$Condition" }
    if ($OrBucket.Count -gt 1) { $ldapFinal += "))" }

    # if there are multiple condition types, close the encapsulation
    if (($AndBucket) -and ($OrBucket)) { $ldapFinal += ")" }

    # close up the complete encapsulation of the filter
    $ldapFinal += ")"

    return $ldapFinal
}

#Function Get-LDAPFilter ($Group) {
Function Get-LDAPFilter {
    Param (
        $ARSConditions
    )
    #$Group = Get-ADGroup $Group -Properties accountNameHistory

    #If ($Group.accountNameHistory) {
    If ($ARSConditions[0].RuleType -and $ARSConditions[0].RuleQuery) {
        #$ARSConditions = Get-uGroupArsARSConditions $Group

        $AndBucket = @()
        $OrBucket = @()

        ForEach ($Object in $ARSConditions) {
        # Add the current condition to either the include or exclude condition array
            # We need to string them together using 'and' and 'or' as appropriate
            if ($Object.RuleType -like "Include*") {
                $OrBucket += $Object.RuleQuery
            } elseif ($Object.RuleType -like "Exclude*") {
                $AndBucket += $Object.RuleQuery
            }
        }

        $LDAP = Build-LdapFilter -AndBucket $AndBucket -OrBucket $OrBucket
        return $LDAP
    } Else {
        Write-Log "Warning -- Cannot get LDAP Filter."
    }
}

Function Convert-ArsToLdap {
    #[CmdletBinding()]
    PARAM (
        $Filter,
        [Switch]$Verbose,
        [Switch]$Help
    )

    Begin {
    # Dot Source any required Function Libraries
        #Import-Module C:\Repository\Team\acorde3\Scripts\uManage\Get-uGroupARSFilter.psm1
        # . "C:\Scripts\Functions.ps1"

    # Set local variables
        $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

        $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
        $LogFolder = "C:\Temp\uManage_Logs" # Log file directory
        $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify
    
        $Intro = "$MyName" # Program introduction
        $Decor = "="*$Intro.Length # Decoration string
    
        $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage

        If ($Help -or !$Filter) {
            $Usage
        } Else {
            Write-Log $Decor
            Write-Log $Intro
            Write-Log $Decor
        }
    } Process{
        Write-Log "$MyName logging to $Logfile..."
        If ($Filter) {
            #Write-Log "Processing $Target"
            Write-Log "Processing Filter"
            Try{
                #Write-Log "Applying operation to $Target"
                Write-Log "Applying operation to $Filter"
                Try {
                    #Get-LdapFilter $Target
                    Get-LdapFilter -ARSConditions $Filter
                    #Set-uGroup -Name $Target -PulloFilter $LDAP
                } Catch {
                    #Write-Log "Error -- Failed to Get AD Group $Target : $($_.Exception.Message)"
                    Write-Log "Error -- Failed to get Filter : $($_.Exception.Message)"
                }
            } Catch {
                #Write-Log "Error -- Failed to apply operation to $Target : $($_.Exception.Message)"
                Write-Log "Error -- Failed to apply operation to Filter : $($_.Exception.Message)"
                Break
            }
            #Write-Log "Completed processing $Target"
            Write-Log "Completed processing Filter"
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}


Export-ModuleMember -Function Convert-ArsToLdap