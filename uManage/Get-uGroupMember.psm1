<#
.SYNOPSIS
    Name: Get-uGroupMember
    Recursively retrieves all (non-group) member objects of a uGroup -- an AD group configured for the corp.Companyx.com domain

.NOTES

#requires -version 2
#>

#[CmdletBinding()]

Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose ) { Write-Host $Message }
    $Message >> $LogFile
}

Function Get-uGroupMemberRecursive ($Object) {
    try { # Check the object you just passed in
        if ($Object -notlike "*,DC=corp,DC=Companyx,DC=com") {
            $Object = (Get-ADObject -ldapfilter "(samaccountname=$Object)").DistinguishedName
        }
        if (($Object -like "*,OU=Groups,*$OUDomainPATH") -and ($Object -notin $Script:Guard)) { # if it's a group, call this function on each member
            Write-Log "Searching group $Object..."
            $Script:Guard += $Object
            #Write-Log $Script:Guard
            (Get-ADGroup -Identity $Object -Properties members).members | % { Get-uGroupMemberRecursive($_) }
        } elseif (($Object -notin $Script:Members) -and ($Object -notin $Script:Guard)) { # else if it's a user, output all unique objects
            Write-Log $Object
            $Script:Members += $Object
            $Object
        }
        $Object = $null
    } catch {
        Write-Log "Error -- Failed to apply operation to $Object : $($_.Exception.Message)"
        Continue
    }
}

Function Get-uGroupMember {
    Param ( 
        [String]$Name,
        [Switch]$Verbose,
        [Switch]$Help
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

        If ($Help -or !$Name) {
            $Usage
            return
        } Else {
            Write-Log $Decor
            Write-Log $Intro
            Write-Log $Decor

            # Declare total membership and loop guard variables
            $Script:Members = $Script:Guard = New-Object System.Collections.ArrayList
        }
    } Process {
        Write-Log "$MyName logging to $Logfile..."
        if ($Name) {
            ForEach ($Target in $Name) {
                try {
                    Write-Log "Processing $Target..."
                    Write-Log "Getting members..."
                    # Call the recursive function on the base object, selecting only unique results
                    $Result = Get-uGroupMemberRecursive($Target) | select -Unique
                    $Result
                    Write-Log "Got $($Result.Count) Members : $Result"
                    Write-Log "Completed processing $Target"
                } catch {
                    Write-Log "Error -- Failed to apply operation to $Target : $($_.Exception.Message)"
                    break
                }
            }
        }

    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}


Export-ModuleMember -Function Get-uGroupMember
