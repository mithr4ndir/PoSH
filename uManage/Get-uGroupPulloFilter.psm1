<#
.SYNOPSIS
    Name: Get-uGroupPulloFilter
    Retrieves the Pullo Filter for a uGroup -- an AD group configured for the corp.Companyx.com domain

.NOTES

#requires -version 2
#>

Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose ) { Write-Host $Message }
    $Message >> $LogFile
}

Function Get-uGroupPulloFilter {
    #[CmdletBinding()]
    PARAM ( 
        [String[]]$Name,
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
            exit
        } Else {
            Write-Log $Decor
            Write-Log $Intro
            Write-Log $Decor
        }
    } Process{
        Write-Log "$MyName logging to $Logfile..."
        ForEach ($Target in $Name) {
            Write-Log "Processing $Target"
            Try{
                Write-Log "Applying operation to $Target"
                Try {
                    $Group = Get-ADGroup $Target -Properties labeleduri
                    Write-Log "Retrieved the following query for group $Target`: $($Group.labeleduri)"
                    Foreach ($Condition in $Group.Labeleduri) {
                        If ($Group.labeleduri) {
                            $Conditions = $Condition.Replace("ldap:///ou=Users,$OUDomainPATH??one?","")
                            $Conditions
                        }
                    }
                } Catch {
                    Write-Log "Error -- Failed to Get AD Group $Target : $($_.Exception.Message)"
                }
            } Catch {
                Write-Log "Error -- Failed to apply operation to $Target : $($_.Exception.Message)"
                Break
            }
            Write-Log "Completed processing $Target"
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}


Export-ModuleMember -Function Get-uGroupPulloFilter

