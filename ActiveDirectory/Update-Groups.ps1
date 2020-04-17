<#
.SYNOPSIS
    Name: Update-Groups.ps1
    Currently this script handles explicit group adds imported from C:\repository\input\Update-Groups.csv. 
    The column header used is RefGrps, which should be comma seperated.
    Logic is implemented to obtain nested groupmembers.
.NOTES
    Author: Chris Ladino  \(^_^)/
    Release Date: March 10, 2018
    
    Revisions to consider: logic to handle explicit users or ldap queries that are added to input file
    #requires -version 2
#>

#[CmdletBinding()]
PARAM ( 
    [String[]]$Name,
    [Switch]$Verbose,
    [Switch]$Help
)


# Dot Source any required Function Libraries
    # . "C:\Scripts\Functions.ps1"

# Set local variables
    $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

    $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
    $LogFolder = "C:\Repository\Logs\UpdateGroups\" # Log file directory
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify
    
    $Intro = "<<<<<<<<<<<<<<<<<<<      $MyName   Har Har!  Your base are belong to us!  >>>>>>>>>>>>>>>>" # Program introduction
    $Decor = "="*$Intro.Length # Decoration string
    
    $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage
    $ADServer = "site1-dc02"
    $GroupUpdateCSV = Import-Csv C:\Repository\input\Update-Groups.csv

Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose ) { $Message }
    $Message >> $LogFile
}

Function Main {
    Begin {
        If ($Help) {
            $Usage
            exit
        } Else {
            ""
            $Decor
            $Intro
            $Decor
        }
    } Process{
        Write-Log "$MyName logging to $Logfile..."
        ForEach ($Group in $GroupUpdateCsv) {
            Write-Log "Processing Update Group Script"
            Try{
                Write-Log "Starting with $($Group.Identity)"
                #Gather Membership for each group in refgroup column, recursively
                If ($Group.RefGroups -is [object]) {
                    Write-Log "Gathering Membership for $($group.RefGroups)"
                    $searchBase = $group.searchbase
                    $refgroupMembers=@()
                    $refGroups=$Group.RefGroups.split(",")
                    Foreach ($grp in $refGroups) {
                        Write-Log "Querying groupmembers recursively for $grp..."
                        $tempGrpDN = get-adgroup -Identity $grp | select -ExpandProperty distinguishedname
                        $tempLDAP = "(&(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:="+"$($tempGrpDN)))"
                        $refgroupMembers += Get-ADUser -LDAPFilter "$tempLDAP" -Server $ADServer
                        Write-Log "Query returned this many members, $($refgroupMembers.Count), for $($grp), and added to array"
                    }
                }
                Else {
                    Write-Log "Nothing to process for $($group.Identity)"
                }
                $CurrentGroupMembers = Get-ADGroup -Identity $Group.identity -pro members -Server $ADServer | select -ExpandProperty members
                $Compare = Compare-Object $CurrentGroupMembers $refgroupMembers.distinguishedname -IncludeEqual
                $Removals = $Compare | ? {$_.sideindicator -eq "<="}
                $Additions = $Compare | ? {$_.sideindicator -eq "=>"}
                IF ($Removals) {
                    Write-Log "Total count of removals: $($Removals.count)"
                    Try {
                        Write-Log "Attempting to Removal stale members...`n$($Removals.InputObject)"
                        Remove-ADGroupMember -Identity $group.identity -Members $Removals.InputObject -Server $ADServer -Confirm:$false
                    } Catch { Write-Log "Error -- Failed to process group removal for $($Group.identity): $($_.Exception.Message)"   }
            } Else {Write-host "No Removals to process"}
                IF ($Additions) {
                    Write-Log "Total count of additions: $($Additions.count)"
                    Try {
                        Write-Log "Attempting to Add members...`n$($Additions.Inputobject)"
                        Add-ADGroupMember -Identity $group.identity -Members $Additions.InputObject -Server $ADServer
                    } Catch { Write-Log "Error -- Failed to process group additions for $($Group.identity): $($_.Exception.Message)" }
            } Else {Write-host "No Additions to process"}
                IF (!$Removals -and !$Additions) {Write-Log "No changes to process, group is up-to-date! Yey!"}

            } Catch {
                Write-Log "Error -- Failed to apply operation to $($Group.identity): $($_.Exception.Message)"
                Break
            }
            Write-Log "Completed processing $($Group.identity)"
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}


Main