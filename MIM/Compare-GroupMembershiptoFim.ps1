<#
.SYNOPSIS
    Name: Compare-GroupMembershipToFim.ps1
    This script compares group membership between AD and MIM

.NOTES
    Release Date: 2018-02-16
   
    Author: Chris Ladino

#requires -version 2
#>

#[CmdletBinding()]

PARAM ( 
    [String[]]$Name = $(throw "-Name is required."),
    [Switch]$ClearCache,
    [Switch]$AddCache,
    [Switch]$Verbose
)

# Dot Source any required Function Libraries
    # . "C:\Scripts\Functions.ps1"

# Set Error Action
    $ErrorActionPreference = "Continue"

# Set any global variables
    $LogFolder = ".\Logs\"
    $MyName = $MyInvocation.MyCommand.Name
    $LogFile = "$LogFolder$MyName`_$(Get-Date -Format FileDateTime).log"
    $DictFile = ".\dict.csv"

Function Write-Log ($Message) {
    $ThisMsg = "$(Get-Date) : $Message"
    $ThisMsg >> $LogFile
    If ($Verbose) { $ThisMsg }
}

Function Usage {
    "Usage:"
}

Function Main {
    Begin {
        $Intro = "$MyName"
        $Decoration = "="*$Intro.Length
        Write-Log $Decoration
        Write-Log $Intro
        Write-Log $Decoration
        Write-Log "$MyName logging to $Logfile..."
        # Set the FIM service URI and authentication data
        $FIMService = @{}
        $FIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
        if ($Cred) { $FIMService["Credential"] = $Cred } 
        # If Local group data is more than 6 hours old, or the -ClearCache switch has been set, pull down the latest Fim group data.
        If (($AddCache -or !$ClearCache) -and (Test-Path $DictFile)) {
            Try {
                $Dict  = ((get-content $DictFile) -replace ",","=") -join "`n" | convertfrom-stringdata
            } Catch {
                Write-Log "Error -- Failed to load Fim group data dictionary : $($_.Exception.Message)"
                Break
            }
        } Else {
            $Dict = @{}
        }
        If (($ClearCache -xor $AddCache) -or !(Test-Path $DictFile)) {
            "Building dictionary object..."
            Write-Log "Building dictionary object..."

            ForEach ($Target in $Name) {
                Try {
                    If (!$Dict[$Target]) {
                        Write-Log "Building dictionary entry for $Target"
                        $Groups = Get-FIMResource -XPathFilters "(/Group[AccountName = `"$Target`"]/ComputedMember)" @FimService
                        If ($Groups) {
                            $FIMMembers = (
                                $Groups |
                                    ConvertFrom-FimResourceToObject |
                                    ? {($_.ObjectType -eq "Person") -or ($_.ObjectType -eq "Group")}
                            ).AccountName
                        }
                        If ($FIMMembers) {
                            $Dict[$Target] = $FIMMembers
                        } Else {
                            $Dict[$Target] = ""
                        }
                        #$Dict[$Target] = $FIMMembers
                        Write-Log "Completed building dictionary entry for $Target"
                    }
                } Catch {
                    Write-Log "Error -- Failed to download Fim group data for $Target : $($_.Exception.Message)"
                    Break
                }
            }
            
            Try {
                "Writing data to dictionary file"
                Write-Log "Writing data to dictionary file"
                Remove-Item $DictFile
                ForEach ($Key in $Dict.Keys) {
                    "$Key,$($Dict[$Key])" >> $DictFile
                }
                "Completed writing data to dictionary file"
                Write-Log "Completed writing data to dictionary file"
            } Catch {
                "Error -- Failed to build dictionary file : $($_.Exception.Message)"
                Write-Log "Error -- Failed to build dictionary file : $($_.Exception.Message)"
                Break
            }
        }
    } Process{
        If ($Name) {

            ForEach ($Target in $Name) {
		"Processing $Target"
                Write-Log "Processing $Target"
                Try{
                    $ADMembers = (
                        Get-ADGroup $Target -Properties Members |
                            ? {
                                ($_.DistinguishedName -like "*,OU=Users,$OUDomainPATH") -or
                                ($_.DistinguishedName -like "*,OU=Groups,$OUDomainPATH")
                            }
                    ).Members
                    $FIMMembers = $Dict[$Target].Split(' ')
                    "Group Membership Comparison"
                    "`tAD Count : $($ADMembers.Count)"
                    "`tFIM Count : $($FIMMembers.Count)"
                    Write-Log "Group Membership Comparison"
                    Write-Log "`tAD Count : $($ADMembers.Count)"
                    Write-Log "`tFIM Count : $($FIMMembers.Count)"
                    If ($ADMembers.Count -eq $FIMMembers.Count) {
                        "`tTEST PASSED: Membership count is correct"
                        Write-Log "`tTEST PASSED: Membership count is correct"
                    } Else {
                        "`tTEST FAILED: Membership count is incorrect"
                        Write-Log "`tTEST FAILED: Membership count is incorrect"                    
                    }
                } Catch {
                    Write-Log "Error -- Failed to compare member count on $Target : $($_.Exception.Message)"
                }
                Try {
                    # Mark any users in the query results that are exclusively in one of the two groups
                    If ($ADMembers.Count -ne $FIMMembers.Count) {
                        $FIMExtra = $FIMMembers | ? { $_ -notin $ADMembers }
                        $ADExtra = $ADMembers | ? { $_ -notin $FIMMembers }
                        If ($FIMExtra) {
                            ForEach ($Extra in $FIMExtra) {
                                Write-Log "`tUser $Extra found in FIM but not in AD!"
                            }
                        }
                        If ($ADExtra) {
                            ForEach ($Extra in $ADExtra) {
                                Write-Log "`tUser $Extra found in AD but not in FIM!"
                            }
                        }
                    }
                } Catch {
                    Write-Log "Error -- Failed to compare membership on $Target : $($_.Exception.Message)"
                }
                "Completed processing $Target"
                Write-Log "Completed processing $Target"
            }
        } Else {
            Usage
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution, now exiting..."
        }
        $LogFile = $null
    }
}

Main


