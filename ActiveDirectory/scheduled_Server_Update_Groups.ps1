<#
.SYNOPSIS
    Name: scheduled_Server_Update_Groups.ps1
    Updates the (previously ARS dynamic) Server and WSUS computer groups.
    MIM is not configured to operate on Computer objects, so this script replaces that functionality.


.NOTES

#requires -version 2
#>

Param (
    [Switch]$WhatIf,
    [Switch]$Verbose
)

# Dot Source any required Function Libraries
    . "C:\Repository\bin\Import-uManage.ps1" | Out-Null

# Set DC for all Active Directory Calls
    $DC = "server"

# Set Email Reporting info
    $toMail = $true
    $to = 'corpsys@company.com'
    $from = "$(hostname)@company.com"
    $smpt = 'site1-smtp01.corp.Companyx.com'

# Set Error Action
    $ErrorActionPreference = "Continue"

# Set global variables
    $LogFolder = "C:\Repository\logs\Scheduled"
    $MyName = $MyInvocation.MyCommand.Name
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"

Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg >> $LogFile
    If ($Verbose) { $ThisMsg }
}

Function Main {
    Begin {
        $Intro = "$MyName"
        $Decoration = "="*$Intro.Length
        Write-Log $Decoration
        Write-Log $Intro
        Write-Log $Decoration
        Write-Log "$MyName logging to $Logfile..."
        
        # Helper function to quickly get DN
        function Get-GrpDN($name) { try { (Get-ADGroup $name -Server $DC).distinguishedname } catch { (Get-ADGroup -LDAPFilter "(displayname=$name)" -Server $DC).distinguishedname } }

        # Declare a hashtable to store the computer group rule definitions
        $Rules = @{
            'GPF-Deny-Workstations-FirewallSettings'="(&(objectCategory=computer)(sAMAccountType=805306369))"
            #'Servers-WSUS-ATG-Group A'="(&(&(objectCategory=computer)(sAMAccountType=805306369))(objectClass=computer))" # Disabled for https://jira.Companyxinternal.com/browse/TSINFRA-8943
            'Servers-All Fintech Nodes'="(&(&(objectCategory=computer)(sAMAccountType=805306369))(&(&(operatingSystem=Windows Server*)(objectClass=computer))(&(samAccountName=*-fintech*)(objectClass=computer))))"
            'WSUS-Servers-ORL-HYP-Even'="(&(&(&(objectCategory=computer)(sAMAccountType=805306369))(|(&(cn=*orl*)(objectClass=computer))(&(cn=*hyp*)(objectClass=computer))))(!(&(&(objectCategory=computer)(sAMAccountType=805306369))(&(userAccountControl:1.2.840.113556.1.4.803:=2)(objectClass=computer))))(!(&(&(objectCategory=computer)(sAMAccountType=805306369))(|(&(cn=*1)(objectClass=computer))(&(cn=*3)(objectClass=computer))(&(cn=*5)(objectClass=computer))(&(cn=*7)(objectClass=computer))(&(cn=*9)(objectClass=computer)))))(!(memberof=$(Get-GrpDN('Servers-WSUS-Update Group CatchAll')))))"
            'WSUS-Servers-ORL-HYP-Odd'="(&(&(&(objectCategory=computer)(sAMAccountType=805306369))(|(&(cn=*-hyp*)(objectClass=computer))(&(cn=*-orl*)(objectClass=computer))(&(cn=*-tm1-*)(objectClass=computer))))(!(&(&(objectCategory=computer)(sAMAccountType=805306369))(&(userAccountControl:1.2.840.113556.1.4.803:=2)(objectClass=computer))))(!(&(&(objectCategory=computer)(sAMAccountType=805306369))(|(&(cn=*2)(objectClass=computer))(&(cn=*4)(objectClass=computer))(&(cn=*6)(objectClass=computer))(&(cn=*8)(objectClass=computer))(&(cn=*10)(objectClass=computer)))))(!(memberof=$(Get-GrpDN('Servers-WSUS-Update Group CatchAll')))))"
            'Servers-WSUS-Update Group CatchAll'="(&(&(&(objectCategory=computer)(sAMAccountType=805306369))(&(operatingSystem=*Windows*Server*)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))))(!(|(name=*tm1*)(name=*Irn1*)(name=*sv2-*)(name=*-orl*)))(!(memberof=$(Get-GrpDN('Servers-WSUS-Update Group B'))))(!(memberof=$(Get-GrpDN('Servers-WSUS-Update Group C'))))(!(memberof=$(Get-GrpDN('Servers-WSUS-Update Group A'))))(!(memberof=$(Get-GrpDN('Domain Controllers-WSUS-Update-ENC'))))(!(memberof=$(Get-GrpDN('Domain Controllers-WSUS-Update Group A'))))(!(memberof=$(Get-GrpDN('Domain Controllers-WSUS-Update Group B'))))(!(memberof=$(Get-GrpDN('Domain Controllers-WSUS-Update Group C'))))(!(memberof=$(Get-GrpDN('Domain Controllers-WSUS-Update Group D'))))(!(memberof=$(Get-GrpDN('TM1-Servers-WSUS-Update Group A'))))(!(memberof=$(Get-GrpDN('TM1-Servers-WSUS-Update Group B'))))(!(memberof=$(Get-GrpDN('WSUS-Servers-ORL-HYP-Even'))))(!(memberof=$(Get-GrpDN('WSUS-Servers-ORL-HYP-Odd'))))(!(memberof=$(Get-GrpDN('Servers-WSUS-ATG-Group A')))))"
        }

        <#$Rules = @{
            'GPF-Deny-Workstations-FirewallSettings' = Get-uGroupARSFilter -Name 'GPF-Deny-Workstations-FirewallSettings'
            'Servers-WSUS-ATG-Group A' = Get-uGroupARSFilter -Name 'Servers-WSUS-ATG-Group A'
            'Servers-All Fintech Nodes' = Get-uGroupARSFilter -Name 'Servers-All Fintech Nodes'
            'WSUS-Servers-ORL-HYP-Even' = Get-uGroupARSFilter -Name 'WSUS-Servers-ORL-HYP-Even'
            'WSUS-Servers-ORL-HYP-Odd' = Get-uGroupARSFilter -Name 'WSUS-Servers-ORL-HYP-Odd'
            'Servers-WSUS Update Group CatchAll' = Get-uGroupARSFilter -Name 'Servers-WSUS Update Group CatchAll'
        }#>

    } Process{
        ForEach ($Target in $Rules.Keys) {
            Write-Log "Processing $Target"
            $ThisFilter = $Rules[$Target]
            Try {
                $Includes = $Excludes = $null
                $ThisFilter | % {
                    Write-Log "Retrieving target computer objects with query $_"
                    $Base = $null
                    if ($Target -eq "GPF-Deny-Workstations-FirewallSettings") {
                        $Base = "OU=Hardware R&D,OU=ATC,OU=Workstations,OU=Computers,$OUDomainPATH"
                    } elseif ($Target -eq "Servers-WSUS-ATG-Group A") {
                        $Base = "OU=ATG,OU=Servers,OU=Computers,$OUDomainPATH"
                    } else {
                        $Base = "OU=Servers,OU=Computers,$OUDomainPATH"
                    }
                    Write-Log "Executing 'Get-ADComputer -LDAPFilter $_ -SearchBase $Base'"
                    $Computers = (Get-ADComputer -LDAPFilter $_ -SearchBase $Base -Server $DC).DistinguishedName
                    
                }
                Write-Log "Completed retrieving computer objects for query for $Target : $Computers"
                
                <#
                $Includes = $Excludes = $null
                $ThisFilter | % {
                    Write-Log "Retrieving target computer objects with query $($_.RuleQuery)"
                    $QueryComputers = (Get-ADComputer -SearchBase $_.RuleScope -LDAPFilter $_.RuleQuery).DistinguishedName
                    if ($_.RuleType -like "Include *") {
                        $Includes += $QueryComputers | Select -Unique
                    } elseif ($_.RuleType -like "Exclude *") {
                        $Excludes += $QueryComputers | Select -Unique
                    }
                }
                $Computers = $Includes | ? { $_ -notin $Excludes }
                Write-Log "Completed retrieving computer objects for query for $Target : $Computers"
                #>

            } Catch {
                Write-Log "Error -- Failed to retrieve computer objects for $Target : $($_.Exception.Message)"
                Continue
            }
            Write-Log "Finding group membership differential for $Target"
            Try {
                # Member Calculation
                Write-Log "Getting current members from AD Group"
                $Members = (Get-AdGroup $Target -Properties Members -Server $DC).Members
                Write-Log "Current Members of $Target : $Members"
                # Remove any computers that are already members but are not in query results
                $Removals = $Members | ? { $Computers -notcontains  $_ }
                # Add any computers in the query results that are not already members 
                $Additions = $Computers | ? { $Members -notcontains  $_ }
                Write-Log "Completed membership differential calculations for $Target"
                Write-Log "Additions ($($Additions.Count)) : $Additions"
                Write-Log "Removals ($($Removals.Count)) : $Removals"
            } Catch {
                Write-Log "Error -- Failed to calculate membership differential for $Target : $($_.Exception.Message)"
                Continue
            }
            Write-Log "Removing stale or incorrect membership for $Target"
            If ($Removals) {
                Try {
                    If ($WhatIf) {
                        Write-Log "Executing 'Remove-ADGroupMember $Target -Members $Removals'"                    
                    } Else {
                        try {
                            Remove-ADGroupMember $Target -Members $Removals -Confirm:$false -Server $DC
                        } catch {
                            Write-Log('----Error with Remove-ADGroupMember ' + $Target + ' on objects ' + $Removals + ' - ' + $_ + ($_.InvocationInfo | Out-String))
		                    if($toMail){
			                    $subject = "Error with Remove-ADGroupMember in Server Groups Script"
			                    $body = "There was an error in the script on Remove-ADGroupMember $Target on objects $Removals :`n`n" + $_ + ($_.InvocationInfo | Out-String)
			                    $mail = @{ 
				                    To = $to
				                    from = $from
				                    Subject = $subject
				                    Body = $body
				                    Smtpserver = $smpt
			                    }
			                    Send-MailMessage @mail
		                    }
                        }
                    }
                    Write-Log "Completed removing stale or incorrect membership for $Target"
                } Catch {
                    Write-Log "Error -- Failed to remove stale or incorrect membership for $Target : $($_.Exception.Message)"
                    Continue
                }
            } Else {
                Write-Log "There are no computers to remove."
            }
                
            Write-Log "Adding new membership"
            If ($Additions) {
                Try {
                    If ($WhatIf) {
                        Write-Log "Executing 'Add-ADGroupMember $Target -Members $Additions'"
                    } Else {
                        try {
                            Add-ADGroupMember $Target -Members $Additions -Server $DC
                        } catch {
                            Write-Log('----Error with Add-ADGroupMember ' + $Target + ' on objects ' + $Additions + ' - ' + $_ + ($_.InvocationInfo | Out-String))
		                    if($toMail){
			                    $subject = "Error with Add-ADGroupMember in Server Groups Script"
			                    $body = "There was an error in the script on Remove-ADGroupMember $Target on objects $Additions :`n`n" + $_ + ($_.InvocationInfo | Out-String)
			                    $mail = @{ 
				                    To = $to
				                    from = $from
				                    Subject = $subject
				                    Body = $body
				                    Smtpserver = $smpt
			                    }
			                    Send-MailMessage @mail
		                    }
                        }
                    }
                    Write-Log "Completed adding new membership for $Target"
                } Catch {
                    Write-Log "Error -- Failed to add new membership for $Target : $($_.Exception.Message)"
                    Continue
                }
            } Else {
                Write-Log "There are no computers to add."
            }
            Write-Log "Completed processing $Target"
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution, now exiting..."
        }
        $LogFile = $null
    }
}

Main
