<#
.SYNOPSIS
    Name: Get-uGroupARSFilter
    Retrieves the Pullo Filter for a uGroup -- an AD group configured for the corp.Companyx.com domain

.NOTES

#requires -version 2
#>

Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose) { Write-Host $Message }
    $Message >> $LogFile
}

Function CleanLogicOperators ($Condition) {
    for ($i=0;$i -le 2;$i++) {
        $Condition = $Condition -Replace '\(\!\)',''
        $Condition = $Condition -Replace '\(\)',''
        $Condition = $Condition -Replace '\(\&\)',''
        $Condition = $Condition -Replace '\(\|\)',''
    }
    return $Condition
}

Function ConvertFrom-ArsConditionsToLdap ($Query) {
    # remove unnecessary ARS conditions
        <#ATTRs to remove when parsing LDAP attributes: objectsid,objectcategory,grouptype,samaccounttype,useraccountcontrol 
        (we should only be parsing one type of useraccountcontrol value, and that would be anything with the value of 2, which
        translates to an account being disabled, for example (userAccountControl:1.2.840.113556.1.4.803:=2))#>
    $RetQuery = @()
    foreach ($Condition in $Query) {
        if ($Verbose) { Write-Log "Parsing ARS attribs from condition: $Condition" }
        
        $Condition = $Condition -Replace '\(userAccountControl:[\d.]*\)',''  

        #$Condition = $Condition -Replace '\(objectCategory=[A-z]*\)',''
        $Condition = $Condition -Replace '\(objectSid=\*\)',''
        #$Condition = $Condition -Replace '\(sAMAccountType[\w\s\d.:=]*\)',''
        $Condition = $Condition -Replace '\(userAccountControl[\w\s\d.:=]*\)',''   
        $Condition = $Condition -Replace '\(objectClass=[A-z]*\)',''
        $Condition = $Condition -Replace '\(groupType:[\w\s\d.=]*\)',''

        # replace any hanging 'not's, 'or's, and 'and's.
        $Condition = CleanLogicOperators($Condition)
        # skip any empty strings
        if ($Condition -ne "") { $RetQuery += $Condition }

        if ($Verbose) { Write-Log "Resulting condition: $Condition" }
    }

    if ($Verbose) { Write-Log "Resulting query: $RetQuery"}

    return $RetQuery
}

Function Get-ARSFilter ($Name) {
    ForEach ($Group in $Name) {
        $array=@()

        $DGConditionlist = (Get-ADGroup $Group -Properties accountNameHistory).accountnamehistory

        If ($DGConditionlist) {
            # Some group queries have '\3d' instead of '=', etc
            $DGConditionlist = $DGConditionlist.replace('\3d','=').
                replace('\28','(').replace('\29',')').replace('&amp;','&').
                replace('&gt;','>').replace('&lt;','<')

            $conditions = $DGConditionlist.split("[")
                Foreach ($condition in $conditions)
                {
                    If ($condition -like "0x1*")
                        {
                        $0x1 = $condition.split(";")
                        $ouGUID = $0x1[1]
                        $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
                        $LDAPSplit = $0x1.split("]")
                        $LDAPQuery = $LDAPSplit[2]
                        $LDAPQuery = (ConvertFrom-ArsConditionsToLdap $LDAPQuery)
                        If ($LDAPQuery) {
                            $objTemp = New-Object PSobject
                            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include LDAP query"
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value $LDAPQuery
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
                            $array += $objTemp
                        }
                        }
                    If  ($condition -like "0x2*")
                        {
                        $0x2 = $condition.split(";")
                        $ouGUID = $0x2[1]
                        $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
                        $LDAPSplit = $0x2.split("]")
                        $LDAPQuery = $LDAPSplit[2]
                        $LDAPQuery = (ConvertFrom-ArsConditionsToLdap $LDAPQuery)
                        If ($LDAPQuery) {
                            $objTemp = New-Object PSobject
                            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude LDAP query"
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!$LDAPQuery)"
                            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
                            $array += $objTemp
                        }
                        }
                    If  ($condition -like "0x3*")
                        {
                        $0x3 = $condition.split(";")
                        $userGUID = $0x3[1]
                        $userRule = Get-ADObject $userguid -Properties samaccountname

                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include User Explicitly"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(distinguishedname=$($userRule.DistinguishedName))"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $UserRule.Distinguishedname
                        $array += $objTemp
                        }
                    If  ($condition -like "0x4*")
                        {
                        $0x4 = $condition.split(";")
                        $userGUID = $0x4[1]
                        $UserRule = Get-ADObject $userguid -Properties samaccountname

                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude User Explicitly"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!(distinguishedname=$($userRule.DistinguishedName)))"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $UserRule.Distinguishedname
                        $array += $objTemp

                        }
                    If  ($condition -like "0x5*")
                        {
                        $0x5 = $condition.split(";")
                        $groupGUID = $0x5[1]
                        $groupRule = Get-ADObject $groupGUID -Properties samaccountname -ErrorAction Stop

                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include Members of Group"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(memberof=$($groupRule.DistinguishedName))"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $groupRule.distinguishedname
                        $array += $objTemp
                        }
                    If  ($condition -like "0x6*")
                        {
                        $0x6 = $condition.split(";")
                        $groupGUID = $0x6[1]
                        $groupRule = Get-ADObject $groupGUID -Properties samaccountname

                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $Group
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude Members of Group"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!(memberof=$($groupRule.DistinguishedName)))"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $groupRule.distinguishedname
                        $array += $objTemp
                        }
                }
                $array
            } Else { "ARS Query not found." }
        }
}

Function Get-uGroupARSFilter {
    Param ( 
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
                Get-ARSFilter -Name $Target
            } Catch {
                Write-Log "Error -- Failed to apply operation to $Target : $($_.Exception.Message)"
                Continue
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

Export-ModuleMember -Function Get-uGroupARSFilter