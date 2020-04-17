<#
.SYNOPSIS
    Name: Convert-LdapToXpath
    Retrieves the ARS Filter for a uGroup -- an AD group configured for the corp.Companyx.com domain

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
        $Condition = $Condition -Replace '\(not\)|not\(\)',''
        $Condition = $Condition -Replace '\(\)',''
        $Condition = $Condition -Replace '\(( (and|or) )*\)',''
        $Condition = $Condition -Replace '\(( (and|or) )*\(','(('
        $Condition = $Condition -Replace '\)( (and|or) )*\)','))'
    }
    return $Condition
}

Function ParseARSAttribs ($Query) {
    # remove unnecessary ARS conditions
        <#ATTRs to remove when parsing LDAP attributes: objectsid,objectcategory,grouptype,samaccounttype,useraccountcontrol 
        (we should only be parsing one type of useraccountcontrol value, and that would be anything with the value of 2, which
        translates to an account being disabled, for example (userAccountControl:1.2.840.113556.1.4.803:=2))#>
    $RetQuery = @()
    $RetQuery += ""
    foreach ($Condition in $Query) {
        if ($Verbose) { Write-Log "Parsing ARS attribs from condition: $Condition" }
        
        $Condition = $Condition -Replace '\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:=2\)','(Disabled = True)'  

        $Condition = $Condition -Replace '\(objectCategory=[A-z]+\)( and | or )*|( and | or )*\(objectCategory=[A-z]+\)|\(objectCategory=[A-z]+\)',''
        $Condition = $Condition -Replace '\(objectSid=\*\)( and | or )*|( and | or )*\(objectSid=\*\)|\(objectSid=\*\)',''
        $Condition = $Condition -Replace '\(sAMAccountType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)( and | or )*|( and | or )*\(sAMAccountType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)|\(sAMAccountType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)',''
        $Condition = $Condition -Replace '\(userAccountControl:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)( and | or )*|( and | or )*\(userAccountControl:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)|\(userAccountControl:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)',''   
        $Condition = $Condition -Replace '\(objectClass=[A-z]+\)( and | or )*|( and | or )*\(objectClass=[A-z]+\)|\(objectClass=[A-z]+\)',''
        $Condition = $Condition -Replace '\(groupType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)( and | or )*|( and | or )*\(groupType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)|\(groupType:1\.2\.840\.113556\.1\.4\.804:=(\d)+\)',''

        # replace any hanging 'not's, 'or's, and 'and's.
        $Condition = CleanLogicOperators($Condition)
        # skip any empty strings
        if ($Condition -ne "") { $RetQuery += $Condition }

        if ($Verbose) { Write-Log "Resulting condition: $Condition" }
    }

    if ($Verbose) { Write-Log "Resulting query: $RetQuery"}

    return $RetQuery
}

Function Convert-LdapToXpath {
    Param (
        $Conditions,
        [Switch]$Verbose
    )

# Set local variables
    $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

    $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
    $LogFolder = "C:\Temp\uManage_Logs" # Log file directory
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify

    $Intro = "$MyName" # Program introduction
    $Decor = "="*$Intro.Length # Decoration string
    
    $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage
    
    $stack = New-Object System.Collections.Stack
    # create three arrays of queries, one for temp conditions, one for includes and one for excludes
    $xpath = @()
    $AndBucket = @()
    $OrBucket = @()

    $ADict  = @{
        samAccountName="AccountName";
        title="JobTitle";
        employeeType="EmployeeType";
        mail="Email";
        l="City";
        physicalDeliveryOfficeName="Country";
        ou="supervisoryOrganization";
        "Companyx-job-level"="Companyx-Job-Level";
        "Companyx-job-family"="Companyx-job-family";
        "Companyx-job-family-group"="Companyx-Job-Family-Group";
    }

    $obj = 0
    foreach ($RuleQuery in $Conditions) {
        # parse chars in RuleQuery string
        # Determine object type (string vs ARSConditionList)
        if ($RuleQuery.RuleQuery -and $RuleQuery.RuleType) {
            Write-Log "Converting ARS Condition List to Xpath..."
            $RuleQuery = $RuleQuery.RuleQuery
            $RuleType = $RuleQuery.RuleType
        }

        # translate AD attribute names to MIM attribute names using dictionary file
        Select-String '\([^!][-_\w]*[!=<>]+' -input $RuleQuery -AllMatches | Foreach {
            for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
                $ThisMatch = $_.matches[$MatchNum]
               
                if ($ThisMatch -match "!") {
                    $ThisMatch = $ThisMatch.ToString().Split("(")[1].Split("!")[0]
                } elseif ($ThisMatch -match ">") {
                    $ThisMatch = $ThisMatch.ToString().Split("(")[1].Split(">")[0]
                } elseif ($ThisMatch -match "<") {
                    $ThisMatch = $ThisMatch.ToString().Split("(")[1].Split("<")[0]
                } elseif ($ThisMatch -match "=") {
                    $ThisMatch = $ThisMatch.ToString().Split("(")[1].Split("=")[0]
                }

                if ($ThisMatch -in $ADict.Keys) {
                    $RuleQuery = $RuleQuery -Replace "\($ThisMatch","($($Adict[$ThisMatch])"
                }
            }
        }

        # Initialize the result array
        $xpath += ""
        
        $char=0
        while ($char -lt $RuleQuery.length) {
            # we need to push paren nests, ands, and ors to the stack
            # when an open paren is found, it is added to the expression
            # and the opposing paren is pushed to the stack
            if ($RuleQuery[$char] -eq '(') { 
                $xpath[$obj] += '('
                $stack.push(')')
            # each subsequent char gets appended, unless '!', '&', '|', or ')'
            # '!'s get translated to 'not'
            } elseif ($RuleQuery[$char] -eq '!') {
                $xpath[$obj] += 'not'
            # '&'s and '|'s get pushed to the stack for later use
            } elseif ($RuleQuery[$char] -in ('&', '|') -and $RuleQuery[$char-1] -eq '(') {
                $stack.push($RuleQuery[$char])
            # when a paren closes, we need to handle the stack to rewrite the notation
            } elseif ($RuleQuery[$char] -eq ')' -and $stack.peek()) {
                # first pop of the ')' from the stack and append it to the expression
                $xpath[$obj] += $stack.pop()
                # if there is a new paren starting, with an '&' on the stack,
                # it must be inserted, and stored for later potential use
                if ($RuleQuery[$char+1] -eq '(') {
                    if ($stack.peek() -eq '&') {
                        $xpath[$obj] += ' and '
                    } elseif ($stack.peek() -eq '|') {
                        $xpath[$obj] += ' or '
                    }
                # if the enclosing paren is also closing, we must pop and discard
                # the conditional on the top of the stack
                } elseif ($RuleQuery[$char+1] -eq ')') {
                    if ($stack.peek() -eq '&') {
                        $stack.pop() | out-null
                    } elseif ($stack.peek() -eq '|') {
                        $stack.pop() | out-null
                    }
                }
            # otherwise, just append the next char to the expression
            } else {
                $xpath[$obj] += $RuleQuery[$char]
            }
            $char++
        }
        
        # Add the current condition to either the include or exclude condition array
        # We need to string them together using 'and' and 'or' as appropriate
        if ($RuleType -like "Include*") {
            $OrBucket += $xpath[$obj]
        } elseif ($RuleType -like "Exclude*") {
            $AndBucket += $xpath[$obj]
        }

        $obj++
    }

    If ($AndBucket -or $OrBucket) {
        $AndBucket = ParseARSAttribs($AndBucket)
        $OrBucket = ParseARSAttribs($OrBucket)
        if($Verbose) { Write-Log "AndBucket: $AndBucket" }
        if($Verbose) { Write-Log "OrBucket: $OrBucket" }
    } Else {
        $xpath = ParseARSAttribs($xpath)
        if($Verbose) { Write-Log "xpath: $xpath" }
    }

    # Logic to rearrange the conditions list in a logical order: ((!C and !P and !G) and (C or P or G))
    # encapsulate each condition in the list with a parenthesis
    $xpathFinal = "/Person["   # This encapsulates the entire xpath statement
    
    If ($AndBucket -or $OrBucket) {
        # If there are multiple condition types to parse, we encapsulate them and append ' and ' in between
        if (($AndBucket) -and ($OrBucket)) {
            $xpathFinal += "("
        }

        $ConditionNum = 0
        foreach ($Condition in $AndBucket) {
            # If there's only one exclude condition, append it to the final xpath expression
            if ($Condition -ne "") {
                if ($Verbose) { Write-Log "Now Processing AndBucket Condition #$ConditionNum of $($AndBucket.length) : $Condition #(Skips empty conditions)" }
                if ($AndBucket.length -eq 1 -or $ConditionNum -eq $AndBucket.length-1) {
                    $xpathFinal += $Condition
                # Else add a '(' to the beginning, ' or ' in between each, and ')' to the end
                } else {
                    $xpathFinal += "$Condition and "
                }
            }
            $ConditionNum++
        }

        # If there are multiple condition types to parse, we encapsulate them append ' and ' in between
        if (($AndBucket) -and ($OrBucket)) {
            $xpathFinal += ") and ("
        }

        $ConditionNum = 0
        foreach ($Condition in $OrBucket) {
            # If there's only one exclude condition, append it to the final xpath expression
            if ($Condition -ne "") {
                if ($Verbose) { Write-Log "Now Processing OrBucket Condition #$ConditionNum of $($OrBucket.length) : $Condition #(Skips empty conditions)" }
                if ($OrBucket.length -eq 1 -or $ConditionNum -eq $OrBucket.length-1) {
                    $xpathFinal += $Condition
                # Else add a '(' to the beginning, ' or ' in between each, and ')' to the end
                } else {
                    $xpathFinal += "$Condition or "
                }
            }
            $ConditionNum++
        }
        # If there are multiple condition types to parse, we encapsulate them append ' and ' in between
        if (($AndBucket) -and ($OrBucket)) {
            $xpathFinal += ")"
        }
    } ElseIf ($xpath) {
        if ($xpath.count -gt 1) {
            $xpathFinal += "("
        }

        $ConditionNum = 0
        foreach ($Condition in $xpath) {
            # If there's only one exclude condition, append it to the final xpath expression
            if ($Condition -ne "") {
                Write-Log "Now Processing Condition #$ConditionNum of $($AndBucket.length) : $Condition #(Skips empty conditions)"
                if (($xpath.length -eq 1) -or ($ConditionNum -eq $xpath.length-1)) {
                    $xpathFinal += $Condition
                # Else add a '(' to the beginning, ' or ' in between each, and ')' to the end
                } else {
                    $xpathFinal += "$Condition and "
                }
            }
            $ConditionNum++
        }
    
        if ($xpath.count -gt 1) {
            $xpathFinal += ")"
        }
    }

    # close the encapsulation for the entire statement and return
    $xpathFinal += ']'


    # '(ObjectID = /Group[ObjectID=OID]/ComputedMember)'
    Select-String '\(memberof=CN=[\w\s\d_,.=-]*[\w\s\d,_-]*\)' -InputObject $xpathFinal -AllMatches -ErrorAction SilentlyContinue | 
        % {
            for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
                $ThisMatch = $_.matches[$MatchNum]
                $ThisMatch = $ThisMatch.ToString().Split("=")[2].Split(",")[0]
                #$ThisCondition = "(ObjectID = /Group[ObjectID = `"$($Qdict["$ThisMatch"])`"]/ComputedMember)"
                $ThisCondition = "(ObjectID = /Group[AccountName = `"$ThisMatch`"]/ComputedMember)"
                $xpathFinal = $xpathFinal -Replace "\(memberof=CN=$ThisMatch[\w\s\d_,.=-]*\)", $ThisCondition # memberof = CN
            }
        }

    #special handling for 'Disabled = True' and 'AccountName = "<dn>"'
    $xpathFinal = $xpathFinal -Replace 'ObjectID = /Group\[AccountName = "locked-users"\]/ComputedMember','Disabled = True'
    $xpathFinal = $xpathFinal -Replace 'ObjectID = /Group\[AccountName = "deprovisioned-users"\]/ComputedMember','Disabled = True'
    $xpathFinal = $xpathFinal -Replace 'ObjectID = /Group\[AccountName = "All_Disabled_Users"\]/ComputedMember','Disabled = True'
    $xpathFinal = $xpathFinal -Replace '\(distinguishedName=CN=([\w\s\d_,.-]*)[\w\s\d_,.-]*\)','(AccountName = "$1")'

    # replace ldap set notation with xpath notation
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=(TRUE|FALSE)\)','($1 = "$2")' # (attr = TRUE|FALSE)
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=([\*]{1})\)','(starts-with($1,"$2"))' # (attr=*)   
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=[\*]([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*\)','(ends-with($1,"$2"))' # (attr = *value) == (ends-with(attr,value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*[\*]?\)','(starts-with($1,"$2"))' # (attr = value*) == (starts-with(attr,value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=[\*]([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*[\*]\)','(starts-with($1,"%$2"))' # (attr = *value*) == (starts-with(attr,%value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)[^<>]=([\d]*)\)','($1 = $2)' # attr = value
    $xpathFinal = $xpathFinal -Replace '&','&amp;'
    $xpathFinal = $xpathFinal -Replace '\*','%'

    $xpathFinal = CleanLogicOperators $xpathFinal
    
    return $xpathFinal
}


Export-ModuleMember -Function Convert-LdapToXpath

