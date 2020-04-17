<#
    MigrateToFim-ArsDynGroup
        Powershell Script By Ava C and Chris Ladino

    Description:

    Usage:

#>

Param(
    [string]$InputFile,
    [switch]$Verbose,
    [switch]$Test
)

Import-Module FIMService

Function ConvertFromARSFormat($DGConditionlist) {

#write-host $DGConditionlist

$array=@()

if ($Verbose) {
    write-host "Full condition list as passed to ConvertFromArs function:"
    foreach ($ThisCondition in $DGConditionlist) { write-host $ThisCondition }
}

# Some group queries have '\3d' instead of '=', etc
$DGConditionlist = $DGConditionlist.replace('\3d','=').replace('\28','(').replace('\29',')')

$conditions = $DGConditionlist.split("[")
    Foreach ($condition in $conditions)
    {
        If  ($condition -like "0x1*")
            {
            $0x1 = $condition.split(";")
            $ouGUID = $0x1[1]
            $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
            $LDAPSplit = $0x1.split("]")
            $LDAPQuery = $LDAPSplit[2]

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Include LDAP query"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value $LDAPQuery
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
            $array += $objTemp
            }
        If  ($condition -like "0x2*")
            {
            $0x2 = $condition.split(";")
            $ouGUID = $0x2[1]
            $ouDN = Get-ADObject $ouGUID | select -ExpandProperty Distinguishedname
            $LDAPSplit = $0x2.split("]")
            $LDAPQuery = $LDAPSplit[2]

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude LDAP query"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!$LDAPQuery)"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $ouDN
            $array += $objTemp

            }
        If  ($condition -like "0x3*")
            {
            $0x3 = $condition.split(";")
            $userGUID = $0x3[1]
            $userRule = Get-ADObject $userguid -Properties samaccountname

            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
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
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
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
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
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
            $objTemp | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $group.samaccountname
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleType" -Value "Exclude Members of Group"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleQuery" -Value "(!(memberof=$($groupRule.DistinguishedName)))"
            $objTemp | Add-Member -MemberType NoteProperty -Name "RuleScope" -Value $groupRule.distinguishedname
            $array += $objTemp
            }
    }

    if ($Verbose) { 
        write-host "Array of length $($array.length) being passed back from ConvertFromARS function:"
        foreach ($obj in $array) { write-host $obj }
    }

return $array
}

Function ConvertLDAPtoXPATH ($ConditionsList) {
    #echo "LtoX function, Condition list length = $($ConditionsList.length)"
    $stack = New-Object System.Collections.Stack

    # create three arrays of queries, one for temp conditions, one for includes and one for excludes
    $xpath = @()
    $AndBucket = @()
    $OrBucket = @()

    # (field = value) [ and (not(field = value)) ... ]

    # next test not necessary because the RuleQuery is already formed to include or exclude the condition?
    # if RuleType == ( Exclude Members of Group || Include Members of Group ||
        # Exclude [ User Explicitly? ] || Include [ User Explicitly ] ||
        # Exclude LDAP query || Include LDAP query )
    $obj = 0
    foreach ($Object in $ConditionsList) {
        # parse chars in RuleQuery string
        $RuleQuery = $Object.RuleQuery

        # translate AD attribute names to MIM attribute names
        <#$RuleQuery = $RuleQuery -Replace '\(l=','(City=' # The '=' might not be needed
        $RuleQuery = $RuleQuery -Replace '\(mail=','(email='
        $RuleQuery = $RuleQuery -Replace '\(sAMAccountName=','(AccountName='
        $RuleQuery = $RuleQuery -Replace '\(CompanyxJobProfile=','(JobTitle='
        $RuleQuery = $RuleQuery -Replace '\(ou=','(supervisoryOrganization='
        $RuleQuery = $RuleQuery -Replace '\(physicalDeliveryOfficeName=','(country='
        $RuleQuery = $RuleQuery -Replace '\(Companyx-job-level=','(Companyx-Job-Level='#>

        # translate AD attribute names to MIM attribute names using dictionary file
        Select-String '\(([-_\w]*)[!=]' -input $RuleQuery -AllMatches | Foreach {
            write-host "Got this far!"
            for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
                $ThisMatch = $_.matches[$MatchNum]
                write-host "Got even further: $($Adict[$ThisMatch])"
                if ($ThisMatch -in $ADict.Keys) {
                    write-host "Got even WOW further still: $($Adict[$ThisMatch])"
                    $RuleQuery = $RuleQuery -Replace "\($ThisMatch","($($Adict[$ThisMatch])"
                }
            }
        }

        # Initialize the result array
        $xpath += ""

        #if ($Object.RuleType -eq "Exclude LDAP query") { $xpath += '(not(' }

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

        # Replace redundant parens
        #$xpath[$obj] -Replace '\(\(([^()]*)\)\)','\($&\)'

        # Add the current condition to either the include or exclude condition array
        # We need to string them together using 'and' and 'or' as appropriate
        if ($Object.RuleType -like "Include*") {
            $OrBucket += $xpath[$obj]
        } elseif ($Object.RuleType -like "Exclude*") {
            $AndBucket += $xpath[$obj]
        }

        #if ($Object.RuleType -eq "Exclude LDAP query") { $xpath += '))' }

        #echo "Query built so far: $($xpath[$obj])`n`n"
        #echo "Current stack (should be empty): $($stack.peek())`n`n"
        $obj++
    }

    if($Verbose) { write-host "AndBucket: $AndBucket" }
    if($Verbose) { write-host "OrBucket: $OrBucket" }

    # Logic to rearrange the conditions list in a logical order: ((!C and !P and !G) and (C or P or G))
    # encapsulate each condition in the list with a parenthesis
    $xpathFinal = "/Person["   # This encapsulates the entire xpath statement

    # If there are multiple condition types to parse, we encapsulate them append ' and ' in between
    if (($AndBucket) -and ($OrBucket)) {
        $xpathFinal += "("
    }

    $ConditionNum = 0
    foreach ($Condition in $AndBucket) {
        if ($Verbose) { write-host "Now Processing AndBucket Condition #$ConditionNum of $($AndBucket.length) : $Condition" }
        # If there's only one exclude condition, append it to the final xpath expression
        if ($AndBucket.length -eq 1) {
            $xpathFinal += "($Condition)"
        # Else add a '(' to the beginning, ' or ' in between each, and ')' to the end
        } else {
            if ($ConditionNum -eq 0) {
                $xpathFinal += "($Condition and "
            } elseif ($ConditionNum -eq $AndBucket.length-1) {
                $xpathFinal += "$Condition)"
            } else {
                $xpathFinal += "$Condition and "
            }
        }
        $ConditionNum++
    }

    # If there are multiple condition types to parse, we encapsulate them append ' and ' in between
    if (($AndBucket) -and ($OrBucket)) {
        $xpathFinal += " and "
    }

    $ConditionNum = 0
    foreach ($Condition in $OrBucket) {
        if ($Verbose) { write-host "Now Processing OrBucket Condition #$ConditionNum of $($OrBucket.length) : $Condition" }
        # If there's only one exclude condition, append it to the final xpath expression
        if ($OrBucket.length -eq 1) {
            $xpathFinal += "($Condition)"
        # Else add a '(' to the beginning, ' or ' in between each, and ')' to the end
        } else {
            if ($ConditionNum -eq 0) {
                $xpathFinal += "($Condition or "
            } elseif ($ConditionNum -eq $OrBucket.length-1) {
                $xpathFinal += "$Condition)"
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

    # close the condition encapsulation paren
    # close the encapsulation for the entire statement and return
    $xpathFinal += ']'

    # remove unnecessary ARS conditions
    $xpathFinal = $xpathFinal.Replace("(((objectCategory=person) and (objectSid=*) and (not(sAMAccountType:1.2.840.113556.1.4.804:=3))) and (not(userAccountControl:1.2.840.113556.1.4.804:=2048))) and ","")
    $xpathFinal = $xpathFinal.Replace("((userAccountControl:1.2.840.113556.1.4.803:=2) and (objectClass=user))","")    
    $xpathFinal = $xpathFinal.Replace(" and (objectClass=user)","")
    $xpathFinal = $xpathFinal.Replace(" or ()","")
    $xpathFinal = $xpathFinal.Replace("((not())) and ","")

    # '(ObjectID = /Group[ObjectID=OID]/ComputedMember)'
    Select-String '\(memberof=CN=([\w\s\d-_]*)[\w\s\d,-_]*\)' -input $xpathFinal -AllMatches | Foreach {
        for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
            $ThisMatch = $_.matches[$MatchNum]
            $ThisMatch = $ThisMatch.ToString().Split("=")[2].Split(",")[0]
            #$ThisObjID = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $ThisMatch @paramFIMService
            #$ThisObjID = $ThisObjID | ConvertFrom-FIMResourceToObject
            #$ThisObjID = $ThisObjID.ObjectID.ToString().Replace("urn:uuid:","")
            #$ThisCondition = "(ObjectID = /Group[ObjectID = `"$ThisObjID`"]/ComputedMember)"
            $ThisCondition = "(ObjectID = /Group[ObjectID = `"$($ODict["$ThisMatch"])`"]/ComputedMember)"
            $xpathFinal = $xpathFinal -Replace "\(memberof=CN=$ThisMatch[\w\s\d,-_]*\)", $ThisCondition # memberof = CN
        }
    }

    #special handling for 'Disabled = True'
    $xpathFinal = $xpathFinal -Replace 'ObjectID = /Group\[ObjectID = "93cd0621-b751-4100-a26b-c4dacbfe3453"\]/ComputedMember','Disabled = True'

    # replace ldap set notation with xpath notation
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=([-_&\w\s]*)\)','(starts-with($1,"%$2"))' # (attr = value) ## what is the correct syntax???
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)=\*([-_&\w\s]*)\*','starts-with($1,"%$2")' # attr = *value*
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)=([-_&\w\s]*)\*','starts-with($1,"$2")' # attr = value*
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)=\*([-_&\w\s]*)','ends-with($1,"$2")' # attr = *value
    
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)[^<>]=[^\s]([-_&\w\s]*)','$1 = "$2"' # attr = value
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)<=([-_&\w\s]*)','$1 &lt;= $2' # attr <= value
    $xpathFinal = $xpathFinal -Replace '([-_\w]*)>=([-_&\w\s]*)','$1 &gt;= $2' # attr >= value

    return $xpathFinal
}

Function Main {
    $Groups = get-content $InputFile
    $ODict  =  ((get-content "C:\Repository\input\DictQueryGroups.csv") -replace ",","=") -join "`n" | convertfrom-stringdata
    $Adict  =  ((get-content "C:\Repository\input\DictAttribNames.csv") -replace ",","=") -join "`n" | convertfrom-stringdata

    #if (!$Cred) { $Cred = Get-Credential domain\account }
    $paramFIMService = @{}
    $paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
    if ($Cred) { $paramFIMService["Credential"] = $Cred } 

    foreach($Group in $Groups) {
        try {
            $group = get-qadgroup $group -Dynamic $true -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist 
        
            echo "`nNow processing group $group"

            $ConditionsList = ConvertFromARSFormat $Group.edsadgconditionslist
    
            <#if ($Verbose) {
                echo "ConditionsList of length $($ConditionsList.length) when passed to LtoX function: `n"
                foreach($ThisCondition in $ConditionsList){echo $ThisCondition}
            }#>

            $xpathFinal = ConvertLDAPtoXPATH $ConditionsList

            #if ($Verbose) { echo "Final conditionslist: `n$xpathFinal" }

            $FimGroup = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group.SamAccountName @paramFIMService
            $FimGroupdata = $FimGroup | ConvertFrom-FIMResourceToObject
            #$Fimrefgroup = (Get-FIMResource -XPathFilters '/Group[AccountName="l1-service-desk"]' @paramFIMService | ConvertFrom-FIMResourceToObject).ObjectID

            $FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpathFinal
        
            echo "FIM Filter: `n$FIMFilter" 

            if ($FimGroupdata.ExplicitMember) {
                $Importchanges = @(
                    New-FIMImportChange "Filter" $FIMFilter
                    New-FIMImportChange "MembershipLocked" $true
                    New-FIMImportChange "MembershipAddWorkflow" "None"
                    New-FIMImportChange "ExplicitMember" $FimGroupdata.ExplicitMember -ImportOperation Delete
                )
            } else {
                $Importchanges = @(
                    New-FIMImportChange "Filter" $FIMFilter
                    New-FIMImportChange "MembershipLocked" $true
                    New-FIMImportChange "MembershipAddWorkflow" "None"
                )
            }

            if (!$Test) { $FimGroup | Set-FIMResource -ImportChanges $Importchanges @paramFIMService - }   
            echo "Success."     
        } catch {
            echo "Failed to process $Group! Please check manually."
        }
    }
}

# Call main function
Main
