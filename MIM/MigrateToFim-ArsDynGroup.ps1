Param(
    [string]$InputFile,
    [string]$Identity,
    [switch]$NewGroup,
    [switch]$Verbose,
    [switch]$Test,
    [switch]$ShowFilters,
    [string]$ApplyFilter,
    [switch]$Help
)

$HelpDoc = "<#
    MigrateToFim-ArsDynGroup.ps1
        Powershell Script By Ava C and Chris Ladino

    Description:
        Powershell script to migrate ARS dynamic groups into FIM dynamic groups. Accepts as input a text or csv file containing a list of (new-line separated) dynamic groups

    Usage:
        MigrateToFim-ArsDynGroup.ps1 -InputFile <Filepath> [-Test] [-Verbose]   # Basic syntax structure
        MigrateToFim-ArsDynGroup.ps1 -InputFile <Filepath>                      # Migrate a list of dynamic groups
        MigrateToFim-ArsDynGroup.ps1 -InputFile <Filepath> -Test                # Test the migration of a list of dynamic groups
        MigrateToFim-ArsDynGroup.ps1 -InputFile <Filepath> -Verbose             # Migrate a list of dynamic groups with verbose reporting enabled
        MigrateToFim-ArsDynGroup.ps1 -InputFile <Filepath> -Test -Verbose       # Test the migration of a list of dynamic groups with verbose reporting enabled
#>"

$LogFolder = "C:\Repository\logs"
$LibFolder = "C:\Repository\lib"

$LogFile = "$LogFolder\$(($MyInvocation.MyCommand.Name).split(".")[0])_$(Get-Date -Format FileDateTime).log"

Function LogInfo ($Message) {
    $now = (date)
    $ThisMsg = "$now : $Message"
    write-host $ThisMsg
    echo $ThisMsg >> $LogFile
}

try { Import-Module FIMService } catch { LogInfo "Error occurred: Module 'FIMService' not found." ; exit }
try { Import-Module ActiveDirectory } catch { LogInfo "Error occurred: Module 'ActiveDirectory' not found." ; exit }

Function ConvertARStoLDAP($DGConditionlist) {
    $array=@()

    if ($Verbose) {
        LogInfo "Condition list passed to ConvertARStoLDAP function:"
        foreach ($ThisCondition in $DGConditionlist) { LogInfo "`t$ThisCondition" }
    }

    # Some group queries have '\3d' instead of '=', etc
    $DGConditionlist = $DGConditionlist.replace('\3d','=').replace('\28','(').replace('\29',')')

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
            LogInfo "Array of length $($array.length) passed back from ConvertARStoLDAP function:"
            foreach ($obj in $array) { LogInfo "`t$obj" }
        }

    return $array
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
        if ($Verbose) { LogInfo "Parsing ARS attribs from condition: $Condition" }
        
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

        if ($Verbose) { LogInfo "Resulting condition: $Condition" }
    }

    if ($Verbose) { LogInfo "Resulting query: $RetQuery"}

    return $RetQuery
}

Function ConvertLDAPtoXPATH ($ConditionsList) {
    $stack = New-Object System.Collections.Stack

    # create three arrays of queries, one for temp conditions, one for includes and one for excludes
    $xpath = @()
    $AndBucket = @()
    $OrBucket = @()

    $obj = 0
    foreach ($Object in $ConditionsList) {
        # parse chars in RuleQuery string
        $RuleQuery = $Object.RuleQuery

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
        if ($Object.RuleType -like "Include*") {
            $OrBucket += $xpath[$obj]
        } elseif ($Object.RuleType -like "Exclude*") {
            $AndBucket += $xpath[$obj]
        }

        $obj++
    }

    $AndBucket = ParseARSAttribs($AndBucket)
    $OrBucket = ParseARSAttribs($OrBucket)

    if($Verbose) { LogInfo "AndBucket: $AndBucket" }
    if($Verbose) { LogInfo "OrBucket: $OrBucket" }

    # Logic to rearrange the conditions list in a logical order: ((!C and !P and !G) and (C or P or G))
    # encapsulate each condition in the list with a parenthesis
    $xpathFinal = "/Person["   # This encapsulates the entire xpath statement

    # If there are multiple condition types to parse, we encapsulate them and append ' and ' in between
    if (($AndBucket) -and ($OrBucket)) {
        $xpathFinal += "("
    }

    $ConditionNum = 0
    foreach ($Condition in $AndBucket) {
        # If there's only one exclude condition, append it to the final xpath expression
        if ($Condition -ne "") {
            if ($Verbose) { LogInfo "Now Processing AndBucket Condition #$ConditionNum of $($AndBucket.length) : $Condition #(Skips empty conditions)" }
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
            if ($Verbose) { LogInfo "Now Processing OrBucket Condition #$ConditionNum of $($OrBucket.length) : $Condition #(Skips empty conditions)" }
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

    # close the encapsulation for the entire statement and return
    $xpathFinal += ']'

    # '(ObjectID = /Group[ObjectID=OID]/ComputedMember)'
    Select-String '\(memberof=CN=[\w\s\d-_]*[\w\s\d,-_]*\)' -input $xpathFinal -AllMatches | Foreach {
        for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
            $ThisMatch = $_.matches[$MatchNum]
            $ThisMatch = $ThisMatch.ToString().Split("=")[2].Split(",")[0]
            $ThisCondition = "(ObjectID = /Group[ObjectID = `"$($Qdict["$ThisMatch"])`"]/ComputedMember)"
            $xpathFinal = $xpathFinal -Replace "\(memberof=CN=$ThisMatch[\w\s\d,-_]*\)", $ThisCondition # memberof = CN
        }
    }

    #special handling for 'Disabled = True' and 'AccountName = "<dn>"'
    $xpathFinal = $xpathFinal -Replace 'ObjectID = /Group\[ObjectID = "93cd0621-b751-4100-a26b-c4dacbfe3453"\]/ComputedMember','Disabled = True'
    $xpathFinal = $xpathFinal -Replace '\(distinguishedName=CN=([\w\s\d-_]*)[\w\s\d,-_]*\)','(AccountName = "$1")'

    # replace ldap set notation with xpath notation
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=(TRUE|FALSE)\)','($1 = "$2")' # (attr = TRUE|FALSE)
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=([\*])\)','(starts-with($1,"$2"))' # (attr=*)   
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=[\*]([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*\)','(ends-with($1,"$2"))' # (attr = *value) == (ends-with(attr,value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*[\*]?\)','(starts-with($1,"$2"))' # (attr = value*) == (starts-with(attr,value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)=[\*]([-\/_&@=,.\w\s]*(\([-\/_&@=,.\w\s]*\))*[-\/_&@=,.\w\s]*)[^\*\)]*[\*]\)','(starts-with($1,"%$2"))' # (attr = *value*) == (starts-with(attr,%value))
    $xpathFinal = $xpathFinal -Replace '\(([-_\w]*)[^<>]=([\d]*)\)','($1 = $2)' # attr = value
    $xpathFinal = $xpathFinal -Replace '&','&amp;'
    $xpathFinal = $xpathFinal -Replace '\*','%'
    
    return $xpathFinal
}

Function TrimXPATHParentheses ($XpathFinal) {
    $stack = New-Object System.Collections.Stack
    $removes = New-Object System.Collections.Stack
    $XpathFinalTrimmed = $XpathFinal
    $content = $false
    $extra = 0
    $char = 0

    while ($char -lt $XpathFinal.Length) {
        # check each character in the filter string in order
        # example filter string: (((starts-with(stuff,stuff)) and (ends-with(stuff,stuff))))
        # if it's an open-paren...
        if ($XpathFinal[$char] -eq '(') {
            # if content boolean is false and stack.peek is open-paren, increment the extra index
            if (!$content -and $stack.Count) { $extra++; }
            # add the open-paren to a stack of dicts
            $stack.Push($char)
        # else if it's a close-paren...
        } elseif ($XpathFinal[$char] -eq ')') {
            # if content boolean is true, set it to false
            if ($content) {
                $content = $false
            # else if content boolean is false, and extra index is greater than 0...
            } elseif (!$content -and ($extra -gt 0)) {
                # new xpath is set to old xpath minus chars at indexes of stack.pop/peek().key and $char
                $removes.Push($stack.Peek())
                $removes.Push($char)
                # decrement the extra index
                $extra--
            }
            # pop the stack
            $stack.Pop() | out-null
        # else (if it's not an open- or close-paren), set content boolean to true
        } elseif ($stack.Count) { $content = $true }
        $char++
        write-host "index: $char`tchar: $($XpathFinalTrimmed[$char])`tcontent: $content`textra: $extra"
    }
    #Write-Host $XpathFinalTrimmed
    while ($removes.Count) { $XpathFinalTrimmed = $XpathFinalTrimmed.Remove($removes.Pop(),1) }
    echo $XpathFinalTrimmed
}

Function Main {
    try {
        if ($Help) {
            echo $HelpDoc
        } else {
            if ($Verbose) { LogInfo "Script starting, logging in $LogFile" }
            # Get the input file, and get the dictionaries for the query groups and attribute names
            if ($Identity) {
                $Groups = @($Identity)
            } else {
                $Groups = get-content $InputFile
            }
            $DDict  = ((get-content "$LibFolder\DictDynGroups.csv") -replace ",","=") -join "`n" | convertfrom-stringdata
            $QDict  = ((get-content "$LibFolder\DictQueryGroups.csv") -replace ",","=") -join "`n" | convertfrom-stringdata
            $ADict  = ((get-content "$LibFolder\DictAttribNames.csv") -replace ",","=") -join "`n" | convertfrom-stringdata

            # Set the FIM service URI and authentication data
            #if (!$Cred) { $Cred = Get-Credential domain\account }
            $paramFIMService = @{}
            $paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
            if ($Cred) { $paramFIMService["Credential"] = $Cred } 

            # Perform the migration operations on each group listed in the input file
            foreach($Group in $Groups) {
                if ($Group) {
                    try {
                        #echo ""
                        if ($Verbose) {
                            if ($Test) {
                                LogInfo "Testing group $Group..."
                            } elseif ($ShowFilters) {
                                LogInfo "Getting filters for group $Group"
                            } else {
                                LogInfo "Migrating group $Group..."
                            }
                        }

                        # Get ARS dynamic group with edsadgconditionslist
                        try {
                            $Group = get-qadgroup $Group -Dynamic $true -Proxy -service site1-ars-app01 -IncludedProperties edsadgconditionslist 2>>$LogFile
                            $ARSMembers = ($Group.Members | ? {$_ -notmatch 'OU=Groups' -and $_ -notmatch 'OU=Disabled'} |measure).count
                            if ($Verbose) {
                                LogInfo "Retrieved ARS group data."
                                LogInfo "Number of users in ARS group $Group : $ARSMembers"
                            }
                        } catch {
                            LogInfo "Error occurred: Failed to retrieve ARS group $Group."
                            continue
                        }

                        # Convert ARS format conditions list into standard LDAP, and convert that to XPATH for MIM
                        if (!$Test -and !$ShowFilters) {
                            try {
                                if ($ApplyFilter) {
                                    $XpathFinal = "/Person[$ApplyFilter]" 
                                    LoginFo "about to apply $xpathfinal"
                                } else {
                                    $ConditionsList = ConvertARStoLDAP $Group.edsadgconditionslist
                                    $XpathFinal = ConvertLDAPtoXPATH $ConditionsList
                                    #$XpathFinal = TrimXPATHParentheses $XpathFinal
                                }
                                
                                #$xpathFinal = '/Person[]'
                                LogInfo "Converted ARS conditions to XPATH."
                                # Cast the XPATH query into a FIM dialect filter
                                $FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpathFinal
                                if ($Verbose) { LogInfo "FIM Filter: $FIMFilter" }
                            } catch {
                                LogInfo "Error occurred: Failed to convert ARS conditions to XPATH query for $Group."
                                continue
                            }
                        } elseif ($ShowFilters) {
                             try {
                                $ConditionsList = ConvertARStoLDAP $Group.edsadgconditionslist
                                $XpathFinal = ConvertLDAPtoXPATH $ConditionsList
                                #$XpathFinal = TrimXPATHParentheses $XpathFinal
                                #$xpathFinal = '/Person[]'
                                # Cast the XPATH query into a FIM dialect filter
                                $FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $xpathFinal
                                echo "$Group`tFIM Filter: $FIMFilter"
                            } catch {
                                LogInfo "Error occurred: Failed to convert ARS conditions to XPATH query for $Group."
                                continue
                            }
                        }

                        if (!$Test -and !$ShowFilters) {
                            # Get the FIM resource object to prepare the dynamic group migration
                            try {
                                LogInfo "Importing FIM resource object for $($Group.SamAccountName)."
                                $FimGroup = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group.SamAccountName @paramFIMService 2>&1 | tee-object $LogFile -Append
                                $FimGroupData = $FimGroup | ConvertFrom-FIMResourceToObject 2>&1 | tee-object $LogFile -Append
                                # Generate the FIM object to call to the FIM service
                                if ($NewGroup) {
                                    # get owner and displayedowner from group
                                    # get OIDs
                                    # set Owner and DisplayOwner to the OID
                                    $OwnerOID = ($FimGroupData | select -ExpandProperty Owner).split(":")[2]
                                    $GroupEmail = $FimGroupData.Email

                                    if ($FimGroupData.ExplicitMember) {
                                        $FimGroup | Set-FIMResource -ImportChanges @(New-FIMImportChange "ExplicitMember" $FimGroupdata.ExplicitMember -ImportOperation Delete) @paramFIMService <#-ErrorAction "Stop"#> 2>&1 | tee-object $LogFile -Append
                                        LogInfo "Completed attempted deletion of Explicit Members from $Group."
                                    }
                                    $GroupType = $FimGroupData.Type
                                    if ($GroupType -eq "MailEnabledSecurity") {
                                        $TempGroupEmail = "Temporary_$GroupEmail"
                                    }

                                    $Importchanges = @(
                                        New-FIMImportChange "Filter" $FIMFilter
                                        New-FIMImportChange "MembershipLocked" $true
                                        New-FIMImportChange "MembershipAddWorkflow" "None"
    
                                        New-FIMImportChange "AccountName" "Temporary_$($Group.SamAccountName)"
                                        New-FIMImportChange "DisplayName" "Temporary_$($Group.SamAccountName)"
                                        New-FIMImportChange "Owner" $OwnerOID -ImportOperation Add
                                        New-FIMImportChange "DisplayedOwner" $OwnerOID
                                        New-FIMImportChange "Domain" "CORP"
                                        New-FIMImportChange "Scope" "Universal"
                                        New-FIMImportChange "Type" $GroupType
                                    )
                                    if ($TempGroupEmail) { $ImportChanges += (New-FIMImportChange "Email" $TempGroupEmail) <# "EMEA-Contract-Experts@company.com"#> }
                                    
                                    LogInfo $ImportChanges
                                    
                                } elseif ($FimGroupData.ExplicitMember) {
                                    $FimGroup | Set-FIMResource -ImportChanges @(New-FIMImportChange "ExplicitMember" $FimGroupdata.ExplicitMember -ImportOperation Delete) @paramFIMService <#-ErrorAction "Stop"#> 2>&1 | tee-object $LogFile -Append
                                    LogInfo "Completed attempted deletion of Explicit Members from $Group."
                                    $Importchanges = @(
                                        New-FIMImportChange "Filter" $FIMFilter
                                        New-FIMImportChange "MembershipLocked" $true
                                        New-FIMImportChange "MembershipAddWorkflow" "None"
                                    )
                                } else {
                                    $Importchanges = @(
                                        New-FIMImportChange "Filter" $FIMFilter
                                        New-FIMImportChange "MembershipLocked" $true
                                        New-FIMImportChange "MembershipAddWorkflow" "None"
                                    )
                                }

                            } catch {
                                LogInfo "Error occurred: Invalid FIM resource object for $($Group.SamAccountName)."
                                continue
                            }
                        } elseif ($Test) {
                            try {
                                LogInfo "Performing FIM XPATH query for $($Group.SamAccountName)."

                                # Query FIM based on groupname, assuming previous import already complete
                                if ($DDict[$Group.SamAccountName]) {
                                    $GroupOID = $($DDict[$Group.SamAccountName])
                                } else {
                                    LogInfo "Warning: $($Group.SamAccountName) not found in $LibFolder\DictDynGroups.csv, now retrieving via API"
                                    $MIMQuery = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group.SamAccountName @paramFIMService | ConvertFrom-FIMResourceToObject
                                    $GroupOID = $MIMQuery.ObjectID -replace "urn:uuid:",""
                                }
                                $XpathGroup = "(/Group[ObjectID = `"$GroupOID`"]/ComputedMember)"
                                $FimGroup = Get-FIMResource -XPathFilters $XpathGroup @paramFIMService # 2>&1 | tee-object $LogFile -Append
                                $FimGroup = $FimGroup | ConvertFrom-FIMResourceToObject # 2>&1 | tee-object $LogFile -Append
                                $FIMMembers = ( $FimGroup | ? { $_.disabled -eq "False" -and $_.ObjectType -eq "Person" } | measure ).count

                                if ($Verbose) { LogInfo "Number of users returned by FIM XPATH query for $Group : $FIMMembers" }
                                LogInfo "ARS MEMBERS: $ARSMembers`tFIM QUERY USERS: $FIMMembers"
                                if ($ARSMembers -eq $FIMMembers) {
                                    LogInfo "Test passed: Query returns the correct number of users."
                                } else {
                                    LogInfo "Test failed: Query returns the incorrect number of users."
                                }
                                LogInfo "Completed testing $($Group.SamAccountName)."
                            } catch {
                                LogInfo "Error occurred: Failed to perform FIM XPATH query for $($Group.SamAccountName)."
                                continue
                            }
                        }

                        # Migrate the group into FIM by importing the changes to the FIM resource
                        if (!$Test -and !$ShowFilters) {
                            try {
                                if ($NewGroup) {
                                    $GroupCopy = New-FIMImportObject -ObjectType Group -ImportState Create -ImportChanges $Importchanges
                                    #$GroupCopy = $GroupCopy | ConvertFrom-FIMResourceToObject
                                    $ImportFailure = $GroupCopy | Import-FIMResource @paramFIMService 2>>$LogFile
                                    
                                    if (!$ImportFailure) {
                                        $FimGroup | Remove-FIMResource -Confirm:$false @paramFIMService
                                        if ($TempGroupEmail) {
                                            Set-FIMResource -ObjectType Group -AttributeValues $GroupCopy.TargetObjectIdentifier -ImportChanges @(
                                                New-FIMImportChange "AccountName" $Group.SamAccountName
                                                New-FIMImportChange "DisplayName" $Group.SamAccountName
                                                New-FIMImportChange "Email" $GroupEmail 
                                            ) @paramFIMService
                                        } else {
                                            Set-FIMResource -ObjectType Group -AttributeValues $GroupCopy.TargetObjectIdentifier -ImportChanges @(
                                                New-FIMImportChange "AccountName" $Group.SamAccountName
                                                New-FIMImportChange "DisplayName" $Group.SamAccountName
                                            ) @paramFIMService
                                        }
                                    } else {
                                        LogInfo "Import Failure: $ImportFailure"
                                    }
                                } else {
                                    if ($Verbose) {
                                        $FimGroup | Set-FIMResource -ImportChanges $Importchanges @paramFIMService 2>&1 | tee $LogFile -Append
                                    } else {
                                        $FimGroup | Set-FIMResource -ImportChanges $Importchanges @paramFIMService -ErrorAction "Stop" 2>&1 | tee-object $LogFile -Append
                                    }
                                }
                                LogInfo "Attempted to import changes to FIM based on group conditions."
                                LogInfo "Completed attempted migration of $($Group.SamAccountName)."
                            } catch {
                                LogInfo "Error occurred: Failed to import changes for FIM resource $($Group.SamAccountName)."
                                continue
                            }
                        }
                    } catch {
                        LogInfo "Error occurred: Failed to process $Group! Please check manually."
                    }
                }
            }
        }
    } catch {
        LogInfo "Error occurred: Script failed!"
        echo $HelpDoc
    }
}

# Call main function
Main


