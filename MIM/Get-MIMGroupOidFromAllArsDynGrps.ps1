

 #####     Script should be used for obtaining all ARS managed dynamic group samaccountnames and query each one for its MIM OID    ####
 #####     Script was developed to help with ARS - MIM Migration (For dynamic groups into criteria based groups                    ####


$ARSDynamicGrps=Get-QADGroup -Dynamic $true -Proxy -Service site1-ars-app01 | select -ExpandProperty samaccountname
$FilePath="C:\Repository\output\AllDynGrps_MIMOIDs.csv"
$FIMService=@{}
$FIMService["Uri"]="http://server:5725"
$MIMOIDArray=@()

foreach ($Group in $ARSDynamicGrps) {
    $MIMQuery = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $Group @FIMService | ConvertFrom-FIMResourceToObject
    $MIMOID = $MIMQuery.ObjectID -replace "urn:uuid:",""
    $OIDObj = New-Object PSObject
    $OIDObj | Add-Member -MemberType NoteProperty -Name GrpSamAccountName -Value $Group
    $OIDObj | Add-Member -MemberType NoteProperty -Name GrpMIMOID -Value $MIMOID
    $MIMOIDArray += $OIDObj
}

If (!(Test-Path $FilePath)) {$MIMOIDArray | export-csv -NoTypeInformation -Path $FilePath} ELSE {Remove-Item $FilePath ; $MIMOIDArray | export-csv -NoTypeInformation -Path $FilePath}

$Obj = $array | ? {$_.RuleType -like "*query*"} | ? {$_.RuleQuery -like "*memberof*"} | select -ExpandProperty RuleQuery

Select-String '\(memberof=CN=([\w\s\d-_]*)[\w\s\d,-_]*\)' -input $obj -AllMatches | Foreach {
    for ($MatchNum = 0; $MatchNum -lt $_.matches.length; $MatchNum++) {
        $ThisMatch = $_.matches[$MatchNum]
        $ThisMatch = $ThisMatch.ToString().Split("=")[2].Split(",")[0]
        $ThisMatch
    }
}
