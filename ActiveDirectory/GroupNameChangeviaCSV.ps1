
#ImportCsv
$ADGroups = Import-CSV -path "C:\Users\rpatte-adm\Desktop\GroupName.csv"
$countNotExist=0
$countRefGrps=0
$grpsNotFound=@()
#ForEach loop that itterates thorugh each row and checks the groups uri 
ForEach ($Row in $ADGroups){
        If ($checkLabeleduri -is [object]) {Remove-Variable checkLabeleduri}
        $checkIfGroupExists=$null
        $temprowGrp=$row.OldName
        $checkIfGroupExists=get-adgroup -filter {samaccountname -eq $temprowGrp} 
        If ($checkIfGroupExists -is [Object]) {
            Write-Output "Processing $($row.oldname)"
            #Creates Variable with ADGroup object assigned via passed in old name. 
            $GroupName = $Row.("OldName")
            #$CurrentADGroup = Get-ADGroup -Filter "SamAccountName -eq '$GroupName'"
            $checkLabeleduri = Get-ADGroup -Filter {labeleduri -like "*$GroupName*"}
            if ($checkLabeleduri -is [Object]) {
                $countRefGrps++
                Write-Output "...group reference found - Total: $($checkLabeleduri.count)"
                Foreach ($grp in $checkLabeleduri) {
                    $tempLabeledURIGrp = $grp.labeleduri
                    $tempLabeledURIGrp = $tempLabeledURIGrp.replace("$($row.oldname)","$($row.newname)")
                    Write-Host "This would be the new labeleduri filter! $tempLabeledURIGrp" -BackgroundColor Yellow
                }
            }
            Else {Write-Output "Renaming $($row.oldname)"}
        }
        Else {
            $countNotExist++
            #$tempObj = New-Object psobject
            #$tempObj | Add-Member -MemberType NoteProperty -Name samaccountname -Value $
            $grpsNotFound += $row.OldName
        
        }
    
}


$grpsNotFound





#create seperate varabile for all groups that have a labeld uir filter.  Labeld uri like "*"

#Put those groups into an array. 


#Mim groups will take care of themselves 


#labedl uri groups need to get name and the filter being used. 