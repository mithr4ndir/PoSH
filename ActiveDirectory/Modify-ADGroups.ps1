$grabUsers=import-csv C:\Users\ChrisL\desktop\TSINFRA-8929\Input-GrabUsers.csv
$keepGrps=@("all_disabled_users","deprovisioned-users","code42","locked-users")
$finalGrps=@()
$logDate=Get-Date -Format yyyyMMdd-hhmm
$logfile = "\\site1-scripts01\c$\Repository\logs\Grab_Request\grab_user_script_$logDate.txt"
$date=(Get-date)
If (!(Test-Path $logfile)) {New-Item -ItemType File -Path $logfile}


Foreach ($user in $grabUsers.username) {
    Write-Output $date"__Processing $user..." | Out-File $logfile -Append
    $tempMemberSh=Get-aduser $user -pro memberof| select -ExpandProperty memberof| sort
    Write-Output $date"___$user's current membership list - no changes made, yet" | Out-File $logfile -Append
    $tempMemberSh | Out-File $logfile -Append
    $tempBuildList=$tempMemberSh 
    foreach ($grp in $keepGrps) {
        $tempBuildList=$tempBuildList | Select-String -NotMatch $grp
    }
    Write-Output $date"____Proposed removals are..." | Out-File $logfile -Append
    $tempBuildList | Out-File $logfile -Append
    If ($tempBuildList -is [object]) {
        Try {
            Write-Output $date"____Proceeding with removals..."| Out-File $logfile -Append
            Remove-ADPrincipalGroupMembership -Identity $user -MemberOf $tempBuildList.Line -Confirm:$false
        }
        Catch {
            Write-Output $date"____Issues trying to remove membership for $user - $($_.exception.message)"| Out-File $logfile -Append
        }
    }
    Else {
        Write-Output $date"____Nothing to remove for $user"| Out-File $logfile -Append
    }
    #Build list of groups that needs to be added if they dont currently exist already
    $tempAddList=@()
    foreach ($grp in $keepGrps) {
        $tempAddList+=$tempMemberSh | Select-String $grp
    }
    #Compare the values from $keepgrps and $tempaddlist so that you can get a list of missing groups that the users should have
    IF ($tempAddList -is [Object]) {
        $tempAddList=$tempAddList.matches.value
        $addGroupsList=Compare-Object $tempAddList $keepGrps
        IF ($addGroupsList -is [object]) {
            $addGroupsList=$addGroupsList.InputObject
            Write-Output $date"____Adding these groups this $user"| Out-File $logfile -Append
            $addGroupsList | Out-File $logfile -Append
            Add-ADPrincipalGroupMembership -Identity $user -MemberOf $addGroupsList
        }
        Else {
        Write-Output $date"____Nothing to add for $user, groups already found - line 44" | Out-File $logfile -Append
        }
    }
    Else {Write-Output $date"____Nothing to add for $user, groups already found - line 47" | Out-File $logfile -Append}
}