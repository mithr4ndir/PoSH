$users=import-csv C:\users\ChrisL\desktop\TSINFRA-8929\Input-GrabUsers.csv
$cGroup="CN=code42,OU=Groups,$OUDomainPATH"
$rGroup="CN=employee,OU=Groups,$OUDomainPATH"

$option = [System.StringSplitOptions]::RemoveEmptyEntries
$separator="CN=",",OU="
$foundCount=0
$notInGroupCount=0
$usersNotFound=@()
$usersNotFoundCount=0
$errorsCount=0
$countRemovals=0
$countRemAttempt=0
$error.clear()

Foreach ($user in $users.username) {
    Try {
        $usermembership = get-aduser $user -pro memberof | select -exp memberof
        }
    Catch {
        IF ($_.categoryinfo.Category -eq "ObjectNotFound") {Write-host "This $user was not found" -BackgroundColor Red
            $tempObj = New-Object psobject
            $tempObj | Add-Member -MemberType NoteProperty -Name AccountName -Value $user
            $tempObj | Add-Member -MemberType NoteProperty -Name Error -Value "User not found in directory"
            $usersNotFound += $tempObj
            $usersNotFoundCount++
        }
        Else {Write-host "An error occurred - $($_.exeception.message)" -BackgroundColor DarkRed;$errorsCount++}
        }
    IF ($usermembership -contains $cGroup) {Write-host "$user is part of $cGroup" -BackgroundColor Black;$foundCount++}
    Else {Write-host "$user not part of $cGroup" -BackgroundColor Green;$notInGroupCount++}
    If ($usermembership -contains $rGroup) {Write-Host "$user is part of $rGroup, removing now...";Try {Remove-ADGroupMember -Identity employees -Members $user -Confirm:$false;$countRemovals++} Catch {Write-Host "Error for $user - $($_.exception.message);$countRemAttempt++"}}
    }

Write-host `n"Results" -BackgroundColor Green
Write-Host "------------------"`n
Write-Host "$usersNotFoundCount users not found in directory"
Write-Host "$foundCount found in $($cGroup.Split($separator,$option)[0])"
Write-host "$notfoundCount not in $($cGroup.Split($separator,$option)[0])"
Write-host "$errorsCount errors occurred"`n
Write-Host "Details on users not found" -BackgroundColor Green
Write-Host "------------------";$usersNotFound
Write-host `n"Removals from $rGroup - $countRemovals"
Write-host "Removal attemps from $rGroup - $countRemAttempt"

