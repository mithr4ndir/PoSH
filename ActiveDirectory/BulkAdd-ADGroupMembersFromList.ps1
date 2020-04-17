$groupMemberList = Import-csv .\desktop\AD_groups_mapped_data.csv
$grouped=$groupMemberList | Group-Object new_group_name | sort name
$LogFolder = "\\site1-scripts01\c$\Repository\logs\CreateGroups"
$MyName = "$Env:computername"
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"

Function Write-Log ($Message) {
        $ThisMsg = "[$MyName] $(Get-Date) : $Message"
        $ThisMsg | Out-File $LogFile -Append
        $ThisMsg
    }
Foreach ($item in $grouped) {
    $userArray=$item.group.username | sort -Unique
    Write-Log "MemberCount:$($($userArray | measure).count) GroupName:$($item.name) GroupMembers: `n$($userarray -join ",")"

    Foreach ($user in $userArray)
    {
        Try {
            Add-ADGroupMember $item.name -Members $user
        }
        Catch {
            Write-log "Cannot add $user to $($item.name) due to this error - $($_.exception.message)"
        }
    }
}