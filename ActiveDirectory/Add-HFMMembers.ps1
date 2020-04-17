$groupMembershipList = Import-csv .\AD_groups_mapped_data.csv
$LogFolder = "\\site1-scripts01\c$\Repository\logs\CreateGroups"
$MyName = "$Env:computername"
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"

Function Write-Log ($Message) {
        $ThisMsg = "[$MyName] $(Get-Date) : $Message"
        $ThisMsg | Out-File $LogFile -Append
        $ThisMsg
    }

Foreach ($user in $groupMembershipList) {
    Try {
        Write-Log "Processing $($user.username) for $($user.new_group_name)"
        Add-ADGroupMember $User.new_group_name -Members $user.username
    }
    Catch {
        Write-log "Cannot add $($user.username) due to this error - $($_.exception.message) "
    }
}
