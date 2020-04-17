$userstogroups = import-csv .\new-groups-users-owner.csv

$alltempcnarray = @()
$alltempsamarray = @()
$Usersnotprocessed = $null

    Foreach ($users in $userstogroups) 
        {

        $temparray = $users.users.split(",")
        $userarray = $temparray.Trim()
        Try   {
            Foreach ($user in $userarray)
                {
                <#$cn = Get-aduser -filter {cn -eq $user} -pro cn | select -ExpandProperty cn
                $tempcnarray = New-Object PSObject
                $tempcnarray | Add-Member -MemberType NoteProperty -Name cn -Value $cn
                $alltempcnarray += $tempcnarray
                $sam = get-aduser -filter {samaccountname -eq $user} | select -ExpandProperty samaccountname
                $tempsamarray = New-Object psobject
                $tempsamarray | add-member -MemberType NoteProperty -name sam -value $sam
                $alltempsamarray += $tempsamarray#>
                
                Add-ADGroupMember -Identity $users.newgroups -Members $user -Verbose -WhatIf -Server site1-dc01.corp.Companyx.com
                }
              }
        Catch {
              $ErrorMessage = $_.Exception.Message
              $FailedItem = $_.Exception.ItemName
              write-host "Error - here is the msg '$ErrorMessage'" -BackgroundColor red
              $Usersnotprocessed += $errormessage + "`n"
              }
    
        }
    



