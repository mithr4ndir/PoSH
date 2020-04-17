$memberServers = gc C:\users\ChrisL\desktop\removesensupuppet.txt
#$DomainDN = (Get-ADDomain).DistinguishedName
#$memberservers = Get-adcomputer -filter {operatingsystem -like "Windows Server 2012*" -and enabled -eq $true -and name -notlike "*-dc*"} -SearchBase "ou=servers,ou=computers,ou=managed,$DomainDN" -pro lastlogondate | select dnshostname,lastlogondate
#$memberservers = Get-adcomputer -filter {name -like "site1-admin01" -or name -like "site1-ChrisL01" -or name -like "site1-scripts01"} | select dnshostname


#####
$AppQuery = "*puppet*","*sensu*"
#####
$QueryArray = $null
#Enter PS Sessions
Remove-PSSession $s
$s = New-PSSession -ComputerName $memberServers

Foreach ($app in $AppQuery)
{
    $InvokeAppQuery = $null
    $InvokeAppQuery = Invoke-Command -Session $s -ScriptBlock {
                param(
                     $rAppQuery = $App
                     )
                Get-ItemProperty -Path HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | Sort displayname| ? {$_.displayname -like $rAppQuery}
                Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Displayname,DisplayVersion,UninstallString | sort displayname | ? {$_.displayname -like $rAppQuery}
                } -ArgumentList $App #,$AppQuery2

    $QueryArray += $InvokeAppQuery
                                                          
}

$QueryArray | sort pscomputername

Foreach ($query in $QueryArray)
    {
    Write-host "Processing application $($query.displayname) version $($query.displayversion) for $($query.pscomputername)" -BackgroundColor Yellow
    $fixeduninstall = $null
    IF ($query.uninstallstring -match "/I")
        {$fixeduninstall = $query.UninstallString -replace "/I","/X"
        }

    IF ($fixeduninstall -ne $null)
    {
    $InvokeFixedUninstall = Invoke-Command -Session $s -ScriptBlock {
                    param(
                         $rfixeduninstall = $fixeduninstall,
                         $rquery = $query
                         )

                    #IF($query.DisplayName -like "*sensu*"){
                    #net stop sensu-client
                    #Wait-Process -Timeout 5
                    $service = Get-WmiObject -Class Win32_Service -Filter "Name='sensu-client'"
                    $service.delete()
                    #cmd /c "sc delete sensu-client"}
                    #cmd /c "$rfixeduninstall /qn"

                    } -ArgumentList $fixeduninstall,$query
    }
    $InvokeAppUninstall = Invoke-Command -Session $s -ScriptBlock {
                    param(
                         $rquery = $query
                         )
                    cmd /c "$($rquery.uninstallstring) /qn"                 
                    } -ArgumentList $query

                    
    }


Invoke-Command -Session $s -ScriptBlock {
$service = get-service *sensu*

IF ($service -ne $null)
{

Write-host "$env:COMPUTERNAME has Sensu Client, status is $($service.status), rebooting..." -BackgroundColor Yellow
Restart-Computer -ComputerName localhost
#$service = Get-WmiObject -Class Win32_Service -Filter "Name='sensu-client'"
#$service.delete()

}
Else
    {Write-host "$env:COMPUTERNAME does not have sensu service so it will not restart" -BackgroundColor Black}
}


Invoke-Command -Session $s -ScriptBlock {get-service "*sensu*"}