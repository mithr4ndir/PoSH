$mnodes = Get-ADComputer -filter {Operatingsystem -like "Windows*Server*2012*" -and enabled -eq $true} -SearchBase "OU=Servers,OU=Computers,$OUDomainPATH" | select -ExpandProperty name | sort 
$mnodesesh | Remove-PSSession
Remove-Variable -Name mnodesesh
$mnodesesh = New-PSSession -ComputerName $mnodes
$App = 'SCCM'


$invokeSession = Invoke-Command -computer site1-admin01 -ScriptBlock {
$service=Get-service CcmExec
Remove-Variable service
If ((Test-Path  C:\Windows\ccmsetup\SCEPInstall.exe) -and ($service=Get-service MsMpSvc) -is [Object]) {Write-host "Uninstalling SCEP..."; Start-process -FilePath C:\Windows\ccmsetup\SCEPInstall.exe -ArgumentList "/u /s" | Wait-Process -Timeout 10 }
If (Test-Path) {}
If ((Test-Path C:\windows\ccmsetup\ccmsetup.exe) -and ($service=Get-service CcmExec) -is [Object]) {Write-Host "Uninstalling Configuration Manager...";}
If (!(Test-Path C:\windows\ccmsetup\ccmsetup.exe) -and ($service=get-service CcmExec) -is [Object]) {Write-host "Service exists but ccmsetup.exe not found";}
$tempobj = New-Object PSObject
$tempobj | Add-Member -MemberType NoteProperty -Name "Server" -Value "$($item.pscomputername)"
$tempobj | Add-Member -MemberType NoteProperty -Name "SCCMRebootLog" -Value "$item"
$ccmnotfound += $tempobj
}
} 



$allObjs = @()
Foreach ($item in $invokeSession) {
    $tempobj = New-Object PSObject
    $tempobj | Add-Member -MemberType NoteProperty -Name "Server" -Value "$($item.pscomputername)"
    $tempobj | Add-Member -MemberType NoteProperty -Name "SCCMRebootLog" -Value "$item"
    $allObjs += $tempobj
}
$allobjs | sort server



