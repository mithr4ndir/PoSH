param
(
    $rb = "ou=workstations,ou=computers,ou=managed",
    $csvout = "bitlockerkeys.csv"
)

$rootDSE = (Get-ADRootDSE).defaultnamingcontext
$sb = $rb + "," + $rootDSE

$computers = Get-ADComputer -filter {(objectclass -eq 'computer') -and (operatingsystem -like "Windows*")} -prop Name -searchbase $sb

$results = Get-ADObject -filter {(objectclass -eq 'msfve-recoveryinformation')} -prop * -searchbase $sb
$export = @() 

foreach ($entry in $results)
{

    $buffer = New-Object -TypeName PsObject
    $computername = $entry.distinguishedname.Split(",")[1].replace("CN=",$null)  #this is the computername
    $child = $entry.CN
    $recoverykey = $entry.'msFVE-RecoveryPassword'
    $buffer | Add-Member -MemberType NoteProperty -Name Name -Value $computername
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerOn -Value "Yes" 
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerObject -Value $child
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerRecoveryPswd -Value $recoverykey
    $export += $buffer



}


$nokeys = Compare-Object -ReferenceObject $computers -DifferenceObject $export -Property Name |  ? { $_.SideIndicator -eq "<=" } #| %{Write-Host $_.Name }

foreach ($entry in $nokeys)
{
    $buffer = New-Object -TypeName PsObject
    $buffer | Add-Member -MemberType NoteProperty -Name Name -Value $entry.name
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerOn -Value "No" 
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerObject -Value " "
    $buffer | Add-Member -MemberType NoteProperty -Name BitlockerRecoveryPswd -Value " "
    $export += $buffer
   


}

$export | Export-Csv -Path $csvout -NoTypeInformation