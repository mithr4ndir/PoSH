$ConfigPartdn=(Get-ADRootDSE).configurationNamingContext
$ServerList=Get-Adobject -searchbase $configpartDN -filter {(objectclass -eq 'dhcpclass') -and (name -ne 'dhcproot')} | ? {($_.name -notlike "cru1-*") -and ($_.name -notlike "*-atg-*") -and ($_.name -notlike "otto1-*") -and ($_.name -notlike "uhq1-*")}| select name | sort name
$Array=@()


Foreach ($server in $ServerList.name)

{
    $WSMAN = $null
    $WSMAN = Test-WSMan $server
    If ($WSMAN -contains "wsmid")
    {
    Write-host This Worked for $server
    }


    Else
    {
    Write-host This didnt work for $server
    }

}