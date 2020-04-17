function Get-Uniquesid()
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [string]$errorlog = "c:\temp\gid.txt",
        [System.Security.Principal.SecurityIdentifier]$sid
        
    )

$groups = Get-ADGroup -SearchBase "OU=CorpSSSD,OU=Groups,$OUDomainPATH" -filter * | Select-Object -ExpandProperty Name

Foreach ($group in $groups)
    {
    $Groupattr = get-adgroup -Identity $group -properties ObjectSid | Select-object -ExpandProperty ObjectSid
    $groupgid =  get-adgroup -Identity $group -properties gidnumber | Select-object -ExpandProperty gidnumber
    $groupvalue = $groupattr.value
    $Numa = $groupvalue.split("-")
    $gidnumber = $Numa[7]
        If ($groupgid -eq $null) {
        Set-ADGroup -Identity $group -Replace @{gidnumber = "$gidnumber"}
        } Else {
        $null 
        }
    }
}