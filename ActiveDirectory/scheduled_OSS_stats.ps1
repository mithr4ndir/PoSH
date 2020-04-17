#The purpose of this script is to obtain OSS upgrade stats
$allObj=@()
$pathFileName=Get-Date -Format yyy_MM_dd-HH_mm_ss
$logpath="\\site1-scripts01\c$\repository\logs\OSS\windows-os-stats-$pathFileName.csv"
$date=(get-date).AddDays(-30)
$servers=Get-ADComputer -Filter {operatingsystem -like "Windows*Server*" -and enabled -eq $true -and lastlogondate -gt $date} `
                          -SearchBase "OU=Servers,OU=Computers,$OUDomainPATH" `
                          -Properties operatingsystem,whencreated | select dnshostname,operatingsystem,whencreated
$dontUpgrade = gc \\site1-scripts01\c$\Repository\input\oss\cantupgrade.txt

Foreach ($server in $servers) {
    IF ($dontUpgrade -match $server.dnshostname) {
        WRITE-OUTPUT "$($server.dnshostname) - Server not upgradable - $($server.operatingsystem)"
        $tempobj = New-Object PSObject
        $tempobj | Add-Member NoteProperty -Name DNSHostname -Value "$($server.dnshostname)"
        $tempobj | Add-Member NoteProperty -Name OperatingSystem -Value "$($server.operatingsystem)"
        $tempobj | Add-Member NoteProperty -Name Whencreated -Value "$(Get-date -Date ($server.whencreated) -UFormat %s)"
        $tempobj | Add-Member NoteProperty -Name Upgradability -Value "Not Upgradable"
        $allObj += $tempobj
    } Elseif ($server.operatingsystem -like "Windows*Server*2012*" -and $dontUpgrade -notmatch $server.dnshostname) {
        WRITE-OUTPUT "$($server.dnshostname) Server upgradable - $($server.operatingsystem)"
        $tempobj = New-Object PSObject
        $tempobj | Add-Member NoteProperty -Name DNSHostname -Value "$($server.dnshostname)"
        $tempobj | Add-Member NoteProperty -Name OperatingSystem -Value "$($server.operatingsystem)"
        $tempobj | Add-Member NoteProperty -Name Whencreated -Value "$(Get-date -Date ($server.whencreated) -UFormat %s)"
        $tempobj | Add-Member NoteProperty -Name Upgradability -Value "Upgradable"
        $allObj += $tempobj
    } Elseif ($server.operatingsystem -like "Windows*Server*2016*" -and $dontUpgrade -notmatch $server.dnshostname) {
        WRITE-OUTPUT "$($server.dnshostname) Not Applicable - $($server.operatingsystem)"
        $tempobj = New-Object PSObject
        $tempobj | Add-Member NoteProperty -Name DNSHostname -Value "$($server.dnshostname)"
        $tempobj | Add-Member NoteProperty -Name OperatingSystem -Value "$($server.operatingsystem)"
        $tempobj | Add-Member NoteProperty -Name Whencreated -Value "$(Get-date -Date ($server.whencreated) -UFormat %s)"
        $tempobj | Add-Member NoteProperty -Name Upgradability -Value "Not applicable"
        $allObj += $tempobj
    }
}
#$serversJson=export-csv -InputObject $allObj

<#$serversJson=$serversJson.Replace("},","}")
$serversJson=$serversJson.Replace("[","")
$serversJson=$serversJson.Replace("]","")
$serversJson=$serversJson.Replace(" ","")
#>

# Save this for safe keeping - @{N='whencreated'; E={[TimeZone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($_.whencreated))}} 

$allObj | ?{$_.operatingsystem -notlike "*2016*"} | ? {$_.upgradability -notlike "not upgradable"}|? {$_.dnshostname -notlike "*-orl-*"} |? {$_.dnshostname -notlike "irn*"}| ? {$_.dnshostname -notlike "*-sccm-*"}|? {$_.dnshostname -notlike "cfi-*"} |? {$_.dnshostname -notlike "*-sage-*"} | Export-Csv $logpath -Encoding utf8 -append -NoTypeInformation