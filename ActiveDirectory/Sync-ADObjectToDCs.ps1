$DCSource = "site1-dc02.corp.Companyx.com"
$DCs = gc C:\repository\input\DCsToReplicateTo.txt

Foreach ($DC in $DCs)
    {
    Write-host "----------------------------------------------------------------------------------------- `r "
    Write-Host Currently processing $dc and checking for krbtgt -ForegroundColor Green
    Sync-ADObject -object "CN=krbtgt,CN=Users,DC=CORP,DC=Companyx,DC=COM" -source $dcsource -destination $dc -Verbose
    Get-ADUser krbtgt -pro passwordlastset | select passwordlastset
    Write-host "----------------------------------------------------------------------------------------- `r "
    }