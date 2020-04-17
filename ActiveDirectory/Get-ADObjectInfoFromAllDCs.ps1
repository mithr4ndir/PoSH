#check against all domain controllers locked out status
[string]$accountQuery = "ChrisL"
$domainControllers = Get-ADDomainController -filter * | sort name | select -ExpandProperty name
$accountArrayQueries=@()
Workflow UnlockADAcc-AllDCs {
    Param ([string[]]$domainControllers
    )
    Foreach -Parallel ($dc in $domainControllers) {
    #(InlineScript {Write-host "Processing query against $dc..."})
    Unlock-ADAccount ChrisL
    }
}
UnlockADAcc-AllDCs -domainControllers $domainControllers -PSRunningTimeoutSec 600


Workflow Ptest {
    Param ([string[]]$domainControllers
    )
    Foreach -Parallel ($dc in $domainControllers) {
    #(InlineScript {Write-host "Processing query against $dc..."})
    $tempquery = Get-aduser ChrisL -pro lockedout,passwordlastset,lastlogon -server $dc | select samaccountname,lockedout,passwordlastset,@{N='LastLogon'; E={[DateTime]::FromFileTime($_.LastLogon)}}
    $tempQuery | Add-Member -MemberType NoteProperty -Name "Server" -Value "$dc"
    $tempquery
    }
}

$array=Ptest -domainControllers $domainControllers -PSRunningTimeoutSec 600 | select samaccountname,lockedout,passwordlastset,lastlogon,server
$array | sort server | ft 


#$accountArrayQueries