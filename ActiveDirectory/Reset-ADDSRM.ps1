$Controllers = Get-ADDomainController -filter * | select -ExpandProperty hostname | sort

Foreach ($Controller in $Controllers)
    
    {
     Write-host "Attempting a ping to $Controller!" -BackgroundColor Blue   
        If ((Test-Connection $Controller -Count 2 -Quiet) -eq $true)
            {
            Write-host "Starting Job!" -BackgroundColor Blue
            Invoke-Command -ComputerName $Controller -ScriptBlock {ntdsutil "set dsrm password" "Sync from domain account dsrm-reset" quit quit}      
            }
        Else 
            {
            Write-host "$Controller is unpingable" -BackgroundColor Red -ForegroundColor White
            }
    }