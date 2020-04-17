$computer         = $ENV:Computername 
#$computer         = "site4-dhcp01" 

$instance         = "_total" 

@("\\$Computer\PhysicalDisk(*)\Current Disk Queue Length") |% { 
    (Get-Counter $_.replace("*",$instance)).CounterSamples } | 
    Select-Object Path,CookedValue | 
    Format-Table -AutoSize 

New-EventLog -LogName Application -Source "MyScript"
Write-EventLog -LogName Application -Source MyScript -Message "Hello World" -EventId 5