$computer         = $ENV:Computername 
#$computer         = "site4-dhcp01" 

$instance         = "_total" 

@("\\$Computer\PhysicalDisk(*)\Current Disk Queue Length", 
  "\\$Computer\PhysicalDisk(*)\% Disk Time", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Read Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk Write Queue Length", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Transfer" 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Read", 
  "\\$Computer\PhysicalDisk(*)\Avg. Disk sec/Write") |% { 
    (Get-Counter $_.replace("*",$instance)).CounterSamples } | 
    Select-Object Path,CookedValue | 
    Format-Table -AutoSize 