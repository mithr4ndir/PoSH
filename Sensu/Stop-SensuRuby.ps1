#
# .SYNOPSIS - Kill all Sensu based ruby processes
# 

#$servers = gc C:\Users\ChrisL\desktop\killnodessensuclient.txt
$servers = "chi1-sw-agent01"
$session = New-PSSession -ComputerName $servers

#Kill the sensu based ruby process's found on targeted boxes
$Results = Invoke-Command -Session $session -ScriptBlock {
       #Local WMI Query for Ruby Process
       $a = gwmi win32_process -ComputerName localhost|select ProcessID,ParentProcessID,Name, @{l="Username";e={$_.getowner().user}},Path,executablepath,commandline | where {$_.commandline -like "*sensu-client*"} | where {$_.Name -eq "ruby.exe"}
       #If $a variable has matched process results kill the process
       If ($a -is[object])
        {
        Stop-Process -id $a.processid -force -PassThru
        }
       #Check if service is running, if so stop the service, otherwise start it
       If ((Get-service sensu-client).Status -eq "Running")
        {
        Stop-Service sensu-client -Force -PassThru
        }
       Start-Service sensu-client -PassThru
}
