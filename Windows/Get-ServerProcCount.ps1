$Servers = Get-Content C:\Repository\input\ListOfSQLServers.txt

ForEach ($Server in $Servers) 
            {
            Get-WmiObject win32_computersystem -computername $Server | Select Name,NumberOfProcessors
            }