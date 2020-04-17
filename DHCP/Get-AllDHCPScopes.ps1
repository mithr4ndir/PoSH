#$DHCPServers = GC "c:\users\ChrisL\desktop\dhcpserversinDC-7-17-2016.txt"
#$ScopeErrorFile = "C:\Users\ChrisL\Desktop\TestScripts\HarnessDHCPScopes\logs\scope"
$DHCPServers = $Null
#$DHCPServers = "sfo3-dhcp01.corp.Companyx.com"
$DHCPServers = Get-DhcpServerInDC | Select dnsname
$OutputFile = "C:\Repository\output\allDHCPScopes.csv"
$Error.Clear()
If (Test-Path $OutputFile) 
    {
    Del $OutputFile
    }

Foreach ($DHCPServer in $DHCPServers.dnsname)

    {
    $TempVar = $null
    Write-host Processing... $DHCPServer
    #$DHCPServer | Out-file $OutputFile -Append -Force
    $DHCPScopes = Get-DhcpServerv4Scope -ComputerName $DHCPServer # | select name,description,scopeid | Out-file $OutputFile -force -Append
    Foreach ($Entry in $DHCPScopes)
        {
        $TempVar = $DHCPServer + "," + $Entry.Name + "," + $Entry.Description + "," + $Entry.ScopeID + "," + $Entry.State + "," + $Entry.LeaseDuration 
        #$Buffer = $TempVar + "," + $Entry
        Out-file -FilePath $OutputFile -Append -InputObject $TempVar #-Encoding ascii
        }
    $Buffer = $Null

   #$DHCPServer.ComputerName + $DHCPScopes.ScopeID.IPAddressToString
       
        <#Foreach ($DHCPScope in $DHCPScopes.ScopeID)
            {
            Write-host Processing $DHCPScope
            }
    <#$DHCPServer + $DHCPScopes | export-csv "C:\Users\ChrisL\Desktop\TestScripts\HarnessDHCPScopes\EntireScopeList.csv" -NoTypeInformation -Append - Force
    $Error | Out-File #>
    }