Clear-Host

###############
##### PRE #####
###############

$ServerList = Get-DhcpServerInDC | Select DnsName #Get all DHCP servers from AD
$ServerList = $ServerList | ? {$_.dnsname -ne "cru1-dhcp01.corp.Companyx.com"}
$DomainName = (Get-ADDomain).NetBIOSName  
$Time = Get-Date -Format t 
$CurrDate = Get-Date -UFormat "%D" 
$array = @()
# Option to create transcript - change to $true to turn on.
$CreateTranscript = $false

# Start Transcript if $CreateTranscript variable above is set to $true.
if($CreateTranscript)
{
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if( -not (Test-Path ($scriptDir + "\Transcripts"))){New-Item -ItemType Directory -Path ($scriptDir + "\Transcripts")}
Start-Transcript -Path ($scriptDir + "\Transcripts\{0:yyyyMMdd}_Log.txt"  -f $(get-date)) -Append
}
 
# Import modules
Import-Module DhcpServer

################ 
##### MAIN ##### 
################ 

Foreach($Server in $ServerList.Dnsname)
    
    {
        #Write-host Processing $Server
        If (Test-connection $Server -Quiet) 
          {
              
              # Obtain all Scopes in $server variable
              $ScopeList = Get-DhcpServerv4Scope -ComputerName $Server

              # Enumurate all scopes found in $server
              ForEach($Scope in $ScopeList.ScopeID.IPAddressToString)
              {
                $Error.Clear()
                Write-Host Processing $Server for $Scope
                Try{
                      # Get DDNS Config and do a few checks; check dynamic updates, deletednsrronleaseexpiry, updatednsrrforolderclients, and nameprotection
                      $DNSDynamic = Get-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope

                            If (!($DNSDynamic.DynamicUpdates -eq "Always"))
                                {
                                Write-host "$scope not set with Dynamic DNS, enabling now..."
                                Set-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope -DynamicUpdates Always 
                                } 
                            
                            If (!($DNSDynamic.DeleteDnsRROnLeaseExpiry -eq $true))
                                {
                                Write-host "$scope not set with DeleteDnsRRonLeaseExpiry, setting now..."
                                Set-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope -DeleteDnsRROnLeaseExpiry $true 
                                }

                            If (!($DNSDynamic.UpdateDnsRRForOlderClients -eq $true))
                                {
                                Write-host "$scope not set with UpdateDnsRRForOlderClients, setting now..."
                                Set-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope -UpdateDnsRRForOlderClients $true
                                }

                            If (!($DNSDynamic.NameProtection -eq $false))
                                {
                                Write-host "$scope set with NameProtection, disabling now..."
                                Set-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope -NameProtection $false 
                                }
                      
                      # Verify that we have desired state
                      $MostRecentDNSConfig = Get-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scope

                      # Create temp array and dump to overall array report
                      $TempArray = New-Object -TypeName PSObject
                      $TempArray | Add-Member -MemberType NoteProperty -Name "Server" -Value "$server"
                      $TempArray | Add-Member -MemberType NoteProperty -Name "Scope" -Value "$scope"
                      $TempArray | Add-Member -MemberType NoteProperty -Name "DynamicUpdates" -Value "$($MostRecentDNSConfig.DynamicUpdates)"
                      $TempArray | Add-Member -MemberType NoteProperty -Name "DeleteDNSOnExpiry" -Value "$($MostRecentDNSConfig.DeleteDnsRROnLeaseExpiry)"
                      $TempArray | Add-Member -MemberType NoteProperty -Name "UpdateDNSOlderClients" -Value "$($MostRecentDNSConfig.UpdateDnsRRForOlderClients)"
                      $TempArray | Add-Member -MemberType NoteProperty -Name "NameProtection" -Value "$($MostRecentDNSConfig.NameProtection)"

                      $array += $TempArray

                   }
                         Catch{ 
                                 Write-host Error Processing $Scope for $Server -background red
                                 $error
                              }
              }
          }

          Else 
            {
            Write-host $server not pingable -BackgroundColor Red
            }
     }

$array | ogv
