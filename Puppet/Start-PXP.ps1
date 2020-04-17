[CmdletBinding()]
PARAM ( 
    [switch]$Help = $false,
    [switch]$Status = $false,
    [switch]$DCs = $false,
    [switch]$Nssm = $false,
    [string]$InFile,
    [string]$FQDN,
    [string]$Pattern
)

$HelpDoc = "<#
    Start-PXP.ps1 -- v1.5

	Use with Admin privileges for best results.

    Powershell script to start the puppet pxp-agent service on the Companyx Corp Domain Windows Server fleet
        Uses Set-Service by default, or Nssm if specified.

    Example Usage:

        Start-PXP.ps1 -Help # -- Prints Help document

        Start-PXP.ps1 # -- Start the service on the entire member fleet
        Start-PXP.ps1 -Nssm # -- Start the service on the entire member fleet, using nssm
        Start-PXP.ps1 -Status # -- Return the service status on the entire member fleet

        Start-PXP.ps1 -DCs # -- Start the service on all DCs in the Domain Controllers OU
        Start-PXP.ps1 -DCs -Nssm # -- Start the service on all DCs in the Domain Controllers OU, using nssm
        Start-PXP.ps1 -DCs -Status # -- Return the service status on all DCs in the Domain Controllers OU

        Start-PXP.ps1 -InFile <path-to-.txt> # -- Start the service given input file (a list of FQDNs)
        Start-PXP.ps1 -InFile <path-to-.txt> -Nssm # -- Start the service given input file (a list of FQDNs), using nssm
        Start-PXP.ps1 -InFile <path-to-.txt> -Status # -- Return the service status on input file (a list of FQDNs)

        Start-PXP.ps1 -Pattern <wildcard-enabled-string> # -- Start the service on machines matching the pattern
        Start-PXP.ps1 -Pattern <wildcard-enabled-string> -DCs # -- Start the service on machines matching the pattern

        Start-PXP.ps1 -Pattern <wildcard-enabled-string> -Nssm # -- Start the service on machines matching the pattern, using nssm
        Start-PXP.ps1 -Pattern <wildcard-enabled-string> -DCs -Nssm # -- Start the service on DCs matching the pattern, using nssm

        Start-PXP.ps1 -FQDN <FQDN> # -- Start the service on the machine matching the FQDN

#>"


Function GetInfo {
    Param(
        $SvrPool
    )

    $Info = Invoke-Command -ComputerName $SvrPool -ScriptBlock { Get-Service -Name pxp-agent -ErrorAction SilentlyContinue } -AsJob
    Wait-Job $Info -Timeout 60 | Out-Null
    $Info = Get-Job | Receive-Job

    echo $Info
    echo ""
    echo "Running PXP Agents:"
    $Running = $Info | where {$_.status -like "running"} | measure
    $Running = $Running.count
    echo $Running

    echo "Paused PXP Agents:"
    $Paused = $Info | where {$_.status -like "paused"} | measure
    $Paused = $Paused.count
    echo $Paused

    echo "Stopped PXP Agents:"
    $Stopped = $Info | where {$_.status -like "stopped"} | measure
    $Stopped = $Stopped.count
    echo $Stopped

    echo "Unreachable or missing PXP Agents:"
    $Unreach = $SvrPool | measure
    $Unreach = $Unreach.count
    $Unreach = $Unreach - ($Running + $Paused + $Stopped)
    echo $Unreach

}

Function StartPXP {
    Param(
        $SvrPool
    )
    Process{
       Try{
            while ($Continue -ne "y") {
                $Continue = Read-Host -Prompt "You are about to start the PXP-agent service on $($SvrPool.count) remote machines in $SB. Are you sure you want to continue? (y/n)" 
                if ($Continue-eq "n") {
                    echo 'Now exiting, run with -Status $true to get service status.'
                    exit
                }
            }

            $Session = New-PSSession -ComputerName $SvrPool

            if ($Nssm) {
                Invoke-Command -Session $Session -ScriptBlock {
                    if ((Get-Service -Name pxp-agent).status -like ("stopped" -or "paused")) {
                        puppet config set use_cached_catalog false --section agent
                        & "C:\Program Files\Puppet Labs\Puppet\service\nssm.exe" restart pxp-agent
                        puppet agent -t
                    }
                }
            } else {
                Invoke-Command -Session $Session -ScriptBlock {
                    if ((Get-Service -Name pxp-agent).status -like ("stopped" -or "paused")) {
                        puppet config set use_cached_catalog false --section agent
                        Restart-Service -Name pxp-agent
                        puppet agent -t
                    }
                }
            }
        } Catch {
            echo "Fatal error occurred in StartPXP function!"
            Break
        } Finally {
            Remove-PSSession -ComputerName $SvrPool -ErrorAction SilentlyContinue
        }
    } End{
        If(!$?){ # only execute if the function was not completely successful.
            echo ""
            echo "Non-fatal errors may have occurred in StartPXP function!"
        }
    }
 }

#----------------[ Main Execution ]----------------------------------------------------

# Script Execution goes here

Function Main{
    Process{
        Try{
            If ($Help) {
                Write-Host $HelpDoc
            } Else {
                $Corp = "DC=corp,DC=Companyx,DC=com"
                if ($DCs) {
                    $SB = "OU=Domain Controllers,$Corp"
                } else {
                    $SB = "OU=Servers,OU=Computers,OU=Managed,$Corp"            
                }

                $date = (get-date).AddDays(-30)

                if ($Infile) {
                    $SvrPool = Get-Content $InFile
                    foreach ($SvrName in $SvrPool) {
                        $SvrName = Get-ADComputer -filter {DNSHostname -eq $SvrName -and operatingsystem -like "windows*server*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase $SB |
                            select -ExpandProperty DNSHostname
                    }
                } elseif ($FQDN) {
                    $SvrPool = @(Get-ADComputer -filter {DNSHostName -eq $FQDN -and operatingsystem -like "windows*server*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase $SB |
                    select -ExpandProperty DNSHostname)
                } elseif ($Pattern) {
                    $SvrPool = Get-ADComputer -filter {name -like $Pattern -and operatingsystem -like "windows*server*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase $SB |
                        select -ExpandProperty DNSHostname
                } else {
                    $SvrPool = Get-ADComputer -filter {name -like "*" -and operatingsystem -like "windows*server*" -and enabled -eq $true -and lastlogondate -gt $date} -SearchBase $SB |
                        select -ExpandProperty DNSHostname            
                }

                $Now = Get-Date -Format "yyyyMMddhhmmss" 
                If (!$Status) {
                    echo $SvrPool
                    StartPXP -SvrPool $SvrPool <#| Out-File -Append "%__CD__%\PXPResults_$Now.txt"#> 2>&1
                }
                GetInfo -SvrPool $SvrPool <#| Out-File -Append "%__CD__%\PXPResults_$Now.txt"#> 2>&1
            }
        } Catch{
            echo "Fatal error occurred in main function!"
            Break
        }
    } End{
        If(!$?){ # only execute if the function was not successful.
            echo "Non-fatal errors may have occurred in main function!"
        }
    }
}


# Invoke main function
Main