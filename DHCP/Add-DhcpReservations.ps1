<#
 
    Code Descripiton
    Name: Add-DhcpReservations

    This script pulls information from a csv to create dhcp reservations. A template of the script can be found on the Scirpts server at:
    //site1-scripts01/C$/repostiory/bin/input/DHCP_Reservations_Template.

#>

#Log Fuction
$LogFolder = "\\site1-scripts01\C$\Repository\logs"
$MyName = $MyInvocation.MyCommand.Name
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg | Out-File $LogFile -Append
    $ThisMsg
}

function Add-DhcpReservation {
    
    begin {

        Write-Log "Starting Add-DHCPReservations Function."

        #Users Prompts for variable
        $filePath = read-host -prompt "Enter the filepath to the CSV"
        Write-Log "CSV filepath entered as $filePath"

        #Local variables.
        $reservationList = import-csv -Path $filePath -Delimiter "," 
        
        #Conters
        $reservationsCreated = 0
        $reservationsFailed = 0

        #Clear errors. 
        if ($errors -is [object]) {
            $errors.clear()
        }
    }
    
    process {
        foreach( $reservation in $reservationlist ){ 
            Write-Log "Attempting reservation of $reservation"
            Try { 
                #If the value is null re-cycle loop. 
                if ($reservation.'MAC address' -eq $null ) { 
                    continue 
                } 
            
                $mac = ($reservation.'MAC address').replace( ":", "-") 
                Add-DhcpServerv4Reservation -ComputerName $reservation.'DHCP Server' `
                                            -ScopeId $reservation.'Scope ID' `
                                            -Description $reservation.'Description' `
                                            -IPAddress $reservation.'IP Address' `
                                            -Name $reservation.'Hostname' `
                                            -ClientId $mac `
                                            -Type Dhcp 
                $reservationsCreated ++
            }Catch{
                Write-Log "Error creating $reservation - $($_.Exception.Message)"
                $reservationsFailed ++
            }
        } 
    }
    
    end {
        Write-Log "$reservationsCreated reservations created"
        Write-Log "$reservationsFailed reservations not created"
        notepad $LogFile
    }
}




 
