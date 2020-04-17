$DomainDN = (Get-ADDomain).DistinguishedName
#membberservers will include any domain joined servers found within the domain that live within the Servers OU. Lastlogondate is also included for each computer class object, which is good for troubleshooting possible scenarios where a server was unreachable due to it either being stale within the directory
$alldcs = Get-adcomputer -filter {operatingsystem -like "Windows Server*" -and enabled -eq $true} -SearchBase "OU=ATG,OU=Servers,OU=Computers,OU=Managed,$DomainDN" -pro lastlogondate | select dnshostname

    $alldchosts = $alldcs.DNSHostname

         foreach($dchost in $alldchosts)
            {
            $software = get-ciminstance -computername $dchost -ClassName win32_product
                if($software.Name -like "*duo*")
                    {
                    $duoinstalledhosts = $dchost
                    Write-output "******The $dchost has duo installed*****"
                    
                    } 
                    Else {
                            $duonotinstalledhosts = $dchost
                            Write-output "The $dchost does not have duo installed"
                           
                         }

            } 

        