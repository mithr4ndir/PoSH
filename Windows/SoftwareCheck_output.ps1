$aResults = @()
$DomainDN = (Get-ADDomain).DistinguishedName
$alldcs = Get-adcomputer -filter {operatingsystem -like "Windows Server*" -and enabled -eq $true} -SearchBase "OU=Virtualization,OU=ATG,OU=Servers,OU=Computers,OU=Managed,$DomainDN" -pro lastlogondate | select dnshostname

    $alldchosts = $alldcs.DNSHostname

         foreach($dchost in $alldchosts)
            {
            $software = get-ciminstance -computername $dchost -ClassName win32_product
                if($software.Name -like "*duo*")
                    {
                    $duoinstalledhosts = $dchost
                    Write-output "The $dchost has duo installed"
                   
                    } 
                    Else {
                           $duonotinstalledhosts = $dchost
                           $nInstalled = Write-output "$dchost does not have duo installed"
                            
                         }
     $aResults = $nInstalled

            } 

        $aResults | Out-File "C:\Users\malvarez-adm\Downloads\NotInstalled.txt" 