#function get-duoinstallstatus
   # {
        $alldcs = (get-adforest).domains | %{get-addomaincontroller -filter * -server $_}
        $alldchosts = $alldcs.Hostname

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
                            Write-output "The $dchost does not haave duo installed"
                         }

            }
    # }