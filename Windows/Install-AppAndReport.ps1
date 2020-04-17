#Test script with single hostname (UNHASHTAG line 2 for testing with just one server)
#$memberserver = Get-adcomputer -filter {name -like "site1-scripts01" -or name -like "site1-gads01"} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" -pro lastlogondate | select name,lastlogondate

$App = "Local Administrator"
$AppFileName = "LAPS.x64.msi"
$msifile = "\\site1-file01.corp.Companyx.com\SWInstall\AdmPwdFAT\LAPS.x64.msi"

#Check if excel process exists, kill it if it does.
$localexcelprocess = gwmi win32_process -ComputerName localhost|select ProcessID,Name, @{l="Username";e={$_.getowner().user}} | where {$_.Username -like "$($env:USERNAME)"} | where {$_.Name -eq "excel.exe"}
If ($localexcelprocess.name -like "excel.exe")
    {
        Foreach ($process in $localexcelprocess)
                {
                Stop-process -ID $process.ProcessID
                }

    }

#Check if the App Status Report exists, if so, delete it.
If (Test-path -path "$env:USERPROFILE\desktop\$app-StatusReport-Members.csv")
    {
    Remove-Item -Path "$env:USERPROFILE\desktop\$app-StatusReport-Members.csv" -Force
    }

#Test script with all servers found based on conditons provided on next line (UNHASHTAG line 5 for all servers found based on conditions below)
$memberserver = Get-adcomputer -filter {operatingsystem -like "Windows Server 2012*" -and enabled -eq $true} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" -pro lastlogondate | select dnshostname,lastlogondate

$array=@()
$error.clear()
$AppError=$null

#Enumerate each hostname of $memberserver array
ForEach  ($member in $memberserver)

        {
        #Ping Server, if unsuccessful jump to else
            If (Test-Connection $member.dnshostname -count 2 -Quiet)
                
                {
                #Maybe use this to test for winrm? "$TestWSMAN=Test-WSMan -ComputerName site1-ars-app01 | select wsmid"

                 
                Write-host "$($member.dnshostname) pingable, gathering data..." -ForegroundColor Yellow -BackgroundColor Black
                $appwmi=$null
                $apperror=$null
                $appwmi = Get-WmiObject -ComputerName $member.dnshostname -Class Win32_Product -ErrorVariable AppError -ErrorAction SilentlyContinue | Where-Object {$_.Name -match $app}
                
                    If ($apperror -notlike $null)
                        {
                        $apperror | Select-String "Get-WMIQuery"
                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "ERROR"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $apperror.
                        $array += $objTemp
                        Write-host "$($member.dnshostname) - Errors while attempting to WinRM" -ForegroundColor DarkMagenta -BackgroundColor Black
                        }
                    
                    #If App found, writes to array
                    If ($appwmi.name -match $app)
                        
                        {
                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Installed"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value "N/A"
                        $array += $objTemp
                        Write-host "$($member.dnshostname) - $app found" -ForegroundColor Green -BackgroundColor Black
                        }

                    #If App name variable is null, app could not be found and tries to install
                    If ($appwmi.name -eq $null)
                        
                        {
                        Write-host "$($member.dnshostname) - $app not found attempting install..." -ForegroundColor DarkYellow -BackgroundColor Black
                        $destinationFile = "\\$($member.dnshostname)\C$\Installs\$AppFileName"
                        $destinationFolder = "\\$($member.dnshostname)\C$\Installs\"
                        
                        #If install file not found locally, copy locally
                        if (!(Test-Path -path $destinationFile))
                            
                            {
                                #Create Installs directory if not exist
                                if (!(Test-path -path $destinationFolder))
                                    {
                                    New-Item $destinationFolder -Type Directory
                                    }
                            Copy-Item -Path $msifile -Destination $destinationFolder -Force
                            }

                        #Begin Install
                        Invoke-Command -ComputerName $member.dnshostname -ScriptBlock {
                        $localmsifile = "c:\Installs\LAPS.x64.msi"
                        $arguments= ' /qn /l*v C:\Installs\LAPS.log ADDLOCAL=CSE TARGETDIR="C:\Program Files\LAPS"'
                        Start-Process -file $localmsifile -arg $arguments -passthru | wait-process} 
                        
                            #Check again if app installed otherwise write in log that app not found
                            $appwmi = $null
                            $appwmi = Get-WmiObject -ComputerName $member.dnshostname -Class Win32_Product -ErrorVariable AppError -ErrorAction SilentlyContinue | Where-Object {$_.Name -match $app}                                 
                            
                            If ($apperror -notlike $null)
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "ERROR"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $apperror
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - Errors while attempting to WinRM" -ForegroundColor DarkMagenta -BackgroundColor Black
                                }
                            
                            If ($appwmi.name -match $app)
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Newly Installed"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value "N/A"
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - $app installed successfully" -ForegroundColor Green -BackgroundColor Black
                                }
                            Else 
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Attempted Install"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $AppError
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - $app still not found or installed, check Error in CSV" -ForegroundColor Red -BackgroundColor Black
                                }
                        }
                }
            
            #Server was unpingable, lets try a test-path to C$, then write results to report
            Elseif (!(test-path "\\$($member.dnshostname)\C$"))
                
                {
                Write-host "$($member.dnshostname) unpingable and testpath failed, moving on to next hostname..." -ForegroundColor Red -BackgroundColor Black
                $objTemp = New-Object PSobject
                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "unpingable, testpath failed"
                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value "N/A"
                $array += $objTemp
                }
            
            #Server reachable via testpath
            Else 
                
                {
                Write-host "$($member.dnshostname) test-path successful, gathering wmi info..." -ForegroundColor Yellow -BackgroundColor Black
                $appwmi=$null
                $apperror=$null

                $appwmi = Get-WmiObject -ComputerName $member.dnshostname -Class Win32_Product -ErrorVariable AppError -ErrorAction SilentlyContinue | Where-Object {$_.Name -match $app}
                

                    If ($apperror -notlike $null)
                        {
                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "ERROR"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $apperror
                        $array += $objTemp
                        Write-host "$($member.dnshostname) - Errors while attempting to WinRM" -ForegroundColor DarkMagenta -BackgroundColor Black
                        }


                    #If App found, writes to array
                    If ($appwmi.name -match $app)
                        
                        {
                        $objTemp = New-Object PSobject
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Installed"
                        $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                        $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value "N/A"
                        $array += $objTemp
                        Write-host "$($member.dnshostname) - $app found" -ForegroundColor Green -BackgroundColor Black
                        }

                    #If App name variable is null, app could not be found and tries to install
                    If ($appwmi.name -eq $null)
                        
                        {
                        Write-host "$($member.dnshostname) - $app not found attempting install..." -ForegroundColor DarkYellow -BackgroundColor Black
                        $destinationFile = "\\$($member.dnshostname)\C$\Installs\$AppFileName"
                        $destinationFolder = "\\$($member.dnshostname)\C$\Installs\"
                        
                        #If install file not found locally, copy locally
                        if (!(Test-Path -path $destinationFile))
                            
                            {
                                #Create Installs directory if not exist
                                if (!(Test-path -path $destinationFolder))
                                    {
                                    New-Item $destinationFolder -Type Directory
                                    }
                            Copy-Item -Path $msifile -Destination $destinationFolder -Force
                            }

                        #Begin Install
                        Invoke-Command -ComputerName $member.dnshostname -ScriptBlock {
                        $localmsifile = "c:\Installs\LAPS.x64.msi"
                        $arguments= ' /qn /l*v C:\Installs\LAPS.log ADDLOCAL=CSE TARGETDIR="C:\Program Files\LAPS"'
                        Start-Process -file $localmsifile -arg $arguments -passthru | wait-process} 
                        
                            #Check again if app installed otherwise write in log that app not found
                            $appwmi = $null
                            $appwmi = Get-WmiObject -ComputerName $member.dnshostname -Class Win32_Product -ErrorVariable AppError | Where-Object {$_.Name -match $app}                                 
                            
                            If ($apperror -notlike $null)
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "ERROR"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $apperror
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - Errors while attempting to WinRM" -ForegroundColor DarkMagenta -BackgroundColor Black
                                }
                            
                            
                            If ($appwmi.name -match $app)
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Newly Installed"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value "N/A"
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - $app installed successfully" -ForegroundColor Green -BackgroundColor Black
                                }
                            Else 
                                {
                                $objTemp = New-Object PSobject
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member.dnshostname
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Attempted Install"
                                $objTemp | Add-Member -MemberType NoteProperty -Name "LastlogonDate" -Value $member.lastlogondate
                                $objTemp | Add-Member -MemberType NoteProperty -Name "Error" -Value $AppError
                                $array += $objTemp
                                Write-host "$($member.dnshostname) - $app still not found or installed, check Error in CSV" -ForegroundColor Red -BackgroundColor Black
                                }
                        }
                } 
        }
        

#Dumps array into a CSV Report
$array | Export-csv "$env:USERPROFILE\desktop\$app-StatusReport-Members.csv" -NoTypeInformation

