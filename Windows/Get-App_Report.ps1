#Test script with single hostname (UNHASHTAG line 2 for testing with just one server)
#$memberserver = "site1-scripts01","site1-gads01"
$app = 'Active Roles'
$reportPath = "$env:USERPROFILE\desktop\$app - StatusReport-Members.csv"
if (Test-path $reportPath) {Remove-Item -Path "$env:USERPROFILE\desktop\$app - StatusReport-Members.csv" -Force; Write-host "$reportPath file has been deleted"}

#Test script with all servers found based on conditons provided on next line (UNHASHTAG line 5 for all servers found based on conditions below)
$memberserver = Get-adcomputer -filter {operatingsystem -like "Windows*Server*" -and enabled -eq $true} -SearchBase "ou=servers,ou=computers,$OUDomainPATH" | select -ExpandProperty name
$array=@()

#Enumerate each hostname of $memberserver array
Foreach ($member in $memberserver)

{
        #Ping Server, if unsuccessful jump to else
        If (Test-Connection $member -count 2 -Quiet)
            {
                Write-host "$member pingable, gathering data..." -ForegroundColor Yellow -BackgroundColor Black
                $appwmi = $null
                $appwmi = Get-WmiObject -ComputerName $member -Class Win32_Product | Where-Object {$_.Name -match $app}
                
                #If App found, writes to array
                If ($appwmi.name -match $app)
                    {
                    $objTemp = New-Object PSobject
                    $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member
                    $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Installed"
                    $array += $objTemp
                    Write-host "$member - $app found" -ForegroundColor Green -BackgroundColor Black
                    }
                #If App name variable is null, app could not be found writes to array
                If ($appwmi.name -eq $null)
                    {
                    Write-host "$member - $app not found" -ForegroundColor DarkYellow -BackgroundColor Black
                    $objTemp = New-Object PSobject
                    $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member
                    $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "Not Found"
                    $array += $objTemp
                    }
            }
        #Server was unpingable, which then writes to array
        Else
            {
            Write-host "$member unpingable, moving on to next hostname..." -ForegroundColor Red -BackgroundColor Black
            $objTemp = New-Object PSobject
            $objTemp | Add-Member -MemberType NoteProperty -Name "Computername" -Value $member
            $objTemp | Add-Member -MemberType NoteProperty -Name "Result" -Value "unpingable"
            $array += $objTemp
            }
}
#Dumps array into a CSV Report
$array | Export-csv -Path $reportPath

