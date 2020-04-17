#$computername = Get-ADComputer -Filter 'name -like "kto-dmzapp-*"' | select -ExpandProperty name
#$computername = gc C:\Repository\input\MemberServers.txt
$computername = "site1-gads01.corp.Companyx.com"

$msufile = "\\site1-file01\SWInstall\Windows_Updates\Windows8.1-KB3062960-x64.msu"

foreach ($computer in $computername)
    {
    $destinationFolder = "\\$computer\C$\Installs\"

        if (!(Test-Path -path $destinationFolder -Verbose))
            {
            New-Item $destinationFolder -Type Directory -Verbose
            }
            Copy-Item -Path $msufile -Destination $destinationFolder -Verbose

            $SB= { Start-Process -FilePath 'wusa.exe' -ArgumentList "C:\Installs\Windows8.1-KB3062960-x64.msu /extract:C:\windows\temp\" -Wait -PassThru }
    
            Invoke-Command -ComputerName $computer -ScriptBlock $SB

            $SB={ Start-Process -FilePath 'dism.exe' -ArgumentList "/online /add-package /PackagePath:C:\temp\Windows8.1-KB3062960-x64.cab" -Wait -PassThru }

            Invoke-Command -ComputerName $computer -ScriptBlock $SB

            Invoke-Command -ComputerName $computer -ScriptBlock {
$localmsifile = "c:\Installs\LAPS.x64.msi"
$arguments= ' /qn /l*v C:\Installs\LAPS.log ADDLOCAL=CSE TARGETDIR="C:\Program Files\LAPS"'
Start-Process -file $localmsifile -arg $arguments -passthru -Verbose| wait-process }
    }


