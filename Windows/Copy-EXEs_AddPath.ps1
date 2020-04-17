<#
.Synopsis
   This script is designed to place single object executables and add a path onto a collection of workstations declared within $memberservers variable. 
   Currently the script is setup to copy over tools into the path C:\windows\system32\tools\ and this path has also been added to the path environment variable.
   This script is not designed to be run as a function, or automation. Please run script in Powershel_ISE and run from console.
.INPUTS
   Within this script $appbits is a variable that will import a csv file. The format of the csv should look like so...
   
    Location	                                Filename
    \\site1-file01\SWInstall\Tools\PortQry.exe	portqry.exe
    \\site1-file01\SWInstall\Tools\procmon.exe	procmon.exe
    \\site1-file01\SWInstall\Tools\procexp.exe	procexp.exe
    \\site1-file01\SWInstall\Tools\putty.exe	    putty.exe

    ... where there are two columns and headers depicting file location and file name.
    This CSV file can be found within \\site1-scripts01\c$\Repository\input\ or create it with the desired values for an additional application you would like to add to the \Tools\ Directory.
.OUTPUTS
   Outputs of the scripts logic are currently displayed within an active console only.
.NOTES
   Keep in mind that this script uses New-PSSession and Invoke-command modules to carry out application queries and install executions. Add-Path function is loaded within this script so that there is no dependancy on whether the module exists within the server fleet.
#>

#DomainDN is an adaptable domain variable, so that you may run this script within prod or dev domains.
$DomainDN = (Get-ADDomain).DistinguishedName
#membberservers will include any domain joined servers found within the domain that live within the Servers OU. Lastlogondate is also included for each computer class object, which is good for troubleshooting possible scenarios where a server was unreachable due to it either being stale within the directory.
$memberservers = Get-adcomputer -filter {operatingsystem -like "Windows*Server*" -and enabled -eq $true} -SearchBase "ou=servers,ou=computers,ou=managed,$DomainDN" -pro lastlogondate | select dnshostname,lastlogondate
#Import your list of executables you would like to see deployed to server fleet (More info found within the .INPUTS section above)
$appbits = Import-csv 'C:\repository\input\apps.csv'

#Create directory and copy tools only if they do not exist.
Foreach ($app in $appbits)
{
Write-Host "App to be copied - $($app.filename)"
    Foreach ($server in $memberservers.dnshostname)
        {
        Write-host "Trying $server" -BackgroundColor white
            if (!(Test-Path -path "\\$server\C$\Windows\System32\Tools\$($app.filename)"))
            {                                            
                #Create Installs directory if not exist
                Write-host "File not found, does path exist?" -BackgroundColor Black -ForegroundColor Red
                if (!(Test-path -path "\\$server\c$\Windows\System32\Tools\"))
                    {
                    Write-Host "Folder not found creating directory now..." -BackgroundColor Black -ForegroundColor Red
                    New-Item "\\$server\c$\Windows\System32\Tools\" -Type Directory
                    }
                Write-Host "Path Exists, going to copy binaries..." -BackgroundColor Black -ForegroundColor Red
                Copy-Item -Path $App.Location -Destination "\\$server\c$\Windows\System32\Tools\" -Force
                Write-host "Apps Created" -BackgroundColor Green
            }
            Else {Write-host "$($app.filename) found on $server"}
        }

}

#Unloads any currenty PSSession and then makes a connection with every server found within $memberservers
Get-PSSession | Remove-PSSession
$s = $null
$s = New-PSSession -ComputerName $memberservers.dnshostname

#Add tools path to environment variable path so that exes found within C:\windows\system32\tools\ can be run from any directory; will only edit if path does not already exist.
$Masschange = $null
$Masschange = Invoke-Command -Session $s -ScriptBlock {

        # Added 'Test-LocalAdmin' function written by Boe Prox to validate is PowerShell prompt is running in Elevated mode 
        # Removed lines for correcting path in ADD-PATH 
        # Switched Path search to an Array for "Exact Match" searching 
        # 2/20/2015 
        Function global:TEST-LocalAdmin() 
            { 
            Return ([security.principal.windowsprincipal] [security.principal.windowsidentity]::GetCurrent()).isinrole([Security.Principal.WindowsBuiltInRole] "Administrator") 
            } 
     
 
        Function global:ADD-PATH() 
        { 
        [Cmdletbinding(SupportsShouldProcess=$TRUE)] 
        param 
            ( 
            [parameter(Mandatory=$True,  
            ValueFromPipeline=$True, 
            Position=0)] 
            [String[]]$AddedFolder 
            ) 
 
        If ( ! (TEST-LocalAdmin) ) { Write-Host 'Need to RUN AS ADMINISTRATOR first'; Return 1 } 
     
        # Get the Current Search Path from the Environment keys in the Registry 
 
        $OldPath=(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path 
 
        # See if a new Folder has been supplied 
 
        IF (!$AddedFolder) 
            { Return ‘No Folder Supplied.  $ENV:PATH Unchanged’} 
 
        # See if the new Folder exists on the File system 
 
        IF (!(TEST-PATH $AddedFolder)) 
            { Return ‘Folder Does not Exist, Cannot be added to $ENV:PATH’ } 
 
        # See if the new Folder is already IN the Path 
 
        $PathasArray=($Env:PATH).split(';') 
        IF ($PathasArray -contains $AddedFolder -or $PathAsArray -contains $AddedFolder+'\') 
            { Return ‘Folder already within $ENV:PATH' } 
 
        If (!($AddedFolder[-1] -match '\')) { $Newpath=$Newpath+'\'} 
 
        # Set the New Path 
 
        $NewPath=$OldPath+';’+$AddedFolder 
        if ( $PSCmdlet.ShouldProcess($AddedFolder) ) 
        { 
        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH –Value $newPath 
 
        # Show our results back to the world 
 
        Return $NewPath  
        } 
        }  
        $Stuff = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH
        $stuff2 = $stuff.Path.split(";")
        If ($stuff2 -notcontains "C:\Windows\System32\Tools") 
                {
                Add-Path -AddedFolder C:\Windows\System32\Tools
                Write-host "Path added to $env:computername" -BackgroundColor Green
                }
        Else { Write-host "Path exists on $env:computername" -BackgroundColor black}
}