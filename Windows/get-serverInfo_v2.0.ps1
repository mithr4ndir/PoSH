<#
   .SYNOPSIS
       This script queries Active Directory for servers in a specified OU and outputs a csv file containing information abou the local administrator account in each machine.

       Script Name: list-computerLocalAdmin.ps1
       Author: corp-systems@company.com


   .DESCRIPTION
       This script queries Active Directory for servers in a specified OU and outputs a csv file containing information abou the local administrator account in each machine.

    .PARAMETER  daysoffset
        
        Indicates the password age threshold for servers to be included in the export.  By default, any machine whose computer password in AD has not be changed within the last 60 days will be excluded from the list.
        
        Optional, default set to 60. 
    
    .PARAMETER  rb

         The relative base DN of the OU where computers will be searched for in Active Directory.

         Optional, default set to "ou=servers,ou=computers,ou=managed". 


    .PARAMETER outCSV

        Specifies the name of the output CSV file where the information about computers will be saved.

        Optional, default is localAdmin-inv.csv in the current directory

        
    .PARAMETER logdir

        Optional.  If specified, the log file is saved to the directory set for this argument.  Default log directory is set to the current directory

    .PARAMETER logfile

        Optional.  If used, it indicates the  file name to be used for logging.  The default name will be <nameOfScript>.log

    .EXAMPLE

        Run the script with default settings.

        .\list-computerLocalAdmin.ps1

    .INPUTS

        The Microsoft .NET Framework types of objects that can be piped to the
        function or script. You can also include a description of the input
        objects.

    .OUTPUTS
        The .NET Framework type of the objects that the cmdlet returns. You can
        also include a description of the returned objects.



    .NOTES






#>

param
(

    [string]$searchbase =  (Get-ADRootDSE).defaultnamingcontext,
    [string]$outcsv = "serverInventory.csv",
    [string]$logFile = ($MyInvocation.MyCommand.Name).Replace(".ps1", ".log"),
    [string]$logDir = ".",
    [switch]$grid

)

Start-Transcript -Path "$($logDir)\$($logfile)"
Write-Output "$(get-date -f u): "


#$daysoffset = 60
#$pwdage = (get-date).AddDays(-$daysoffset)

#$rootDSE = (Get-ADRootDSE).defaultnamingcontext

#$sb = $rb + "," + $rootDSE

$export = @()


$computers = get-adcomputer -filter {(operatingsystem -like "windows server*")} -searchbase $searchbase -prop DNSHostName,IPv4Address,PasswordLastSet,OperatingSystem


foreach ($entry in $computers)
{
    
    Write-Output "$(get-date -f u):Now processing $($entry.DNSHostName)..."
    $buffer = New-Object -TypeName PsObject
    $online = $false

    $buffer | Add-Member -MemberType NoteProperty -Name HostName -Value $entry.DNSHostName
    $buffer | Add-Member -MemberType NoteProperty -Name IPAddress -Value $entry.IPv4Address
    $buffer | Add-Member -MemberType NoteProperty -Name ComputerPwdLastSet -Value $entry.PasswordLastSet
    $buffer | Add-Member -MemberType NoteProperty -Name OS -Value $entry.OperatingSystem
    $nxlogState = "N/A"

        $manufacturer = "N/A"
        $model = "N/A"
        $ram = "N/A"
        $domain = "N/A"
        $serverRole = "N/A"
        $osCaption = "N/A"
        $osInstallDate = "N/A"
        $osLastBootUpTime = "N/A"
        $adminName = "N/A"
        $adminSid = "N/A"
        $adminStatus = "N/A"


    if (Test-Connection $entry.dnshostname -count 1 -quiet)
    {

        $online = $true
        
        $buffer | Add-Member -MemberType NoteProperty -Name Online -Value $online
        #get computer information
        Write-Output "$(get-date -f u):Connecting to $($entry.DNSHostName) to gather computer system info..."
        $computerdb = Get-WmiObject Win32_ComputerSystem -ComputerName $entry.DNSHostName
        $nxlogService = Get-Service nxlog -ComputerName $entry.dnsHostName -ErrorAction SilentlyContinue

        if ($nxlogService -isnot [Object])
        {
            $nxlogState = "NotInstalled"
        }
        else
        {
            $nxlogState = $nxlogService.Status
        }

        $manufacturer = $computerDB.manufacturer
        $model = $computerdb.model
        $ram = "$($computerDB.TotalPhysicalMemory/1GB) GB"
        $domain = $computerDB.domain

        if (($computerDB.Roles -match "domain_controller").count -gt 0)
        {
            $serverRole = "Domain Controller"
        }
        else
        {
            $serverRole = "Member Server"
        }
                    
        #get os info
        Write-Output "$(get-date -f u):Connecting to $($entry.DNSHostName) to gather OS info..."
        $osinfo = Get-WmiObject Win32_OperatingSystem -ComputerName $entry.DNSHostname
        $osCaption =$osinfo.Caption
        $osInstallDate = $osinfo.InstallDate
        $osLastBootUpTime = $osinfo.LastBootUpTime



        #get local admin information
        Write-Output "$(get-date -f u):Connecting to $($entry.DNSHostName) to gather local admin information..."
        $admin = Get-WmiObject Win32_useraccount -ComputerName $entry.dnshostname -filter "LocalAccount='True' AND SID LIKE '%500'"|Select PSComputername,Name,Status,Disabled,AccountType,Lockout,PasswordRequired,PasswordChangeable,SID
        $adminName = $admin.Name
        $adminSid = $admin.SID
        $adminStatus = $admin.Status
    }
    else
    {
        $buffer | Add-Member -MemberType NoteProperty -Name Online -Value $online
        Write-Output "$(get-date -f u):Skipping $($entry.DNSHostName) as it is offline..."


    }
        $buffer | Add-Member -MemberType NoteProperty -Name Manufacturer -Value $manufacturer
        $buffer | Add-Member -MemberType NoteProperty -Name Model -Value $model
        $buffer | Add-Member -MemberType NoteProperty -Name RAM -Value $ram
        $buffer | Add-Member -MemberType NoteProperty -Name Domain -Value $domain
        $buffer | Add-Member -MemberType NoteProperty -Name NxLogService -Value $nxlogState
        $buffer | Add-Member -MemberType NoteProperty -Name ServerRole -Value $serverRole
        $buffer | Add-Member -MemberType NoteProperty -Name OSVersion -Value $osCaption
        $buffer | Add-Member -MemberType NoteProperty -Name InstallDate -Value $osInstallDate
        $buffer | Add-Member -MemberType NoteProperty -Name LastBootupTime -Value $osLastBootupTime
        $buffer | Add-Member -MemberType NoteProperty -Name LocalAdminName -Value $adminName
        $buffer | Add-Member -MemberType NoteProperty -Name LocalAdminSID -Value $adminSID
        $buffer | Add-Member -MemberType NoteProperty -Name LocalAdminStatus -Value $adminStatus

    $buffer
    $export += $buffer
    $export

}
if ($grid) { $export|Out-GridView -PassThru -Title "Computers: Local Admin List" }
$export | Export-Csv -Path $outcsv -NoTypeInformation


Write-Host
Stop-Transcript