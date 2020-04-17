<#
    Code Descripiton
    Name: duplciate_UIDNumber_Notifcation.ps1
    Scans the UIDNumber property of all ADUser Objects within directory If any dupliate UIDNumbers are found an email will be sent to notify the team. 
#>

#SetGlobalVariables
#$LogFolder = "C:\Repository\logs\Scheduled"
$LogFolder = "C:\Repository\logs\Scheduled\DuplicateUIDNumber"
$MyName = $MyInvocation.MyCommand.Name
$LogFileName = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
$DuplicateUIDUsers ={};

function main
{
    #Helper Functions

    #Gets UIDNumber Duplicates and sets them in an array. 
    function Get-DuplicateIDs
    {
        $ADusers = Get-ADUser -Filter * -Properties UIDNumber
        $UIDArray = @{};

        $ADusers | ForEach-Object { if($_.UIDNumber) { $UIDArray[$_.UIDNumber] += 1 } }
        $Script:DuplicateUIDUsers = $ADusers | Where-Object { if($_.UIDNumber) { $UIDArray[$_.UIDNumber] -gt 1 } }

        #Check to see if any Duplicates exist and write them to the log
        if ($DuplicateIDUsers)
        {
            Write-Log "Duplicate UIDNumbers found for the following users: "  
            $DuplicateIDUsers | Select-Object -Property SamAccountName, UIDNumber | Sort-Object -Property UIDNumber | ForEach-Object
            {
               Write-Log "$_"
            }
        }
        else
        {
            Write-Log "No Duplicate UIDNumbers found."
        }

        Return $DuplicateUIDUsers
    }

    #Sends a Notifcation Email with Duplicate ID's
    function Send-Email ($DuplicateIDUsers)
    {

        $smtpServer = "192.168.44.22"
        $to = "thing@company1.com"
        $from = "thing@company1.com"
        $subject = "Duplicate UIDNumber(s) found in Active Directory"
        $message = "The following users have duplicate UIDNumbers in Active Directory: " + "$DuplicateIDUsers"
        $DuplicateIDUsers
        Send-MailMessage -to $to -From $from -Subject $subject -Body $message -SmtpServer $smtpServer
    }

    #Writes all actions taken to log file. 
    Function Write-Log ($Message) 
    {
        $LogMesssage = "[$MyName] $(Get-Date) : $Message"
        $LogMesssage >> $LogFileName
        If ($Verbose) 
        { 
            $LogMesssage 
        }
    }

        #Creates Log file and header.
        $Intro = "$MyName"
        $Padding = "="*$Intro.Length
        Write-Log $Padding
        Write-Log $Intro
        Write-Log $Padding
        Write-Log "$MyName logging to $LogfileName..."
        Write-Log "Collecting UIDNumbers for AD users..."

        #Compares UIDNumbers to find duplicates and writes them to log. 
        Write-Log "Comparining UIDNumbers for duplicate instnaces..."
        $DuplicateUIDUsers = Get-DuplicateIDs


        #If there are duplicate UIDNumbers notify team via email. 
        If ($DuplicateUIDUsers) {
            Send-Email($DuplicateUIDUsers)
         }


        #Close logs after exacution. 
        Write-Log "$MyName has completed execution, closing log." 
        $LogFileName = $null
}

main















