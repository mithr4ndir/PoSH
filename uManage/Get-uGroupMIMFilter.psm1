<#
.SYNOPSIS
    Name: Module-Name
    Description goes here

.NOTES

#requires -version 2
#>


#[CmdletBinding()]


Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose ) { Write-Host $Message }
    $Message >> $LogFile
}

Function Get-MIMFilter {
    Param (
        [String]$Group
    )
    # Set the FIM service URI and authentication data
    #if (!$Cred) { $Cred = Get-Credential domain\account }
    $paramFIMService = @{}
    $paramFIMService["Uri"] = "http://groupweb.corp.Companyx.com:5725"
    if ($Cred) { $paramFIMService["Credential"] = $Cred } 
    
    <#if ($MIMFilter) {
        $XpathFinal = "/Person[$MIMFilter]" 
        Write-Log "about to apply $xpathfinal"
    }#>

    # Cast the XPATH query into a FIM dialect filter
    $FIMFilter = '<Filter xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Dialect="http://schemas.microsoft.com/2006/11/XPathFilterDialect" xmlns="http://schemas.xmlsoap.org/ws/2004/09/enumeration">{0}</Filter>' -f $Filter
    Write-Log "FIM Filter: $FIMFilter"

    Write-Log "Importing FIM resource object for $Group."
    $ThisGroup = Get-ADGroup -Identity $Group

    $FimGroup = Get-FIMResource -ObjectType Group -AttributeName AccountName -AttributeValues $ThisGroup.SamAccountName @paramFIMService 2>&1 | tee-object $LogFile -Append
    $FimGroupData = $FimGroup | ConvertFrom-FIMResourceToObject 2>&1 | tee-object $LogFile -Append

    $FimGroupData.Filter
}

Function Get-uGroupMIMFilter {
    Param ( 
        [String[]]$Name,
        [Switch]$Verbose,
        [Switch]$Help
    )

    Begin {
        # Dot Source any required Function Libraries
        # . "C:\Scripts\Functions.ps1"

        # Set local variables
        $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

        $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
        $LogFolder = "C:\Temp\uManage_Logs" # Log file directory
        $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify
    
        $Intro = "$MyName" # Program introduction
        $Decor = "="*$Intro.Length # Decoration string
    
        $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage
        If ($Help -or !$Name) {
            $Usage
            break
        } Else {
            Write-Log $Decor
            Write-Log $Intro
            Write-Log $Decor
        }
    } Process{
        Write-Log "$MyName logging to $Logfile..."
        ForEach ($Target in $Name) {
            Write-Log "Processing $Target"
            Try{
                Write-Log "Applying operation to $Target"
                Get-MIMFilter -Group $Target
            } Catch {
                Write-Log "Error -- Failed to apply operation to $Target : $($_.Exception.Message)"
                Continue
            }
            Write-Log "Completed processing $Target"
        }
    } End {
        If($?){ # only execute if the function was successful.
            Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}


Export-ModuleMember -Function Get-uGroupMIMFilter


