<#
.SYNOPSIS
    Name: Revoke-uCerts.ps1
    Description goes here

.NOTES
    Author: Chris Ladino (roar!)
    Release Date: 

#requires -version 2
#>


[CmdletBinding()]
PARAM ( 
    [String]$Name,
    [String]$filePath,
    [String]$Reason,
    [Parameter(Mandatory=$True)]
    [ValidateSet("site1-csent01.corp.Companyx.com","site1-csent02.corp.Companyx.com")]$CAs,
    [boolean]$confirm=$false
)


# Dot Source any required Function Libraries
    # . "C:\Scripts\Functions.ps1"

# Set local variables
    #Import Modules
    Import-Module PSPKI
    $ImportedData = import-csv $filePath

    If ($temprequest -is [object]) {Remove-Variable temprequest}
    If ($temprequest -is [object]) {Remove-Variable arrayAllRequests}
    $ErrorActionPreference = "Continue" # Error Action = (Continue,SilentlyContinue,Stop)

    $MyName = $MyInvocation.MyCommand.Name # Binary file name - do not modify
    
    $LogFolder = "C:\Repository\Team\ChrisL\Logs" # Log file directory
    $LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log" # Log file path - do not modify
    
    $Intro = "|--/,  |(-_-)|  ,\--|    $MyName   by Chris   Roar!!!!    |--/,  |(-_-)|  ,\--|" # Program introduction
    $Decor = "="*$Intro.Length # Decoration string
    
    $Usage = "$MyName Usage:`n`t$MyName -Name name1[,name2,...] [-Verbose]" # Executable file usage


Function Write-Log ($Message) {
    $Message = "[$MyName] $(Get-Date) : $Message"
    If ($Verbose ) { $Message }
    $Message >> $LogFile
}


Function Revoke-uCerts {
    Begin {
        If ($Help) {
            $Usage
            exit
        } Else {
            ""
            $Decor
            $Intro
            $Decor
        }
    } Process{
        Write-Log "$MyName logging to $Logfile..."
        ForEach ($bit in $ImportedData) {
            Write-Log "Finding all certs with this commonname $($bit.commonname)"
            Try{
                Write-Output "Processing $($bit.commonname)"
                $tempRequest=Get-IssuedRequest -certificationauthority $CAs -Filter "CommonName -eq $($bit.commonname)"
                $arrayAllRequests+=$tempRequest
            } Catch {
                Write-Log "Error -- Failed to apply operation to $($bit.commonname) : $($_.Exception.Message)"
                Break
            }
            #Write-Log "Completed processing $Target"
        }
    } End {
        Write-Log "Now displaying all certs found"
        Write-Log "Total of $($arrayallrequests.count) certs found"
        #If confirm is defined as $true this will revoke all certificates found from Process block
        If ($confirm -eq $true -and $arrayAllRequests -is [object]) { 
            #Write-Log "$MyName completed execution successfuly, see details in logfile $LogFile. Now exiting..."
            Foreach ($cert in $arrayAllRequests) {
            
                Try{
                    $tempRequest=Get-IssuedRequest -certificationauthority $CAs -Filter "CommonName -eq $($bit.commonname)"
                    $arrayAllRequests+=$tempRequest
                } Catch {
                    Write-Log "Error -- Failed to apply operation to $($bit.commonname) : $($_.Exception.Message)"
                    Break
                }
            }
        } Else {
            Write-Log "$MyName execution failed, see details in logfile $LogFile. Now exiting..."
        }
    }
}
Revoke-uCerts