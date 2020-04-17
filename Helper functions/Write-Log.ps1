# Copy the below code to use the Write-Log function in your ps scripts

$LogFolder = "C:\Repository\logs"
$MyName = $MyInvocation.MyCommand.Name
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"

Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg | Out-File $LogFile -Append
    $ThisMsg
}


# Call the function like so
#Write-Log "$MyName, by Ava, Logging to $LogFile..."

