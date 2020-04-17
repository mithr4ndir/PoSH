#Create service accounts for Eli's group (physical security), these service accounts will be used for cameras, which will require a user object in the directory, and a certificate for authentication

#Log Fuction
$LogFolder = "\\site1-Scripts01\C$\Repository\logs"
$MyName = $MyInvocation.MyCommand.Name
$LogFile = "$LogFolder\$MyName`_$(Get-Date -Format FileDateTime).log"
Function Write-Log ($Message) {
    $ThisMsg = "[$MyName] $(Get-Date) : $Message"
    $ThisMsg | Out-File $LogFile -Append
    $ThisMsg
}
#Create Security Camera Service Accounts 
Function Create-RDK_ServiceAccts {
    $pass=Read-Host -AsSecureString "input password"
    $input=gc C:\Repository\input\cams.txt
    
    #Clear errors variable
    if ($errors -is [object]) {$errors.clear()}

    #Counters
    $created=0
    $notcreated=0
    Write-Log "Starting Create RDK User Function!"
    foreach ($u in $input) {
        #Pre-append svc- to mac addresses
        $svcNameAct= "svc-" + $u
        #Create them one at a time!
        Write-Log "Attempting to create $svcNameAct"
        Try {
        New-ADUser -Name $svcNameAct `
                   -DisplayName $svcNameAct `
                   -SamAccountName $svcNameAct `
                   -GivenName $svcNameAct `
                   -AccountPassword $pass `
                   -UserPrincipalName $svcNameAct@CORP.Companyx.COM `
                   -Path "OU=Security Cameras,OU=Services,$OUDomainPATH" `
                   -Enabled $true
        $created++
        }
        Catch {
        Write-Log "Error creating $svcNameAct - $($_.Exception.Message)"
        $notcreated++
        }
    }
    #Write to log the stats of what was created and what was not
    Write-Log "$created service accounts created"
    Write-Log "$notcreated service accounts not created"
    #Nice to haves:
    #-Would like to dump array of errorneous service account names that were not created.
    #Write-Log "Adding list of just service accounts not created... `n$($error.TargetObject.ConnectionInfo.ComputerName)"
    notepad $LogFile
}