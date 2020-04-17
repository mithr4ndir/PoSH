param
(
    [Parameter(Mandatory=$true)]$inputCSV,
    $ouRB = "ou=ServiceDesk,ou=admin accounts,$OUPath",
    $password = ""

)

if (!(Test-Path $inputCSV))
{
    Write-Output "The input file, $($inputCSV), does not exist!"
    Write-Output "Exiting script now."
    Exit
}

$groups = @("ADR-ServiceDesk-L1","ADR-Workstation Admin")
$domainDN = (Get-ADRootDSE).defaultnamingcontext
$targetOU = $ouRB + "," + $domainDN
$records = import-csv $inputCSV
$tempPassword = ConvertTo-SecureString -AsPlainText $password -Force

$templateL1user = "_template_sd_l1"
$groups = @()
$addToGroups = $false

get-aduser -ide $templateL1user -prop memberof|select -ExpandProperty memberof|foreach {$groups += (get-adgroup -filter {(distinguishedname -eq $_)}).samaccountname}

$records | Out-GridView -PassThru | foreach `
{

    Write-Output "Processing $($_.regularID)"
    $error.Clear()
    try
    {
        $user = get-aduser -ide $_.regularID -ea SilentlyContinue
        Write-Output "Regular account, $($_.regularID), exists"
    }
    catch 
    {  
        Write-Host "Error looking for $($_.regularID) in AD"
        Write-Host "Error message: $($error.exception.message)" 
    }

    $upn = $_.adminID + "@" + (Get-ADDomain).dnsroot
    $adminID = $_.adminID
    $regularID = $_.regularID
    $error.Clear()
    try
    {
#        $adminID
#        New-ADUser -name $_.adminID -GivenName $_.givenName -Surname "$($_.surname) (Admin)" -Path "$($targetOU)"  -SamAccountName $_.adminID -AccountPassword $tempPassword -Enabled $true -UserPrincipalName $upn -HomePage "Owner:$($_.regularID)" -ErrorAction SilentlyContinue
        New-ADUser -name $adminID -GivenName $_.givenName -Surname "$($_.surname) (Admin)" -Path "$($targetOU)"  -SamAccountName $adminID -AccountPassword $tempPassword -Enabled $true -UserPrincipalName $upn -HomePage "Owner:$($regularID)" -ErrorAction SilentlyContinue
        Write-Output "Successfully created $($adminID)  account"
        $addToGroups = $true

    }
    catch
    {
#        Write-Output "Error creating admin account, $($_.adminID), for $($_.regularID)"
        Write-Host "Error creating admin account, $($adminid), for $($regularID)"
        Write-Host "Error message: $($error.exception.message)" 
        
    }
    
    if ($addToGroups)
    {
        Write-Output "Adding $($_.adminID) to groups"
        foreach ($entry in $groups)
        {
        
            Write-Output "Adding $($_.adminID) to $($entry)"
            $error.Clear()
            try 
            {
                Add-ADPrincipalGroupMembership -Identity $_.adminID -MemberOf $entry -ErrorAction SilentlyContinue
                 Write-Output "Successfully added $($_.adminID) to $($entry)"

           }            
            catch
            {
                Write-Host "Error adding $($_.adminID) to $($entry)"
                Write-Host "Error message: $($error.exception.message)" 

                
            }
            $error.Clear()

        
        } 

    }
}