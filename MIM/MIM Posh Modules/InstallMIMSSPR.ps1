[CmdletBinding()]
Param (
    # Directory where deployment resources are located
    [Parameter(Mandatory=$false, Position=0)]
    [string] $WorkspaceDirectory = "\\hostname.domain.com\MIM",
    # Directory where deployment software is located
    [Parameter(Mandatory=$false, Position=1)]
    [string] $SoftwareDirectory,
    # Directory where deployment logs are located
    [Parameter(Mandatory=$false, Position=2)]
    [string] $LogDirectory = (Join-Path $WorkspaceDirectory "Logs"),
    # MIM Self-Service Password Reset (SSPR) Service Account Credential
    [Parameter(Mandatory=$false, Position=5)]
    [pscredential] $SSPRServiceAccount
)

if (!$SSPRServiceAccount) { [pscredential] $SSPRServiceAccount = (Get-Credential -UserName "domain\MIMSSPR" -Message "Please enter the MIM SSPR Service Account Credential") }

Remove-Module MIMInstallationTools -ErrorAction SilentlyContinue
Import-Module .\MIMInstallationTools.psm1
Import-Module Storage

[hashtable] $paramGetMIMPrerequisites = @{}
if ($WorkspaceDirectory) { $paramGetMIMPrerequisites['WorkspaceDirectory'] = $WorkspaceDirectory }
if ($SoftwareDirectory) { $paramGetMIMPrerequisites['SoftwareDirectory'] = $SoftwareDirectory }
if ($LogDirectory) { $paramGetMIMPrerequisites['LogDirectory'] = $LogDirectory }

## Get deployment resources
[System.Collections.Generic.Dictionary[string,System.IO.FileInfo]] $ResourcePath = Get-MIMPrerequisites -ErrorAction Stop @paramGetMIMPrerequisites
return

## MIM Service & Portal Prerequisite Tasks
# Install .NET 3.5 and IIS
Install-WindowsFeature NET-Framework-Core -Source "C:\Windows\Sources\sxs" -LogPath (Join-Path $LogDirectory (New-LogFilename 'NET-Framework-Core')) -ErrorAction Stop
Install-WindowsFeature Web-WebServer,Web-Static-Content,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Http-Redirect,Web-Asp-Net,Web-Asp-Net45,Web-Net-Ext,Web-Net-Ext45,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Http-Logging,Web-Request-Monitor,Web-Basic-Auth,Web-Windows-Auth,Web-Filtering,Web-Stat-Compression,Web-Dyn-Compression,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,Web-Lgcy-Scripting,Web-WMI,Web-Scripting-Tools -Source "C:\Windows\Sources\sxs" -LogPath (Join-Path $LogDirectory (New-LogFilename 'Web Server (IIS)')) -ErrorAction Stop

# Disable Default Site
Import-Module WebAdministration
Set-ItemProperty "IIS:\Sites\Default Web Site" -Name serverAutoStart -Value $false
Stop-Website "Default Web Site"

# Mount MIM Installation ISO
$diskMIM = Get-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -ErrorAction SilentlyContinue
if (!$diskMIM -or !$diskMIM.Attached) { $diskMIM = Mount-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -PassThru -ErrorAction Stop }
$driveMIM = '{0}:\' -f ($diskMIM | Get-Volume).DriveLetter


## Install MIM Service & Portal
Install-MIMService (Join-Path $driveMIM "Service and Portal\Service and Portal.msi") `
    -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory -Verbose -ErrorAction Stop `
    -AcceptEULA -Features 'SSPRRegistrationPortal','SSPRResetPortal' -ConfigureFirewall `
    -InstallPath "E:\Program Files\Microsoft Identity Manager\2016" `
    -ServiceAddress "mim.domain.com" `
    -SSPRRegistrationHostName "registration.domain.com" -SSPRRegistrationPort 8080 -SSPRRegistrationAccount $SSPRServiceAccount `
    -SSPRResetHostName "reset.domain.com" -SSPRResetPort 8088 -SSPRResetExtranetAccess -SSPRResetAccount $SSPRServiceAccount


## MIM Sync Post-Install Tasks
# Dismount ISO
Dismount-DiskImage -InputObject $diskMIM

# Update MIM Synchronization Service
Invoke-WindowsInstaller $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM Service/Portal'].FullName -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory

# Update MIM Password Registration Site Bindings
$DNS = Resolve-DnsName "registration.domain.com" -Type A | where Type -eq A
New-WebBinding -Name "MIM Password Registration Site" -IPAddress $DNS.IPAddress -Protocol https -Port 443 -HostHeader $DNS.Name
$WebBinding = Get-WebBinding -Name "MIM Password Registration Site" -IPAddress $DNS.IPAddress -Protocol https -Port 443 -HostHeader $DNS.Name
[System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificate = Get-ChildItem -Path cert:\LocalMachine\My -DnsName $DNS.Name -SSLServerAuthentication
$WebBinding.AddSslCertificate($Certificate[0].Thumbprint,"My")
Remove-WebBinding -Protocol http -Port 8080 -HostHeader $DNS.Name

# Update MIM Password Reset Site Bindings
$DNS = Resolve-DnsName "reset.domain.com" -Type A | where Type -eq A
New-WebBinding -Name "MIM Password Reset Site" -IPAddress $DNS.IPAddress -Protocol https -Port 443 -HostHeader $DNS.Name
$WebBinding = Get-WebBinding -Name "MIM Password Reset Site" -IPAddress $DNS.IPAddress -Protocol https -Port 443 -HostHeader $DNS.Name
[System.Security.Cryptography.X509Certificates.X509Certificate2[]] $Certificate = Get-ChildItem -Path cert:\LocalMachine\My -DnsName $DNS.Name -SSLServerAuthentication
$WebBinding.AddSslCertificate($Certificate[0].Thumbprint,"My")
Remove-WebBinding -Protocol http -Port 8088 -HostHeader $DNS.Name
