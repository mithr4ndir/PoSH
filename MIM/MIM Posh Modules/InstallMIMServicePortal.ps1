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
    # MIM Admin Account Credential
    [Parameter(Mandatory=$false, Position=3)]
    [pscredential] $MIMAdminAccount,
    # SharePoint Service Account Credential
    [Parameter(Mandatory=$false, Position=4)]
    [pscredential] $SPServiceAccount,
    # MIM Service Account Credential
    [Parameter(Mandatory=$false, Position=5)]
    [pscredential] $MIMServiceAccount,
    # MIM Service Sync Account Credential for the MIM MA
    [Parameter(Mandatory=$false, Position=6)]
    [pscredential] $MIMServiceSyncAccount,
    # MIM SSPR Service Account Credential
    [Parameter(Mandatory=$false, Position=7)]
    [pscredential] $MIMSSPRServiceAccount
)

if (!$SPServiceAccount) { [pscredential] $SPServiceAccount = (Get-Credential -UserName "domain\MIMSharePoint" -Message "Please enter the SharePoint Service Account Credential") }
if (!$MIMServiceAccount) { [pscredential] $MIMServiceAccount = (Get-Credential -UserName "domain\MIMService" -Message "Please enter the MIM Service Account Credential") }

Remove-Module MIMInstallationTools
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
# Install .NET 3.5
Install-WindowsFeature NET-Framework-Core -Source "C:\Windows\Sources\sxs" -LogPath (Join-Path $LogDirectory (New-LogFilename 'NET-Framework-Core')) -ErrorAction Stop

# Install SQL Native Client
Invoke-WindowsInstaller $ResourcePath['Microsoft SQL Server 2012 SP2 Native Client'].FullName -UserInterfaceMode Basic -PublicProperties @{ IACCEPTSQLNCLILICENSETERMS="Yes" } -LoggingOptions '*' -LogPath $LogDirectory -ErrorAction Stop

# Install SharePoint Prerequisites
Use-StartProcess -ErrorAction Stop -FilePath $ResourcePath['SharePoint Foundation 2013 with SP1 Prerequisites'].FullName -ArgumentList @(
    '/unattended'
    ('/SQLNCli:"{0}"' -f $ResourcePath['Microsoft SQL Server 2008 R2 SP1 Native Client (x64)'].FullName)
    ('/PowerShell:"{0}"' -f $ResourcePath['Windows Management Framework 3.0 (Windows6.1-KB2506143-x64)'].FullName)
    ('/NETFX:"{0}"' -f $ResourcePath['Microsoft .NET Framework 4.5'].FullName)
    ('/IDFX:"{0}"' -f $ResourcePath['Windows Identity Foundation (Windows6.1-KB974405-x64)'].FullName)
    ('/Sync:"{0}"' -f $ResourcePath['Microsoft Sync Framework Runtime v1.0 SP1 (x64)'].FullName)
    ('/AppFabric:"{0}"' -f $ResourcePath['Windows Server AppFabric (x64)'].FullName)
    ('/IDFX11:"{0}"' -f $ResourcePath['Windows Identity Foundation v1.1 (Windows Identity Extensions)'].FullName)
    ('/MSIPCClient:"{0}"' -f $ResourcePath['Microsoft Information Protection and Control Client'].FullName)
    ('/WCFDataServices:"{0}"' -f $ResourcePath['Microsoft WCF Data Services 5.0 for OData V3'].FullName)
    ('/KB2671763:"{0}"' -f $ResourcePath['Cumulative Update Package 1 for Microsoft AppFabric 1.1 for Windows Server (KB2671763-x64-ENU)'].FullName)
    ('/WCFDataServices56:"{0}"' -f $ResourcePath['Microsoft WCF Data Services 5.6'].FullName)
)

# Install SharePoint
Import-Module .\SPModule.misc
Import-Module .\SPModule.setup
Install-SharePoint -SetupExePath $ResourcePath['SharePoint Foundation 2013 with SP1 Setup'].FullName `
    -DisplayLevel basic -LoggingType verbose -LogPath $LogDirectory -LogTemplate (New-LogFilename 'SharePointSetup') `
    -AcceptEula -SkipPreReqInstaller `
    -ServerRole APPLICATION -SetupType CLEAN_INSTALL 

# Create SharePoint Farm
New-SharePointFarm -DatabaseAccessAccount $SPServiceAccount -DatabaseServer "SQL.domain.com" -Verbose

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction "SilentlyContinue" | Out-Null

# Create a SharePoint Web Application to host the MIM Portal
$dbManagedAccount = Get-SPManagedAccount -Identity $SPServiceAccount.UserName
New-SpWebApplication -Name "MIM Portal" -ApplicationPool "MIMAppPool" -ApplicationPoolAccount $dbManagedAccount -AuthenticationMethod "Kerberos" -Port 80 -URL http://mim.domain.com/ -DatabaseName ('{0}_{1}' -f ([System.Environment]::MachineName),'WSS_Content')

# Create a SharePoint Site Collection associated with that web application to host the MIM Portal
$SPWebTemplate = Get-SPWebTemplate -compatibilityLevel 14 -Identity "STS#1"
$SPWebApplication = Get-SPWebApplication 'http://mim.domain.com/'
$SPWebApplication.AlternateUrls.Add((New-Object Microsoft.SharePoint.Administration.SPAlternateUrl 'http://mygroups.domain.com/',Default))
$SPWebApplication.AlternateUrls.Add((New-Object Microsoft.SharePoint.Administration.SPAlternateUrl ('http://{0}.domain.com/' -f [System.Environment]::MachineName),Default))
$SPWebApplication.AlternateUrls.Add((New-Object Microsoft.SharePoint.Administration.SPAlternateUrl ('http://{0}/' -f [System.Environment]::MachineName),Default))
$SPWebApplication.AlternateUrls.Add((New-Object Microsoft.SharePoint.Administration.SPAlternateUrl 'http://localhost/',Default))
New-SPSite -Url $SPWebApplication.Url -Template $SPWebTemplate -OwnerAlias domain\MIMAdmin -CompatibilityLevel 14 -Name "MIM Portal" -SecondaryOwnerAlias domain\secondaryuser
$SPSite = SpSite($SPWebApplication.Url)
$SPSite.AllowSelfServiceUpgrade = $false
#$SPSiteRootFolder = $SPSite.RootWeb.RootFolder
#$SPSiteRootFolder.WelcomePage = "default.aspx"
#$SPSiteRootFolder.Update()

# Optimize SharePoint for MIM Portal
$contentService = [Microsoft.SharePoint.Administration.SPWebService]::ContentService;
$contentService.ViewStateOnServer = $false;
$contentService.Update();
Get-SPTimerJob hourly-all-sptimerservice-health-analysis-job | Disable-SPTimerJob

# Enable Kernel-mode authentication and use App Pool Credentials
$appcmdPath = Join-Path $env:windir "system32\inetsrv\appcmd.exe"
& $appcmdPath set config "SharePoint Central Administration v4" -section:windowsAuthentication /useKernelMode:"True" /useAppPoolCredentials:”True” /commit:apphost
& $appcmdPath set config "MIM Portal" -section:windowsAuthentication /useKernelMode:"True" /useAppPoolCredentials:”True” /commit:apphost

# Mount MIM Installation ISO
$diskMIM = Get-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -ErrorAction SilentlyContinue
if (!$diskMIM -or !$diskMIM.Attached) { $diskMIM = Mount-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -PassThru -ErrorAction Stop }
$driveMIM = '{0}:\' -f ($diskMIM | Get-Volume).DriveLetter


## Install MIM Service & Portal
Install-MIMServicePortal (Join-Path $driveMIM "Service and Portal\Service and Portal.msi") `
    -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory -Verbose `
    -AcceptEULA -Features 'MIMService','MIMPortal' -ConfigureFirewall `
    -InstallPath "E:\Program Files\Microsoft Identity Manager\2016" `
    -SQLServer "SQL.domain.com" `
    -MailServer "smtp.domain.com:25" -MailServerUseSSL -MailServerIsExchange -MailServerPollExchange `
    -ServiceAccount $MIMServiceAccount -ServiceAccountEmail 'MIM@domain.com' -ServiceAddress "mim.domain.com"`
    -ServiceSyncAccount 'domain\MIMSyncMIM' -SyncServer "MIMsync.domain.com" `
    -SharePointUrl "http://localhost" -GrantUsersAccessToMIMPortal `
    -SSPRRegistrationUrl "https://registration.domain.com" -SSPRRegistrationAccount 'domain\MIMSSPR' `
    -SSPRResetAccount 'domain\MIMSSPR'


## MIM Post-Install Tasks
# Dismount ISO
Dismount-DiskImage -InputObject $diskMIM

# Update MIM Service & Portal
Stop-Service -Name FIMService
Invoke-WindowsInstaller $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM Service/Portal'].FullName -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory

# Update Resource Management Client in web.config
Update-WebConfigResourceManagementClient -resourceManagementServiceBaseAddress ('http://{0}:5725' -f $env:COMPUTERNAME) -requireKerberos -WebConfigPath "C:\inetpub\wwwroot\wss\VirtualDirectories\805dcfdea5-6748-4a32-87c1-4a783d3cd260\web.config"

# Install MIMWAL
Start-Process powershell.exe -NoNewWindow -Wait -WorkingDirectory $ResourcePath['MIM Workflow Activity Library Register'].DirectoryName -ArgumentList @(
    '-NoProfile'
    '-File {0} -PortalSiteName "MIM Portal"' -f $ResourcePath['MIM Workflow Activity Library Register'].Name
)
Start-Process powershell.exe -NoNewWindow -Wait -WorkingDirectory $ResourcePath['MIM Workflow Activity Library UpdateWorkflowXoml'].DirectoryName -ArgumentList @(
    '-NoProfile'
    '-File {0}' -f $ResourcePath['MIM Workflow Activity Library UpdateWorkflowXoml'].Name
)

# Install MIM Hybrid Reporting
[string] $TempPath = Join-Path $env:TEMP $ResourcePath['MIM Hybrid Reporting Installer'].Directory.Name
[string] $TempPathInstaller = Join-Path $TempPath $ResourcePath['MIM Hybrid Reporting Installer'].Name
Copy-Item -LiteralPath $ResourcePath['MIM Hybrid Reporting Installer'].Directory.FullName -Destination $TempPath -Recurse
Invoke-WindowsInstaller $TempPathInstaller -UserInterfaceMode Full -LoggingOptions '*' -LogPath $LogDirectory -ErrorAction Stop
Remove-Item -LiteralPath $TempPath -Recurse -Force


# Update logo
#C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\14\template\images\MSILM2
