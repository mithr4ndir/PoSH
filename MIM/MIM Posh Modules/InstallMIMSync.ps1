[CmdletBinding()]
Param (
    # Directory where deployment resources are located
    [Parameter(Mandatory=$false, Position=0)]
    [string] $WorkspaceDirectory = "\\hostname.domain.com\MIM",
    # Directory where deployment logs are located
    [Parameter(Mandatory=$false, Position=2)]
    [string] $LogDirectory = (Join-Path $WorkspaceDirectory "Logs"),
    # MIM Sync Service Account Credentials
    [Parameter(Mandatory=$false, Position=1)]
    [pscredential] $MIMSyncServiceAccount = (Get-Credential -UserName "domain\MIMSync" -Message "Please enter the MIM Sync Service Account Credentials")
)

Remove-Module MIMInstallationTools
Import-Module .\MIMInstallationTools.psm1
Import-Module Storage

## Get deployment resources
[System.Collections.Generic.Dictionary[string,System.IO.FileInfo]] $ResourcePath = Get-MIMPrerequisites -WorkspaceDirectory $WorkspaceDirectory
return

## MIM Sync Prerequisite Tasks
# Install .NET 3.5
Install-WindowsFeature NET-Framework-Core -Source "C:\Windows\Sources\sxs" -LogPath (Join-Path $LogDirectory (New-LogFilename 'NET-Framework-Core')) -ErrorAction Stop
# Install AD Tools (Optional)
Install-WindowsFeature RSAT-AD-Tools -Source "C:\Windows\Sources\sxs" -LogPath (Join-Path $LogDirectory (New-LogFilename 'RSAT-AD-Tools'))

# Install SQL Native Client
Invoke-WindowsInstaller $ResourcePath['Microsoft SQL Server 2012 SP2 Native Client'].FullName -UserInterfaceMode Basic -PublicProperties @{ IACCEPTSQLNCLILICENSETERMS="Yes" } -LoggingOptions '*' -LogPath $LogDirectory -ErrorAction Stop

# Mount MIM Installation ISO
$diskMIM = Get-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -ErrorAction SilentlyContinue
if (!$diskMIM -or !$diskMIM.Attached) { $diskMIM = Mount-DiskImage $ResourcePath['Microsoft Identity Manager 2016'].FullName -PassThru -ErrorAction Stop }
$driveMIM = '{0}:\' -f ($diskMIM | Get-Volume).DriveLetter


## Install MIM Synchronization Service
Install-MIMSynchronizationService (Join-Path $driveMIM "Synchronization Service\Synchronization Service.msi") -AcceptEULA -UserInterfaceMode None -ServiceAccount $MIMSyncServiceAccount -InstallPath "E:\Program Files\Microsoft Identity Manager\2016" -SQLServer "sql.domain.com" -GroupsDomain "domain" -AdminsGroup "MIMSyncAdmins" -OperatorsGroup "MIMSyncOperators" -JoinersGroup "MIMSyncJoiners" -BrowseGroup "MIMSyncBrowse" -PasswordSetGroup "MIMSyncPasswordSet" -ConfigureFirewall -LoggingOptions '*' -LogPath $LogDirectory -ErrorAction Stop


## MIM Sync Post-Install Tasks
# Dismount ISO
Dismount-DiskImage -InputObject $diskMIM

# Backup Encryption Key
$MIMInstallation = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\FIMSynchronizationService\Parameters"
Use-StartProcess (Join-Path $MIMInstallation.Path "Bin\miiskmu.exe") -ArgumentList @(
    ('/e "{0}"' -f (Join-Path $WorkspaceDirectory 'MIMSyncKey.bin')),
    ('/u:{0} {1}' -f $MIMSyncServiceAccount.Username, $MIMSyncServiceAccount.GetNetworkCredential().Password)
)

# Update MIM Synchronization Service
Stop-Service -Name FIMSynchronizationService
Invoke-WindowsInstaller $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM Sync'].FullName -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory

# Install MIM Connectors
Invoke-WindowsInstaller $ResourcePath['MIM Generic LDAP Connector'].FullName -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory
Invoke-WindowsInstaller $ResourcePath['MIM Generic SQL Connector'].FullName -UserInterfaceMode Basic -LoggingOptions '*' -LogPath $LogDirectory
