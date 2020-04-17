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

#if (!$MIMServiceAccount) { [pscredential] $MIMServiceAccount = (Get-Credential -UserName "domain\svcaccount" -Message "Please enter the MIM Service Account Credential") }

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


## MIM Service Post-Install Tasks
# Install MIM Hybrid Reporting
[string] $TempPath = Join-Path $env:TEMP $ResourcePath['MIM Hybrid Reporting Installer'].Directory.Name
[string] $TempPathInstaller = Join-Path $TempPath $ResourcePath['MIM Hybrid Reporting Installer'].Name
Copy-Item -LiteralPath $ResourcePath['MIM Hybrid Reporting Installer'].Directory.FullName -Destination $TempPath -Recurse
Invoke-WindowsInstaller $TempPathInstaller -UserInterfaceMode Full -LoggingOptions '*' -LogPath $LogDirectory -ErrorAction Stop
Remove-Item -LiteralPath $TempPath -Recurse -Force
