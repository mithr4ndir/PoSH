function New-LogFilename ([string] $Path) { return ('{0}.{1}.log' -f $Path, (Get-Date -Format "yyyyMMddThhmmss")) }
function Get-ExtractionFolder ([System.IO.FileInfo] $Path) { return Join-Path $Path.DirectoryName $Path.BaseName }

function Use-StartBitsTransfer {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        # Specifies the source location and the names of the files that you want to transfer.
        [Parameter(Mandatory=$true, Position=0)]
        [string] $Source,
        # Specifies the destination location and the names of the files that you want to transfer.
        [Parameter(Mandatory=$false, Position=1)]
        [string] $Destination,
        # Specifies the proxy usage settings
        [Parameter(Mandatory=$false, Position=3)]
        [ValidateSet('SystemDefault','NoProxy','AutoDetect','Override')]
        [string] $ProxyUsage,
        # Specifies a list of proxies to use
        [Parameter(Mandatory=$false, Position=4)]
        [uri[]] $ProxyList,
        # Specifies the authentication mechanism to use at the Web proxy
        [Parameter(Mandatory=$false, Position=5)]
        [ValidateSet('Basic','Digest','NTLM','Negotiate','Passport')]
        [string] $ProxyAuthentication,
        # Specifies the credentials to use to authenticate the user at the proxy
        [Parameter(Mandatory=$false, Position=6)]
        [pscredential] $ProxyCredential,
        # Returns an object representing transfered item.
        [Parameter(Mandatory=$false)]
        [switch] $PassThru
    )
    [hashtable] $paramStartBitsTransfer = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -notin 'ProxyUsage','ProxyList','ProxyAuthentication','ProxyCredential') {
            $paramStartBitsTransfer.Remove($Parameter)
        }
    }
    
    if (!$Destination) { $Destination = (Get-Location).ProviderPath }
    if (![System.IO.Path]::HasExtension($Destination)) { $Destination = Join-Path $Destination (Split-Path $Source -Leaf) }
    if (Test-Path $Destination) { Write-Verbose ('The Source [{0}] was not transfered to Destination [{0}] because it already exists.' -f $Source, $Destination) }
    else {
        Write-Verbose ('Downloading Source [{0}] to Destination [{1}]' -f $Source, $Destination);
        Start-BitsTransfer $Source $Destination @paramStartBitsTransfer
    }
    if ($PassThru) { return Get-Item $Destination }
}

function Use-StartProcess {
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        # Specifies the path (optional) and file name of the program that runs in the process.
        [Parameter(Mandatory=$true, Position=0)]
        [string] $FilePath,
        # Specifies parameters or parameter values to use when starting the process.
        [Parameter(Mandatory=$false)]
        [string[]] $ArgumentList,
        # Specifies the working directory for the process.
        [Parameter(Mandatory=$false)]
        [string] $WorkingDirectory,
        # Specifies a user account that has permission to perform this action.
        [Parameter(Mandatory=$false)]
        [pscredential] $Credential,
        # Regex pattern in cmdline to replace with '**********'
        [Parameter(Mandatory=$false)]
        [string[]] $SensitiveDataFilters
    )
    [hashtable] $paramStartProcess = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -in 'SensitiveDataFilters') {
            $paramStartProcess.Remove($Parameter)
        }
    }
    [string] $cmd = '"{0}" {1}' -f $FilePath, ($ArgumentList -join ' ')
    foreach ($Filter in $SensitiveDataFilters) {
        $cmd = $cmd -replace $Filter,'**********'
    }
    if ($PSCmdlet.ShouldProcess([System.Environment]::MachineName, $cmd)) {
        [System.Diagnostics.Process] $process = Start-Process -PassThru -Wait @paramStartProcess
        if ($process.ExitCode -ne 0) { Write-Error -Category FromStdErr -CategoryTargetName (Split-Path $FilePath -Leaf) -CategoryTargetType "Process" -TargetObject $cmd -CategoryReason "Exit Code not equal to 0" -Message ('Process [{0}] with Id [{1}] terminated with Exit Code [{2}]' -f $FilePath, $process.Id, $process.ExitCode) }
    }
}

function Invoke-WindowsInstaller {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        # Path to msi or msp
        [Parameter(Mandatory=$true, Position=0)]
        [System.IO.FileInfo] $Path,
        # Sets user interface level
        [Parameter(Mandatory=$false)]
        [ValidateSet('None','Basic','Reduced','Full')]
        [string] $UserInterfaceMode,
        # Restart Options
        [Parameter(Mandatory=$false)]
        [ValidateSet('No','Prompt','Force')]
        [string] $RestartOptions,
        # Logging Options
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[iwearucmopvx\+!\*]{0,14}$')]
        [string] $LoggingOptions,
        # Path of log file
        [Parameter(Mandatory=$false)]
        [System.IO.FileInfo] $LogPath,
        # Public Properties
        [Parameter(Mandatory=$false)]
        [hashtable] $PublicProperties,
        # Specifies the working directory for the process.
        [Parameter(Mandatory=$false)]
        [string] $WorkingDirectory,
        # Regex pattern in cmdline to replace with '**********'
        [Parameter(Mandatory=$false)]
        [string[]] $SensitiveDataFilters
    )
 
    [System.IO.FileInfo] $itemLogPath = (Get-Location).ProviderPath
    if ($LogPath) { $itemLogPath = $LogPath }
    if (!$itemLogPath.Extension) { $itemLogPath = Join-Path $itemLogPath.FullName ('{0}.{1}.log' -f (Split-Path $Path -Leaf),(Get-Date -Format "yyyyMMddThhmmss")) }

    ## Windows Installer Arguments
    [System.Collections.Generic.List[string]] $argMsiexec = New-Object "System.Collections.Generic.List[string]"
    switch ($UserInterfaceMode)
    {
        'None' { $argMsiexec.Add('/qn'); break }
        'Basic' { $argMsiexec.Add('/qb'); break }
        'Reduced' { $argMsiexec.Add('/qr'); break }
        'Full' { $argMsiexec.Add('/qf'); break }
    }
    
    switch ($Restart)
    {
        'No' { $argMsiexec.Add('/norestart'); break }
        'Prompt' { $argMsiexec.Add('/promptrestart'); break }
        'Force' { $argMsiexec.Add('/forcerestart'); break }
    }

    if ($LoggingOptions -or $LogPath) { $argMsiexec.Add(('/l{0} "{1}"' -f $LoggingOptions, $itemLogPath.FullName)) }
    switch ($Path.Extension)
    {
        '.msi' { $argMsiexec.Add('/i "{0}"' -f $Path); break }
        '.msp' { $argMsiexec.Add('/update "{0}"' -f $Path); break }
        Default { $argMsiexec.Add('/i "{0}"' -f $Path); break }
    }

    foreach ($PropertyKey in $PublicProperties.Keys) {
        $argMsiexec.Add(('{0}="{1}"' -f $PropertyKey.ToUpper(), $PublicProperties[$PropertyKey]))
    }

    [hashtable] $paramStartProcess = @{}
    if ($argMsiexec) { $paramStartProcess["ArgumentList"] = $argMsiexec }
    if ($WorkingDirectory) { $paramStartProcess["WorkingDirectory"] = $WorkingDirectory }

    Use-StartProcess msiexec @paramStartProcess
}

function Get-MIMPrerequisites {
    [CmdletBinding()]
    Param (
        # Directory where deployment resources are located
        [Parameter(Mandatory=$true, Position=0)]
        [string] $WorkspaceDirectory,
        # Directory where deployment software is located
        [Parameter(Mandatory=$false, Position=1)]
        [string] $SoftwareDirectory = (Join-Path $WorkspaceDirectory "Software"),
        # Directory where deployment logs are located
        [Parameter(Mandatory=$false, Position=2)]
        [string] $LogDirectory = (Join-Path $WorkspaceDirectory "Logs"),
        # Specifies the proxy usage settings
        [Parameter(Mandatory=$false, Position=3)]
        [ValidateSet('SystemDefault','NoProxy','AutoDetect','Override')]
        [string] $ProxyUsage,
        # Specifies a list of proxies to use
        [Parameter(Mandatory=$false, Position=4)]
        [uri[]] $ProxyList,
        # Specifies the authentication mechanism to use at the Web proxy
        [Parameter(Mandatory=$false, Position=5)]
        [ValidateSet('Basic','Digest','NTLM','Negotiate','Passport')]
        [string] $ProxyAuthentication,
        # Specifies the credentials to use to authenticate the user at the proxy
        [Parameter(Mandatory=$false, Position=6)]
        [pscredential] $ProxyCredential
    )
 
    [hashtable] $paramUseStartBitsTransfer = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -notin 'ProxyUsage','ProxyList','ProxyAuthentication','ProxyCredential') {
            $paramUseStartBitsTransfer.Remove($Parameter)
        }
    }

    ### Modules and Functions
    Import-Module BitsTransfer

    ### Create Directories
    if (!(Get-Item $WorkspaceDirectory -ErrorAction SilentlyContinue)) { New-Item $WorkspaceDirectory -Type directory | Out-Null }
    if (!(Get-Item $SoftwareDirectory -ErrorAction SilentlyContinue)) { New-Item $SoftwareDirectory -Type directory | Out-Null }
    if (!(Get-Item $LogDirectory -ErrorAction SilentlyContinue)) { New-Item $LogDirectory -Type directory | Out-Null }

    ### Download & Extract
    ## Download MIM Sync, Service, Portal Prerequisites
    [System.Collections.Generic.Dictionary[string,System.IO.FileInfo]] $ResourcePath = New-Object 'System.Collections.Generic.Dictionary[string,System.IO.FileInfo]'
    $ResourcePath['Microsoft Identity Manager 2016'] = Join-Path $SoftwareDirectory "SW_DVD5_Identity_Manager-CAL_2016w_SP1_64Bit_English_-2_MLF_X21-21816.ISO" #"en_microsoft_identity_manager_2016_x64_dvd_6818274.iso" or "SW_DVD5_Identity_Manager-CAL_2016_64Bit_English_Core_MLF_X20-29215.ISO"
#    $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM 2016'] = Use-StartBitsTransfer 'http://hotfixv4.microsoft.com/Microsoft%20Identity%20Manager/latest/KB3092179/4.3.2064.0/free/488603_intl_x64_zip.exe' $SoftwareDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['MIM Workflow Activity Library'] = Join-Path $SoftwareDirectory "MIMWAL.zip"
#    $ResourcePath['MIM Hybrid Reporting'] = Join-Path $SoftwareDirectory "HybridReportingInstaller.zip"
    $ResourcePath['Microsoft SQL Server 2012 SP2 Native Client'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/3/A/6/3A632674-A016-4E31-A675-94BE390EA739/ENU/x64/sqlncli.msi' $SoftwareDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['SharePoint Foundation 2013 with SP1'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/6/E/3/6E3A0B03-F782-4493-950B-B106A1854DE1/sharepoint.exe' $SoftwareDirectory -PassThru @paramUseStartBitsTransfer

    ## Extract MIM Update
#    [string] $MIMUpdateDirectory = Get-ExtractionFolder $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM 2016']
#    if (!(Test-Path $MIMUpdateDirectory -PathType Container)) {
#        $MIMUpdateDirectory | clip
#        Write-Host ('Extract Package [{0}] to Directory [{1}]. The directory path was already copied to the clipboard so it can be pasted in.' -f $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM 2016'].BaseName, $MIMUpdateDirectory)
#        Use-StartProcess -ErrorAction Stop -FilePath $ResourcePath['Hotfix Rollup Package (4.3.2064.0) for MIM 2016'].FullName
#    }
    $ResourcePath['Hotfix Rollup Package (4.4.1459.0) for MIM Sync'] = Join-Path $SoftwareDirectory "FIMSyncService_x64_KB4012498.msp"
    $ResourcePath['Hotfix Rollup Package (4.4.1459.0) for MIM Service/Portal'] = Join-Path $SoftwareDirectory "FIMService_x64_KB4012498.msp"

    ## Extract MIM Workflow Activity 
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [string] $MIMWALDirectory = Get-ExtractionFolder $ResourcePath['MIM Workflow Activity Library']
    if (!(Test-Path $MIMWALDirectory -PathType Container)) { [System.IO.Compression.ZipFile]::ExtractToDirectory($ResourcePath['MIM Workflow Activity Library'].FullName,$MIMWALDirectory) }
    $ResourcePath['MIM Workflow Activity Library Register'] = Join-Path $MIMWALDirectory "Register.ps1"
    $ResourcePath['MIM Workflow Activity Library UpdateWorkflowXoml'] = Join-Path $MIMWALDirectory "UpdateWorkflowXoml.ps1"
    
    ## Extract MIM Hybrid Reporting
#    Add-Type -AssemblyName System.IO.Compression.FileSystem
#    [string] $MIMHybridReportingDirectory = Get-ExtractionFolder $ResourcePath['MIM Hybrid Reporting']
#    if (!(Test-Path $MIMHybridReportingDirectory -PathType Container)) { [System.IO.Compression.ZipFile]::ExtractToDirectory($ResourcePath['MIM Hybrid Reporting'].FullName,$MIMHybridReportingDirectory) }
#    $ResourcePath['MIM Hybrid Reporting Installer'] = Join-Path $MIMHybridReportingDirectory "MIMHybridReportingAgent.msi"
#    $ResourcePath['MIM Hybrid Reporting Certificate'] = Join-Path $MIMHybridReportingDirectory "tenant.cert"

    ## Extract SharePoint
    [string] $SharePointDirectory = Get-ExtractionFolder $ResourcePath['SharePoint Foundation 2013 with SP1']
    [string] $SharePointPrerequisitesDirectory = (Join-Path $SharePointDirectory 'prerequisiteinstallerfiles')
    if (!(Test-Path $SharePointDirectory -PathType Container)) {
        Use-StartProcess -ErrorAction Stop -FilePath $ResourcePath['SharePoint Foundation 2013 with SP1'].FullName -ArgumentList @(
            '/quiet',
            ('/extract:"{0}"' -f $SharePointDirectory),
            ('/log:"{0}"' -f (Join-Path $LogDirectory (New-LogFilename $ResourcePath['SharePoint Foundation 2013 with SP1'].BaseName)))
        )
    }
    $ResourcePath['SharePoint Foundation 2013 with SP1 Prerequisites'] = Join-Path $SharePointDirectory 'prerequisiteinstaller.exe'
    $ResourcePath['SharePoint Foundation 2013 with SP1 Setup'] = Join-Path $SharePointDirectory 'setup.exe'

    ## Download SharePoint Prerequisites
    $ResourcePath['Microsoft SQL Server 2008 R2 SP1 Native Client (x64)'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/9/1/3/9138773A-505D-43E2-AC08-9A77E1E0490B/1033/x64/sqlncli.msi' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Windows Management Framework 3.0 (Windows6.1-KB2506143-x64)'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/E/7/6/E76850B8-DA6E-4FF5-8CCE-A24FC513FD16/Windows6.1-KB2506143-x64.msu' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Microsoft .NET Framework 4.5'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/b/a/4/ba4a7e71-2906-4b2d-a0e1-80cf16844f5f/dotnetfx45_full_x86_x64.exe' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Windows Identity Foundation (Windows6.1-KB974405-x64)'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/D/7/2/D72FD747-69B6-40B7-875B-C2B40A6B2BDD/Windows6.1-KB974405-x64.msu' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Windows Identity Foundation v1.1 (Windows Identity Extensions)'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/0/1/D/01D06854-CA0C-46F1-ADBA-EBF86010DCC6/rtm/MicrosoftIdentityExtensions-64.msi' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Microsoft Sync Framework Runtime v1.0 SP1 (x64)'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/E/0/0/E0060D8F-2354-4871-9596-DC78538799CC/Synchronization.msi' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Windows Server AppFabric (x64)'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/A/6/7/A678AB47-496B-4907-B3D4-0A2D280A13C0/WindowsServerAppFabricSetup_x64.exe' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Cumulative Update Package 1 for Microsoft AppFabric 1.1 for Windows Server (KB2671763-x64-ENU)'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/7/B/5/7B51D8D1-20FD-4BF0-87C7-4714F5A1C313/AppFabric1.1-RTM-KB2671763-x64-ENU.exe' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Microsoft Information Protection and Control Client'] = Use-StartBitsTransfer 'http://download.microsoft.com/download/9/1/D/91DA8796-BE1D-46AF-8489-663AB7811517/setup_msipc_x64.msi' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Microsoft WCF Data Services 5.0 for OData V3'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/8/F/9/8F93DBBD-896B-4760-AC81-646F61363A6D/WcfDataServices.exe' $SharePointPrerequisitesDirectory -PassThru @paramUseStartBitsTransfer
    $ResourcePath['Microsoft WCF Data Services 5.6'] = Use-StartBitsTransfer 'https://download.microsoft.com/download/1/C/A/1CAA41C7-88B9-42D6-9E11-3C655656DAB1/WcfDataServices.exe' (Join-Path $SharePointPrerequisitesDirectory 'WcfDataServices56.exe') -PassThru @paramUseStartBitsTransfer

    return $ResourcePath
}

function Install-MIMSynchronizationService {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        # Path to 'Synchronization Service.msi'
        [Parameter(Mandatory=$true, Position=0)]
        [System.IO.FileInfo] $Path,
        # Sets user interface level
        [Parameter(Mandatory=$false)]
        [ValidateSet('None','Basic','Reduced','Full')]
        [string] $UserInterfaceMode,
        # Restart Options
        [Parameter(Mandatory=$false)]
        [ValidateSet('No','Prompt','Force')]
        [string] $RestartOptions,
        # Logging Options
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[iwearucmopvx\+!\*]{0,14}$')]
        [string] $LoggingOptions,
        # Path of log file
        [Parameter(Mandatory=$false)]
        [System.IO.FileInfo] $LogPath,

        # Accept the EULA
        [Parameter(Mandatory=$true)]
        [switch] $AcceptEULA,
        # Path to install MIM should end with "Microsoft Identity Manager\2016"
        [Parameter(Mandatory=$false)]
        [string] $InstallPath,
        # Name of SQL Server
        [Parameter(Mandatory=$false)]
        [string] $SQLServer,
        # Name of database instance
        [Parameter(Mandatory=$false)]
        [string] $SQLServerInstance,
        # Name of database
        [Parameter(Mandatory=$false)]
        [string] $SQLServerDatabaseName,
        # Service account credential
        [Parameter(Mandatory=$true)]
        [pscredential] $ServiceAccount,

        # Domain of FIM groups
        [Parameter(Mandatory=$false)]
        [string] $GroupsDomain,
        # Name of admin group
        [Parameter(Mandatory=$false)]
        [string] $AdminsGroup,
        # Name of operators group
        [Parameter(Mandatory=$false)]
        [string] $OperatorsGroup,
        # Name of joiners group
        [Parameter(Mandatory=$false)]
        [string] $JoinersGroup,
        # Name of browse group
        [Parameter(Mandatory=$false)]
        [string] $BrowseGroup,
        # Name of password set group
        [Parameter(Mandatory=$false)]
        [string] $PasswordSetGroup,
        # Configure firewall
        [Parameter(Mandatory=$false)]
        [switch] $ConfigureFirewall,
        # Opt in to Software Quality Management (SQM)
        [Parameter(Mandatory=$false)]
        [switch] $OptInSQM
    )

    [hashtable] $paramInvokeWindowsInstaller = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -notin 'Path','UserInterfaceMode','RestartOptions','LoggingOptions','LogPath') {
            $paramInvokeWindowsInstaller.Remove($Parameter)
        }
    }

    if ($GroupsDomain) {
        if (!$AdminsGroup) { $AdminsGroup = "MIMSyncAdmins" }
        if (!$OperatorsGroup) { $OperatorsGroup = "MIMSyncOperators" }
        if (!$JoinersGroup) { $JoinersGroup = "MIMSyncJoiners" }
        if (!$BrowseGroup) { $BrowseGroup = "MIMSyncBrowse" }
        if (!$PasswordSetGroup) { $PasswordSetGroup = "MIMSyncPasswordSet" }

        if (!$AdminsGroup.Contains('\')) { $AdminsGroup = '{0}\{1}' -f $GroupsDomain, $AdminsGroup }
        if (!$OperatorsGroup.Contains('\')) { $OperatorsGroup = '{0}\{1}' -f $GroupsDomain, $OperatorsGroup }
        if (!$JoinersGroup.Contains('\')) { $JoinersGroup = '{0}\{1}' -f $GroupsDomain, $JoinersGroup }
        if (!$BrowseGroup.Contains('\')) { $BrowseGroup = '{0}\{1}' -f $GroupsDomain, $BrowseGroup }
        if (!$PasswordSetGroup.Contains('\')) { $PasswordSetGroup = '{0}\{1}' -f $GroupsDomain, $PasswordSetGroup }
    }

    [hashtable] $hashPublicProperties = @{}
    if ($AcceptEULA) { $hashPublicProperties['ACCEPT_EULA'] = [int][bool]$AcceptEULA }
    if ($InstallPath) { $hashPublicProperties['INSTALLDIR'] = $InstallPath }
    if ($SQLServer) { $hashPublicProperties['STORESERVER'] = $SQLServer }
    if ($SQLServerInstance) { $hashPublicProperties['SQLINSTANCE'] = $SQLServerInstance }
    if ($SQLServerDatabaseName) { $hashPublicProperties['SQLDB'] = $SQLServerDatabaseName }
    if ($ServiceAccount) {
        [System.Net.NetworkCredential] $ServiceAccountNetCred = $ServiceAccount.GetNetworkCredential()
        if ($ServiceAccountNetCred.UserName) { $hashPublicProperties['SERVICEACCOUNT'] = $ServiceAccountNetCred.UserName }
        if ($ServiceAccountNetCred.Password) { $hashPublicProperties['SERVICEPASSWORD'] = $ServiceAccountNetCred.Password }
        if ($ServiceAccountNetCred.Domain) { $hashPublicProperties['SERVICEDOMAIN'] = $ServiceAccountNetCred.Domain }
        Remove-Variable ServiceAccountNetCred -WhatIf:$false
    }
    if ($AdminsGroup) { $hashPublicProperties['GROUPADMINS'] = $AdminsGroup }
    if ($OperatorsGroup) { $hashPublicProperties['GROUPOPERATORS'] = $OperatorsGroup }
    if ($JoinersGroup) { $hashPublicProperties['GROUPACCOUNTJOINERS'] = $JoinersGroup }
    if ($BrowseGroup) { $hashPublicProperties['GROUPBROWSE'] = $BrowseGroup }
    if ($PasswordSetGroup) { $hashPublicProperties['GROUPPASSWORDSET'] = $PasswordSetGroup }
    if ($ConfigureFirewall) { $hashPublicProperties['FIREWALL_CONF'] = [int][bool]$ConfigureFirewall }
    if ($OptInSQM) { $hashPublicProperties['SQMOPTINSETTING'] = [int][bool]$OptInSQM }

    Invoke-WindowsInstaller -PublicProperties $hashPublicProperties -SensitiveDataFilters '(?<=SERVICE_ACCOUNT_PASSWORD=")(.*?)(?=")' @paramInvokeWindowsInstaller
}

function Install-MIMService {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param (
        # Path to 'Service and Portal.msi'
        [Parameter(Mandatory=$true, Position=0)]
        [System.IO.FileInfo] $Path,
        # Sets user interface level
        [Parameter(Mandatory=$false)]
        [ValidateSet('None','Basic','Reduced','Full')]
        [string] $UserInterfaceMode,
        # Restart Options
        [Parameter(Mandatory=$false)]
        [ValidateSet('No','Prompt','Force')]
        [string] $RestartOptions,
        # Logging Options
        [Parameter(Mandatory=$false)]
        [ValidatePattern('^[iwearucmopvx\+!\*]{0,14}$')]
        [string] $LoggingOptions,
        # Path of log file
        [Parameter(Mandatory=$false)]
        [System.IO.FileInfo] $LogPath,

        # Features to Install
        [Parameter(Mandatory=$true)]
        [ValidateSet('MIMService','MIMPortal','SSPRRegistrationPortal','SSPRResetPortal')]
        [string[]] $Features,
        # Accept the EULA
        [Parameter(Mandatory=$true)]
        [switch] $AcceptEULA,
        # Path to install MIM should end with "Microsoft Identity Manager\2016"
        [Parameter(Mandatory=$false)]
        [string] $InstallPath,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $UseExistingDatabase,
        # Name of SQL Server
        [Parameter(Mandatory=$false)]
        [string] $SQLServer,
        # Name of database instance
        [Parameter(Mandatory=$false)]
        [string] $SQLServerInstance,
        # Name of database
        [Parameter(Mandatory=$false)]
        [string] $SQLServerDatabaseName,
        # Service account credential
        [Parameter(Mandatory=$false)]
        [pscredential] $ServiceAccount,
        # 
        [Parameter(Mandatory=$false)]
        [string] $ServiceAccountEmail,
        # 
        [Parameter(Mandatory=$false)]
        [string] $MailServer,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $MailServerUseSSL,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $MailServerIsExchange,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $MailServerPollExchange,
        # 
        [Parameter(Mandatory=$false)]
        [string] $ServiceAddress,
        
        # 
        [Parameter(Mandatory=$false)]
        [string] $CertificateName,

        # 
        [Parameter(Mandatory=$false)]
        [string] $ServiceSyncAccount,
        # 
        [Parameter(Mandatory=$false)]
        [string] $SyncServer,
        
        # 
        [Parameter(Mandatory=$false)]
        [string] $ServiceManagerServer,

        # 
        [Parameter(Mandatory=$false)]
        [string] $SharePointUrl,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $GrantUsersAccessToMIMPortal,

        # 
        [Parameter(Mandatory=$false)]
        [string] $SSPRRegistrationUrl,
        # 
        [Parameter(Mandatory=$false)]
        [pscredential] $SSPRRegistrationAccount,
        # 
        [Parameter(Mandatory=$false)]
        [string] $SSPRRegistrationHostName,
        # 
        [Parameter(Mandatory=$false)]
        [int] $SSPRRegistrationPort,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $SSPRRegistrationExtranetAccess,
        # 
        [Parameter(Mandatory=$false)]
        [pscredential] $SSPRResetAccount,
        # 
        [Parameter(Mandatory=$false)]
        [string] $SSPRResetHostName,
        # 
        [Parameter(Mandatory=$false)]
        [int] $SSPRResetPort,
        # 
        [Parameter(Mandatory=$false)]
        [switch] $SSPRResetExtranetAccess,
        
        # Configure firewall
        [Parameter(Mandatory=$false)]
        [switch] $ConfigureFirewall,
        # Opt in to Software Quality Management (SQM)
        [Parameter(Mandatory=$false)]
        [switch] $OptInSQM
    )

    [hashtable] $paramInvokeWindowsInstaller = $PSBoundParameters
    foreach ($Parameter in $PSBoundParameters.Keys) {
        if ($Parameter -notin 'Path','UserInterfaceMode','RestartOptions','LoggingOptions','LogPath') {
            $paramInvokeWindowsInstaller.Remove($Parameter)
        }
    }

    if ($SQLServerInstance) {
        if (!$SQLServer) { $SQLServer = '{0}\{1}' -f 'localhost', $SQLServerInstance }
        elseif (!$SQLServer.Contains('\')) { $SQLServer = '{0}\{1}' -f $SQLServer, $SQLServerInstance }
    }

    [string[]] $AddLocal = $Features -replace 'MIMService','CommonServices' -replace 'MIMPortal','WebPortals' -replace 'SSPRRegistrationPortal','RegistrationPortal' -replace 'SSPRResetPortal','ResetPortal'

    [hashtable] $hashPublicProperties = @{}
    if ($AddLocal) { $hashPublicProperties['ADDLOCAL'] = $AddLocal -join ',' }
    if ($PSBoundParameters.ContainsKey('AcceptEULA')) { $hashPublicProperties['ACCEPT_EULA'] = [int][bool]$AcceptEULA }
    if ($InstallPath) { $hashPublicProperties['INSTALLDIR'] = $InstallPath }
    if ($UseExistingDatabase) { $hashPublicProperties['EXISTINGDATABASE'] = [int][bool]$UseExistingDatabase }
    if ($SQLServer) { $hashPublicProperties['SQLSERVER_SERVER'] = $SQLServer }
    if ($SQLServerDatabaseName) { $hashPublicProperties['SQLSERVER_DATABASE'] = $SQLServerDatabaseName }
    if ($ServiceAddress) { $hashPublicProperties['SERVICEADDRESS'] = $ServiceAddress }
    if ($ServiceAccount) {
        [System.Net.NetworkCredential] $ServiceAccountNetCred = $ServiceAccount.GetNetworkCredential()
        if ($ServiceAccountNetCred.UserName) { $hashPublicProperties['SERVICE_ACCOUNT_NAME'] = $ServiceAccountNetCred.UserName }
        if ($ServiceAccountNetCred.Password) { $hashPublicProperties['SERVICE_ACCOUNT_PASSWORD'] = $ServiceAccountNetCred.Password }
        if ($ServiceAccountNetCred.Domain) { $hashPublicProperties['SERVICE_ACCOUNT_DOMAIN'] = $ServiceAccountNetCred.Domain }
        Remove-Variable ServiceAccountNetCred -WhatIf:$false
    }
    if ($ServiceAccountEmail) { $hashPublicProperties['SERVICE_ACCOUNT_EMAIL'] = $ServiceAccountEmail }
    if ($MailServer) { $hashPublicProperties['MAIL_SERVER'] = $MailServer }
    if ($PSBoundParameters.ContainsKey('MailServerUseSSL')) { $hashPublicProperties['MAIL_SERVER_USE_SSL'] = [int][bool]$MailServerUseSSL }
    if ($PSBoundParameters.ContainsKey('MailServerIsExchange')) { $hashPublicProperties['MAIL_SERVER_IS_EXCHANGE'] = [int][bool]$MailServerIsExchange }
    if ($PSBoundParameters.ContainsKey('MailServerPollExchange')) { $hashPublicProperties['POLL_EXCHANGE_ENABLED'] = [int][bool]$MailServerPollExchange }
    
    if ($CertificateName) { $hashPublicProperties['CERTIFICATE_NAME'] = $CertificateName }

    if ($SyncServer) { $hashPublicProperties['SYNCHRONIZATION_SERVER'] = $SyncServer }
    if ($ServiceSyncAccount) { $hashPublicProperties['SYNCHRONIZATION_SERVER_ACCOUNT'] = $ServiceSyncAccount }
    
    if ($SharePointUrl) { $hashPublicProperties['SHAREPOINT_URL'] = $SharePointUrl }
    if ($PSBoundParameters.ContainsKey('GrantUsersAccessToMIMPortal')) { $hashPublicProperties['SHAREPOINTUSERS_CONF'] = [int][bool]$GrantUsersAccessToMIMPortal }

    if ($SSPRRegistrationUrl) { $hashPublicProperties['REGISTRATION_PORTAL_URL'] = $SSPRRegistrationUrl }
    if ($SSPRRegistrationAccount) {
        [System.Net.NetworkCredential] $SSPRRegistrationAccountNetCred = $SSPRRegistrationAccount.GetNetworkCredential()
        if ($SSPRRegistrationAccount.UserName) { $hashPublicProperties['REGISTRATION_ACCOUNT'] = $SSPRRegistrationAccount.UserName }
        if ($SSPRRegistrationAccountNetCred.Password) { $hashPublicProperties['REGISTRATION_ACCOUNT_PASSWORD'] = $SSPRRegistrationAccountNetCred.Password }
        Remove-Variable SSPRRegistrationAccountNetCred -WhatIf:$false
    }
    if ($SSPRRegistrationHostName) { $hashPublicProperties['REGISTRATION_HOSTNAME'] = $SSPRRegistrationHostName }
    if ($SSPRRegistrationPort) { $hashPublicProperties['REGISTRATION_PORT'] = $SSPRRegistrationPort }
    if ($PSBoundParameters.ContainsKey('ConfigureFirewall')) { $hashPublicProperties['REGISTRATION_FIREWALL_CONFIG'] = [int][bool]$ConfigureFirewall }
    if ($ServiceAddress) { $hashPublicProperties['REGISTRATION_SERVERNAME'] = $ServiceAddress }
    if ($PSBoundParameters.ContainsKey('SSPRRegistrationExtranetAccess')) { $hashPublicProperties['IS_REGISTRATION_EXTRANET'] = if ($SSPRRegistrationExtranetAccess) { "Extranet" } else { "None" } }
    if ($SSPRResetAccount) {
        [System.Net.NetworkCredential] $SSPRResetAccountNetCred = $SSPRResetAccount.GetNetworkCredential()
        if ($SSPRResetAccount.UserName) { $hashPublicProperties['RESET_ACCOUNT'] = $SSPRResetAccount.UserName }
        if ($SSPRResetAccountNetCred.Password) { $hashPublicProperties['RESET_ACCOUNT_PASSWORD'] = $SSPRResetAccountNetCred.Password }
        Remove-Variable SSPRResetAccountNetCred -WhatIf:$false
    }
    if ($SSPRResetHostName) { $hashPublicProperties['RESET_HOSTNAME'] = $SSPRResetHostName }
    if ($SSPRResetPort) { $hashPublicProperties['RESET_PORT'] = $SSPRResetPort }
    if ($PSBoundParameters.ContainsKey('ConfigureFirewall')) { $hashPublicProperties['RESET_FIREWALL_CONFIG'] = [int][bool]$ConfigureFirewall }
    if ($ServiceAddress) { $hashPublicProperties['RESET_SERVERNAME'] = $ServiceAddress }
    if ($PSBoundParameters.ContainsKey('SSPRResetExtranetAccess')) { $hashPublicProperties['IS_RESET_EXTRANET'] = if ($SSPRResetExtranetAccess) { "Extranet" } else { "None" } }


    if ($PSBoundParameters.ContainsKey('ConfigureFirewall')) { $hashPublicProperties['FIREWALL_CONF'] = [int][bool]$ConfigureFirewall }
    if ($PSBoundParameters.ContainsKey('OptInSQM')) { $hashPublicProperties['SQMOPTINSETTING'] = [int][bool]$OptInSQM }

    Invoke-WindowsInstaller -PublicProperties $hashPublicProperties -Verbose @paramInvokeWindowsInstaller
}

function Update-WebConfigResourceManagementClient {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $WebConfigPath = (Join-Path $env:SystemDrive 'inetpub\wwwroot\wss\VirtualDirectories\80\web.config'),
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true)]
        [uri] $resourceManagementServiceBaseAddress, # ('http://{0}:5725' -f $env:COMPUTERNAME)
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true)]
        [switch] $requireKerberos,
        [Parameter(Mandatory=$false, ValueFromPipeline=$false, ValueFromPipelineByPropertyName=$true)]
        [int] $timeoutInMilliseconds
    )

    # Check Path
    [string] $pathWebConfig = Resolve-Path ([Environment]::ExpandEnvironmentVariables($WebConfigPath)) -ErrorAction Stop

    # Load XML File
    $xmlWebConfig = New-Object XML
    $xmlWebConfig.Load($pathWebConfig)
   
    # Edit XML File
    if ($PSBoundParameters.ContainsKey('resourceManagementServiceBaseAddress')) { $xmlWebConfig.configuration.resourceManagementClient.SetAttribute('resourceManagementServiceBaseAddress',$resourceManagementServiceBaseAddress) }
    if ($PSBoundParameters.ContainsKey('requireKerberos')) { $xmlWebConfig.configuration.resourceManagementClient.SetAttribute('requireKerberos',$requireKerberos) }
    if ($PSBoundParameters.ContainsKey('timeoutInMilliseconds')) { $xmlWebConfig.configuration.resourceManagementClient.SetAttribute('timeoutInMilliseconds',$timeoutInMilliseconds) }

    # Save XML File
    $xmlWebConfig.Save($pathWebConfig)

}
