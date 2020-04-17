[CmdletBinding()]
Param (
    # Directory where deployment resources are located
    [Parameter(Mandatory=$false, Position=0)]
    [string] $WorkspaceDirectory = "\\site1-file01\SWInstall\Microsoft\MIM",
    # Directory where deployment software is located
    [Parameter(Mandatory=$false, Position=1)]
    [string] $SoftwareDirectory,
    # Directory where deployment logs are located
    [Parameter(Mandatory=$false, Position=2)]
    [string] $LogDirectory,
    # Specifies the proxy usage settings
    [Parameter(Mandatory=$false, Position=3)]
    [ValidateSet('SystemDefault','NoProxy','AutoDetect','Override')]
    [string] $ProxyUsage = 'SystemDefault',
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
cd C:\Repository\bin\MIM
Import-Module .\MIMInstallationTools.psm1

[hashtable] $paramGetMIMPrerequisites = @{}
if ($WorkspaceDirectory) { $paramGetMIMPrerequisites['WorkspaceDirectory'] = $WorkspaceDirectory }
if ($SoftwareDirectory) { $paramGetMIMPrerequisites['SoftwareDirectory'] = $SoftwareDirectory }
if ($LogDirectory) { $paramGetMIMPrerequisites['LogDirectory'] = $LogDirectory }
if ($ProxyUsage) { $paramGetMIMPrerequisites['ProxyUsage'] = $ProxyUsage }
if ($ProxyList) { $paramGetMIMPrerequisites['ProxyList'] = $ProxyList }
if ($ProxyAuthentication) { $paramGetMIMPrerequisites['ProxyAuthentication'] = $ProxyAuthentication }
if ($ProxyCredential) { $paramGetMIMPrerequisites['ProxyCredential'] = $ProxyCredential }

## Get deployment resources
[System.Collections.Generic.Dictionary[string,System.IO.FileInfo]] $ResourcePath = Get-MIMPrerequisites -ErrorAction Stop @paramGetMIMPrerequisites
