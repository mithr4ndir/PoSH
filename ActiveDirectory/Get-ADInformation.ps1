<#
Domain admin access required, specially for Get-ADFineGrainedPasswordPolicy
#>
$starttime = Get-Date
$FileLocation = "\\site1-CSRPT01\C$\Windows\Web\ADInfo","\\site2-CSRPT01\C$\Windows\Web\ADInfo"
Function Append-ADUserAccountControl 
{
    [cmdletbinding()]
    param
    (
        [Parameter(HelpMessage='User or users to process.',
                   Mandatory=$true,
                   ValueFromPipeline=$true)]
        [psobject[]]$User
    )

    BEGIN
    {
        Add-Type -TypeDefinition @" 
        [System.Flags]
        public enum userAccountControlFlags {
            SCRIPT                                  = 0x0000001,
            ACCOUNTDISABLE                          = 0x0000002,
            NOT_USED                                = 0x0000004,
            HOMEDIR_REQUIRED                        = 0x0000008,
            LOCKOUT                                 = 0x0000010,
            PASSWD_NOTREQD                          = 0x0000020,
            PASSWD_CANT_CHANGE                      = 0x0000040,
            ENCRYPTED_TEXT_PASSWORD_ALLOWED         = 0x0000080,
            TEMP_DUPLICATE_ACCOUNT                  = 0x0000100,
            NORMAL_ACCOUNT                          = 0x0000200,
            INTERDOMAIN_TRUST_ACCOUNT               = 0x0000800,
            WORKSTATION_TRUST_ACCOUNT               = 0x0001000,
            SERVER_TRUST_ACCOUNT                    = 0x0002000,
            DONT_EXPIRE_PASSWD                      = 0x0010000,
            MNS_LOGON_ACCOUNT                       = 0x0020000,
            SMARTCARD_REQUIRED                      = 0x0040000,
            TRUSTED_FOR_DELEGATION                  = 0x0080000,
            NOT_DELEGATED                           = 0x0100000,
            USE_DES_KEY_ONLY                        = 0x0200000,
            DONT_REQUIRE_PREAUTH                    = 0x0400000,
            PASSWORD_EXPIRED                        = 0x0800000,
            TRUSTED_TO_AUTH_FOR_DELEGATION          = 0x1000000
        }
"@
        $Users = @()
        $UACAttribs = @(
            'SCRIPT',
            'ACCOUNTDISABLE',
            'NOT_USED',
            'HOMEDIR_REQUIRED',
            'LOCKOUT',
            'PASSWD_NOTREQD',
            'PASSWD_CANT_CHANGE',
            'ENCRYPTED_TEXT_PASSWORD_ALLOWED',
            'TEMP_DUPLICATE_ACCOUNT',
            'NORMAL_ACCOUNT',
            'INTERDOMAIN_TRUST_ACCOUNT',
            'WORKSTATION_TRUST_ACCOUNT',
            'SERVER_TRUST_ACCOUNT',
            'DONT_EXPIRE_PASSWD',
            'MNS_LOGON_ACCOUNT',
            'SMARTCARD_REQUIRED',
            'TRUSTED_FOR_DELEGATION',
            'NOT_DELEGATED',
            'USE_DES_KEY_ONLY',
            'DONT_REQUIRE_PREAUTH',
            'PASSWORD_EXPIRED',
            'TRUSTED_TO_AUTH_FOR_DELEGATION',
            'PARTIAL_SECRETS_ACCOUNT'
        )
    }
    PROCESS
    {
        $Users += $User
    }
    END
    {
        Foreach ($usr in $Users)
        {
            if ($usr.PSObject.Properties.Match('useraccountcontrol').Count) 
            {
                try 
                {
                    $UAC = [Enum]::Parse('userAccountControlFlags', $usr.useraccountcontrol)
                    $UACAttribs | Foreach {
                        Add-Member -InputObject $usr -MemberType NoteProperty `
                        -Name $_ -Value ($UAC -match $_) -Force
                    }
                }
                catch
                {
                    Write-Warning -Message ('Append-ADUserAccountControl: {0}' -f $_.Exception.Message)
                }
            }
            $usr
        }
    }
}

$DomainDN = (Get-ADDomain).DistinguishedName

# Forest Information
$ForestInfo = "" | select Name,FunctionalLevel,DomainNamingMaster,SchemaMaster,Domains,Sites,"Domain Controllers","Global Catalogs",TombstoneLifetime,RecycleBinEnabled

$ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() #Get-ADForest 
$Tombstone = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$DomainDN" -properties "tombstonelifetime").tombstonelifetime 
$RecycleBin = (Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes 
    $ForestInfo.Name = $ADForest.Name
    $ForestInfo.FunctionalLevel = $ADForest.ForestMode
    $ForestInfo.Domains = $ADForest.Domains.Count
    $ForestInfo.SchemaMaster = $ADForest.SchemaRoleOwner
    $ForestInfo.DomainNamingMaster = $ADForest.NamingRoleOwner
    $ForestInfo.Sites = $ADForest.Sites.Count
    $ForestInfo.'Domain Controllers' = $ADForest.Domains.DomainControllers.Count
    $ForestInfo.'Global Catalogs' = $ADForest.GlobalCatalogs.Count
    $ForestInfo.TombstoneLifetime = if (!$Tombstone) {"60 days (default)"} else {$Tombstone}
    $ForestInfo.RecycleBinEnabled = if (!$RecycleBin) {$false} else {$true}

# Domains Info
$DomainsInfo = $ADForest.Domains | select Forest,DomainMode,Parent,PdcRoleOwner,RidRoleOwner,InfrastructureRoleOwner,Name
"DomainControllers","Children" | % {$DomainsInfo | Add-Member -MemberType NoteProperty -Name $_ -Value "" }
$DomainsInfo | % `
    {$DoName = $_.Name; 
    $_.DomainControllers = ($ADForest.Domains | ?{$_.Name -eq $DoName}).DomainControllers.Count
    $_.Children = ($ADForest.Domains | ?{$_.Name -eq $DoName}).Children.Name}
$DomainsInfo = $DomainsInfo | select Name,Forest,DomainControllers,Children,DomainMode,Parent,PdcRoleOwner,RidRoleOwner,InfrastructureRoleOwner

# Domain controllers ~ 45 sec
$CompanyxCorp = (Get-ADDomain -Current LocalComputer).replicadirectoryservers | % {Get-ADDomainController -Identity $_}
$NoneCompanyxCorp = ($ADForest.Domains | ?{$_.name -ne $env:USERDNSDOMAIN}).DomainControllers
# Since Get-ADDomainController not working as We implemented WAN optimization appliances, in our case Riverbed, and that's what in the end caused the Get-ADDomainController command to stop working.
$DCInfo = @() 
$GCNames = $ADForest.GlobalCatalogs.Name
$DCNames = if ($NoneCompanyxCorp) {$CompanyxCorp.Name + $NoneCompanyxCorp.name | ?{Test-Connection $_ -Count 1 -Quiet}}
           else {$CompanyxCorp.Name | ?{Test-Connection $_ -Count 1 -Quiet}}

if ($NoneCompanyxCorp) {
    $NoneCompanyxCorp | % `
        {
        $DCInfo += New-Object psobject -Property @{
            Domain = $_.Domain
            Site = $_.SiteName
            Name = $_.Name
            OS = $_.OSVersion.replace("Windows Server ","").replace("Technical Preview","TP").replace("Datacenter","DC").replace("Standard","Std").replace("Enterprise","Ent")
            IPv4Address = $_.IPAddress
            IPv6Address = ''
            SEP = ""
            PING = Test-Connection $_.Name -Count 1 -Quiet
            GC = if ($GCNames -contains $_.name) {$true} else {$false}
            Infra = if ($_.Roles -contains "InfrastructureRole") {$true} else {$false}
            Naming = if ($_.Roles -contains "NamingRole") {$true} else {$false}
            Schema = if ($_.Roles -contains "SchemaRole") {$true} else {$false}
            RID = if ($_.Roles -contains "RidRole") {$true} else {$false}
            PDC = if ($_.Roles -contains "PdcRole") {$true} else {$false}
            }
        }
    }

$CompanyxCorp | sort -Property @{Expression = {$_.OperationMasterRoles}; Ascending = $false}, Name | % `
    {$DC = $_.Name
    $DCInfo += New-Object psobject -Property @{
        Domain = $_.Domain
        Site = $_.Site
        Name = $_.HostName
        OS = $_.OperatingSystem.replace("Windows Server ","").replace("Technical Preview","TP").replace("Datacenter","DC").replace("Standard","Std").replace("Enterprise","Ent")
        IPv4Address = $_.IPv4Address
        IPv6Address = $_.IPv6Address #((Get-CimInstance win32_networkadapterconfiguration -filter "ipenabled = 'True'" -ComputerName $DC).IPAddress | ? {$_ -like "*:*:*" -and $_ -notlike "fe80:*"}) -join "; "
        PING = Test-Connection $_.Name -Count 1 -Quiet
        GC = $_.IsGlobalCatalog
        Infra = if ($_.OperationMasterRoles -contains "InfrastructureMaster") {$true} else {$false}
        Naming = if ($_.OperationMasterRoles -contains "DomainNamingMaster") {$true} else {$false}
        Schema = if ($_.OperationMasterRoles -contains "SchemaMaster") {$true} else {$false}
        RID = if ($_.OperationMasterRoles -contains "RIDMaster") {$true} else {$false}
        PDC = if ($_.OperationMasterRoles -contains "PDCEmulator") {$true} else {$false}
        }
    }

$DCInfo = $DCInfo | select Domain, Site, Name,OS,IPv4Address,IPv6Address,PING,GC,Schema,Naming,Infra,RID,PDC

# Domain password policies
$DomainPwdPolicies = $DomainPwdPolicies1 = @() # Domain,AppliesTo,Complexity,LockoutDuration,LockoutObservation,LockoutThreshold, MaxPwdAge, MinPwdAge,MinPwdLength,PwdHistory
$defaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $env:USERDNSDOMAIN
$DomainPwdPolicies += New-Object psobject -Property @{
    Domain = $env:USERDNSDOMAIN
    AppliesTo = "Default Domain Password Policy"
    Complexity = $defaultPwdPolicy.ComplexityEnabled
    LockoutDuration = $defaultPwdPolicy.LockoutDuration.TotalMinutes.ToString() + " Minutes"
    LockoutObservation = $defaultPwdPolicy.LockoutObservationWindow.TotalMinutes.ToString() + " Minutes"
    LockoutThreshold = $defaultPwdPolicy.LockoutThreshold
    MaxPwdAge = $defaultPwdPolicy.MaxPasswordAge.TotalDays.ToString() + " Days"
    MinPwdAge = $defaultPwdPolicy.MinPasswordAge.TotalDays.ToString() + " Days"
    MinPwdLength = $defaultPwdPolicy.MinPasswordLength
    PwdHistory = $defaultPwdPolicy.PasswordHistoryCount
    }

Get-ADFineGrainedPasswordPolicy -Filter * | % `
    {
    $DomainPwdPolicies1 += New-Object psobject -Property @{
        Domain = $env:USERDNSDOMAIN
        AppliesTo = $_.AppliesTo.Value
        Complexity = $_.ComplexityEnabled
        LockoutDuration = $_.LockoutDuration.TotalMinutes.ToString() + " Minutes"
        LockoutObservation = $_.LockoutObservationWindow.TotalMinutes.ToString() + " Minutes"
        LockoutThreshold = $_.LockoutThreshold
        MaxPwdAge = $_.MaxPasswordAge.TotalDays.ToString() + " Days"
        MinPwdAge = if ($_.MinPasswordAge.TotalDays -lt 1) {$_.MinPasswordAge.TotalMinutes.ToString() + " Minutes"} else {$_.MinPasswordAge.TotalDays.ToString() + " Days"}
        MinPwdLength = $_.MinPasswordLength
        PwdHistory = $_.PasswordHistoryCount
        }
    }
$DomainPwdPolicies = $DomainPwdPolicies  + $DomainPwdPolicies1 | Select Domain,AppliesTo,Complexity,LockoutDuration,LockoutObservation,LockoutThreshold, MaxPwdAge, MinPwdAge,MinPwdLength,PwdHistory

# Registered DNS Servers
$DNSSrvs = $DomainsInfo | % {Resolve-DnsName -Name $_.Name -Type A}
$DNSServerInfo = @()
$DNSSrvs | % `
    {
    $DNSServerInfo += New-Object psobject -Property @{
        Domain = $_.Name
        Name = $(Try {(Resolve-DnsName -Name $_.IPAddress -ErrorAction Stop).NameHost} Catch {"Unavailable"})
        IPAddress = $_.IPAddress
        }
    }
$DNSServerInfo = $DNSServerInfo | select Domain,Name,IPAddress | sort Domain,Name

# Registered DHCP Servers
$DHCPServers = @()
$DHCPs = Get-DhcpServerInDC
Get-ADObject -SearchBase “cn=configuration,$DomainDN” -Filter “objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'” -Properties whencreated | % `
    {$DHCPName = $_.Name
    $DHCPServers += New-Object psobject -Property @{
        Name = $_.Name
        IP = ($DHCPs | ?{$_.DnsName -eq $DHCPName}).IPAddress
        CreationDate = $_.whencreated
        }
    }

$DHCPServers = $DHCPServers | select Name, IP, CreationDate

<#
#NPS Servers Info 200 sec
$RegisteredNPS = (Get-ADGroupMember “RAS and IAS Servers").Name
$AllNPS = Invoke-Command -ComputerName $DCNames -ScriptBlock {if ((Get-Service IAS -erroraction 'silentlycontinue').Status -eq "Running") {$env:COMPUTERNAME}} | sort
$NPSInfo = @()
$AllNPS | % `
    {
    $NPSInfo += New-Object psobject -Property @{
        Domain = "linkedin.biz"
        NPSServer = $_
        Registered = if ($RegisteredNPS -contains $_) {$true} else {$false}
        }
    }
#>

# Site Information
# site summary
$SiteSummary = "" | select SiteCount,SubnetCount,ConnectionCount,SiteLinkCount,SitesWithoutISTGCount, SitesWithoutSubnetCount, SitesWithoutServerCount
    $SiteSummary.SiteCount = (Get-ADReplicationSite -Filter *).Count
    $SiteSummary.SubnetCount = (Get-ADReplicationSubnet -Filter *).Count
    $SiteSummary.ConnectionCount = (Get-ADReplicationConnection -Filter *).Count
    $SiteSummary.SiteLinkCount =  (Get-ADReplicationSiteLink -Filter *).count
    $SiteSummary.SitesWithoutISTGCount = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | ?{!($_.InterSiteTopologyGenerator)}).Count
    $SiteSummary.SitesWithoutSubnetCount = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | ?{!($_.Subnets)}).Count
    $SiteSummary.SitesWithoutServerCount = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | ?{!($_.Servers)}).Count

# 54 sec
$SiteInfo = @()
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | % `
    {
    $SiteInfo += New-Object psobject -Property @{
        Name = $_.Name
        Location = $_.Location
        Domains = $_.Domains.Name -join "; "
        DCs = $_.Servers.Name -join "; "
        Subnets = $_.Subnets.Name -join "; "
        Options = $_.Options
        ISTG = $_.InterSiteTopologyGenerator
        Bridgeheads = $_.BridgeheadServers.Name -join "; "
        AdjacentSites = $_.AdjacentSites.Name -join "; "
        }
    }
$SiteInfo = $SiteInfo | select Name,Location,Domains,DCs,Subnets,Options,ISTG,Bridgeheads,AdjacentSites | sort Name

#Site Subnets
$SubnetInfo = @()
Get-ADReplicationSubnet -Filter * | % `
    {$Sitename = if ($_.Site){(Get-ADReplicationSite $_.Site).Name}
    $SubnetInfo += New-Object psobject -Property @{
        Subnet = $_.Name
        SiteName = $Sitename
        Location = $_.Location
        }
    }
$SubnetInfo = $SubnetInfo | Sort Subnet

# Site Connections - From,To,Enabled,AutoGenerated,Options,transportType
$ConnectionInfo = @() 
Get-ADReplicationConnection -Filter * -Properties enabledConnection,Options,transportType | % `
    {
    $ConnectionInfo += New-Object psobject -Property @{
        From = (Get-ADObject $_.ReplicateFromDirectoryServer.Replace("CN=NTDS Settings,","")).Name
        To = (Get-ADObject $_.ReplicateToDirectoryServer.Replace("CN=NTDS Settings,","")).Name
        Enabled = $_.enabledConnection
        AutoGenerated = $_.AutoGenerated
        Options = $_.Options
        transportType = if ($_.transportType){(Get-ADObject $_.transportType).Name}
        }
    }
$ConnectionInfo = $ConnectionInfo | select From,To,Enabled,Options,AutoGenerated,transportType | sort options,From

# Site Links - Name,Cost,replInterval,SitesIncluded,InterSiteTransportProtocol
$LinksInfo = @()
Get-ADReplicationSiteLink -Filter * -Properties InterSiteTransportProtocol | % `
    {
    $LinksInfo += New-Object psobject -Property @{
        Name = $_.Name
        Cost = $_.Cost
        replInterval = [String]$_.ReplicationFrequencyInMinutes + " Minutes"
        SitesIncluded = ($_.SitesIncluded | % {(Get-ADObject $_).Name}) -join "; "
        InterSiteTransportProtocol = $_.InterSiteTransportProtocol
        }
    }
$LinksInfo = $LinksInfo | Select Name,Cost,SitesIncluded,replInterval,InterSiteTransportProtocol | sort Name

#Domain Information
#RID info - Domain,FunctionalLevel,ForestRoot,RIDsIssued,RIDsRemain
$CurDomain = Get-ADDomain
$RIDs = (Get-ADObject “cn=rid manager$,cn=system,$($CurDomain.DistinguishedName)” -property RIDAvailablePool).RIDAvailablePool
[int32]$TotalSIDS = $RIDs / ([math]::Pow(2,32))
[int64]$Temp64val = $TotalSIDS * ([math]::Pow(2,32))
[int32]$CurrentRIDPoolCount = $RIDs – $Temp64val
$RIDsRemaining = $TotalSIDS – $CurrentRIDPoolCount

$RIDsIssuedPcntOfTotal = ( $CurrentRIDPoolCount / $TotalSIDS )
$RIDsIssuedPercentofTotal = “{0:P2}” -f $RIDsIssuedPcntOfTotal
$RIDsRemainingPcntOfTotal = ( $RIDsRemaining / $TotalSIDS )
$RIDsRemainingPercentofTotal = “{0:P2}” -f $RIDsRemainingPcntOfTotal

$RIDInfo = "" | select Domain,FunctionalLevel,ForestRoot,RIDsIssued,RIDsRemain
    $RIDInfo.Domain = $CurDomain.Name
    $RIDInfo.FunctionalLevel = $CurDomain.DomainMode
    $RIDInfo.ForestRoot = $CurDomain.Forest
    $RIDInfo.RIDsIssued = "$CurrentRIDPoolCount ($RIDsIssuedPercentofTotal)"
    $RIDInfo.RIDsRemain = "$RIDsRemaining ($RIDsRemainingPercentofTotal) "

# Domain Trusts - Name,Source,Target,Direction,TrustAttributes,TrustType,whenCreated,whenChanged,DisallowTransivity
$TrustInfo = @()
Get-ADTrust -Properties whenCreated,whenChanged,DisallowTransivity,TrustAttributes -Filter * | % `
    {$TrustAttributesNumber = $_.TrustAttributes
    Switch ($TrustAttributesNumber) 
		{ 
		1 { $TrustAttributes = "1-NonTransitive"} 
		2 { $TrustAttributes = "2-UpLevelOnly"} 
		4 { $TrustAttributes = "4-QuarantinedDomain"} 
		8 { $TrustAttributes = "8-ForestTransitive"} 
		16 { $TrustAttributes = "16-CrossOrganisation"} 
		24 { $TrustAttributes = "24-CrossOrganisation"} 
        20 { $TrustAttributes = "20-WithinForest"}
		32 { $TrustAttributes = "32-WithinForest"} 
		64 { $TrustAttributes = "64-TreatAsExternal"} 
		128 { $TrustAttributes = "128-UsesRC4Encryption"} 
		Default { $TrustAttributes = $TrustAttributesNumber }
		} 
    $TrustInfo += New-Object psobject -Property @{
        Name = $_.Name
        Source = $_.Source
        Target = $_.Target
        TrustAttributes = $TrustAttributes
        Direction = $_.Direction
        TrustType = $_.TrustType
        Created = $_.whenCreated
        Modified = $_.whenChanged
        DisallowTransivity = $_.DisallowTransivity
        }
    }
$TrustInfo = $TrustInfo | Select Name,Source,Target,Direction,TrustAttributes,TrustType,Created,Modified,DisallowTransivity | sort Name

#Domain DFS name space Information
$DFSNInfo = @()
Get-ADObject -Filter {objectclass -eq "fTDfs"} -Properties remoteServerName | % `
    {
    $DFSNInfo += New-Object psobject -Property @{
        Domain = $env:USERDOMAIN
        Name = $_.Name
        DN = $_.DistinguishedName
        RemoteServer = ($_.remoteServerName | % {$_.split("\")[2]}) -join "; "
        }
    }
$DFSNInfo = $DFSNInfo | select Domain,Name,DN,RemoteServer

<# DFSR Information - DfsrGroup,ReplMembers,ReplFolders,ReplStatus,Content
$DFSRInfo = @()
$AllDFSRGroups = Get-DfsReplicationGroup | % {$_.GroupName} | sort
$AllDFSRMembers = (Get-DfsrMember).ComputerName | sort -Unique
$DFSRMembers = @()
$AllDFSRMembers | % `
    {$DfsrSrv = Get-ADComputer $_ -Properties IPV4Address,Created,OperatingSystem
    $DFSRMembers += New-Object psobject -Property @{
        Name = $_
        OperatingSystem = $DfsrSrv.OperatingSystem
        IP = $DfsrSrv.IPV4Address
        Created = $DfsrSrv.Created
        }
    }
$DFSRMembers = $DFSRMembers | Select Name,OperatingSystem,IP,Created
#>

<# DFSR Status 60 sec
#$DFSRStatus = @()
#$AllDFSRMembers | % {$DFSRStatus += Get-DfsrStatus $_}

# DFSR Folders 14 sec
$DFSRFolders = $AllDFSRGroups | % {Get-DfsReplicatedFolder -GroupName $_ | select GroupName,FolderName,IsDfsnPathPublished,State}
# 26 sec
$DFSRFolders | % `
    {$Folder = $_.FolderName
    $DFSRInfo += New-Object psobject -Property @{
        DfsrGroup = $_.GroupName
        ReplMembers = ((get-DfsrMembership -GroupName $_.GroupName).ComputerName | sort -Unique) -join "; "
        ReplFolders = $_.FolderName
        ReplStatus = $_.State
        Content = ((get-DfsrMembership -GroupName $_.GroupName | ? {$_.FolderName -eq $Folder}).ContentPath | sort -Unique) -join "; "
        }
    }
$DFSRInfo = $DFSRInfo | select DfsrGroup,ReplMembers,ReplFolders,ReplStatus,Content | sort DfsrGroup
#>

#DNS Zones Information - Domain,AppPartition,Name,RecordCount,Created,Changed        iglored .arpa
$DNSZoneInfo = @(); $DNSZoneCount = "" | select TotalZones,Arpa,NonArpa,Primary,Secondary,Stub,Forwarder
$LocalDNS = (gwmi Win32_NetworkAdapterConfiguration | ?{$_.IPEnabled -eq "True"}).DNSServerSearchOrder[0]
$AllDNSZones = Get-DnsServerZone -ComputerName site1-dc01 #$LocalDNS
$DNSZoneCount.Arpa = ($AllDNSZones | ?{$_.Zonename -like "*.arpa"}).count
$DNSZoneCount.NonArpa = ($AllDNSZones | ?{$_.Zonename -notlike "*.arpa"}).count
$DNSZoneCount.TotalZones = $AllDNSZones.Count
$DNSZoneCount.Primary = ($AllDNSZones | ?{$_.Zonename -notlike "*.arpa" -and $_.ZoneType -eq "Primary"} | Measure-Object).count
$DNSZoneCount.Stub = ($AllDNSZones | ?{$_.Zonename -notlike "*.arpa" -and $_.ZoneType -eq "Stub"} | Measure-Object).count
$DNSZoneCount.Secondary = ($AllDNSZones | ?{$_.Zonename -notlike "*.arpa" -and $_.ZoneType -eq "Secondary"} | Measure-Object).count
$DNSZoneCount.Forwarder = ($AllDNSZones | ?{$_.Zonename -notlike "*.arpa" -and $_.ZoneType -eq "Forwarder"} | Measure-Object).count

$ForestDnsZones = Get-ADObject -SearchBase "DC=ForestDnsZones,$DomainDN" -Filter {objectclass -eq 'dnsZone'} -Properties whenchanged,whencreated |  ?{$_.name -notlike "*.arpa"}
$DomainDnsZones = Get-ADObject -SearchBase "DC=DomainDnsZones,$DomainDN" -Filter {objectclass -eq 'dnsZone'} -Properties whenchanged,whencreated |  ?{$_.name -notlike "*.arpa"}
$LegacyDnsZones = Get-ADObject -SearchBase "CN=MicrosoftDNS,CN=System,$DomainDN" -Filter {objectclass -eq 'dnsZone'} -Properties whenchanged,whencreated |  ?{$_.name -notlike "*.arpa"}

$AllDNSZones | ?{$_.Zonename -notlike "*.arpa"} | % `
    {$zone = $_.ZoneName
    if ($ForestDnsZones | ?{$_.Name -eq $zone})
        {$wZone = $ForestDnsZones | ?{$_.Name -eq $zone}
        $DNSZoneInfo += New-Object psobject -Property @{
            Domain = $env:USERDOMAIN
            AppPartition = 'Forest'
            Name  = $wZone.name
            ZoneType = $_.ZoneType
            IsSigned = $_.IsSigned
            RecordCount = (Get-ADObject -SearchBase $wZone.DistinguishedName -Filter {objectclass -eq 'dnsNode'}).count
            Created = $wZone.whencreated
            Changed = $wZone.whenchanged
            }
        }
     if ($DomainDnsZones | ?{$_.Name -eq $zone})
        {$wZone = $DomainDnsZones | ?{$_.Name -eq $zone}
        $DNSZoneInfo += New-Object psobject -Property @{
            Domain = $env:USERDOMAIN
            AppPartition = 'Domain'
            Name  = $wZone.name
            ZoneType = $_.ZoneType
            IsSigned = $_.IsSigned
            RecordCount = (Get-ADObject -SearchBase $wZone.DistinguishedName -Filter {objectclass -eq 'dnsNode'}).count
            Created = $wZone.whencreated
            Changed = $wZone.whenchanged
            }
        }
     if ($LegacyDnsZones | ?{$_.Name -eq $zone})
        {$wZone = $LegacyDnsZones | ?{$_.Name -eq $zone}
        $DNSZoneInfo += New-Object psobject -Property @{
            Domain = $env:USERDOMAIN
            AppPartition = 'Domain'
            Name  = $wZone.name
            ZoneType = $_.ZoneType
            IsSigned = $_.IsSigned
            RecordCount = (Get-ADObject -SearchBase $wZone.DistinguishedName -Filter {objectclass -eq 'dnsNode'}).count
            Created = $wZone.whencreated
            Changed = $wZone.whenchanged
            }
        }
    }
$DNSZoneInfo = $DNSZoneInfo | select Name,ZoneType,RecordCount,IsSigned,Domain,AppPartition,Created,Changed


#Domain GPOs
$AllGPOs = Get-GPO -All | Select Id,DisplayName,Path,Owner,DomainName,CreationTime,ModificationTime,GPOstatus,WmiFilter,Description
$AllGPOCount = $AllGPOs.Count


#Domain Printers
$AllPrinters = Get-ADObject -LDAPFilter "(objectCategory=printQueue)" -Properties cn,drivername,location,printername,portname,servername,uNCName  | select cn,drivername,location,printername,servername,uNCName


#SCCM Servers
$SMSServers = Get-ADObject -LDAPFilter "(objectclass=mSSMSManagementPoint)" # Domain,Name,SiteCode,Version,DefaultMP,DeviceMP
$SMSSites = Get-ADObject -LDAPFilter "(objectclass=mSSMSSite)" # Domain,Name,SiteCode,RoamingBoundaries


# Domain Statistics
    # User Account Statistics 66 sec
#$AllUserAccount = Get-ADUser -Filter * -Properties LockedOut,PasswordNeverExpires,PasswordExpired,PasswordNotRequired
            $Filter_Users = '(samAccountType=805306368)'
            $Filter_User_Locked = '(samAccountType=805306368)(lockoutTime:1.2.840.113556.1.4.804:=4294967295)'
            $Filter_User_PasswordChangeReq = '(samAccountType=805306368)(pwdLastSet=0)(!useraccountcontrol:1.2.840.113556.1.4.803:=2)'
            $Filter_User_Enabled = '(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
            $Filter_User_Disabled = '(samAccountType=805306368)(useraccountcontrol:1.2.840.113556.1.4.803:=2)'
            $Filter_User_NoPasswordReq = '(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=32)'
            $Filter_User_PasswordNeverExpires = '(samAccountType=805306368)(UserAccountControl:1.2.840.113556.1.4.803:=65536)'
            $Filter_User_DialinEnabled = '(samAccountType=805306368)(msNPAllowDialin=TRUE)'
            $Filter_User_UnconstrainedDelegation = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            $Filter_User_NotTrustedForDelegation = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            $Filter_User_NoPreauth = '(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            $Filter_User_ControlAccessWithNPS = '(samAccountType=805306368)(!(msNPAllowDialin=*))'

$UserStats = "" | select Total,Enabled,Disabled,Locked,PwdDoesNotExpire,PwdNotRequired,PwdMustChange,DialInEnabled,UnconstrainedDelegation,NotTrustedForDelegation,NoPreAuthRequired,ControlAccessWithNPS
$UserStats.Total = (Get-ADUser -LDAPFilter $Filter_Users | Measure-Object).Count
$UserStats.Enabled = (Get-ADUser -LDAPFilter $Filter_User_Enabled | Measure-Object).Count
$UserStats.Disabled = (Get-ADUser -LDAPFilter $Filter_User_Disabled | Measure-Object).Count
$UserStats.Locked = (Get-ADUser -LdapFilter $Filter_User_Locked | Measure-Object).count
$UserStats.PwdDoesNotExpire = (Get-ADUser -LDAPFilter $Filter_User_PasswordNeverExpires | Measure-Object).Count
$UserStats.PwdNotRequired = (Get-ADUser -LDAPFilter $Filter_User_NoPasswordReq | Measure-Object).Count
$UserStats.PwdMustChange = (Get-ADUser -LdapFilter $Filter_User_PasswordChangeReq | Measure-Object).count
$UserStats.DialInEnabled = (Get-ADUser -LDAPFilter $Filter_User_DialinEnabled | Measure-Object).Count
$UserStats.UnconstrainedDelegation = (Get-ADUser -LDAPFilter $Filter_User_UnconstrainedDelegation | Measure-Object).Count
$UserStats.NotTrustedForDelegation = (Get-ADUser -LDAPFilter $Filter_User_NotTrustedForDelegation | Measure-Object).Count
$UserStats.NoPreAuthRequired = (Get-ADUser -LDAPFilter $Filter_User_NoPreauth | Measure-Object).Count
$UserStats.ControlAccessWithNPS = (Get-ADUser -LDAPFilter $Filter_User_ControlAccessWithNPS | Measure-Object).Count

#Total Groups
$AllGroups = Get-ADGroup -LDAPFilter '(objectClass=group)' -Properties GroupCategory,GroupScope,groupType
    $GroupStats = New-Object psobject -Property @{
        'Total' = $AllGroups.Count
        'Builtin' = @($AllGroups | ?{$_.groupType -eq '-2147483643'}).Count
        'UniversalSecurity' = @($AllGroups |?{$_.groupType -eq '-2147483640'}).Count
        'UniversalDist' = @($AllGroups | ?{$_.groupType -eq '8'}).Count
        'GlobalSecurity' = @($AllGroups | ?{$_.groupType -eq '-2147483646'}).Count
        'GlobalDist' = @($AllGroups | ?{$_.groupType -eq '2'}).Count
        'DomainLocalSecurity' = @($AllGroups | ?{$_.groupType -eq '-2147483644'}).Count
        'DomainLocalDist' = @($AllGroups | ?{$_.groupType -eq '4'}).Count
        }


# Privileged Group Statistics
$PriGroupInfo = @()
$DomSid = (Get-ADDomain).DomainSID.Value
    $StaticPrivGroupDesc = @{
        'S-1-5-32-544' = "Administrators"
        'S-1-5-32-548' = "Account Operators"
        'S-1-5-32-549' = "Server Operators"
        'S-1-5-32-550' = "Print Operators"
        'S-1-5-32-551' = "Backup Operators"
        "$DomSid-517" = "Cert Publishers"
        "$DomSid-518"  = "Schema Admins"
        "$DomSid-519"  = "Enterprise Admins"
        "$DomSid-520"  = "Group Policy Creator Owners"
        "$DomSid-512"  = "Domain Admins"
        }
#79 sec
Foreach ($GrpSid in $StaticPrivGroupDesc.Keys)
    {
    $GP = Get-ADGroup -LDAPFilter "(objectSID=$GrpSid)" -Properties CN
    $GPMembers = Get-ADUser -LDAPFilter "(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf:1.2.840.113556.1.4.1941:=$($GP.DistinguishedName))"
    $PriGroupInfo += New-Object psobject -Property @{
        Domain = $env:USERDOMAIN
        Group = $StaticPrivGroupDesc[$GrpSid]
        GroupDN = $GP.DistinguishedName
        GroupCN = $GP.CN
        GroupName = $GP.Name
        SID = $GP.SID
        MemberCount = ($GPMembers | Measure-Object).Count
        MembersNM = $GPMembers.Name -join "; "
        MembersSAM = $GPMembers.SamAccountName -join "; "
        }
    }

#Account information for the prior groups
$PriUserInfo = @()
$PriGroupInfo | % `
    {$Grpn = $_.GroupName
    if ($_.MembersSAM)
        {
        ($_.MembersSAM -split "; ") | % `
            {
            $UserProp = Get-ADUser $_ -Properties userAccountControl,PasswordLastSet,PasswordNotRequired,PasswordNeverExpires,LastLogonDate,PasswordExpired | Append-ADUserAccountControl
            $PriUserInfo += New-Object psobject -Property @{
                GroupName = $Grpn
                LogonID = $UserProp.SamAccountName
                Name = $UserProp.Name
                PwdNeverExpire = $UserProp.PasswordNeverExpires
                PasswordNotRequired = $UserProp.PasswordNotRequired
                PwdAge = (New-TimeSpan -Start $UserProp.PasswordLastSet -End (Get-Date)).Days
                PwdReversable = $UserProp.ENCRYPTED_TEXT_PASSWORD_ALLOWED
                LastLogon = $UserProp.LastLogonDate
                PasswordExpired = $UserProp.PasswordExpired
                }
            }
        }
    }

$PriUserInfo = $PriUserInfo | select GroupName,LogonID,Name,PwdAge,LastLogon,PasswordExpired,PwdNeverExpire,PwdReversable,PasswordNotRequired

Function Build-Header($title){
@"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$title</title>
<style type="text/css">
<!--
        body {
            font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
        }
        
        table{
            border-collapse: collapse;
            border: none;
            font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
            color: black;
            margin-bottom: 0px;
            margin: 0px auto;
        }
        table caption {
            font-weight: bold;
            font-size: 16px;
            background: #4f81bd;
            color: white;
        }
        table td{
            font-size: 10px;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
        }
        table td:last-child{
            padding-right: 5px;
        }
        table th {
            font-size: 12px;
            font-weight: bold;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
            border-bottom: 1px  grey solid;
        }
        h2{ 
            clear: both;
            font-size: 200%; 
            margin-left: 20px;
            font-weight: bold;
        }
        h3{
            clear: both;
            font-size: 115%;
            margin-left: 20px;
            margin-top: 30px;
        }
        p{ 
            margin-left: 20px; font-size: 12px;
        }
        mark {
            background-color: yellow;
            color: black;
        }
        table.list{
            float: left;
        }
        table.list td:nth-child(1){
            font-weight: bold;
            border-right: 1px grey solid;
            text-align: right;
        }
        table.list td:nth-child(2){
            padding-left: 7px;
        }
        table tr:nth-child(even) td:nth-child(even){ background: #CCCCCC; }
        table tr:nth-child(odd) td:nth-child(odd){ background: #F2F2F2; }
        table tr:nth-child(even) td:nth-child(odd){ background: #DDDDDD; }
        table tr:nth-child(odd) td:nth-child(even){ background: #E5E5E5; }
        
        /*  Error and warning highlighting - Row*/
        table tr.warn:nth-child(even) td:nth-child(even){ background: #FFFF88; }
        table tr.warn:nth-child(odd) td:nth-child(odd){ background: #FFFFBB; }
        table tr.warn:nth-child(even) td:nth-child(odd){ background: #FFFFAA; }
        table tr.warn:nth-child(odd) td:nth-child(even){ background: #FFFF99; }
        
        table tr.alert:nth-child(even) td:nth-child(even){ background: #FF8888; }
        table tr.alert:nth-child(odd) td:nth-child(odd){ background: #FFBBBB; }
        table tr.alert:nth-child(even) td:nth-child(odd){ background: #FFAAAA; }
        table tr.alert:nth-child(odd) td:nth-child(even){ background: #FF9999; }
        
        table tr.healthy:nth-child(even) td:nth-child(even){ background: #88FF88; }
        table tr.healthy:nth-child(odd) td:nth-child(odd){ background: #BBFFBB; }
        table tr.healthy:nth-child(even) td:nth-child(odd){ background: #AAFFAA; }
        table tr.healthy:nth-child(odd) td:nth-child(even){ background: #99FF99; }
        
        /*  Error and warning highlighting - Cell*/
        table tr:nth-child(even) td.warn:nth-child(even){ background: #FFFF88; }
        table tr:nth-child(odd) td.warn:nth-child(odd){ background: #FFFFBB; }
        table tr:nth-child(even) td.warn:nth-child(odd){ background: #FFFFAA; }
        table tr:nth-child(odd) td.warn:nth-child(even){ background: #FFFF99; }
        
        table tr:nth-child(even) td.alert:nth-child(even){ background: #FF8888; }
        table tr:nth-child(odd) td.alert:nth-child(odd){ background: #FFBBBB; }
        table tr:nth-child(even) td.alert:nth-child(odd){ background: #FFAAAA; }
        table tr:nth-child(odd) td.alert:nth-child(even){ background: #FF9999; }
        
        table tr:nth-child(even) td.healthy:nth-child(even){ background: #88FF88; }
        table tr:nth-child(odd) td.healthy:nth-child(odd){ background: #BBFFBB; }
        table tr:nth-child(even) td.healthy:nth-child(odd){ background: #AAFFAA; }
        table tr:nth-child(odd) td.healthy:nth-child(even){ background: #99FF99; }
        
        /* security highlighting */
        table tr.security:nth-child(even) td:nth-child(even){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(odd){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(even) td:nth-child(odd){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(even){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table th.title{ 
            text-align: center;
            background: #848482;
            border-bottom: 1px  black solid;
            font-weight: bold;
            color: white;
        }
        table th.sectioncomment{ 
            text-align: left;
            background: #848482;
            font-style : italic;
            color: white;
            font-weight: normal;
            
            padding: 0px;
        }
        table th.sectioncolumngrouping{ 
            text-align: center;
            background: #AAAAAA;
            color: black;
            font-weight: bold;
            border:1px solid white;
        }
        table th.sectionbreak{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 130%;
        }
        table th.reporttitle{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 150%;
        }
        table tr.divide{
            border-bottom: 1px  grey solid;
        }
    -->
</style>

<script type=""text/javascript"">
var stIsIE = /*@cc_on!@*/false;

sorttable = {
  init: function() {
    // quit if this function has already been called
    if (arguments.callee.done) return;
    // flag this function so we don't do the same thing twice
    arguments.callee.done = true;
    // kill the timer
    if (_timer) clearInterval(_timer);

    if (!document.createElement || !document.getElementsByTagName) return;

    sorttable.DATE_RE = /^(\d\d?)[\/\.-](\d\d?)[\/\.-]((\d\d)?\d\d)$/;

    forEach(document.getElementsByTagName('table'), function(table) {
      if (table.className.search(/\bsortable\b/) != -1) {
        sorttable.makeSortable(table);
      }
    });

  },

  makeSortable: function(table) {
    if (table.getElementsByTagName('thead').length == 0) {
      // table doesn't have a tHead. Since it should have, create one and
      // put the first table row in it.
      the = document.createElement('thead');
      the.appendChild(table.rows[0]);
      table.insertBefore(the,table.firstChild);
    }
    // Safari doesn't support table.tHead, sigh
    if (table.tHead == null) table.tHead = table.getElementsByTagName('thead')[0];

    if (table.tHead.rows.length != 1) return; // can't cope with two header rows

    // Sorttable v1 put rows with a class of "sortbottom" at the bottom (as
    // "total" rows, for example). This is B&R, since what you're supposed
    // to do is put them in a tfoot. So, if there are sortbottom rows,
    // for backwards compatibility, move them to tfoot (creating it if needed).
    sortbottomrows = [];
    for (var i=0; i<table.rows.length; i++) {
      if (table.rows[i].className.search(/\bsortbottom\b/) != -1) {
        sortbottomrows[sortbottomrows.length] = table.rows[i];
      }
    }
    if (sortbottomrows) {
      if (table.tFoot == null) {
        // table doesn't have a tfoot. Create one.
        tfo = document.createElement('tfoot');
        table.appendChild(tfo);
      }
      for (var i=0; i<sortbottomrows.length; i++) {
        tfo.appendChild(sortbottomrows[i]);
      }
      delete sortbottomrows;
    }

    // work through each column and calculate its type
    headrow = table.tHead.rows[0].cells;
    for (var i=0; i<headrow.length; i++) {
      // manually override the type with a sorttable_type attribute
      if (!headrow[i].className.match(/\bsorttable_nosort\b/)) { // skip this col
        mtch = headrow[i].className.match(/\bsorttable_([a-z0-9]+)\b/);
        if (mtch) { override = mtch[1]; }
	      if (mtch && typeof sorttable["sort_"+override] == 'function') {
	        headrow[i].sorttable_sortfunction = sorttable["sort_"+override];
	      } else {
	        headrow[i].sorttable_sortfunction = sorttable.guessType(table,i);
	      }
	      // make it clickable to sort
	      headrow[i].sorttable_columnindex = i;
	      headrow[i].sorttable_tbody = table.tBodies[0];
	      dean_addEvent(headrow[i],"click", sorttable.innerSortFunction = function(e) {

          if (this.className.search(/\bsorttable_sorted\b/) != -1) {
            // if we're already sorted by this column, just
            // reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted',
                                                    'sorttable_sorted_reverse');
            this.removeChild(document.getElementById('sorttable_sortfwdind'));
            sortrevind = document.createElement('span');
            sortrevind.id = "sorttable_sortrevind";
            sortrevind.innerHTML = stIsIE ? '&nbsp<font face="webdings">5</font>' : '&nbsp;&#x25B4;';
            this.appendChild(sortrevind);
            return;
          }
          if (this.className.search(/\bsorttable_sorted_reverse\b/) != -1) {
            // if we're already sorted by this column in reverse, just
            // re-reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted_reverse',
                                                    'sorttable_sorted');
            this.removeChild(document.getElementById('sorttable_sortrevind'));
            sortfwdind = document.createElement('span');
            sortfwdind.id = "sorttable_sortfwdind";
            sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
            this.appendChild(sortfwdind);
            return;
          }

          // remove sorttable_sorted classes
          theadrow = this.parentNode;
          forEach(theadrow.childNodes, function(cell) {
            if (cell.nodeType == 1) { // an element
              cell.className = cell.className.replace('sorttable_sorted_reverse','');
              cell.className = cell.className.replace('sorttable_sorted','');
            }
          });
          sortfwdind = document.getElementById('sorttable_sortfwdind');
          if (sortfwdind) { sortfwdind.parentNode.removeChild(sortfwdind); }
          sortrevind = document.getElementById('sorttable_sortrevind');
          if (sortrevind) { sortrevind.parentNode.removeChild(sortrevind); }

          this.className += ' sorttable_sorted';
          sortfwdind = document.createElement('span');
          sortfwdind.id = "sorttable_sortfwdind";
          sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
          this.appendChild(sortfwdind);

	        // build an array to sort. This is a Schwartzian transform thing,
	        // i.e., we "decorate" each row with the actual sort key,
	        // sort based on the sort keys, and then put the rows back in order
	        // which is a lot faster because you only do getInnerText once per row
	        row_array = [];
	        col = this.sorttable_columnindex;
	        rows = this.sorttable_tbody.rows;
	        for (var j=0; j<rows.length; j++) {
	          row_array[row_array.length] = [sorttable.getInnerText(rows[j].cells[col]), rows[j]];
	        }
	        /* If you want a stable sort, uncomment the following line */
	        //sorttable.shaker_sort(row_array, this.sorttable_sortfunction);
	        /* and comment out this one */
	        row_array.sort(this.sorttable_sortfunction);

	        tb = this.sorttable_tbody;
	        for (var j=0; j<row_array.length; j++) {
	          tb.appendChild(row_array[j][1]);
	        }

	        delete row_array;
	      });
	    }
    }
  },

  guessType: function(table, column) {
    // guess the type of a column based on its first non-blank row
    sortfn = sorttable.sort_alpha;
    for (var i=0; i<table.tBodies[0].rows.length; i++) {
      text = sorttable.getInnerText(table.tBodies[0].rows[i].cells[column]);
      if (text != '') {
        if (text.match(/^-?[£$¤]?[\d,.]+%?$/)) {
          return sorttable.sort_numeric;
        }
        // check for a date: dd/mm/yyyy or dd/mm/yy
        // can have / or . or - as separator
        // can be mm/dd as well
        possdate = text.match(sorttable.DATE_RE)
        if (possdate) {
          // looks like a date
          first = parseInt(possdate[1]);
          second = parseInt(possdate[2]);
          if (first > 12) {
            // definitely dd/mm
            return sorttable.sort_ddmm;
          } else if (second > 12) {
            return sorttable.sort_mmdd;
          } else {
            // looks like a date, but we can't tell which, so assume
            // that it's dd/mm (English imperialism!) and keep looking
            sortfn = sorttable.sort_ddmm;
          }
        }
      }
    }
    return sortfn;
  },

  getInnerText: function(node) {
    // gets the text we want to use for sorting for a cell.
    // strips leading and trailing whitespace.
    // this is *not* a generic getInnerText function; it's special to sorttable.
    // for example, you can override the cell text with a customkey attribute.
    // it also gets .value for <input> fields.

    if (!node) return "";

    hasInputs = (typeof node.getElementsByTagName == 'function') &&
                 node.getElementsByTagName('input').length;

    if (node.getAttribute("sorttable_customkey") != null) {
      return node.getAttribute("sorttable_customkey");
    }
    else if (typeof node.textContent != 'undefined' && !hasInputs) {
      return node.textContent.replace(/^\s+|\s+$/g, '');
    }
    else if (typeof node.innerText != 'undefined' && !hasInputs) {
      return node.innerText.replace(/^\s+|\s+$/g, '');
    }
    else if (typeof node.text != 'undefined' && !hasInputs) {
      return node.text.replace(/^\s+|\s+$/g, '');
    }
    else {
      switch (node.nodeType) {
        case 3:
          if (node.nodeName.toLowerCase() == 'input') {
            return node.value.replace(/^\s+|\s+$/g, '');
          }
        case 4:
          return node.nodeValue.replace(/^\s+|\s+$/g, '');
          break;
        case 1:
        case 11:
          var innerText = '';
          for (var i = 0; i < node.childNodes.length; i++) {
            innerText += sorttable.getInnerText(node.childNodes[i]);
          }
          return innerText.replace(/^\s+|\s+$/g, '');
          break;
        default:
          return '';
      }
    }
  },

  reverse: function(tbody) {
    // reverse the rows in a tbody
    newrows = [];
    for (var i=0; i<tbody.rows.length; i++) {
      newrows[newrows.length] = tbody.rows[i];
    }
    for (var i=newrows.length-1; i>=0; i--) {
       tbody.appendChild(newrows[i]);
    }
    delete newrows;
  },

  /* sort functions
     each sort function takes two parameters, a and b
     you are comparing a[0] and b[0] */
  sort_numeric: function(a,b) {
    aa = parseFloat(a[0].replace(/[^0-9.-]/g,''));
    if (isNaN(aa)) aa = 0;
    bb = parseFloat(b[0].replace(/[^0-9.-]/g,''));
    if (isNaN(bb)) bb = 0;
    return aa-bb;
  },
  sort_alpha: function(a,b) {
    if (a[0]==b[0]) return 0;
    if (a[0]<b[0]) return -1;
    return 1;
  },
  sort_ddmm: function(a,b) {
    mtch = a[0].match(sorttable.DATE_RE);
    y = mtch[3]; m = mtch[2]; d = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt1 = y+m+d;
    mtch = b[0].match(sorttable.DATE_RE);
    y = mtch[3]; m = mtch[2]; d = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt2 = y+m+d;
    if (dt1==dt2) return 0;
    if (dt1<dt2) return -1;
    return 1;
  },
  sort_mmdd: function(a,b) {
    mtch = a[0].match(sorttable.DATE_RE);
    y = mtch[3]; d = mtch[2]; m = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt1 = y+m+d;
    mtch = b[0].match(sorttable.DATE_RE);
    y = mtch[3]; d = mtch[2]; m = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt2 = y+m+d;
    if (dt1==dt2) return 0;
    if (dt1<dt2) return -1;
    return 1;
  },

  shaker_sort: function(list, comp_func) {
    // A stable sort function to allow multi-level sorting of data
    // see: http://en.wikipedia.org/wiki/Cocktail_sort
    // thanks to Joseph Nahmias
    var b = 0;
    var t = list.length - 1;
    var swap = true;

    while(swap) {
        swap = false;
        for(var i = b; i < t; ++i) {
            if ( comp_func(list[i], list[i+1]) > 0 ) {
                var q = list[i]; list[i] = list[i+1]; list[i+1] = q;
                swap = true;
            }
        } // for
        t--;

        if (!swap) break;

        for(var i = t; i > b; --i) {
            if ( comp_func(list[i], list[i-1]) < 0 ) {
                var q = list[i]; list[i] = list[i-1]; list[i-1] = q;
                swap = true;
            }
        } // for
        b++;

    } // while(swap)
  }
}

/* ******************************************************************
   Supporting functions: bundled here to avoid depending on a library
   ****************************************************************** */

// Dean Edwards/Matthias Miller/John Resig

/* for Mozilla/Opera9 */
if (document.addEventListener) {
    document.addEventListener("DOMContentLoaded", sorttable.init, false);
}

/* for Internet Explorer */
/*@cc_on @*/
/*@if (@_win32)
    document.write("<script id=__ie_onload defer src=javascript:void(0)><\/script>");
    var script = document.getElementById("__ie_onload");
    script.onreadystatechange = function() {
        if (this.readyState == "complete") {
            sorttable.init(); // call the onload handler
        }
    };
/*@end @*/

/* for Safari */
if (/WebKit/i.test(navigator.userAgent)) { // sniff
    var _timer = setInterval(function() {
        if (/loaded|complete/.test(document.readyState)) {
            sorttable.init(); // call the onload handler
        }
    }, 10);
}

/* for other browsers */
window.onload = sorttable.init;

// written by Dean Edwards, 2005
// with input from Tino Zijdel, Matthias Miller, Diego Perini

// http://dean.edwards.name/weblog/2005/10/add-event/

function dean_addEvent(element, type, handler) {
	if (element.addEventListener) {
		element.addEventListener(type, handler, false);
	} else {
		// assign each event handler a unique ID
		if (!handler.`$`$guid) handler.`$`$guid = dean_addEvent.guid++;
		// create a hash table of event types for the element
		if (!element.events) element.events = {};
		// create a hash table of event handlers for each element/event pair
		var handlers = element.events[type];
		if (!handlers) {
			handlers = element.events[type] = {};
			// store the existing event handler (if there is one)
			if (element["on" + type]) {
				handlers[0] = element["on" + type];
			}
		}
		// store the event handler in the hash table
		handlers[handler.`$`$guid] = handler;
		// assign a global event handler to do all the work
		element["on" + type] = handleEvent;
	}
};
// a counter used to create unique IDs
dean_addEvent.guid = 1;

function removeEvent(element, type, handler) {
	if (element.removeEventListener) {
		element.removeEventListener(type, handler, false);
	} else {
		// delete the event handler from the hash table
		if (element.events && element.events[type]) {
			delete element.events[type][handler.`$`$guid];
		}
	}
};

function handleEvent(event) {
	var returnValue = true;
	// grab the event object (IE uses a global event object)
	event = event || fixEvent(((this.ownerDocument || this.document || this).parentWindow || window).event);
	// get a reference to the hash table of event handlers
	var handlers = this.events[event.type];
	// execute each event handler
	for (var i in handlers) {
		this.`$`$handleEvent = handlers[i];
		if (this.`$`$handleEvent(event) === false) {
			returnValue = false;
		}
	}
	return returnValue;
};

function fixEvent(event) {
	// add W3C standard event methods
	event.preventDefault = fixEvent.preventDefault;
	event.stopPropagation = fixEvent.stopPropagation;
	return event;
};
fixEvent.preventDefault = function() {
	this.returnValue = false;
};
fixEvent.stopPropagation = function() {
  this.cancelBubble = true;
}

// Dean's forEach: http://dean.edwards.name/base/forEach.js
/*
	forEach, version 1.0
	Copyright 2006, Dean Edwards
	License: http://www.opensource.org/licenses/mit-license.php
*/

// array-like enumeration
if (!Array.forEach) { // mozilla already supports this
	Array.forEach = function(array, block, context) {
		for (var i = 0; i < array.length; i++) {
			block.call(context, array[i], i, array);
		}
	};
}

// generic enumeration
Function.prototype.forEach = function(object, block, context) {
	for (var key in object) {
		if (typeof this.prototype[key] == "undefined") {
			block.call(context, object[key], key, object);
		}
	}
};

// character enumeration
String.forEach = function(string, block, context) {
	Array.forEach(string.split(""), function(chr, index) {
		block.call(context, chr, index, string);
	});
};

// globally resolve forEach enumeration
var forEach = function(object, block, context) {
	if (object) {
		var resolve = Object; // default
		if (object instanceof Function) {
			// functions have a "length" property
			resolve = Function;
		} else if (object.forEach instanceof Function) {
			// the object implements a custom forEach method so use that
			object.forEach(block, context);
			return;
		} else if (typeof object == "string") {
			// the object is a string
			resolve = String;
		} else if (typeof object.length == "number") {
			// the object is array-like
			resolve = Array;
		}
		resolve.forEach(object, block, context);
	}
};

</script>

</head>
<body>
<br>
<div id=$title>
"@
}

Function Create-SaerchTable ($TableID) {
@"
<script>
function searchTable() {
    var input, filter, found, table, tr, td, i, j;
    input = document.getElementById("myInput");
    filter = input.value.toUpperCase();
    table = document.getElementById("$TableID");
    tr = table.getElementsByTagName("tr");
    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td");
        for (j = 0; j < td.length; j++) {
            if (td[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
                found = true;
            }
        }
        if (found) {
            tr[i].style.display = "";
            found = false;
        } else {
            if (tr[i].id != 'tableHeader'){tr[i].style.display = "none";}
        }
    }
}
</script>
"@
}

$HTMLEnd = @"
</div>
</body>
</html>
"@

$GoBackButton = @"
 <button style="position:fixed;top:5px;left:170px;background:green;font-weight: bold;font-size: 16px;color:white;" onclick="goBack()">Go Back</button>
<script>
function goBack() {
    window.history.back();
}
</script>
"@

$SearchInput = @"
<input id='myInput' onkeyup='searchTable()' type='text' placeholder='Type to search' style="position:fixed;top:8px;left:10px;background:#DDDDDD;">
"@

$htmlMiddle = ""
$htmlMiddle += $GoBackButton
$htmlMiddle += "<h1 style='text-align:center'>Forest Information Report<p>- as of $(Get-Date -Format 'MM/dd/yyyy HH:mm')</p></h1>"

# Forest Info
$title = "Forest Info"
$Caption = "Forest Information"
$ArrayToHtml = $ForestInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Domains info
$title = "Domains Info"
$Caption = "Domains Information"
$ArrayToHtml = $DomainsInfo | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+$ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Domain controllers Info

#$Caption = "Domain Controllers"
#$Link = "Domain Controllers Information"
#$htmlMiddle += "<br><table><caption>$Caption</caption><tr><th><a href=`"pages/DCInfo.html`"><p><font size=`"4`">$Link</font></p></a></th></tr></table>"

$Caption = "DCs/GPOs/Printers/DNS Zones Information"
$Link = "Domain Controllers Information"
$Link1 = "GPO Information"
$Link2 = "Registered Printers Information"
$Link3 = "DNS Zones Information"
$htmlMiddle += @"
<br><table><caption>$Caption</caption><tr>
<th><a href="pages/DCInfo.html"><p><font size="4">$Link</font></p></a></th>
<th><a href="pages/AllGPOs.html"><p><font size="4">$Link1</font></p></a></th>
<th><a href="pages/AllPrinters.html"><p><font size="4">$Link2</font></p></a></th>
<th><a href="pages/DNSZoneInfo.html"><p><font size="4">$Link3</font></p></a></th>
</tr></table>
"@


# Site Summary
$title = "Site Sum"
$Caption = "Site Summary"
$ArrayToHtml = $SiteSummary | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+$ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Sites Information
$Caption = "AD Sites Information"
$Link = "Sites Information"
$Link1 = "Subnets Information"
$Link2 = "Connections Information"
$Link3 = "Site Links Information"
$htmlMiddle += @"
<br><table><caption>$Caption</caption><tr>
<th><a href="pages/SiteInfo.html"><p><font size="4">$Link</font></p></a></th>
<th><a href="pages/SubnetInfo.html"><p><font size="4">$Link1</font></p></a></th>
<th><a href="pages/ConnectionInfo.html"><p><font size="4">$Link2</font></p></a></th>
<th><a href="pages/LinksInfo.html"><p><font size="4">$Link3</font></p></a></th>
</tr></table>
"@

# Domain password policies
$title = "Pwd Policy"
$Caption = "Domain Password Policies"
$ArrayToHtml = $DomainPwdPolicies | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+$ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Trust Info
$title = "Trust Info"
$Caption = "Domain Trust Information"
$ArrayToHtml = $TrustInfo | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+$ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# RID Info
$title = "RID Info"
$Caption = "Domain RID Information"
$ArrayToHtml = $RIDInfo | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+$ArrayToHtml[0] + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Registered Server Information
$Caption = "DNS/DHCP/NPS/DFS Server Information"
$Link = "DNS Server Information"
$Link1 = "DHCP Server Information"
$Link2 = "NPS Server Information"
#$Link3 = "DFSR Members Information"
$htmlMiddle += @"
<br><table><caption>$Caption</caption><tr>
<th><a href="pages/DNSServerInfo.html"><p><font size="4">$Link</font></p></a></th>
<th><a href="pages/DHCPServers.html"><p><font size="4">$Link1</font></p></a></th>
<th><a href="pages/NPSInfo.html"><p><font size="4">$Link2</font></p></a></th>
</tr></table>
"@

# User Stats
$title = "User stats"
$Caption = "User Account Statistics"
$ArrayToHtml = $UserStats | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+"<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Group Stats
$title = "Group stats"
$Caption = "Group Account Statistics"
$ArrayToHtml = $GroupStats | ConvertTo-HTML -fragment 
$htmlMiddle += "`n<br>"+"<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]

# Privileged Group/User Information
$Caption = "Privileged Group/User & DFSR Information"
$Link = "Privileged Group Information"
$Link1 = "Privileged User Information"
#$Link2 = "DFS Replication Information"
$htmlMiddle += @"
<br><table><caption>$Caption</caption><tr>
<th><a href="pages/PriGroupInfo.html"><p><font size="4">$Link</font></p></a></th>
<th><a href="pages/PriUserInfo.html"><p><font size="4">$Link1</font></p></a></th>
</tr></table>
"@


$HTMLmessage = (Build-Header -title "Active Directory Asset Info") + $HTMLMiddle + $HTMLEnd
#$HTMLmessage | Out-File $FileLocation\main.html
$FileLocation | % {$HTMLmessage | Out-File $_\Main.html}

#DCInfo page
$htmlMiddle = ""
$title = "DC Info"
$TableID = "DC"
$Caption = "Domain Controllers Information"
$ArrayToHtml = $DCInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DCInfo.html}

#Sites Information
$htmlMiddle = ""
$title = "Site Info"
$TableID = "Site"
$Caption = "Detailed Site Information"
$ArrayToHtml = $SiteInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\SiteInfo.html}

#Subnets Information
$htmlMiddle = ""
$title = "Subnet Info"
$TableID = "Subnet"
$Caption = "Detailed Subnet Information"
$ArrayToHtml = $SubnetInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\SubnetInfo.html}

#Connections Information
$htmlMiddle = ""
$title = "Connection Info"
$TableID = "Connection"
$Caption = "Detailed Connections Information"
$ArrayToHtml = $ConnectionInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\ConnectionInfo.html}

#Sites Information
$htmlMiddle = ""
$title = "Links Info"
$TableID = "Links"
$Caption = "Site Links Information"
$ArrayToHtml = $LinksInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\LinksInfo.html}

#DNS Server Information
$htmlMiddle = ""
$title = "DNSSrv Info"
$TableID = "DNSSrv"
$Caption = "DNS Server Information"
$ArrayToHtml = $DNSServerInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DNSServerInfo.html}

#DHCP Server Information
$htmlMiddle = ""
$title = "DHCPSrv Info"
$TableID = "DHCPSrv"
$Caption = "DHCP Server Information"
$ArrayToHtml = $DHCPServers | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DHCPServers.html}

#NPS Information
$htmlMiddle = ""
$title = "NPS Info"
$TableID = "NPS"
$Caption = "NPS Server Information"
$ArrayToHtml = $NPSInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\NPSInfo.html}

#DFSR Member Information
$htmlMiddle = ""
$title = "DFSRMem Info"
$TableID = "DFSRMem"
$Caption = "DFSR Member Information"
$ArrayToHtml = $DFSRMembers | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DFSRMembers.html}

#GPO Information
$htmlMiddle = ""
$title = "GPO Info"
$TableID = "GPO"
$Caption = "GPO Information"
$ArrayToHtml = $AllGPOs | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\AllGPOs.html}

#Printer Information
$htmlMiddle = ""
$title = "Printer Info"
$TableID = "Printer"
$Caption = "Domain Printer Information"
$ArrayToHtml = $AllPrinters | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\AllPrinters.html}

#DNS Zone Information
$htmlMiddle = ""
$title = "DNSZone Info"
$TableID = "DNSZone"
$Caption = "DNZ Zone Information"
$ArrayToHtml = $DNSZoneInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DNSZoneInfo.html}

#Privileged Group Information
$htmlMiddle = ""
$title = "PriGrp Info"
$TableID = "PriGrp"
$Caption = "Privileged Group Information"
$ArrayToHtml = $PriGroupInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\PriGroupInfo.html}

#Privileged user Information
$htmlMiddle = ""
$title = "PriUsr Info"
$TableID = "PriUsr"
$Caption = "Privileged user Information"
$ArrayToHtml = $PriUserInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\PriUserInfo.html}

#DFS Replication Information
$htmlMiddle = ""
$title = "DFSR Info"
$TableID = "DFSR"
$Caption = "DFS Replication Information"
$ArrayToHtml = $DFSRInfo | ConvertTo-HTML -fragment 
$htmlMiddle += $GoBackButton 
#$htmlMiddle += "<table id=`"$title`" class=`"sortable`">" + "<caption>$Caption</caption>" + $ArrayToHtml[1..($ArrayToHtml.Count -1)]
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $HTMLMiddle + $HTMLEnd
$FileLocation | % {$HTMLmessage | Out-File $_\Pages\DFSRInfo.html}

$endtime = Get-Date
New-TimeSpan -Start $starttime -End $endtime

