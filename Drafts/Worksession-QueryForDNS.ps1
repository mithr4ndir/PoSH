$DomainName = ‘corp.Companyx.com’
$AdIntegrationType = ‘Domain’
$DomainDn = (Get-AdDomain).DistinguishedName
Get-ChildItem "AD:DC=$DomainName,CN=MicrosoftDNS,DC=$AdIntegrationType`DnsZones,$DomainDn" | ? {$_.name -like "028520-w10"} | foreach {
     Get-Acl -Path “ActiveDirectory:://RootDSE/$($_.DistinguishedName)” | select *
}


Get-Acl -Path “ActiveDirectory:://RootDSE/DC=028520-W10,DC=corp.Companyx.com,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=Companyx,DC=com" | FL *
