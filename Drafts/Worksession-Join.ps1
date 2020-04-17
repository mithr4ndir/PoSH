


#Set IP Address and Gateway for ethernet0
New-netipaddress -InterfaceAlias Ethernet0 -IPAddress  192.168.169.102 -PrefixLength "22" -DefaultGateway 192.168.168.1

#Set DNS Client Settings
Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses 192.168.168.111,192.168.108.40

#Define credential and encrypted string text
$user = "string1"
$string='strings'

#Encrypt String 
$estring = convertto-securestring -string $string

#Load Encrypted Credential
$credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $user,$estring

#Join Machine to Domain place in path OU and with specific name
add-computer -DomainName corp.Companyx.com -ComputerName $env:computername -newname site4-fintech02 -Credential $credential -Restart -WhatIf -OUPath "ou=fintech,ou=servers,ou=computers,$OUDomainPATH"
