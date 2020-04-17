$stuff =Get-DnsServerResourceRecord -RRType A -ZoneName corp.Companyx.com -ComputerName site4-dc02 -Name "corp.Companyx.com" | select -first 70

