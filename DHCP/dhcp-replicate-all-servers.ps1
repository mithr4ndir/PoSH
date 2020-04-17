Import-Module ActiveDirectory

Start-Transcript C:\Transcripts\DHCP-Replication.txt -Verbose -Force
$date=date 
$server=Get-ADComputer -Filter {name -like "*dhcp*"} -SearchBase "OU=Servers,OU=Computers,$OUDomainPATH"

foreach ($s in $server) {

    $dhcp=$s.name
    Invoke-DhcpServerv4FailoverReplication -ComputerName $dhcp -Confirm:$false -Force

}
Stop-Transcript

$EmailFrom = "DHCP-Monitor@company.com" 
$EmailTo = "corp-systems@company.com" 
$EmailSubject = "Replicated scopes"  
$SMTPServer = "site1-smtp01.corp.Companyx.com"
$attach = C:\Transcripts\DHCP-Replication.txt
Send-MailMessage -To $emailTo -From $emailFrom -SmtpServer $SMTPServer -Subject "$EmailSubject $date" -Body dhcp -Attachments C:\Transcripts\DHCP-Replication.txt
