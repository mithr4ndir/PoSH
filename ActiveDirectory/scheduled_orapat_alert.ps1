$request = Invoke-WebRequest https://server -SessionVariable fb -ErrorAction Continue
if ($request.StatusDescription -eq 'OK' )
    {
        #Write-host "Orapat is ok"
        Return
    }
    else {
        Send-MailMessage -To email@email.com -Subject "Orapat is down - Pleae refresh the pool" -SmtpServer server1
    }