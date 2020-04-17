
$members=get-adgroupmember -Identity "bod-accounts" | select SamAccountName
foreach ($user in $members)
{
$users=Get-ADUser -Identity $user.SamAccountName | select SamAccountName,Enabled,surname,givenname
#Send-message
if($users.enabled -eq $false)
      { 
        $server="site1-smtp01.corp.Companyx.com" 
        $from="site1-scripts@company.com" 
        $to= "user2@company.com","user3@company.com","User1@company.com" 
        $cc="ChrisL@company.com" 
        $subject="BOD-Accounts - $($user.Givenname) $($user.surname)'s AD account is disabled" 
        $body="$($user.givename) $($user.surname) - $($user.samaccountname) is disabled" 
        Send-MailMessage -SmtpServer $server -From $from -To $to -Subject $subject -Body $body -Cc $cc
      }
}

$members=get-adgroupmember -Identity "executives" | select SamAccountName
foreach ($user in $members)
{
$users=Get-ADUser -Identity $user.SamAccountName | select SamAccountName,Enabled,surname,givenname
#Send-message
if($users.enabled -eq $false)
      { 
        $server="site1-smtp01.corp.Companyx.com" 
        $from="site1-scripts@company.com" 
        $to= "user2@company.com","user3@company.com","User1@company.com" 
        $cc="ChrisL@company.com" 
        $subject="BOD-Accounts - $($user.Givenname) $($user.surname)'s AD account is disabled" 
        $body="$($user.givename) $($user.surname) - $($user.samaccountname) is disabled" 
        Send-MailMessage -SmtpServer $server -From $from -To $to -Subject $subject -Body $body -Cc $cc
      }
}