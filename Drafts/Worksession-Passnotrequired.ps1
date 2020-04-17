
$date = (Get-Date).AddMonths(-6)

# Password not required not logged in before prior to $date or never logged in and enabled first five
get-aduser -filter {useraccountcontrol -band 32 -and enabled -eq $true -and lastlogondate -notlike "*" -and created -lt $date} -pro lastlogondate,created,useraccountcontrol,passwordnotrequired,passwordlastset,passwordexpired,samaccountname -SearchBase "ou=users,$OUDomainPATH"

$disabledADAcct = get-aduser -filter {useraccountcontrol -band 32 -and passwordexpired -eq $true} -pro lastlogondate,created,useraccountcontrol,passwordnotrequired,passwordlastset,passwordexpired,samaccountname -SearchBase "ou=users,$OUDomainPATH"


get-aduser -filter {lastlogondate -lt $date -and enabled -eq $true} -pro lastlogondate,created,useraccountcontrol,passwordnotrequired,passwordlastset  | select -first 5 | ft

get-aduser -filter {useraccountcontrol -band 32 -and lastlogondate -lt $date -and enabled -eq $true} -pro lastlogondate,created,useraccountcontrol,passwordnotrequired,passwordlastset -SearchBase "ou=users,$OUDomainPATH" | select -first 5 | ft


get-aduser -filter {useraccountcontrol -band 32} -pro lastlogondate,created,useraccountcontrol,passwordnotrequired,passwordlastset,passwordexpired -SearchBase "ou=users,$OUDomainPATH"
