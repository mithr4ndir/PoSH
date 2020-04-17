$groups = get-adgroup -filter {mail -like "*"} -SearchBase "ou=googlesync,ou=groups,$OUDomainPATH"| select -exp mail
$groups | foreach {$_.split("@")[1]} | sort -Unique
$groups | ? {$_ -like "*@company.com "}
$groups | ? {$_ -like "*Companyx"}
$groups | ? {$_ -like "*ext.Companyx"}
$groups | ? {$_ -like "*ext.Companyx.com"}
$groups | ? {$_ -like "*@company.com "}
$groups | ? {$_ -like "*@company.com "} 