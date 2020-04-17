[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile('https://site1-puppet-prod-master01.corp.Companyx.internal:8140/packages/current/install.ps1', 'install.ps1')
.\install.ps1