cert:\currentuser\my\
$Test = Get-aduser ChrisL -pro usercertificate | select @{name="usercertificate";expression={$_.usercertificate -join ","}}
$test -join ","
$array = @(().join(","))
$string = [System.Text.Encoding]::UTF8.GetString($array)
$string.length
$string
