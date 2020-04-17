
$date = get-date -Format "yyyy-MM-dd_HH-mm"
 
$Table = Get-aduser -filter {mail -like "*"} -pro mail,uid,whencreated,passwordlastset,lastlogondate,employeenumber,employeetype -SearchBase "ou=users,$OUDomainPATH" | select mail,samaccountname,whencreated,lastlogondate,passwordlastset,employeenumber,employeetype,enabled,@{name="uid";expression={$_.uid -join ","}}
$NotMatchingArray = @()
 Foreach ($thing in $table)

        {
             $modifiedthing = $thing.mail
             $modifiedthingmail = $modifiedthing.split("@")[0]
                If ($thing.samaccountname -notmatch $modifiedthingmail)
                    {
                    write-host "$($thing.samaccountname) does not matches $($thing.mail)" -BackgroundColor Red
                    $TempObject = New-Object psobject
                    $TempObject | Add-member -MemberType NoteProperty -Name Samaccountname -value "$($thing.samaccountname)"
                    $TempObject | Add-Member -MemberType NoteProperty -name Mail -value "$($thing.mail)"
                    $TempObject | Add-Member -MemberType NoteProperty -name UID -value "$($thing.uid)"
                    $TempObject | Add-Member -MemberType NoteProperty -name enabled -value "$($thing.enabled)"
                    $TempObject | Add-Member -MemberType NoteProperty -name whencreated -value "$($thing.whencreated)"
                    $TempObject | Add-Member -MemberType NoteProperty -name passwordlastset -value "$($thing.passwordlastset)"
                    $TempObject | Add-Member -MemberType NoteProperty -name lastlogondate -value "$($thing.lastlogondate)"
                    $TempObject | Add-Member -MemberType NoteProperty -name employeenumber -value "$($thing.employeenumber)"
                    $TempObject | Add-Member -MemberType NoteProperty -name employeetype -value "$($thing.employeetype)"
                    $NotMatchingArray += $TempObject

                    }
                else
                    {
                    Write-host "$($thing.samaccountname) Matches $($thing.mail)" -BackgroundColor Green
                    }


        }

$NotMatchingArray | export-csv -NoTypeInformation C:\users\ChrisL\desktop\UnmatchedSamaccountnameAndMail_$date.csv

<#
$Samaccountname = Get-aduser -filter {mail -like "*" -and enabled -eq $true} | Select samaccountname
$UID = Get-aduser -filter {mail -like "*" -and enabled -eq $true} -pro uid | Select uid
#>

<#

Foreach ($user in $NotMatchingArray.mail)

{

Get-aduser -filter {mail -like $user}
}


Foreach ($user in $NotMatchingArray)
{
If ($user.lastlogondate -like "*/*")
{
write-host "Lastlogon for this user is $($user.lastlogondate), and when created was $($user.whencreated)"

}
else 
{
Write-host "Lastlogon for this user is actually null" -BackgroundColor red 
}
}



$stuff = $NotMatchingArray | sort lastlogondate | ? {$_.lastlogondate -like $null} 


$stuff | sort whencreated | ft


$allarray = @()
foreach ($thingy in $stufftoimport)

{
$temparray = Get-aduser -filter {mail -like $thingy} -pro mail,samaccountname,whencreated,lastlogondate,employeenumber,manager | select mail,samaccountname,whencreated,lastlogondate,employeenumber,manager
$allarray += $temparray

}

$allarray | export-csv -NoTypeInformation C:\users\ChrisL\desktop\ADaccountdupeissues.csv

#>