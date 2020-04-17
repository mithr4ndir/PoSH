
$date = get-date -Format "yyyy-MM-dd_HH-mm"
 
$Table = Get-aduser -filter {mail -like "*"} -pro mail,uid,whencreated,passwordlastset,lastlogondate,employeenumber,employeetype -SearchBase "ou=users,$OUDomainPATH" | select mail,samaccountname,whencreated,lastlogondate,passwordlastset,employeenumber,employeetype,enabled,@{name="uid";expression={$_.uid -join ","}}
$NotMatchingArray = @()
 Foreach ($thing in $table)

        {
             $modifiedthing = $thing.mail
             $modifiedthingmail = $modifiedthing.split("@")[0]
                If ($thing.uid -notmatch $modifiedthingmail)
                    {
                    write-host "$($thing.uid) does not matches $($thing.mail)" -BackgroundColor Red
                    $TempObject = New-Object psobject
                    $TempObject | Add-member -MemberType NoteProperty -Name UID -value "$($thing.uid)"
                    $TempObject | Add-Member -MemberType NoteProperty -name Mail -value "$($thing.mail)"
                    $TempObject | Add-Member -MemberType NoteProperty -name samaccountname -value "$($thing.samaccountname)"
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
                    Write-host "$($thing.uid) Matches $($thing.mail)" -BackgroundColor Green
                    }


        }

$NotMatchingArray | export-csv -NoTypeInformation C:\users\ChrisL\desktop\UnmatchedUIDAndMail_$date.csv
