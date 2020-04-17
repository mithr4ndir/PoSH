$schemaPath = (Get-ADRootDSE).schemaNamingContext

Get-ADObject -filter {name -like "Companyx-job*"} -SearchBase $schemaPath -Properties * | where {$_.objectclass -eq "attributeschema"} | sort name | select name,objectclass,ldapdisplayname,admindisplayname,cn | FT

Get-ADObject -filter {name -like "*"} -SearchBase $schemaPath -Properties * | sort name | select name,objectclass,ldapdisplayname,admindisplayname,cn | select *

Get-ADObject -filter {name -like "Companyx-job*"} -SearchBase $schemaPath -Properties * | where {$_.objectclass -eq "attributeschema"} 