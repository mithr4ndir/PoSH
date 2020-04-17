#More function is broken in powershell_Ise, therefore the below, out-more, was created to allow paging of results
function Out-More {
    param(   
        $Lines = 30,
        [Parameter(ValueFromPipeline=$true)]
        $InputObject
    )
    
    begin{
        $counter = 0
    }
    
    process{
        $counter++
        if ($counter -ge $Lines){
            $counter = 0
            Write-Host 'Press ENTER to continue' -ForegroundColor Yellow
            Read-Host  
        }
        $InputObject
    }
} 

$RawNames=import-csv C:\Users\ChrisL\Desktop\ddb-svcs.csv
$finalName=@()

Foreach ($t in $RawNames) {
    Try {
        #Concatenate each string
        $tempName="svc-"+$t.citycode.Replace('city_code: "',"").replace('"}',"")+`
        $t.officename.Replace('{"recon": {"office_name": "',"-").Replace('"',"")+`
        $t.roomfloor.replace("room_floor: ","-")+`
        $t.roomname.Replace('room_name: "',"-").Replace('"',"-")+`
        $t.roomcapacity.Replace("room_capacity: ","")
        
        #Remove encoded font
        ##If \abcyz1\ or \abcyz1, remove characters, the raw data sometimes contains font encoding
        IF ($tempName -match "\\[ -~][ -~][ -~][ -~][ -~][ -~]\\" -or` # <-- backtick, because scrolling to the right sucks
            $tempName -match "\\[ -~][ -~][ -~][ -~][ -~][ -~]") {$tempName=$tempName -replace "\\[ -~][ -~][ -~][ -~][ -~][ -~]",""}
        ##If \abyz1\ or \abyz1, remove characters
        IF ($tempName -match "\\[ -~][ -~][ -~][ -~][ -~]\\" -or` # <-- seriously, i love this thing
            $tempName -match "\\[ -~][ -~][ -~][ -~][ -~]") {$tempName=$tempName -replace "\\[ -~][ -~][ -~][ -~][ -~]",""}

        #Remove some special characters and other such as --,-,/,\, and .
        If ($tempName -like "*(*") {$tempName=$tempName.Replace("(","")}
        If ($tempName -like "*)*") {$tempName=$tempName.Replace(")","")}
        If ($tempName -like "*null*") {$tempName=$tempName.Replace("null","")}
        If ($tempName -like "*-") {$tempName=$tempName -replace "(-+$)",""}
        If ($tempName -like "*.*") {$tempName=$tempName -replace "\.",""}
        If ($tempName -like "*'*") {$tempName=$tempName -replace "\.",""}
        If ($tempName -match "/") {$tempName=$tempName -replace "/","_"}
        If ($tempName -like "*\*") {$tempName=$tempName -replace "\\","_"}
        If ($tempName -like "*--*") {$tempName=$tempName.Replace("--","-")}
        If ($tempName -like "*--") {$tempName=$tempName.Replace("--","")}

        #Remove Spaces regex style
        $tempName=$tempName -replace "\s",""

        #Aggregate all the temp objects into an array
        }
    #Catch error block to account for any non-conforming data
    Catch { Write-host "Error Processing $t - $($_.Exception.Message)" -BackgroundColor Red -ForegroundColor Yellow}
    $finalName+=$tempName
}
#Output data to out-gridview
$finalName | ogv