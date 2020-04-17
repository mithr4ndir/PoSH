#Import this
$data = import-csv 'C:\Users\ChrisL\Desktop\AV Service Accounts Conf (1).csv' | select -ExpandProperty macos | select -first 2
$tempArray=@()
$fullArray=@()

Foreach ($d in $data) {
    $split = $d -split ("-")
    Foreach ($s in $split) {
        If($truncatedSplitArray -is [object]) {Remove-Variable truncatedSplitArray}
        If($truncatedCombinedArray -is [object]) {Remove-Variable truncatedCombinedArray}
        IF ($s.length -gt 10) {$s=$s.substring(0,10)}
            $truncatedSplitArray += $s 
        }
        $truncatedCombinedArray=$truncatedSplitArray -join "-"
        $tempArray = New-Object PSObject
        $tempArray | Add-Member -MemberType NoteProperty -Name MacNames -Value $truncatedCombinedArray
        $fullArray+=$tempArray
}