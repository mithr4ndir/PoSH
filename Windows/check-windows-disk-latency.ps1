#
#   check-windows-disk-latency.ps1
#
# DESCRIPTION:
#   This plugin collects the disk queue length latency and compares against the WARNING and CRITICAL thresholds.
#
# OUTPUT:
#   plain text
#
# PLATFORMS:
#   Windows
#
# DEPENDENCIES:
#   Powershell 3.0 or above
#
# USAGE:
#   Powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -NoLogo -File C:\\etc\\sensu\\plugins\\check-windows-disk-latency.ps1 2 3
#
# NOTES:
#

#Requires -Version 3.0

[CmdletBinding()]
Param(
   [Parameter(Mandatory=$True,Position=1)]
   [int]$WARNING,

   [Parameter(Mandatory=$True,Position=2)]
   [int]$CRITICAL
)

$computer=$ENV:Computername 
$allParts=Get-Partition | select -exp DriveLetter | ? {$_}
$critArray=@()
$warnArray=@()
$okayArray=@()
Foreach ($part in $allParts) {
    
    $check = (Get-Counter "\\$Computer\LogicalDisk($part$(":"))\Current Disk Queue Length").CounterSamples | 
    Select-Object Path,CookedValue

    If ($check.cookedvalue -gt $CRITICAL) { 
        $critArray+= "CheckWindowsDiskLatency CRITICAL: $part disk queue length is $($check.cookedvalue)."
        }

    If ($check.cookedvalue -gt $WARNING) {
        $warnArray+= "CheckWindowsDiskLatency WARNING: $part disk queue length is $($check.cookedvalue)."
        }

    Else {
        $okayArray+= "CheckWindowsDiskLatency OK: $part disk queue length is $($check.cookedvalue)."
    }

}
IF ($critArray) {$critArray;Write-Output "Exit 2"}
IF ($warnArray) {$warnArray;Write-Output "Exit 1"}
IF ($okayArray) {$okayArray;Write-Output "Exit 0"}