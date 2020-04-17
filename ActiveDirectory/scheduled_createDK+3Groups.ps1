# Updated:
#       02/21/18 - Decommision ARS and port to local QAD proxy

# Uncomment the three lines below if running outside of ARS
Import-Module ActiveRolesConfiguration
Import-Module ActiveRolesManagementShell

Connect-QADService

# Set DC <---!
$adServer = "server1"

$timer = [system.diagnostics.stopwatch]::StartNew() 
 if (-not (Get-Module -Name ActiveDirectory)) { Import-Module -Name ActiveDirectory -ErrorAction 'Stop' -Verbose:$false }
$START = Get-Date

function Get-ADDirectReports
{

	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[string[]]$Identity,
		[switch]$Recurse,
		[string]$SearchRoot,
		[int]$ComboBreaker = 100
	)
	begin
	{

	}
	process
	{
		foreach ($Account in $Identity)
		{
			try
			{
				if ($PSBoundParameters['Recurse'])
				{
					# Get the DirectReports
					if($ComboBreaker -eq 0){Write-Verbose -Message 'BREAKING';break}
					Write-Verbose -Message "[PROCESS] Account: $Account (Recursive). Break:$ComboBreaker"
					try {
                        "Getting and processing direct reports for $Account." | Out-File $log -Append
                        Get-ADUser -Server $adServer -Identity $Account -Properties directreports  |# -IncludedProperties directreports -SearchRoot $SearchRoot |
					    ForEach-Object -Process {
						    $_.directreports | ForEach-Object -Process {
							    # Output the current object with the properties Name, SamAccountName, Mail and Manager
							    Get-ADUser -Server $adServer -filter {(distinguishedname -eq $PSItem) -and (enabled -eq $true)}  -Properties mail, manager | Select-Object -Property Name, SamAccountName, Mail, @{ Name = "Manager"; Expression = { (Get-Aduser -Server $adServer -identity $psitem.manager).samaccountname } }
							    # Gather DirectReports under the current object and so on...
							    Get-ADDirectReports -Identity $PSItem -Recurse -ComboBreaker ($ComboBreaker -1) -SearchRoot $SearchRoot
						    }
					    }
                        "Finished getting and processing direct reports for $Account" | Out-File $log -Append
                    } catch {
                        "Error -- Failed to get and process direct reports for $Account : $($_.Exception.Message)" | Out-File $log -Append    
                    }
				}#IF($PSBoundParameters['Recurse'])
				if (-not ($PSBoundParameters['Recurse']))
				{
					Write-Verbose -Message "[PROCESS] Account: $Account"
					# Get the DirectReports
                    try {
                        "Getting and processing direct reports for $Account." | Out-File $log -Append
                        Get-QAduser -Service $adServer -identity $Account -Properties directreports -SearchRoot $SearchRoot | Select-Object -ExpandProperty directReports |
					    Get-QADUser -Service $adServer -Properties mail, manager -SearchRoot $SearchRoot | Select-Object -Property Name, SamAccountName, Mail, @{ Name = "Manager"; Expression = { (Get-QAduser -Service $adServer -identity $psitem.manager).samaccountname } }
				        "Finished getting and processing direct reports for $Account" | Out-File $log -Append
                    } catch {
                        "Error -- Failed to get and process direct reports for DK : $($_.Exception.Message)" | Out-File $log -Append    
                    }
                }#IF (-not($PSBoundParameters['Recurse']))
			}#TRY
			catch
			{
				Write-Verbose -Message "[PROCESS] Something wrong happened"
				Write-Verbose -Message $Error[0].Exception.Message
			}
		}
	}
	end
	{
#		Remove-Module -Name ActiveDirectory -ErrorAction 'SilentlyContinue' -Verbose:$false | Out-Null
	}
}

# Log information
$logStructure = 'C:\Repository\logs\Scheduled\scheduled_createDK+3Groups-{0}.txt' # Get-Date
#if($Env:COMPUTERNAME -eq 'IAMS01'){$logStructure = 'C:\Repository\\scheduled_UpdateOrCreate_Direct_Report_2_Groups-{0}.txt'} # Get-Date}
$log = [string]::Format($logStructure,(Get-Date -Format MM.dd.yy))
$toLog = $true

$topUser = 'DK'

try {
    $domainDN = (Get-ADRootDSE -Server $adServer).defaultnamingcontext
} catch {
    "Error -- Failed to get domain defaultnamingcontext: $($_.Exception.Message)" | Out-File $log -Append    
}

#$searchBase = 'ou=users,ou=managed,dc=corp-dev,dc=Companyx,dc=com'
$searchBase = 'ou=users,ou=managed,' + $domainDN
#$searchBase = $domainDN

try {
    "Getting all direct reports for DK" | Out-File $log -Append
    $users = Get-ADDirectReports -Identity $topUser -comboBreaker 3 -SearchRoot $searchBase -Recurse | select -expandproperty samaccountname
    "Found the following direct reports for DK: `n$($usersWithDirectReports.samaccountname)" | Out-File $log -Append
} catch {
    "Error -- Failed to get all direct reports for DK : $($_.Exception.Message)" | Out-File $log -Append    
}

$groupParentOU = 'OU=Conditional AccessControl,OU=Groups,OU=Restricted,OU=Managed,' + $domainDN 
$tempADUserArray = @()
$usersAdded = 0
$usersRemoved = 0

foreach($user in $users){
	#Write-Host "Processing: $user"
	if(Get-ADUser -Server $adServer -Properties directReports -Filter {(samaccountname -eq $user) -and (directreports -like '*')} -SearchBase $searchBase){
		$tempADUserArray += $user
	}
}

if($tempGroup = Get-QADGroup -Service $adServer 'ARS-IndirectTargets'){
    if ($tempADGroupMember = Get-QADGroupMember -Service $adServer 'ARS-IndirectTargets')
    {
    	$comps = Compare-Object $tempADUserArray ($tempADGroupMember | select -ExpandProperty samaccountname)
        Set-QADGroup -Service $adServer -identity 'ARS-IndirectTargets' -member ($tempADUserArray | select -Unique)
        $usersAdded = ($comps | ?{$_.SideIndicator -eq '<='}).count
    	$usersRemoved = ($comps | ?{$_.SideIndicator -eq '=>'}).count
    }
    else
    {
       Set-QADGroup -Service $adServer -identity 'ARS-IndirectTargets' -member ($tempADUserArray|select -Unique) 
    }
}
else
{
    New-QADGroup -name 'ARS-IndirectTargets' -displayname 'ARS-IndirectTargets' -samaccountname 'ARS-IndirectTargets' -member ($tempADUserArray|select -Unique) -ParentContainer $groupParentOU
    $usersAdded = $tempADUserArray.count
 
} 

Remove-Module -Name ActiveDirectory -ErrorAction 'SilentlyContinue' -Verbose:$false | Out-Null
$runTime = [string]::Format( " | Runtime: {0} hours, {1} minutes, {2} seconds",$timer.Elapsed.Hours,$timer.Elapsed.Minutes, $timer.Elapsed.Seconds)
$timer.Stop()
$END = ("Ending scheduled_createTK+3Groups: Start Time: $START | End Time: "  + (Get-Date)) + $runTime + "`nUsers added: " + $usersAdded + " | Users removed: " + $usersRemoved
$END | Out-File -Append $log
#$EventLog.ReportEvent($Constants.EDS_EVENTLOG_WARNING_TYPE, $END)

 