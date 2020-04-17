<#
.Synopsis
   Create Bulk Groups
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>


function Create-GroupsInBulk
{
    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'http://www.microsoft.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        $listpath,
        [Parameter(Mandatory=$true)]
        $ouPath,
        [Parameter(Mandatory=$true)]
        $managedBy
    )

    Begin
    {
        Try {
        $Groups = Import-csv -path "$listpath"
        $Groups
        } Catch { "Error importing CSV into array - $($_.exception.message)" }
        Write-Log "$($($Groups|measure).Count) to be created"
    }
    Process
    {
        Foreach ($group in $groups)
        {
            Try {
                Write-log "Creating $($group.newname)..."
                New-ADGroup -DisplayName $group.newname -Description $group.description -GroupCategory Security -GroupScope Universal -SamAccountName $group.newname -Name $group.newname -Path "$ouPath" -ManagedBy $managedBy
            }
            Catch {Write-log "Error creating group - $($_.Exception.Message)"}
        }
    }
    End
    {
    }
}