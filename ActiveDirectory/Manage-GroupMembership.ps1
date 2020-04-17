function Set-ADPermissionModifyGroupMembership{
<#
.DESCRIPTION
Sets the Delegation permission for a user or a group to Modify the Membership of an AD Group
.EXAMPLE
Set-ADPermissionModifyGroupMembership -User "chris ladino" -Group TestGroup
.PARAMETER User
The user name or group name you want to delegate permission for
.PARAMETER Group
The target group name you want to delegate to
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $User,
      
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $Group
  )
  begin {
    try {
      Import-Module activedirectory
      $guidWriteMembers = New-Object Guid bf9679c0-0de6-11d0-a285-00aa003049e2
    }
    catch {
    }
  }
  process {
    try {
      Write-Verbose "collect the NTAccount for the user/group we will be delegating"
      $adObject = Get-ADObject -Filter {Name -eq $User -or SamAccountName -eq $User} -Properties sAMAccountName
      if (!$adObject) {Write-Error -Exception "Cannot find an object with identity: $User under: $(([adsi]'').distinguishedName)"}
      $objNTAccount = New-Object System.Security.Principal.NTAccount "$env:USERDOMAIN\$($adObject.sAMAccountName)"
      Write-Verbose "create access rule for group membership management"
      $aceManageGroupMembership = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $objNTAccount,"ReadProperty, WriteProperty","Allow",$guidWriteMembers,"None",$guidWriteMembers
      Write-Verbose "add the access rule to the group"
      $ADObject = [ADSI]("LDAP://" + (Get-ADGroup $Group).DistinguishedName)
      $ADObject.ObjectSecurity.AddAccessRule($aceManageGroupMembership)
      $ADObject.CommitChanges()

    }
    catch {$Error[0].Exception
    }
  }
}

function Remove-ADPermissionModifyGroupMembership{
<#
.DESCRIPTION
Remove the Delegation permission for a user or a group to Modify the Membership of an AD Group
.EXAMPLE
Remove-ADPermissionModifyGroupMembership -User "jibin peng" -Group TestGroup
.PARAMETER User
The user name or group name you want to delegate permission for
.PARAMETER Group
The target group name you want to delegate to
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $User,
      
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $Group
  )
  begin {
    try {
      import-module activedirectory
    }
    catch {$Error[0].Exception
    }
  }
  process {
    try {
      Write-Verbose "collect the NTAccount for the user/group we will be delegating"
      $adObject = Get-ADObject -Filter {Name -eq $User -or SamAccountName -eq $User} -Properties sAMAccountName
      if (!$adObject) {Write-Error -Exception "Cannot find an object with identity: $User under: $(([adsi]'').distinguishedName)."}
      $objNTAccount = New-Object System.Security.Principal.NTAccount "$env:USERDOMAIN\$($adObject.sAMAccountName)"
      $GroupDN = (Get-ADGroup $Group).DistinguishedName
      $AccessEntry = (Get-Acl "AD:$GroupDN").access | ? {$_.IdentityReference -eq $objNTAccount.Value}
      if ($AccessEntry) 
      {
          Write-Verbose "remove access rule"
          $ADObject = [ADSI]("LDAP://" + $GroupDN)
          $ADObject.ObjectSecurity.RemoveAccessRuleSpecific($AccessEntry)
          $ADObject.CommitChanges()
      }
      Else 
      {
          "The user - $User has no specific privilege to the group - $Group."
      }
    }
    catch {$Error[0].Exception
    }
  }
}

function Test-UserGroupMembershipAccess{
<#
.DESCRIPTION
Test to see if user have access to Modify the Membership of an AD Group
.EXAMPLE
Test-UserGroupMembershipAccess -User "jibin peng" -Group TestGroup
#>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $User,
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
    [ValidateNotNullOrEmpty()]
    [System.String]
    $Group
  )
    Begin {Import-Module ActiveDirectory}
    Process{
      Try {
        $GroupDN = (Get-ADGroup $Group).DistinguishedName
        $AccessEntry = (Get-Acl "AD:$GroupDN").access | `
        ? {$_.ActiveDirectoryRights -match "WriteProperty" -and ($_.IdentityReference -match $env:USERDOMAIN -or $_.IdentityReference -match 'BUILTIN')}

        $UserSamAcc = (Get-ADUser -Filter {Name -eq $User -or SamAccountName -eq $User}).SamAccountName
        $NTAcc = "$env:USERDOMAIN\$UserSamAcc"
        $UserName = (Get-ADUser -Filter {Name -eq $User -or SamAccountName -eq $User}).Name
        if (!$UserSamAcc -or !$UserName)
        {
            Write-Error "Get-ADUser: Cannot find an object with identity: $User under: $env:USERDNSDOMAIN."
            Break
        }
        $WithAccess = $false
        $AccessEntry | % `
        {
            if ($WithAccess) {Return}
            $SamAcc = $_.IdentityReference.Value.Replace("$env:USERDOMAIN\",'').Replace('BUILTIN\','')
            $ObjClass = (Get-ADObject -Filter {SamAccountName -eq $SamAcc}).ObjectClass
            if ($ObjClass -eq 'User' -and $_.IdentityReference -eq $NTAcc)
            {
                $WithAccess = $true; Return
            }
            if ($ObjClass -eq 'Group' -and ((Get-ADGroupMember $SamAcc -Recursive).Name -contains $UserName))
            {
                $WithAccess = $true; Return
            }
        }
        Return $WithAccess
      }
      Catch {$Error[0].Exception}
    }
}
