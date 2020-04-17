#$Computers = (Import-Csv (Get-ChildItem \\site1-file01\csreports\ServerInfo | ? {$_.Name -like "ServerInfo*"})[-1].FullName | ? {(($_.Duo -eq $false) ) -and (($_.Name -notmatch '-fintech') -and ($_.Name -notmatch '-RDS'))}).DNSName
Function Upgrade-DUO
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][String[]]$Computers
    )
    $InstallString = "MsiExec.exe /i C:\Bits\DuoWindowsLogon64.msi IKEY=`"THISKEY`" SKEY=`"THATKEY`" HOST=`"APIADDRESS`" AUTOPUSH=`"#1`" FAILOPEN=`"#1`" SMARTCARD=`"#0`" RDPONLY=`"#0`" /quiet /qn /norestart"
    $UninstallString = "MsiExec.exe /X{AF828DB1-476C-4EDD-BFF1-44456828764F} /quiet /qn /norestart"

    $Computers | % `
    {
        $srv= $_
        Write-host "Processing $srv..."
        if (!(Test-Path \\$srv\C$\Bits)) 
        {
            Write-Verbose "    Create folder C:\Bits on $srv"
            New-Item -Path \\$srv\C$ -Name Bits -ItemType Directory
        }
        if (!(Test-Path \\$srv\c$\Bits\DuoWindowsLogon64.msi)) 
        {
            Write-Verbose "    Copy installation files to $srv"
            Copy-Item \\site1-file01\SWInstall\Duomst\DuoWindowsLogon64.msi \\$srv\c$\Bits -Force
        }
        if (Test-Path \\$srv\c$\Bits\DuoWindowsLogon64.msi)
        {
        # check Duo version
        if ((Get-CimInstance -ComputerName $srv -ClassName win32_product | ? {$_.Name -eq 'Duo Authentication for Windows Logon x64'}).Version -match '2.0.0')
        {
            Write-Verbose "Uninstall older version of Duo on $srv"
            Invoke-Command -ComputerName $srv -ScriptBlock {}
            $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($UninstallString)
            If ($newProc.ReturnValue -eq 0) 
            { 
                Write-Host "Uninstalling DUO on $srv process ID - $($newProc.ProcessId)" 
            } 
            else 
            { 
                Write-Host $srv Process create failed with $newProc.ReturnValue
            }
            while ((Get-Process -Id $newProc.ProcessId -ErrorAction SilentlyContinue) -ne $null) {sleep 1} # ensure process completed and closed before install
        }
            Write-Verbose "Install new version of Duo to $srv"
            $newProc=([WMICLASS]"\\$srv\root\cimv2:win32_Process").Create($InstallString)
            If ($newProc.ReturnValue -eq 0) 
            { 
                Write-Host "Installing DUO on $srv process ID - $($newProc.ProcessId)"
            } 
            else 
            { 
                write-host $srv Process create failed with $newProc.ReturnValue
            }
        }
    }
}