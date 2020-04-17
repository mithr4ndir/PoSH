$modules = Get-module Vmware* -ListAvailable | select Name

Foreach ($module in $modules) 
{
Import-Module $module.name
}
Connect-VIServer vcenter.corp.Companyx.com

get-vm

#Set-PowerCLIConfiguration <- might need this to set some config stuff for invaldcertaction

