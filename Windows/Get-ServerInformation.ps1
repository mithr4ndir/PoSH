Get-Job | Stop-Job | Remove-Job; $Error.Clear()
$null = $Svrs = $DCs = $Servers
$Svrs = Get-ADComputer -SearchBase '$OUDomainPATH' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server*" -and servicePrincipalName -notlike "MSClusterVirtualServer*"} -Properties Created,CanonicalName,IPv4Address,MemberOf,PasswordLastSet,DNSHostName
$DCs = Get-ADComputer -SearchBase 'OU=Domain Controllers,DC=corp,DC=Companyx,DC=com' -Filter {Enabled -eq $true -and operatingsystem -like "*windows server*" -and servicePrincipalName -notlike "MSClusterVirtualServer*"} -Properties Created,CanonicalName,IPv4Address,MemberOf,PasswordLastSet,DNSHostName
$Svrs = $Svrs + $DCs
$Servers = $Svrs.DNSHostName
$ReportDate = (Get-Date).DateTime
$SaveFormatDate = Get-Date -format yyyyMMddHHmm
$DaystoSave = 60
$OutputLocation1 = "\\site1-CSRPT01\C$\Windows\Web\PatchInfo","\\site2-CSRPT01\C$\Windows\Web\PatchInfo"
$OutputLocation2 = "\\site1-CSRPT01\C$\Windows\Web\ServerInfo","\\site2-CSRPT01\C$\Windows\Web\ServerInfo"

$DataLocation1 = "\\site1-file01\csreports\PatchStatus"
$DataLocation2 = "\\site1-file01\csreports\ServerInfo"

#delete old reports
Get-ChildItem $DataLocation1\PatchStatus20* | ?{$_.CreationTime -lt (Get-Date).AddDays(-$DaystoSave)} | Remove-Item
Get-ChildItem $DataLocation2\ServerInfo20* | ?{$_.CreationTime -lt (Get-Date).AddDays(-$DaystoSave)} | Remove-Item
$OutputLocation1 | % {Get-ChildItem $_\PatchStatus20* | ?{$_.CreationTime -lt (Get-Date).AddDays(-$DaystoSave)} | Remove-Item}
$OutputLocation2 | % {Get-ChildItem $_\ServerInfo20* | ?{$_.CreationTime -lt (Get-Date).AddDays(-$DaystoSave)} | Remove-Item}
#>

$ServerInfo = @(); $PatchStatus = @()
Workflow Get-Patchinfo {
    Inlinescript {
$CT = Get-WmiObject win32_operatingsystem
    $OS = $CT.Caption
    $LB = Get-Date $ct.ConvertToDateTime((Get-WmiObject win32_operatingsystem).LastBootUpTime) #-Format yyyy/M/dd
    $CBSRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $WUAURegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $SessionMgrPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $CBSRegCheck = Test-Path $CBSRegPath; $WUAURegCheck = Test-Path $WUAURegPath; $SessionMgrCheck = 
    if ($CBSRegCheck -or $WUAURegCheck) {$RebootPending = $true} Else {$RebootPending = $false}
    #if (Get-ItemProperty $SessionMgrPath -Name PendingFileRenameOperations -EA Ignore) {$RebootPending = $true}
    if ((Get-CimInstance win32_operatingsystem).Caption -match '2016') {$EMETCheck = $AntimalwareCheck = 'N/A'}
    else
    {
        try {Get-Service EMET_Service -ErrorAction Stop | Out-Null; $EMETCheck=$true} catch {$EMETCheck=$false}
        try {Get-Service MsMpSvc -ErrorAction Stop | Out-Null; $AntimalwareCheck=$true} catch {$AntimalwareCheck=$false}
    }
    $LastPatchDate = Get-Date (Get-HotFix  | ? {$_.InstalledOn} | sort InstalledOn | select -Last 1).InstalledOn -Format MM/dd/yyyy
    $updateSession = New-Object -ComObject "Microsoft.Update.Session"
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $SearchResult = try {$updateSearcher.Search("IsInstalled=0 and Type='Software'")} catch {$a="Exception from HRESULT:"+$error[0].Exception.Message.split(":")[-1].replace("`"","")}
    if ($SearchResult) 
        {$NumOfUpdates=$SearchResult.Updates.Count
        $i=4 #5 KB per row
        $UpdatesNeed = $SearchResult.Updates |  % {$_.title.split() | ?{$_ -like "(KB*)"}}
        if ($NumOfUpdates -gt 5)
            {Do {$UpdatesNeed[$i] = $UpdatesNeed[$i] + "<br>"; $i = $i + 5}
            Until ($i -gt $NumOfUpdates)
            }
        $UpdatesNeeded = ($UpdatesNeed -join ", ") -replace "<br>,","<br>"
        } 
    Else {$UpdatesNeeded=$a}
    if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU)
    {
        $WUServer = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate).WUServer.replace("https://","").split(".")[0]
        $AUOptions = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).AUOptions
        $ScheduledInstallDay = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).ScheduledInstallDay
        $ScheduledInstallTime = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).ScheduledInstallTime
        $Day=switch ($ScheduledInstallDay){0{"EveryDay"}1{"Sun"}2{"Mon"}3{"Tue"}4{"Wed"}5{"Thu"}6{"Fri"}7{"Sat"}}
        $AutoUpdate = if ($AUOptions -ne 4) {$false} Else {$Day + " @ " + $ScheduledInstallTime.ToString("00")+":00"}
    }
    else
    {
        $WUServer = "No WSUS Configued"
        $AutoUpdate = "No WSUS Configued"
    }
    $DNSServers = (gwmi Win32_NetworkAdapterConfiguration | ?{$_.IPEnabled -eq "True"}).DNSServerSearchOrder -join "; "
    $NumOfCPU = (Get-CimInstance win32_processor).count
    $RAM = [String](Get-CimInstance CIM_PhysicalMemory | Measure-Object -Property capacity -sum | % {[math]::round(($_.sum / 1GB),2)}) + "GB"
    
    New-Object psobject -Property @{
        OS = $OS.replace("Microsoft Windows Server ","").replace("Technical Preview","TP").replace("Datacenter","DC").replace("Standard","Std").replace("Enterprise","Ent")
        LastBootTime = $LB
        LastPatchDate = $LastPatchDate
        NumOfUpdates = $NumOfUpdates
        RebootPending = $RebootPending
        UpdatesNeeded = $UpdatesNeeded.Replace("(","" ).Replace(")","").TrimEnd("<br>")
        WUServer = $WUServer
        AutoUpdate = $AutoUpdate
        DNSServers = $DNSServers
        EMET = $EMETCheck
        Antimalware = $AntimalwareCheck
        CPUs = $NumOfCPU
        Memory = $RAM
        } | select PSComputerName,OS,CPUs,Memory,WUServer,AutoUpdate,LastBootTime,RebootPending,LastPatchDate,NumOfUpdates,UpdatesNeeded,DNSServers,EMET,Antimalware
    }
}

Get-patchinfo -PSComputerName $Servers -AsJob -PSRunningTimeoutSec 600 
Do {sleep 5
$leftServers = (Get-Job -IncludeChildJob | ?{$_.State -eq "running" -or $_.State -eq "NotStarted"}).count
write-progress -Activity 'Collect Patch Status Info' -percentComplete ((($Servers.Count - $leftServers)/$Servers.Count)*100) -Status "Completed $($Servers.Count - $leftServers) out of $($Servers.Count) Servers"
} 
Until ((Get-Job -IncludeChildJob | ?{$_.State -eq "running"}).count -eq 0)
$ServerInfo = Get-Job | Receive-Job

$Diff = (Compare-Object $Servers $($ServerInfo.PSComputerName)).InputObject 
$j=0
$Diff | % `
    {
    write-progress -Activity 'Checking un-finished servers' -percentComplete (($j/$Diff.Count)*100) -CurrentOperation "$([int](($j/$Diff.Count)*100))% Complete" -Status "Completed $j Servers"
    if (!(Test-Connection $_ -Count 1 -Quiet))
        {$ServerInfo += New-Object psobject -Property @{PSComputerName = $_; OS = ""; WUServer = ""; AutoUpdate = "";
        LastBootTime = ""; RebootPending = ""; LastPatchDate = ""; NumOfUpdates = ""; UpdatesNeeded = "Unresponsive to Ping";SepEnabled="";SepVersion="";DNSServers="";SEPM="";LatestVirusDefsDate="";SyslogNG="";PSSourceJobInstanceId=""} 
        }
    else
        {if ([bool](Test-WSMan $_))
             {$ServerInfo += New-Object psobject -Property @{PSComputerName = $_; OS = ""; WUServer = ""; AutoUpdate = "";
            LastBootTime = ""; RebootPending = ""; LastPatchDate = ""; NumOfUpdates = ""; UpdatesNeeded = "Unresponsive to Invoke-Command";SepEnabled="";SepVersion="";DNSServers="";SEPM="";LatestVirusDefsDate="";SyslogNG="";PSSourceJobInstanceId=""}
            }
        Else
             {$ServerInfo += New-Object psobject -Property @{PSComputerName = $_; OS = ""; WUServer = ""; AutoUpdate = "";
            LastBootTime = ""; RebootPending = ""; LastPatchDate = ""; NumOfUpdates = ""; UpdatesNeeded = "Unresponsive to Test-WSMan";SepEnabled="";SepVersion="";DNSServers="";SEPM="";LatestVirusDefsDate="";SyslogNG="";PSSourceJobInstanceId=""}
            }
        }
    $j++
    }

$PatchStatus = $ServerInfo | select PSComputerName,OS,WUServer,AutoUpdate,LastBootTime,RebootPending,LastPatchDate,NumOfUpdates,UpdatesNeeded,EMET,Antimalware | sort PSComputerName

$Exceptions = $PatchStatus | ?{$_.UpdatesNeeded -like "Exception*"}
$Left1 = @(); $PatchStatus | % {if ($Exceptions -notcontains $_){$Left1+=$_}}
$Unresponsive = $Left1 | ? {$_.UpdatesNeeded -like "Unresponsive*"}
$Left2 = @(); $Left1 | % {if ($Unresponsive -notcontains $_){$Left2+=$_}}

$Over90D = $Left2 | ? {(Get-Date $($_.LastPatchDate)) -lt (Get-Date).AddDays(-90)} 
$Left3 = @(); $Left2 | % {if ($Over90D -notcontains $_){$Left3+=$_}}
$Over30Updates = $Left3 | ?{$_.NumOfUpdates -gt 30}
$LefOver = @(); $Left3 | % {if ($Over30Updates -notcontains $_){$LefOver+=$_}}

$PatchStatus = $Exceptions + $Over90D + $Over30Updates + $Unresponsive + $LefOver
Get-Job | Remove-Job

$PatchStatus | Export-Csv $DataLocation1\PatchStatus$SaveFormatDate.csv -NoTypeInformation -Force

Function Build-Header($title){
@"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
<html><head><title>$title</title>
"@
}

$CSS = @"

<style type="text/css">
<!--
        body {
            font-family: Verdana, Geneva, Arial, Helvetica, sans-serif;
        }
        
        table{
            border-collapse: collapse;
            border: none;
            font: 10pt Verdana, Geneva, Arial, Helvetica, sans-serif;
            color: black;
            margin-bottom: 0px;
            margin: 0px auto;
        }
        table caption {
            font-weight: bold;
            font-size: 16px;
            background: #4f81bd;
            color: white;
        }
        table td{
            font-size: 10px;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
        }
        table td:last-child{
            padding-right: 5px;
        }
        table th {
            font-size: 12px;
            font-weight: bold;
            padding-left: 0px;
            padding-right: 20px;
            text-align: left;
            border-bottom: 1px  grey solid;
        }
        h2{ 
            clear: both;
            font-size: 200%; 
            margin-left: 20px;
            font-weight: bold;
        }
        h3{
            clear: both;
            font-size: 115%;
            margin-left: 20px;
            margin-top: 30px;
        }
        p{ 
            margin-left: 20px; font-size: 12px;
        }
        mark {
            background-color: yellow;
            color: black;
        }
        table.list{
            float: left;
        }
        table.list td:nth-child(1){
            font-weight: bold;
            border-right: 1px grey solid;
            text-align: right;
        }
        table.list td:nth-child(2){
            padding-left: 7px;
        }
        table tr:nth-child(even) td:nth-child(even){ background: #CCCCCC; }
        table tr:nth-child(odd) td:nth-child(odd){ background: #F2F2F2; }
        table tr:nth-child(even) td:nth-child(odd){ background: #DDDDDD; }
        table tr:nth-child(odd) td:nth-child(even){ background: #E5E5E5; }
        
        /*  Error and warning highlighting - Row*/
        table tr.warn:nth-child(even) td:nth-child(even){ background: #FFFF88; }
        table tr.warn:nth-child(odd) td:nth-child(odd){ background: #FFFFBB; }
        table tr.warn:nth-child(even) td:nth-child(odd){ background: #FFFFAA; }
        table tr.warn:nth-child(odd) td:nth-child(even){ background: #FFFF99; }
        
        table tr.alert:nth-child(even) td:nth-child(even){ background: #FF8888; }
        table tr.alert:nth-child(odd) td:nth-child(odd){ background: #FFBBBB; }
        table tr.alert:nth-child(even) td:nth-child(odd){ background: #FFAAAA; }
        table tr.alert:nth-child(odd) td:nth-child(even){ background: #FF9999; }
        
        table tr.healthy:nth-child(even) td:nth-child(even){ background: #88FF88; }
        table tr.healthy:nth-child(odd) td:nth-child(odd){ background: #BBFFBB; }
        table tr.healthy:nth-child(even) td:nth-child(odd){ background: #AAFFAA; }
        table tr.healthy:nth-child(odd) td:nth-child(even){ background: #99FF99; }
        
        /*  Error and warning highlighting - Cell*/
        table tr:nth-child(even) td.warn:nth-child(even){ background: #FFFF88; }
        table tr:nth-child(odd) td.warn:nth-child(odd){ background: #FFFFBB; }
        table tr:nth-child(even) td.warn:nth-child(odd){ background: #FFFFAA; }
        table tr:nth-child(odd) td.warn:nth-child(even){ background: #FFFF99; }
        
        table tr:nth-child(even) td.alert:nth-child(even){ background: #FF8888; }
        table tr:nth-child(odd) td.alert:nth-child(odd){ background: #FFBBBB; }
        table tr:nth-child(even) td.alert:nth-child(odd){ background: #FFAAAA; }
        table tr:nth-child(odd) td.alert:nth-child(even){ background: #FF9999; }
        
        table tr:nth-child(even) td.healthy:nth-child(even){ background: #88FF88; }
        table tr:nth-child(odd) td.healthy:nth-child(odd){ background: #BBFFBB; }
        table tr:nth-child(even) td.healthy:nth-child(odd){ background: #AAFFAA; }
        table tr:nth-child(odd) td.healthy:nth-child(even){ background: #99FF99; }
        
        /* security highlighting */
        table tr.security:nth-child(even) td:nth-child(even){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(odd){ 
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(even) td:nth-child(odd){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table tr.security:nth-child(odd) td:nth-child(even){
            border-color: #FF1111; 
            border: 1px #FF1111 solid;
        }
        table th.title{ 
            text-align: center;
            background: #848482;
            border-bottom: 1px  black solid;
            font-weight: bold;
            color: white;
        }
        table th.sectioncomment{ 
            text-align: left;
            background: #848482;
            font-style : italic;
            color: white;
            font-weight: normal;
            
            padding: 0px;
        }
        table th.sectioncolumngrouping{ 
            text-align: center;
            background: #AAAAAA;
            color: black;
            font-weight: bold;
            border:1px solid white;
        }
        table th.sectionbreak{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 130%;
        }
        table th.reporttitle{ 
            text-align: center;
            background: #848482;
            border: 2px black solid;
            font-weight: bold;
            color: white;
            font-size: 150%;
        }
        table tr.divide{
            border-bottom: 1px  grey solid;
        }
    -->
</style>

<script type=""text/javascript"">
var stIsIE = /*@cc_on!@*/false;

sorttable = {
  init: function() {
    // quit if this function has already been called
    if (arguments.callee.done) return;
    // flag this function so we don't do the same thing twice
    arguments.callee.done = true;
    // kill the timer
    if (_timer) clearInterval(_timer);

    if (!document.createElement || !document.getElementsByTagName) return;

    sorttable.DATE_RE = /^(\d\d?)[\/\.-](\d\d?)[\/\.-]((\d\d)?\d\d)$/;

    forEach(document.getElementsByTagName('table'), function(table) {
      if (table.className.search(/\bsortable\b/) != -1) {
        sorttable.makeSortable(table);
      }
    });

  },

  makeSortable: function(table) {
    if (table.getElementsByTagName('thead').length == 0) {
      // table doesn't have a tHead. Since it should have, create one and
      // put the first table row in it.
      the = document.createElement('thead');
      the.appendChild(table.rows[0]);
      table.insertBefore(the,table.firstChild);
    }
    // Safari doesn't support table.tHead, sigh
    if (table.tHead == null) table.tHead = table.getElementsByTagName('thead')[0];

    if (table.tHead.rows.length != 1) return; // can't cope with two header rows

    // Sorttable v1 put rows with a class of "sortbottom" at the bottom (as
    // "total" rows, for example). This is B&R, since what you're supposed
    // to do is put them in a tfoot. So, if there are sortbottom rows,
    // for backwards compatibility, move them to tfoot (creating it if needed).
    sortbottomrows = [];
    for (var i=0; i<table.rows.length; i++) {
      if (table.rows[i].className.search(/\bsortbottom\b/) != -1) {
        sortbottomrows[sortbottomrows.length] = table.rows[i];
      }
    }
    if (sortbottomrows) {
      if (table.tFoot == null) {
        // table doesn't have a tfoot. Create one.
        tfo = document.createElement('tfoot');
        table.appendChild(tfo);
      }
      for (var i=0; i<sortbottomrows.length; i++) {
        tfo.appendChild(sortbottomrows[i]);
      }
      delete sortbottomrows;
    }

    // work through each column and calculate its type
    headrow = table.tHead.rows[0].cells;
    for (var i=0; i<headrow.length; i++) {
      // manually override the type with a sorttable_type attribute
      if (!headrow[i].className.match(/\bsorttable_nosort\b/)) { // skip this col
        mtch = headrow[i].className.match(/\bsorttable_([a-z0-9]+)\b/);
        if (mtch) { override = mtch[1]; }
	      if (mtch && typeof sorttable["sort_"+override] == 'function') {
	        headrow[i].sorttable_sortfunction = sorttable["sort_"+override];
	      } else {
	        headrow[i].sorttable_sortfunction = sorttable.guessType(table,i);
	      }
	      // make it clickable to sort
	      headrow[i].sorttable_columnindex = i;
	      headrow[i].sorttable_tbody = table.tBodies[0];
	      dean_addEvent(headrow[i],"click", sorttable.innerSortFunction = function(e) {

          if (this.className.search(/\bsorttable_sorted\b/) != -1) {
            // if we're already sorted by this column, just
            // reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted',
                                                    'sorttable_sorted_reverse');
            this.removeChild(document.getElementById('sorttable_sortfwdind'));
            sortrevind = document.createElement('span');
            sortrevind.id = "sorttable_sortrevind";
            sortrevind.innerHTML = stIsIE ? '&nbsp<font face="webdings">5</font>' : '&nbsp;&#x25B4;';
            this.appendChild(sortrevind);
            return;
          }
          if (this.className.search(/\bsorttable_sorted_reverse\b/) != -1) {
            // if we're already sorted by this column in reverse, just
            // re-reverse the table, which is quicker
            sorttable.reverse(this.sorttable_tbody);
            this.className = this.className.replace('sorttable_sorted_reverse',
                                                    'sorttable_sorted');
            this.removeChild(document.getElementById('sorttable_sortrevind'));
            sortfwdind = document.createElement('span');
            sortfwdind.id = "sorttable_sortfwdind";
            sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
            this.appendChild(sortfwdind);
            return;
          }

          // remove sorttable_sorted classes
          theadrow = this.parentNode;
          forEach(theadrow.childNodes, function(cell) {
            if (cell.nodeType == 1) { // an element
              cell.className = cell.className.replace('sorttable_sorted_reverse','');
              cell.className = cell.className.replace('sorttable_sorted','');
            }
          });
          sortfwdind = document.getElementById('sorttable_sortfwdind');
          if (sortfwdind) { sortfwdind.parentNode.removeChild(sortfwdind); }
          sortrevind = document.getElementById('sorttable_sortrevind');
          if (sortrevind) { sortrevind.parentNode.removeChild(sortrevind); }

          this.className += ' sorttable_sorted';
          sortfwdind = document.createElement('span');
          sortfwdind.id = "sorttable_sortfwdind";
          sortfwdind.innerHTML = stIsIE ? '&nbsp<font face="webdings">6</font>' : '&nbsp;&#x25BE;';
          this.appendChild(sortfwdind);

	        // build an array to sort. This is a Schwartzian transform thing,
	        // i.e., we "decorate" each row with the actual sort key,
	        // sort based on the sort keys, and then put the rows back in order
	        // which is a lot faster because you only do getInnerText once per row
	        row_array = [];
	        col = this.sorttable_columnindex;
	        rows = this.sorttable_tbody.rows;
	        for (var j=0; j<rows.length; j++) {
	          row_array[row_array.length] = [sorttable.getInnerText(rows[j].cells[col]), rows[j]];
	        }
	        /* If you want a stable sort, uncomment the following line */
	        //sorttable.shaker_sort(row_array, this.sorttable_sortfunction);
	        /* and comment out this one */
	        row_array.sort(this.sorttable_sortfunction);

	        tb = this.sorttable_tbody;
	        for (var j=0; j<row_array.length; j++) {
	          tb.appendChild(row_array[j][1]);
	        }

	        delete row_array;
	      });
	    }
    }
  },

  guessType: function(table, column) {
    // guess the type of a column based on its first non-blank row
    sortfn = sorttable.sort_alpha;
    for (var i=0; i<table.tBodies[0].rows.length; i++) {
      text = sorttable.getInnerText(table.tBodies[0].rows[i].cells[column]);
      if (text != '') {
        if (text.match(/^-?[£$¤]?[\d,.]+%?$/)) {
          return sorttable.sort_numeric;
        }
        // check for a date: dd/mm/yyyy or dd/mm/yy
        // can have / or . or - as separator
        // can be mm/dd as well
        possdate = text.match(sorttable.DATE_RE)
        if (possdate) {
          // looks like a date
          first = parseInt(possdate[1]);
          second = parseInt(possdate[2]);
          if (first > 12) {
            // definitely dd/mm
            return sorttable.sort_ddmm;
          } else if (second > 12) {
            return sorttable.sort_mmdd;
          } else {
            // looks like a date, but we can't tell which, so assume
            // that it's dd/mm (English imperialism!) and keep looking
            sortfn = sorttable.sort_ddmm;
          }
        }
      }
    }
    return sortfn;
  },

  getInnerText: function(node) {
    // gets the text we want to use for sorting for a cell.
    // strips leading and trailing whitespace.
    // this is *not* a generic getInnerText function; it's special to sorttable.
    // for example, you can override the cell text with a customkey attribute.
    // it also gets .value for <input> fields.

    if (!node) return "";

    hasInputs = (typeof node.getElementsByTagName == 'function') &&
                 node.getElementsByTagName('input').length;

    if (node.getAttribute("sorttable_customkey") != null) {
      return node.getAttribute("sorttable_customkey");
    }
    else if (typeof node.textContent != 'undefined' && !hasInputs) {
      return node.textContent.replace(/^\s+|\s+$/g, '');
    }
    else if (typeof node.innerText != 'undefined' && !hasInputs) {
      return node.innerText.replace(/^\s+|\s+$/g, '');
    }
    else if (typeof node.text != 'undefined' && !hasInputs) {
      return node.text.replace(/^\s+|\s+$/g, '');
    }
    else {
      switch (node.nodeType) {
        case 3:
          if (node.nodeName.toLowerCase() == 'input') {
            return node.value.replace(/^\s+|\s+$/g, '');
          }
        case 4:
          return node.nodeValue.replace(/^\s+|\s+$/g, '');
          break;
        case 1:
        case 11:
          var innerText = '';
          for (var i = 0; i < node.childNodes.length; i++) {
            innerText += sorttable.getInnerText(node.childNodes[i]);
          }
          return innerText.replace(/^\s+|\s+$/g, '');
          break;
        default:
          return '';
      }
    }
  },

  reverse: function(tbody) {
    // reverse the rows in a tbody
    newrows = [];
    for (var i=0; i<tbody.rows.length; i++) {
      newrows[newrows.length] = tbody.rows[i];
    }
    for (var i=newrows.length-1; i>=0; i--) {
       tbody.appendChild(newrows[i]);
    }
    delete newrows;
  },

  /* sort functions
     each sort function takes two parameters, a and b
     you are comparing a[0] and b[0] */
  sort_numeric: function(a,b) {
    aa = parseFloat(a[0].replace(/[^0-9.-]/g,''));
    if (isNaN(aa)) aa = 0;
    bb = parseFloat(b[0].replace(/[^0-9.-]/g,''));
    if (isNaN(bb)) bb = 0;
    return aa-bb;
  },
  sort_alpha: function(a,b) {
    if (a[0]==b[0]) return 0;
    if (a[0]<b[0]) return -1;
    return 1;
  },
  sort_ddmm: function(a,b) {
    mtch = a[0].match(sorttable.DATE_RE);
    y = mtch[3]; m = mtch[2]; d = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt1 = y+m+d;
    mtch = b[0].match(sorttable.DATE_RE);
    y = mtch[3]; m = mtch[2]; d = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt2 = y+m+d;
    if (dt1==dt2) return 0;
    if (dt1<dt2) return -1;
    return 1;
  },
  sort_mmdd: function(a,b) {
    mtch = a[0].match(sorttable.DATE_RE);
    y = mtch[3]; d = mtch[2]; m = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt1 = y+m+d;
    mtch = b[0].match(sorttable.DATE_RE);
    y = mtch[3]; d = mtch[2]; m = mtch[1];
    if (m.length == 1) m = '0'+m;
    if (d.length == 1) d = '0'+d;
    dt2 = y+m+d;
    if (dt1==dt2) return 0;
    if (dt1<dt2) return -1;
    return 1;
  },

  shaker_sort: function(list, comp_func) {
    // A stable sort function to allow multi-level sorting of data
    // see: http://en.wikipedia.org/wiki/Cocktail_sort
    // thanks to Joseph Nahmias
    var b = 0;
    var t = list.length - 1;
    var swap = true;

    while(swap) {
        swap = false;
        for(var i = b; i < t; ++i) {
            if ( comp_func(list[i], list[i+1]) > 0 ) {
                var q = list[i]; list[i] = list[i+1]; list[i+1] = q;
                swap = true;
            }
        } // for
        t--;

        if (!swap) break;

        for(var i = t; i > b; --i) {
            if ( comp_func(list[i], list[i-1]) < 0 ) {
                var q = list[i]; list[i] = list[i-1]; list[i-1] = q;
                swap = true;
            }
        } // for
        b++;

    } // while(swap)
  }
}

/* ******************************************************************
   Supporting functions: bundled here to avoid depending on a library
   ****************************************************************** */

// Dean Edwards/Matthias Miller/John Resig

/* for Mozilla/Opera9 */
if (document.addEventListener) {
    document.addEventListener("DOMContentLoaded", sorttable.init, false);
}

/* for Internet Explorer */
/*@cc_on @*/
/*@if (@_win32)
    document.write("<script id=__ie_onload defer src=javascript:void(0)><\/script>");
    var script = document.getElementById("__ie_onload");
    script.onreadystatechange = function() {
        if (this.readyState == "complete") {
            sorttable.init(); // call the onload handler
        }
    };
/*@end @*/

/* for Safari */
if (/WebKit/i.test(navigator.userAgent)) { // sniff
    var _timer = setInterval(function() {
        if (/loaded|complete/.test(document.readyState)) {
            sorttable.init(); // call the onload handler
        }
    }, 10);
}

/* for other browsers */
window.onload = sorttable.init;

// written by Dean Edwards, 2005
// with input from Tino Zijdel, Matthias Miller, Diego Perini

// http://dean.edwards.name/weblog/2005/10/add-event/

function dean_addEvent(element, type, handler) {
	if (element.addEventListener) {
		element.addEventListener(type, handler, false);
	} else {
		// assign each event handler a unique ID
		if (!handler.`$`$guid) handler.`$`$guid = dean_addEvent.guid++;
		// create a hash table of event types for the element
		if (!element.events) element.events = {};
		// create a hash table of event handlers for each element/event pair
		var handlers = element.events[type];
		if (!handlers) {
			handlers = element.events[type] = {};
			// store the existing event handler (if there is one)
			if (element["on" + type]) {
				handlers[0] = element["on" + type];
			}
		}
		// store the event handler in the hash table
		handlers[handler.`$`$guid] = handler;
		// assign a global event handler to do all the work
		element["on" + type] = handleEvent;
	}
};
// a counter used to create unique IDs
dean_addEvent.guid = 1;

function removeEvent(element, type, handler) {
	if (element.removeEventListener) {
		element.removeEventListener(type, handler, false);
	} else {
		// delete the event handler from the hash table
		if (element.events && element.events[type]) {
			delete element.events[type][handler.`$`$guid];
		}
	}
};

function handleEvent(event) {
	var returnValue = true;
	// grab the event object (IE uses a global event object)
	event = event || fixEvent(((this.ownerDocument || this.document || this).parentWindow || window).event);
	// get a reference to the hash table of event handlers
	var handlers = this.events[event.type];
	// execute each event handler
	for (var i in handlers) {
		this.`$`$handleEvent = handlers[i];
		if (this.`$`$handleEvent(event) === false) {
			returnValue = false;
		}
	}
	return returnValue;
};

function fixEvent(event) {
	// add W3C standard event methods
	event.preventDefault = fixEvent.preventDefault;
	event.stopPropagation = fixEvent.stopPropagation;
	return event;
};
fixEvent.preventDefault = function() {
	this.returnValue = false;
};
fixEvent.stopPropagation = function() {
  this.cancelBubble = true;
}

// Dean's forEach: http://dean.edwards.name/base/forEach.js
/*
	forEach, version 1.0
	Copyright 2006, Dean Edwards
	License: http://www.opensource.org/licenses/mit-license.php
*/

// array-like enumeration
if (!Array.forEach) { // mozilla already supports this
	Array.forEach = function(array, block, context) {
		for (var i = 0; i < array.length; i++) {
			block.call(context, array[i], i, array);
		}
	};
}

// generic enumeration
Function.prototype.forEach = function(object, block, context) {
	for (var key in object) {
		if (typeof this.prototype[key] == "undefined") {
			block.call(context, object[key], key, object);
		}
	}
};

// character enumeration
String.forEach = function(string, block, context) {
	Array.forEach(string.split(""), function(chr, index) {
		block.call(context, chr, index, string);
	});
};

// globally resolve forEach enumeration
var forEach = function(object, block, context) {
	if (object) {
		var resolve = Object; // default
		if (object instanceof Function) {
			// functions have a "length" property
			resolve = Function;
		} else if (object.forEach instanceof Function) {
			// the object implements a custom forEach method so use that
			object.forEach(block, context);
			return;
		} else if (typeof object == "string") {
			// the object is a string
			resolve = String;
		} else if (typeof object.length == "number") {
			// the object is array-like
			resolve = Array;
		}
		resolve.forEach(object, block, context);
	}
};


</script>

</head>
<body>
<br>
"@

Function Create-SaerchTable ($TableID) {
@"
<script>
function searchTable() {
    var input, filter, found, table, tr, td, i, j;
    input = document.getElementById("myInput");
    filter = input.value.toUpperCase();
    table = document.getElementById("$TableID");
    tr = table.getElementsByTagName("tr");
    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName("td");
        for (j = 0; j < td.length; j++) {
            if (td[j].innerHTML.toUpperCase().indexOf(filter) > -1) {
                found = true;
            }
        }
        if (found) {
            tr[i].style.display = "";
            found = false;
        } else {
            if (tr[i].id != 'tableHeader'){tr[i].style.display = "none";}
        }
    }
}
</script>
"@
}

$HTMLEnd = @"
</div>
</body>
</html>
"@

$GoBackButton = @"
 <button style="position:fixed;top:5px;left:170px;background:green;font-weight: bold;font-size: 16px;color:white;" onclick="goBack()">Go Back</button>
<script>
function goBack() {
    window.history.back();
}
</script>
"@

$SearchInput = @"
<input id='myInput' onkeyup='searchTable()' type='text' placeholder='Type to search' style="position:fixed;top:8px;left:10px;background:#DDDDDD;">
"@


$PatchStatus| % `
    {
    if ($_.OS -notlike "*201*") {$_.OS = "<mark><FONT COLOR=`"Coral`">$($_.OS)</FONT></mark>"}
    if ($_.RebootPending -eq $true) {$_.RebootPending = "<mark><FONT COLOR=`"BurlyWood`">$($_.RebootPending)</FONT></mark>"}
    if ($_.WUServer -eq "No WSUS Configued") {$_.WUServer = "<mark><FONT COLOR=`"BurlyWood`">$($_.WUServer)</FONT></mark>"}
    if ($_.AutoUpdate -eq "No WSUS Configued") {$_.AutoUpdate = "<mark><FONT COLOR=`"BurlyWood`">$($_.AutoUpdate)</FONT></mark>"}
    if ($_.EMET -eq $false) {$_.EMET = "<mark><FONT COLOR=`"BurlyWood`">$($_.EMET)</FONT></mark>"}
    if ($_.Antimalware -eq $false) {$_.Antimalware = "<mark><FONT COLOR=`"BurlyWood`">$($_.Antimalware)</FONT></mark>"}
    if ($_.LastPatchDate) 
        {if ((Get-Date $($_.LastPatchDate)) -lt (Get-Date).AddDays(-90))
            {$_.LastPatchDate = "<mark><FONT COLOR=`"red`">$($_.LastPatchDate)</FONT></mark>"}
        }
    if ([int32]$_.NumOfUpdates -gt 30) {$_.NumOfUpdates = "<mark><FONT COLOR=`"Red`">$($_.NumOfUpdates)</FONT></mark>"}
    if ($_.UpdatesNeeded -like "Exception*" -or $_.UpdatesNeeded -like "Unresponsive*") {$_.UpdatesNeeded = "<mark><FONT COLOR=`"Coral`">$($_.UpdatesNeeded)</FONT></mark>"}
    }

$title = "PatchStatus Info"
$TableID = "PatchStatus"
$Caption = "Patch Status Information"

$htmlMiddle = ""
$htmlMiddle += "<div id='$title'>"
$ArrayToHtml = $PatchStatus | ConvertTo-HTML -fragment 
$ArrayToHtml = $ArrayToHtml -replace "&lt;","<" -replace "&quot;","`"" -replace "&gt;",">"

$htmlMiddle += $GoBackButton
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $css + $HTMLMiddle + $HTMLEnd

    #$HTMLmessage | Out-File C:\Temp\patchTest.html

	$OutputLocation1 | % {$HTMLmessage | Out-File $_\PatchStatus$SaveFormatDate.html}
	
	# Now create the detail launch page
	$html = @()
	$html = "<html>`n"
	$html += "<head><title>Patch Status - Corp.Companyx.com</title>`n"
	$html += "<script type=""text/javascript"">`n"
	$html += "function open_win() `n"
 	$html += "{	var myEle=document.getElementById('gopage');`n"
	$html += "	var myiFrame=document.getElementById('iframe');`n"
	$html += "	var myPage=myEle.options[myEle.selectedIndex].value;`n"
	$html += "	if (myPage != '') `n"
	$html += "	{	myiFrame.src=myPage;`n"
	$html += "	}`n"
	$html += "}`n"
	$html += "</script></head>`n"
	$html += "<body>`n"
	$html += "<iframe id=""iframe"" width=""100%"" height=""95%"" src=""PatchStatus$SaveFormatDate.html""></iframe>`n"
	$html += "<br>Show Report from: &nbsp;<select id=""gopage"" onChange=""open_win()"">`n"
	$html += "	<option value="""" selected></option>`n"
	$Files = Get-ChildItem "$($OutputLocation1[0])\PatchStatus20*.html" | Sort CreationTime -Descending
	ForEach ($File in $Files)
	{	$FileName = $File.Name.Substring(15,2) + "/" + $File.Name.Substring(17,2) + "/" + $File.Name.Substring(11,4) + " " + $File.Name.Substring(19,2) + ":" + $File.Name.Substring(21,2)
		$html += "	<option value=""" + $File.Name + """>" + $FileName +"</option>`n"
	}
	$html += "</select></body></html>`n"
	$OutputLocation1 | % {$html | Out-File $_\PatchStatusIndex.html}
	

"DNSName","Name","DeployedOn","OrganizationalUnit","IPv4","WsusGroup","PasswordLastSet" | % {$ServerInfo | Add-Member -MemberType NoteProperty -Name $_ -Value ""}
$WsusGroups = (Get-ADGroup -Filter {Name -like "*WSUS*"}).Name

$ServerInfo | % `
{
    $srv = $_.PSComputerName; $server = $Svrs | ? {$_.DNSHostName -eq $srv}
    $WsusMemberMatch = $null; $WsusMemberMatch = $WsusGroups | % {$server.MemberOf -match $_}
    $_.DeployedOn = if ($server.Created) {Get-Date $server.Created -Format MM/dd/yyyy}
    $_.OrganizationalUnit = $server.CanonicalName -replace ($server.Name,"")
    $_.IPv4 = $server.IPv4Address
    $_.WsusGroup = if ($WsusMemberMatch) {$WsusMemberMatch.split(",")[0].Split("=")[1]} else {"None"}
    $_.PasswordLastSet = if ($server.PasswordLastSet) {Get-Date $server.PasswordLastSet -Format MM/dd/yyyy}
    $_.DNSName = $srv
    $_.Name = $server.Name
}

$ServerInfo = $ServerInfo | select DNSName,Name,OS,IPv4,DNSServers,CPUs,Memory,DeployedOn,OrganizationalUnit,PasswordLastSet,EMET,Antimalware,WsusGroup,WUServer,AutoUpdate,LastBootTime,RebootPending,LastPatchDate,NumOfUpdates,UpdatesNeeded | Sort DNSName
$ServerInfo | Export-Csv $DataLocation2\ServerInfo$SaveFormatDate.csv -NoTypeInformation -Force




## build the detailed Server info page
$ServerInfo | % `
    {$srvn = $_.Name
    if ($_.DNSServers) 
        {$_.DNSServers = ($_.DNSServers.split(";").trimstart() | % `
            {$x=$_;if ($x -match "127.0.0.1"){$srvn} else {Try {(Resolve-DnsName $x -ErrorAction Stop).NameHost} catch {$x}}}) -join "; " }
    if ($_.PasswordLastSet) 
        {if ((New-TimeSpan $(Get-Date $_.PasswordLastSet) $(Get-Date)).Days -gt 90)
            {$_.PasswordLastSet = "<mark><FONT COLOR=`"Red`">$($_.PasswordLastSet)</FONT></mark>"}
        }
    if ($_.RebootPending -eq $true) 
            {$_.RebootPending = "<mark><FONT COLOR=`"BurlyWood`">$($_.RebootPending)</FONT></mark>"}
    if ($_.WUServer -eq "No WSUS Configued") {$_.WUServer = "<mark><FONT COLOR=`"RED`">$($_.WUServer)</FONT></mark>"}
    if ($_.AutoUpdate -eq "No WSUS Configued") {$_.AutoUpdate = "<mark><FONT COLOR=`"RED`">$($_.AutoUpdate)</FONT></mark>"}
    if ($_.EMET -eq $false) {$_.EMET = "<mark><FONT COLOR=`"BurlyWood`">$($_.EMET)</FONT></mark>"}
    if ($_.Antimalware -eq $false) {$_.Antimalware = "<mark><FONT COLOR=`"BurlyWood`">$($_.Antimalware)</FONT></mark>"}
 	if ($_.LastPatchDate)
        {if ((Get-Date $($_.LastPatchDate)) -lt (Get-Date).AddDays(-90))
            {$_.LastPatchDate = "<mark><FONT COLOR=`"Red`">$($_.LastPatchDate)</FONT></mark>"}}
	if ([int]$_.NumOfUpdates -gt 30)
        {$_.NumOfUpdates = "<mark><FONT COLOR=`"Red`">$($_.NumOfUpdates)</FONT></mark>"}

	if ($_.UpdatesNeeded -like "Exception*" -or $_.UpdatesNeeded -like "Unresponsive*")
        {$_.UpdatesNeeded = "<mark><FONT COLOR=`"Coral`">$($_.UpdatesNeeded)</FONT></mark>"}
    elseif ($_.UpdatesNeeded -match "KB\d{5}") 
        {$_.UpdatesNeeded = "<div title=""$($_.UpdatesNeeded -replace "<br> "," &#13;&#10;")""><p style=""text-decoration:underline;"">Mouseover for detail</p></div>"}
    #if ($_.WsusGroup){$_.WsusGroup = "<div title=""$($_.ViaGRP)""><p style=""text-decoration:underline;"">$($_.WsusGroup)</p></div>"}
    if ($_.DNSName.Split(".")[0] -ne $_.Name) 
        {
        $_.DNSName = "<mark><FONT COLOR=`"Red`">$($_.DNSName)</FONT></mark>"; $_.Name = "<mark><FONT COLOR=`"Red`">$($_.Name)</FONT></mark>"
        }
    if ($_.OS -notmatch '2016')
        {
        $_.OS = "<mark><FONT COLOR=`"BurlyWood`">$($_.OS)</FONT></mark>"
        }
    }

$title = "Server Info"
$TableID = "Server"
$Caption = "Server Information"

$htmlMiddle = ""
$htmlMiddle += "<div id='$title'>"
$ArrayToHtml = $ServerInfo | ConvertTo-HTML -fragment 
$ArrayToHtml = $ArrayToHtml -replace "&lt;","<" -replace "&quot;","`"" -replace "&gt;",">" -replace "&amp;#13","&#13" -replace "&amp;#10","&#10"

$htmlMiddle += $GoBackButton
$htmlMiddle += $SearchInput
$htmlMiddle += "<table id=`"$TableID`" class=`"sortable`">" + "`n<caption>$Caption<p>$(Get-Date)</p></caption>`n" + $ArrayToHtml[1]+ $($ArrayToHtml[2] -replace "<tr>","<tr id=`"tableHeader`">") +$ArrayToHtml[3..($ArrayToHtml.Count -1)]
$htmlMiddle +=  "`n$(Create-SaerchTable -TableID $TableID)`n"
$HTMLmessage = (Build-Header -title $title) + $css + $HTMLMiddle + $HTMLEnd

$OutputLocation2 | % {$HTMLmessage | Out-File $_\ServerInfo$SaveFormatDate.html}
	
	# Now create the detail launch page
	$html = @()
	$html = "<html>`n"
	$html += "<head><title>Server Information - Corp.Companyx.com</title>`n"
	$html += "<script type=""text/javascript"">`n"
	$html += "function open_win() `n"
 	$html += "{	var myEle=document.getElementById('gopage');`n"
	$html += "	var myiFrame=document.getElementById('iframe');`n"
	$html += "	var myPage=myEle.options[myEle.selectedIndex].value;`n"
	$html += "	if (myPage != '') `n"
	$html += "	{	myiFrame.src=myPage;`n"
	$html += "	}`n"
	$html += "}`n"
	$html += "</script></head>`n"
	$html += "<body>`n"
	$html += "<iframe id=""iframe"" width=""100%"" height=""95%"" src=""ServerInfo$SaveFormatDate.html""></iframe>`n"
	$html += "<br>Show Report from: &nbsp;<select id=""gopage"" onChange=""open_win()"">`n"
	$html += "	<option value="""" selected></option>`n"
	$Files = Get-ChildItem "$($OutputLocation2[0])\ServerInfo20*.html" | Sort CreationTime -Descending
	ForEach ($File in $Files)
	{	$FileName = $File.Name.Substring(14,2) + "/" + $File.Name.Substring(16,2) + "/" + $File.Name.Substring(10,4) + " " + $File.Name.Substring(18,2) + ":" + $File.Name.Substring(20,2)
		$html += "	<option value=""" + $File.Name + """>" + $FileName +"</option>`n"
	}
	$html += "</select></body></html>`n"
	$OutputLocation2 | % {$html | Out-File $_\ServerInfoIndex.html}
