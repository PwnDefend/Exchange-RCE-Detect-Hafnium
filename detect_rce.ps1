#Requires -RunAsAdministrator
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

#RCE pwnage check for Exchange OAB Pwnage
#Version 1
# Created by mRr3b00t https://twitter.com/UK_Daniel_Card
# Thanks to @TomQuinn8

#some bits here are redundant but i've left them in as this is in dev

$StartDate=(GET-DATE)

get-OWAVirtualDirectory | select -Property Name,WhenChanged

$owastamp = get-OWAVirtualDirectory | select -Property WhenChanged,WhenCreated

#if you were pwn3d this stamp will have changed
get-OabVirtualDirectory | select -Property Name,WhenChanged
$oabstamp = get-OabVirtualDirectory | select -Property WhenChanged,WhenCreated


Get-AutodiscoverVirtualDirectory | select -Property Name,WhenChanged

$diff = NEW-TIMESPAN –Start $oabstamp.WhenCreated–End $oabstamp.WhenChanged

$fromnow = New-TimeSpan -Start $oabstamp.WhenChanged -End $StartDate.Date
$lapsed = $fromnow.Days

write-host "This should not have a large diff unless you had a managed change to this URL" -ForegroundColor Red
write-host "Difference between OAB created and OAB Modified Dates is :" + $diff.Days
write-host "The OAB modified date was changed $lapsed days ago" -ForegroundColor Gray
if($lapsed -le 60){
write-host "Your OAB Virtual Directory Modified date was recent - this is indicitive of either an authorised change or remote code execution" -ForegroundColor Red

}
else
{
write-host "Your OAB Virtual Directory Modified date was not recent - this is indicitive of normal operation. Please check the system for SSRF based data exfiltration." -ForegroundColor Yellow

}

#adding this in as a fasst edit
#update your path
#be mindful of how many lof files you have

write-host "Checking for RESET VIRTUAL DIRECTORY CALLS IN THE IIS LOGS - if you have these within the last 60 odd days that's probably not a good sign" -ForegroundColor Gray

findstr /snip /c:"ResetVirtualDirectory.aspx" C:\inetpub\logs\LogFiles\*.log
