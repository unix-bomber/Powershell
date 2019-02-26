# Specific to pfts

## Description     A Powershell & WinSCP based file transfer service

## Dependencies    Powershell 3.0, .net 3.5, WinSCP 5.13

## Notes   

### References
Pfts (powershell file transfer service) is an extension of the WinSCP FTP client. Versioning is available at https://github.com/unix-bomber/Powershell.git fts is heavily reliant on the PSService.ps1 JFLarvoire created. The most updated version of his code is at https://github.com/JFLarvoire/SysToolsLib/Powershell
https://blogs.technet.microsoft.com/askperf/2014/08/11/wmi-high-memory-usage-by-wmi-service-or-wmiprvse-exe/ You may wish to increase the amount of WMI handlers. Too many WMI handlers open owing to McAfee or SCCM may crash the service


### Program Usage & Setup

# External Assumptions:
There's a Linux server configured with SFTP access, and an account with permissions to access required directories

# Installation:
 1.) Ensure WinSCP is installed in its default directory at "C:\Program Files (x86)\WinSCP"
 2.) Create folder C:\Program Files\pfts
 3.) Place pfts.ps1 into C:\Program Files\pfts

# Configuration: Management
1.) By default, all production data and logging passes through C:\pfts. This can, and should be modified to a partition/ seperate disk.
This can be modified by editing lines 1024, 1025, 1026, 1027, 1030, 1035 to suit your environment.

2.) Add a pulling datafeed, specify a name in double quotes on line 1029. To add multiple feeds, provide a comma after the closing double quote and a space and enter another name in the same format
ex. "coastguard", "airforce", "army"

For the remainder of this document, "coastguard" will be the example

3.) Add a pushing datafeed, specify a name in double quotes on line 1034. To add multiple feeds, provide a comma after the closing double quote and a space and enter another name in the same format
ex. "coastguard", "airforce", "army"

4.) Open Powershell, and run 
"C:\Program Files\pfts\pfts.ps1" -setup
"C:\Program Files\pfts\pfts.ps1" -start
wait 30 seconds for all feeds to be created
"C:\Program Files\pfts\pfts.ps1" -stop

# Configuration: Individual Feeds
This readme only covers sftp with basic authentication

1.) For each name added in steps 2 and 3 of "Configuration: Management" there will be a new .ps1 file in C:\pfts\pulling\originators\conf and C:\pfts\pushing\destination\conf

2.) Open C:\pfts\pulling\destination\conf\coastguard.ps1 with your favorite text editor

3.) Lines 7 - 17 are used to connect to have descriptions on requirements. Read each requirement for each line

4.) Lines 21 - 24 are used to format data in transit, only transfers from and to Linux are currently supported 

note: basic authentication can only survive reboots if the GPO "Network access: Do not allow storage of passwords and credentials for network authentication" is set to default, or disabled

# Starting:

1.) Once all feeds are configured, run 
"C:\Program Files\pfts\pfts.ps1" -start

# Long term administration:

Pfts will log to the application event viewer store. If anything goes wrong, this should be your first stop to check for issues.
If there's no valuable information there, check C:\pfts\log for errors that the WinSCP .dll may be encountering
Should that provide no tangible information, as a last ditch effort, check C:\Windows\Logs\pfts.log

# Additional information
 Some arguments are inspired by Linux' service management arguments: -Start, -Stop, -Restart, -Status Others are more in the Windows' style: -Setup, -Remove  The actual start and stop operations are done when  running as SYSTEM, under the control of the SCM (Service  Control Manager). 

Dynamic help section below, or run: help .\pfts.ps1 -Detailed  

  Debugging: The Log function writes messages into a file called C:\Windows\Logs\pfts.log (or actually ${env:windir}\Logs\$serviceName.log). It is very convenient to monitor what's written into that  file with a WIN32 port of the Unix tail program. Usage:tail -f C:\Windows\Logs\pfts.log
