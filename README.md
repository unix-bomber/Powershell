# Tim's Awesome PowerShell Scripts

## Description     A Powershell & WinSCP based file transfer service

## Dependencies    Powershell 3.0, .net 3.5, WinSCP 5.13

## Notes   

### References
Pfts (powershell file transfer service) is an extension of the WinSCP FTP client. Versioning is available at https://github.com/unix-bomber/Powershell.git fts is heavily reliant on the PSService.ps1 JFLarvoire created. The most updated version of his code is at https://github.com/JFLarvoire/SysToolsLib/Powershell

### Program Usage
 Some arguments are inspired by Linux' service management arguments: -Start, -Stop, -Restart, -Status Others are more in the Windows' style: -Setup, -Remove  The actual start and stop operations are done when  running as SYSTEM, under the control of the SCM (Service  Control Manager). 

  Service installation and usage: See the dynamic help  section below, or run: help .\pfts.ps1 -Detailed  

  Debugging: The Log function writes messages into a file called C:\Windows\Logs\pfts.log (or actually ${env:windir}\Logs\$serviceName.log). It is very convenient to monitor what's written into that  file with a WIN32 port of the Unix tail program. Usage:tail -f C:\Windows\Logs\pfts.log

  History
  2018-3-15 TWK tim@pueobusinesssolutions.com created file transfer script
  2018-4-3  TWK tim@pueobusinesssolutions.com first push to master branch
