###############################################################################
#                                                                             #
#   File name       pfts.ps1                                                  #
#                                                                             #
#   Description     A powershell based file transfer service                  #
#   									      #
#   Dependencies    Powershell 3.0, Windows 2016 (10), WinSCP 3.0.0?          #
#                                                                             #
#   Notes           Pfts (powershell file transfer service) is an extension   #
#		    of the WinSCP FTP client. Versioning is available at      #
#		    https://github.com/unix-bomber/Powershell.git             #
#		    pfts is heavily reliant on the standard means of          #
#		    allowing powershell scripts to run as a service - the     #
#		    PSService.ps1 JFLarvoire created. The most updated 	      #
#		    version of his code is at 				      #
#		    https://github.com/JFLarvoire/SysToolsLib/Powershell      #
#		    and the msdn article he wrote is at			      #
#                   https://msdn.microsoft.com/en-us/magazine/mt703436.aspx   #
#                                                                             #
#                   Some arguments are inspired by Linux' service management  #
#                   arguments: -Start, -Stop, -Restart, -Status               #
#                   Others are more in the Windows' style: -Setup, -Remove    #
#                                                                             #
#                   The actual start and stop operations are done when        #
#                   running as SYSTEM, under the control of the SCM (Service  #
#                   Control Manager).                                         #
#									      #
#                   Service installation and usage: See the dynamic help      #
#                   section below, or run: help .\pfts.ps1 -Detailed          #
#                                                                             #
#                   Debugging: The Log function writes messages into a file   #
#                   called C:\Windows\Logs\pfts.log (or actually              #
#                   ${env:windir}\Logs\$serviceName.log).                     #
#                   It is very convenient to monitor what's written into that #
#                   file with a WIN32 port of the Unix tail program. Usage:   #
#                   tail -f C:\Windows\Logs\pfts.log                          #
#                                                                             #
#   History                                                                   #
#    2018-3-15 TWK tim@pueobusinesssolutions.com created file transfer script #
#    									      #
###############################################################################
#Requires -version 2

<#

  -Basic Installation & Configuration:
#!#!#!#!#!#!#For brevity, assume any file paths mentioning pulling include pushing#!#!#!#!#!#!#

   1.) Ensure WinSCP is installed in its default directory at "C:\Program Files (x86)\WinSCP"

   2.) Create a directory called C:\Temp & place pfts.ps1 inside
       
	2.a) If you want to change to a folder of your choice...
	Right click on pfts.ps1, (or use your favorite text editor)
	and search for variable $scriptFullName. Change this to the
	file path of your choice.

   3.) Edit C:\Temp\pfts.ps1 (or whatever path you've specified) and
       search for the variable "$LocalFriendlyPulling" and $LocalFriendlyPushing
       and edit according to the datafeeds you need to pull and push (examples are present)

   4.) Open powershell (any version except (x86)) and run
       C:\Temp\pfts.ps1 -setup (or whatever path you've specified)
       Then run
       C:\Temp\pfts.ps1 -start

   5.) After setup (wait five to 10 seconds) stop the service with
       C:\Temp\pfts.ps1 -stop

   6.) You will have a new folder named C:\pfts, this is where files enter and exit. This
       is also where your transactional logs are C:\pfts\pulling\log. The file structure 
       will depend based on the friendly names that you placed into 
       $LocalFriendlyPulling/Pushing
   
   7.) Under C:\pfts\pulling\config, there will be a set of scripts based on the friendly
       names you input. Follow the instructions at the top of them, and edit the variables
       based on your needs.

   8.) Start the service by using 
       C:\Temp\pfts.ps1 -start
       MONITOR YOUR LOGS, AND DIRECTORIES FOR ANYTHING ABNORMAL.

  .SYNOPSIS
    A Windows service, in a standalone PowerShell script.
  .DESCRIPTION
    This script dynamically generates a small PSService.exe wrapper. In turn,
    this invokes the PowerShell script again to start and stop.
  .PARAMETER Start
    Start the service.
  .PARAMETER Stop
    Stop the service.
  .PARAMETER Restart
    Stop then restart the service.
  .PARAMETER Status
    Get the current service status: Not installed / Stopped / Running
  .PARAMETER Setup
    Install the service.
    Optionally use the -Credential or -UserName arguments to specify the user
    account for running the service. By default, uses the LocalSystem account.
    Known limitation with the old PowerShell v2: It is necessary to use -Credential
    or -UserName. For example, use -UserName LocalSystem to emulate the v3+ default.
  .PARAMETER Credential
    User and password credential to use for running the service.
    For use with the -Setup command.
    Generate a PSCredential variable with the Get-Credential command.
  .PARAMETER UserName
    User account to use for running the service.
    For use with the -Setup command, in the absence of a Credential variable.
    The user must have the "Log on as a service" right. To give him that right,
    open the Local Security Policy management console, go to the
    "\Security Settings\Local Policies\User Rights Assignments" folder, and edit
    the "Log on as a service" policy there.
    Services should always run using a user account which has the least amount
    of privileges necessary to do its job.
    Three accounts are special, and do not require a password:
    * LocalSystem - The default if no user is specified. Highly privileged.
    * LocalService - Very few privileges, lowest security risk.
      Apparently not enough privileges for running PowerShell. Do not use.
    * NetworkService - Idem, plus network access. Same problems as LocalService.
  .PARAMETER Password
    Password for UserName. If not specified, you will be prompted for it.
    It is strongly recommended NOT to use that argument, as that password is
    visible on the console, and in the task manager list.
    Instead, use the -UserName argument alone, and wait for the prompt;
    or, even better, use the -Credential argument.
  .PARAMETER Remove
    Uninstall the service.
  .PARAMETER Service
    Run the service in the background. Used internally by the script.
    Do not use, except for test purposes.
  .PARAMETER SCMStart
    Process Service Control Manager start requests. Used internally by the script.
    Do not use, except for test purposes.
  .PARAMETER SCMStop
    Process Service Control Manager stop requests. Used internally by the script.
    Do not use, except for test purposes.
  .PARAMETER Control
    Send a control message to the service thread.
  .PARAMETER Version
    Display this script version and exit.
  .EXAMPLE
    # Setup the service and run it for the first time
    C:\PS>.\PSService.ps1 -Status
    Not installed
    C:\PS>.\PSService.ps1 -Setup
    C:\PS># At this stage, a copy of PSService.ps1 is present in the path
    C:\PS>PSService -Status
    Stopped
    C:\PS>PSService -Start
    C:\PS>PSService -Status
    Running
    C:\PS># Load the log file in Notepad.exe for review
    C:\PS>notepad ${ENV:windir}\Logs\PSService.log
  .EXAMPLE
    # Stop the service and uninstall it.
    C:\PS>PSService -Stop
    C:\PS>PSService -Status
    Stopped
    C:\PS>PSService -Remove
    C:\PS># At this stage, no copy of PSService.ps1 is present in the path anymore
    C:\PS>.\PSService.ps1 -Status
    Not installed
  .EXAMPLE
    # Configure the service to run as a different user
    C:\PS>$cred = Get-Credential -UserName LAB\Assistant
    C:\PS>.\PSService -Setup -Credential $cred
  .EXAMPLE
    # Send a control message to the service, and verify that it received it.
    C:\PS>PSService -Control Hello
    C:\PS>Notepad C:\Windows\Logs\PSService.log
    # The last lines should contain a trace of the reception of this Hello message
#>