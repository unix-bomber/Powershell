###############################################################################
#                                                                             #
#   File name       pfts.ps1                                                  #
#                                                                             #
#   Description     A powershell based file transfer service                  #
#                                                                             #
#   Notes           The latest PSService.ps1 version is available in GitHub   #
#                   repository https://github.com/JFLarvoire/SysToolsLib/ ,   #
#                   in the PowerShell subdirectory.                           #
#                   Please report any problem in the Issues tab in that       #
#                   GitHub repository in                                      #
#                   https://github.com/JFLarvoire/SysToolsLib/issues          #
#                   If you do submit a pull request, please add a comment at  #
#                   the end of this header with the date, your initials, and  #
#                   a description of the changes. Also update $scriptVersion. #
#                                                                             #
#                   The initial version of this script was described in an    #
#                   article published in the May 2016 issue of MSDN Magazine. #
#                   https://msdn.microsoft.com/en-us/magazine/mt703436.aspx   #
#                   This updated version has one major change:                #
#                   The -Service handler in the end has been rewritten to be  #
#                   event-driven, with a second thread waiting for control    #
#                   messages coming in via a named pipe.                      #
#                   This allows fixing a bug of the original version, that    #
#                   did not stop properly, and left a zombie process behind.  #
#                   The drawback is that the new code is significantly longer,#
#                   due to the added PowerShell thread management routines.   #
#                   On the other hand, these thread management routines are   #
#                   reusable, and will allow building much more powerful      #
#                   services.                                                 #
#                                                                             #
#                   Dynamically generates a small PSService.exe wrapper       #
#                   application, that in turn invokes this PowerShell script. #
#                                                                             #
#                   Some arguments are inspired by Linux' service management  #
#                   arguments: -Start, -Stop, -Restart, -Status               #
#                   Others are more in the Windows' style: -Setup, -Remove    #
#                                                                             #
#                   The actual start and stop operations are done when        #
#                   running as SYSTEM, under the control of the SCM (Service  #
#                   Control Manager).                                         #
#                                                                             #
#                   To create your own service, make a copy of this file and  #
#                   rename it. The file base name becomes the service name.   #
#                   Then implement your own service code in the if ($Service) #
#                   {block} at the very end of this file. See the TO DO       #
#                   comment there.                                            #
#                   There are global settings below the script param() block. #
#                   They can easily be changed, but the defaults should be    #
#                   suitable for most projects.                               #
#                                                                             #
#                   Service installation and usage: See the dynamic help      #
#                   section below, or run: help .\PSService.ps1 -Detailed     #
#                                                                             #
#                   Debugging: The Log function writes messages into a file   #
#                   called C:\Windows\Logs\PSService.log (or actually         #
#                   ${env:windir}\Logs\$serviceName.log).                     #
#                   It is very convenient to monitor what's written into that #
#                   file with a WIN32 port of the Unix tail program. Usage:   #
#                   tail -f C:\Windows\Logs\PSService.log                     #
#                                                                             #
#   History                                                                   #
#    2015-07-10 JFL jf.larvoire@hpe.com created this script.                  #
#    2015-10-13 JFL Made this script completely generic, and added comments   #
#                   in the header above.                                      #
#    2016-01-02 JFL Moved the Event Log name into new variable $logName.      #
#                   Improved comments.                                        #
#    2016-01-05 JFL Fixed the StartPending state reporting.                   #
#    2016-03-17 JFL Removed aliases. Added missing explicit argument names.   #
#    2016-04-16 JFL Moved the official repository on GitHub.                  #
#    2016-04-21 JFL Minor bug fix: New-EventLog did not use variable $logName.#
#    2016-05-25 JFL Bug fix: The service task was not properly stopped; Its   #
#                   finally block was not executed, and a zombie task often   #
#                   remained. Fixed by using a named pipe to send messages    #
#                   to the service task.                                      #
#    2016-06-05 JFL Finalized the event-driven service handler.               #
#                   Fixed the default command setting in PowerShell v2.       #
#                   Added a sample -Control option using the new pipe.        #
#    2016-06-08 JFL Rewrote the pipe handler using PSThreads instead of Jobs. #
#    2016-06-09 JFL Finalized the PSThread management routines error handling.#
#                   This finally fixes issue #1.                              #
#    2016-08-22 JFL Fixed issue #3 creating the log and install directories.  #
#                   Thanks Nischl.                                            #
#    2016-09-06 JFL Fixed issue #4 detecting the System account. Now done in  #
#                   a language-independent way. Thanks A Gonzalez.            #
#    2016-09-19 JFL Fixed issue #5 starting services that begin with a number.#
#                   Added a $ServiceDescription string global setting, and    #
#                   use it for the service registration.                      #
#                   Added comments about Windows event logs limitations.      #
#    2016-11-17 RBM Fixed issue #6 Mangled hyphen in final Unregister-Event.  #
#    2017-05-10 CJG Added execution policy bypass flag.                       #
#    2017-10-04 RBL rblindberg Updated C# code OnStop() routine fixing        #
#                   orphaned process left after stoping the service.          #
#    2017-12-05 NWK omrsafetyo Added ServiceUser and ServicePassword to the   #
#                   script parameters.                                        #
#    2017-12-10 JFL Removed the unreliable service account detection tests,   #
#                   and instead use dedicated -SCMStart and -SCMStop          #
#                   arguments in the PSService.exe helper app.                #
#                   Renamed variable userName as currentUserName.             #
#                   Renamed arguments ServiceUser and ServicePassword to the  #
#                   more standard UserName and Password.                      #
#                   Also added the standard argument -Credential.             #
#                                                                             #
###############################################################################
#Requires -version 2

<#
  .SYNOPSIS
    A sample Windows service, in a standalone PowerShell script.
  .DESCRIPTION
    This script demonstrates how to write a Windows service in pure PowerShell.
    It dynamically generates a small PSService.exe wrapper, that in turn
    invokes this PowerShell script again for its start and stop events.
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