###############################################################################
#                                                                             #
#   File name       PSService.ps1                                             #
#                                                                             #
#   Description     A sample service in a standalone PowerShell script        #
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

[CmdletBinding(DefaultParameterSetName='Status')]
Param(
  [Parameter(ParameterSetName='Start', Mandatory=$true)]
  [Switch]$Start,               # Start the service

  [Parameter(ParameterSetName='Stop', Mandatory=$true)]
  [Switch]$Stop,                # Stop the service

  [Parameter(ParameterSetName='Restart', Mandatory=$true)]
  [Switch]$Restart,             # Restart the service

  [Parameter(ParameterSetName='Status', Mandatory=$false)]
  [Switch]$Status = $($PSCmdlet.ParameterSetName -eq 'Status'), # Get the current service status

  [Parameter(ParameterSetName='Setup', Mandatory=$true)]
  [Parameter(ParameterSetName='Setup2', Mandatory=$true)]
  [Switch]$Setup,               # Install the service

  [Parameter(ParameterSetName='Setup', Mandatory=$true)]
  [String]$UserName,              # Set the service to run as this user
  
  [Parameter(ParameterSetName='Setup', Mandatory=$false)]
  [String]$Password,              # Use this password for the user
  
  [Parameter(ParameterSetName='Setup2', Mandatory=$false)]
  [System.Management.Automation.PSCredential]$Credential, # Service account credential

  [Parameter(ParameterSetName='Remove', Mandatory=$true)]
  [Switch]$Remove,              # Uninstall the service

  [Parameter(ParameterSetName='Service', Mandatory=$true)]
  [Switch]$Service,               # Run the service (Internal use only)

  [Parameter(ParameterSetName='SCMStart', Mandatory=$true)]
  [Switch]$SCMStart,              # Process SCM Start requests (Internal use only)

  [Parameter(ParameterSetName='SCMStop', Mandatory=$true)]
  [Switch]$SCMStop,               # Process SCM Stop requests (Internal use only)

  [Parameter(ParameterSetName='Control', Mandatory=$true)]
  [String]$Control = $null,     # Control message to send to the service

  [Parameter(ParameterSetName='Version', Mandatory=$true)]
  [Switch]$Version              # Get this script version
)

$scriptVersion = "2017-12-10"

# This script name, with various levels of details
$argv0 = Get-Item $MyInvocation.MyCommand.Definition
$script = "pfts"               # Ex: PSService
$scriptName = "pfts.ps1"               # Ex: PSService.ps1
$scriptFullName = "C:\Temp\pfts.ps1"       # Ex: C:\Temp\PSService.ps1

# Global settings
$serviceName = $script                  # A one-word name used for net start commands
$serviceDisplayName = "Powershell file transfer service"
$ServiceDescription = "Moves files from a source to a destination via encrypted FTP or SCP"
$pipeName = "Service_$serviceName"      # Named pipe name. Used for sending messages to the service task
# $installDir = "${ENV:ProgramFiles}\$serviceName" # Where to install the service files
$installDir = "${ENV:windir}\System32"  # Where to install the service files
$scriptCopy = "$installDir\$scriptName"
$exeName = "$serviceName.exe"
$exeFullName = "$installDir\$exeName"
$logDir = "${ENV:windir}\Logs"          # Where to log the service messages
$logFile = "$logDir\$serviceName.log"
$logName = "Application"                # Event Log name (Unrelated to the logFile!)
# Note: The current implementation only supports "classic" (ie. XP-compatble) event logs.
#	To support new style (Vista and later) "Applications and Services Logs" folder trees, it would
#	be necessary to use the new *WinEvent commands instead of the XP-compatible *EventLog commands.
# Gotcha: If you change $logName to "NEWLOGNAME", make sure that the registry key below does not exist:
#         HKLM\System\CurrentControlSet\services\eventlog\Application\NEWLOGNAME
#	  Else, New-EventLog will fail, saying the log NEWLOGNAME is already registered as a source,
#	  even though "Get-WinEvent -ListLog NEWLOGNAME" says this log does not exist!

# If the -Version switch is specified, display the script version and exit.
if ($Version) {
  Write-Output $scriptVersion
  return
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Now                                                       #
#                                                                             #
#   Description     Get a string with the current time.                       #
#                                                                             #
#   Notes           The output string is in the ISO 8601 format, except for   #
#                   a space instead of a T between the date and time, to      #
#                   improve the readability.                                  #
#                                                                             #
#   History                                                                   #
#    2015-06-11 JFL Created this routine.                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Now {
  Param (
    [Switch]$ms,        # Append milliseconds
    [Switch]$ns         # Append nanoseconds
  )
  $Date = Get-Date
  $now = ""
  $now += "{0:0000}-{1:00}-{2:00} " -f $Date.Year, $Date.Month, $Date.Day
  $now += "{0:00}:{1:00}:{2:00}" -f $Date.Hour, $Date.Minute, $Date.Second
  $nsSuffix = ""
  if ($ns) {
    if ("$($Date.TimeOfDay)" -match "\.\d\d\d\d\d\d") {
      $now += $matches[0]
      $ms = $false
    } else {
      $ms = $true
      $nsSuffix = "000"
    }
  } 
  if ($ms) {
    $now += ".{0:000}$nsSuffix" -f $Date.MilliSecond
  }
  return $now
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Log                                                       #
#                                                                             #
#   Description     Log a string into the PSService.log file                  #
#                                                                             #
#   Arguments       A string                                                  #
#                                                                             #
#   Notes           Prefixes the string with a timestamp and the user name.   #
#                   (Except if the string is empty: Then output a blank line.)#
#                                                                             #
#   History                                                                   #
#    2016-06-05 JFL Also prepend the Process ID.                              #
#    2016-06-08 JFL Allow outputing blank lines.                              #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Log () {
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [String]$string
  )
  if (!(Test-Path $logDir)) {
    New-Item -ItemType directory -Path $logDir | Out-Null
  }
  if ($String.length) {
    $string = "$(Now) $pid $currentUserName $string"
  }
  $string | Out-File -Encoding ASCII -Append "$logFile"
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Start-PSThread                                            #
#                                                                             #
#   Description     Start a new PowerShell thread                             #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           Returns a thread description object.                      #
#                   The completion can be tested in $_.Handle.IsCompleted     #
#                   Alternative: Use a thread completion event.               #
#                                                                             #
#   References                                                                #
#    https://learn-powershell.net/tag/runspace/                               #
#    https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/
#    http://www.codeproject.com/Tips/895840/Multi-Threaded-PowerShell-Cookbook
#                                                                             #
#   History                                                                   #
#    2016-06-08 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

$PSThreadCount = 0              # Counter of PSThread IDs generated so far
$PSThreadList = @{}             # Existing PSThreads indexed by Id

Function Get-PSThread () {
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [int[]]$Id = $PSThreadList.Keys     # List of thread IDs
  )
  $Id | % { $PSThreadList.$_ }
}

Function Start-PSThread () {
  Param(
    [Parameter(Mandatory=$true, Position=0)]
    [ScriptBlock]$ScriptBlock,          # The script block to run in a new thread
    [Parameter(Mandatory=$false)]
    [String]$Name = "",                 # Optional thread name. Default: "PSThread$Id"
    [Parameter(Mandatory=$false)]
    [String]$Event = "",                # Optional thread completion event name. Default: None
    [Parameter(Mandatory=$false)]
    [Hashtable]$Variables = @{},        # Optional variables to copy into the script context.
    [Parameter(Mandatory=$false)]
    [String[]]$Functions = @(),         # Optional functions to copy into the script context.
    [Parameter(Mandatory=$false)]
    [Object[]]$Arguments = @()          # Optional arguments to pass to the script.
  )

  $Id = $script:PSThreadCount
  $script:PSThreadCount += 1
  if (!$Name.Length) {
    $Name = "PSThread$Id"
  }
  $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
  foreach ($VarName in $Variables.Keys) { # Copy the specified variables into the script initial context
    $value = $Variables.$VarName
    Write-Debug "Adding variable $VarName=[$($Value.GetType())]$Value"
    $var = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry($VarName, $value, "")
    $InitialSessionState.Variables.Add($var)
  }
  foreach ($FuncName in $Functions) { # Copy the specified functions into the script initial context
    $Body = Get-Content function:$FuncName
    Write-Debug "Adding function $FuncName () {$Body}"
    $func = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($FuncName, $Body)
    $InitialSessionState.Commands.Add($func)
  }
  $RunSpace = [RunspaceFactory]::CreateRunspace($InitialSessionState)
  $RunSpace.Open()
  $PSPipeline = [powershell]::Create()
  $PSPipeline.Runspace = $RunSpace
  $PSPipeline.AddScript($ScriptBlock) | Out-Null
  $Arguments | % {
    Write-Debug "Adding argument [$($_.GetType())]'$_'"
    $PSPipeline.AddArgument($_) | Out-Null
  }
  $Handle = $PSPipeline.BeginInvoke() # Start executing the script
  if ($Event.Length) { # Do this after BeginInvoke(), to avoid getting the start event.
    Register-ObjectEvent $PSPipeline -EventName InvocationStateChanged -SourceIdentifier $Name -MessageData $Event
  }
  $PSThread = New-Object PSObject -Property @{
    Id = $Id
    Name = $Name
    Event = $Event
    RunSpace = $RunSpace
    PSPipeline = $PSPipeline
    Handle = $Handle
  }     # Return the thread description variables
  $script:PSThreadList[$Id] = $PSThread
  $PSThread
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Receive-PSThread                                          #
#                                                                             #
#   Description     Get the result of a thread, and optionally clean it up    #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-06-08 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PSThread () {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [PSObject]$PSThread,                # Thread descriptor object
    [Parameter(Mandatory=$false)]
    [Switch]$AutoRemove                 # If $True, remove the PSThread object
  )
  Process {
    if ($PSThread.Event -and $AutoRemove) {
      Unregister-Event -SourceIdentifier $PSThread.Name
      Get-Event -SourceIdentifier $PSThread.Name | Remove-Event # Flush remaining events
    }
    try {
      $PSThread.PSPipeline.EndInvoke($PSThread.Handle) # Output the thread pipeline output
    } catch {
      $_ # Output the thread pipeline error
    }
    if ($AutoRemove) {
      $PSThread.RunSpace.Close()
      $PSThread.PSPipeline.Dispose()
      $PSThreadList.Remove($PSThread.Id)
    }
  }
}

Function Remove-PSThread () {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
    [PSObject]$PSThread                 # Thread descriptor object
  )
  Process {
    $_ | Receive-PSThread -AutoRemove | Out-Null
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Send-PipeMessage                                          #
#                                                                             #
#   Description     Send a message to a named pipe                            #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-05-25 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Send-PipeMessage () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$PipeName,          # Named pipe name
    [Parameter(Mandatory=$true)]
    [String]$Message            # Message string
  )
  $PipeDir  = [System.IO.Pipes.PipeDirection]::Out
  $PipeOpt  = [System.IO.Pipes.PipeOptions]::Asynchronous

  $pipe = $null # Named pipe stream
  $sw = $null   # Stream Writer
  try {
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, $PipeDir, $PipeOpt)
    $sw = new-object System.IO.StreamWriter($pipe)
    $pipe.Connect(1000)
    if (!$pipe.IsConnected) {
      throw "Failed to connect client to pipe $pipeName"
    }
    $sw.AutoFlush = $true
    $sw.WriteLine($Message)
  } catch {
    Log "Error sending pipe $pipeName message: $_"
  } finally {
    if ($sw) {
      $sw.Dispose() # Release resources
      $sw = $null   # Force the PowerShell garbage collector to delete the .net object
    }
    if ($pipe) {
      $pipe.Dispose() # Release resources
      $pipe = $null   # Force the PowerShell garbage collector to delete the .net object
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Receive-PipeMessage                                       #
#                                                                             #
#   Description     Wait for a message from a named pipe                      #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           I tried keeping the pipe open between client connections, #
#                   but for some reason everytime the client closes his end   #
#                   of the pipe, this closes the server end as well.          #
#                   Any solution on how to fix this would make the code       #
#                   more efficient.                                           #
#                                                                             #
#   History                                                                   #
#    2016-05-25 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PipeMessage () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$PipeName           # Named pipe name
  )
  $PipeDir  = [System.IO.Pipes.PipeDirection]::In
  $PipeOpt  = [System.IO.Pipes.PipeOptions]::Asynchronous
  $PipeMode = [System.IO.Pipes.PipeTransmissionMode]::Message

  try {
    $pipe = $null       # Named pipe stream
    $pipe = New-Object system.IO.Pipes.NamedPipeServerStream($PipeName, $PipeDir, 1, $PipeMode, $PipeOpt)
    $sr = $null         # Stream Reader
    $sr = new-object System.IO.StreamReader($pipe)
    $pipe.WaitForConnection()
    $Message = $sr.Readline()
    $Message
  } catch {
    Log "Error receiving pipe message: $_"
  } finally {
    if ($sr) {
      $sr.Dispose() # Release resources
      $sr = $null   # Force the PowerShell garbage collector to delete the .net object
    }
    if ($pipe) {
      $pipe.Dispose() # Release resources
      $pipe = $null   # Force the PowerShell garbage collector to delete the .net object
    }
  }
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Start-PipeHandlerThread                                   #
#                                                                             #
#   Description     Start a new thread waiting for control messages on a pipe #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes           The pipe handler script uses function Receive-PipeMessage.#
#                   This function must be copied into the thread context.     #
#                                                                             #
#                   The other functions and variables copied into that thread #
#                   context are not strictly necessary, but are useful for    #
#                   debugging possible issues.                                #
#                                                                             #
#   History                                                                   #
#    2016-06-07 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

$pipeThreadName = "Control Pipe Handler"

Function Start-PipeHandlerThread () {
  Param(
    [Parameter(Mandatory=$true)]
    [String]$pipeName,                  # Named pipe name
    [Parameter(Mandatory=$false)]
    [String]$Event = "ControlMessage"   # Event message
  )
  Start-PSThread -Variables @{  # Copy variables required by function Log() into the thread context
    logDir = $logDir
    logFile = $logFile
    currentUserName = $currentUserName
  } -Functions Now, Log, Receive-PipeMessage -ScriptBlock {
    Param($pipeName, $pipeThreadName)
    try {
      Receive-PipeMessage "$pipeName" # Blocks the thread until the next message is received from the pipe
    } catch {
      Log "$pipeThreadName # Error: $_"
      throw $_ # Push the error back to the main thread
    }
  } -Name $pipeThreadName -Event $Event -Arguments $pipeName, $pipeThreadName
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Receive-PipeHandlerThread                                 #
#                                                                             #
#   Description     Get what the pipe handler thread received                 #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2016-06-07 JFL Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

Function Receive-PipeHandlerThread () {
  Param(
    [Parameter(Mandatory=$true)]
    [PSObject]$pipeThread               # Thread descriptor
  )
  Receive-PSThread -PSThread $pipeThread -AutoRemove
}

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        $source                                                   #
#                                                                             #
#   Description     C# source of the PSService.exe stub                       #
#                                                                             #
#   Arguments                                                                 #
#                                                                             #
#   Notes           The lines commented with "SET STATUS" and "EVENT LOG" are #
#                   optional. (Or blocks between "// SET STATUS [" and        #
#                   "// SET STATUS ]" comments.)                              #
#                   SET STATUS lines are useful only for services with a long #
#                   startup time.                                             #
#                   EVENT LOG lines are useful for debugging the service.     #
#                                                                             #
#   History                                                                   #
#    2017-10-04 RBL Updated the OnStop() procedure adding the sections        #
#                       try{                                                  #
#                       }catch{                                               #
#                       }finally{                                             #
#                       }                                                     #
#                   This resolved the issue where stopping the service would  #
#                   leave the PowerShell process -Service still running. This #
#                   unclosed process was an orphaned process that would       #
#                   remain until the pid was manually killed or the computer  #
#                   was rebooted                                              #
#                                                                             #
#-----------------------------------------------------------------------------#

$scriptCopyCname = $scriptCopy -replace "\\", "\\" # Double backslashes. (The first \\ is a regexp with \ escaped; The second is a plain string.)
$source = @"
  using System;
  using System.ServiceProcess;
  using System.Diagnostics;
  using System.Runtime.InteropServices;                                 // SET STATUS
  using System.ComponentModel;                                          // SET STATUS
  public enum ServiceType : int {                                       // SET STATUS [
    SERVICE_WIN32_OWN_PROCESS = 0x00000010,
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
  };                                                                    // SET STATUS ]
  public enum ServiceState : int {                                      // SET STATUS [
    SERVICE_STOPPED = 0x00000001,
    SERVICE_START_PENDING = 0x00000002,
    SERVICE_STOP_PENDING = 0x00000003,
    SERVICE_RUNNING = 0x00000004,
    SERVICE_CONTINUE_PENDING = 0x00000005,
    SERVICE_PAUSE_PENDING = 0x00000006,
    SERVICE_PAUSED = 0x00000007,
  };                                                                    // SET STATUS ]
  [StructLayout(LayoutKind.Sequential)]                                 // SET STATUS [
  public struct ServiceStatus {
    public ServiceType dwServiceType;
    public ServiceState dwCurrentState;
    public int dwControlsAccepted;
    public int dwWin32ExitCode;
    public int dwServiceSpecificExitCode;
    public int dwCheckPoint;
    public int dwWaitHint;
  };                                                                    // SET STATUS ]
  public enum Win32Error : int { // WIN32 errors that we may need to use
    NO_ERROR = 0,
    ERROR_APP_INIT_FAILURE = 575,
    ERROR_FATAL_APP_EXIT = 713,
    ERROR_SERVICE_NOT_ACTIVE = 1062,
    ERROR_EXCEPTION_IN_SERVICE = 1064,
    ERROR_SERVICE_SPECIFIC_ERROR = 1066,
    ERROR_PROCESS_ABORTED = 1067,
  };
  public class Service_$serviceName : ServiceBase { // $serviceName may begin with a digit; The class name must begin with a letter
    private System.Diagnostics.EventLog eventLog;                       // EVENT LOG
    private ServiceStatus serviceStatus;                                // SET STATUS
    public Service_$serviceName() {
      ServiceName = "$serviceName";
      CanStop = true;
      CanPauseAndContinue = false;
      AutoLog = true;
      eventLog = new System.Diagnostics.EventLog();                     // EVENT LOG [
      if (!System.Diagnostics.EventLog.SourceExists(ServiceName)) {         
        System.Diagnostics.EventLog.CreateEventSource(ServiceName, "$logName");
      }
      eventLog.Source = ServiceName;
      eventLog.Log = "$logName";                                        // EVENT LOG ]
      EventLog.WriteEntry(ServiceName, "$exeName $serviceName()");      // EVENT LOG
    }
    [DllImport("advapi32.dll", SetLastError=true)]                      // SET STATUS
    private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);
    protected override void OnStart(string [] args) {
      EventLog.WriteEntry(ServiceName, "$exeName OnStart() // Entry. Starting script '$scriptCopyCname' -SCMStart"); // EVENT LOG
      // Set the service state to Start Pending.                        // SET STATUS [
      // Only useful if the startup time is long. Not really necessary here for a 2s startup time.
      serviceStatus.dwServiceType = ServiceType.SERVICE_WIN32_OWN_PROCESS;
      serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
      serviceStatus.dwWin32ExitCode = 0;
      serviceStatus.dwWaitHint = 2000; // It takes about 2 seconds to start PowerShell
      SetServiceStatus(ServiceHandle, ref serviceStatus);               // SET STATUS ]
      // Start a child process with another copy of this script
      try {
        Process p = new Process();
        // Redirect the output stream of the child process.
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.FileName = "PowerShell.exe";
        p.StartInfo.Arguments = "-ExecutionPolicy Bypass -c & '$scriptCopyCname' -SCMStart"; // Works if path has spaces, but not if it contains ' quotes.
        p.Start();
        // Read the output stream first and then wait. (To avoid deadlocks says Microsoft!)
        string output = p.StandardOutput.ReadToEnd();
        // Wait for the completion of the script startup code, that launches the -Service instance
        p.WaitForExit();
        if (p.ExitCode != 0) throw new Win32Exception((int)(Win32Error.ERROR_APP_INIT_FAILURE));
        // Success. Set the service state to Running.                   // SET STATUS
        serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;    // SET STATUS
      } catch (Exception e) {
        EventLog.WriteEntry(ServiceName, "$exeName OnStart() // Failed to start $scriptCopyCname. " + e.Message, EventLogEntryType.Error); // EVENT LOG
        // Change the service state back to Stopped.                    // SET STATUS [
        serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
        Win32Exception w32ex = e as Win32Exception; // Try getting the WIN32 error code
        if (w32ex == null) { // Not a Win32 exception, but maybe the inner one is...
          w32ex = e.InnerException as Win32Exception;
        }    
        if (w32ex != null) {    // Report the actual WIN32 error
          serviceStatus.dwWin32ExitCode = w32ex.NativeErrorCode;
        } else {                // Make up a reasonable reason
          serviceStatus.dwWin32ExitCode = (int)(Win32Error.ERROR_APP_INIT_FAILURE);
        }                                                               // SET STATUS ]
      } finally {
        serviceStatus.dwWaitHint = 0;                                   // SET STATUS
        SetServiceStatus(ServiceHandle, ref serviceStatus);             // SET STATUS
        EventLog.WriteEntry(ServiceName, "$exeName OnStart() // Exit"); // EVENT LOG
      }
    }
    protected override void OnStop() {
      EventLog.WriteEntry(ServiceName, "$exeName OnStop() // Entry");   // EVENT LOG
      // Start a child process with another copy of ourselves
      try {
        Process p = new Process();
        // Redirect the output stream of the child process.
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.FileName = "PowerShell.exe";
        p.StartInfo.Arguments = "-ExecutionPolicy Bypass -c & '$scriptCopyCname' -SCMStop"; // Works if path has spaces, but not if it contains ' quotes.
        p.Start();
        // Read the output stream first and then wait. (To avoid deadlocks says Microsoft!)
        string output = p.StandardOutput.ReadToEnd();
        // Wait for the PowerShell script to be fully stopped.
        p.WaitForExit();
        if (p.ExitCode != 0) throw new Win32Exception((int)(Win32Error.ERROR_APP_INIT_FAILURE));
        // Success. Set the service state to Stopped.                   // SET STATUS
        serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;      // SET STATUS
      } catch (Exception e) {
        EventLog.WriteEntry(ServiceName, "$exeName OnStop() // Failed to stop $scriptCopyCname. " + e.Message, EventLogEntryType.Error); // EVENT LOG
        // Change the service state back to Started.                    // SET STATUS [
        serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
        Win32Exception w32ex = e as Win32Exception; // Try getting the WIN32 error code
        if (w32ex == null) { // Not a Win32 exception, but maybe the inner one is...
          w32ex = e.InnerException as Win32Exception;
        }    
        if (w32ex != null) {    // Report the actual WIN32 error
          serviceStatus.dwWin32ExitCode = w32ex.NativeErrorCode;
        } else {                // Make up a reasonable reason
          serviceStatus.dwWin32ExitCode = (int)(Win32Error.ERROR_APP_INIT_FAILURE);
        }                                                               // SET STATUS ]
      } finally {
        serviceStatus.dwWaitHint = 0;                                   // SET STATUS
        SetServiceStatus(ServiceHandle, ref serviceStatus);             // SET STATUS
        EventLog.WriteEntry(ServiceName, "$exeName OnStop() // Exit"); // EVENT LOG
      }
    }
    public static void Main() {
      System.ServiceProcess.ServiceBase.Run(new Service_$serviceName());
    }
  }
"@

#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        Main                                                      #
#                                                                             #
#   Description     Execute the specified actions                             #
#                                                                             #
#   Arguments       See the Param() block at the top of this script           #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#                                                                             #
#-----------------------------------------------------------------------------#

# Identify the user name. We use that for logging.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserName = $identity.Name # Ex: "NT AUTHORITY\SYSTEM" or "Domain\Administrator"

if ($Setup) {Log ""}    # Insert one blank line to separate test sessions logs
Log $MyInvocation.Line # The exact command line that was used to start us

# The following commands write to the event log, but we need to make sure the PSService source is defined.
New-EventLog -LogName $logName -Source $serviceName -ea SilentlyContinue

# Workaround for PowerShell v2 bug: $PSCmdlet Not yet defined in Param() block
$Status = ($PSCmdlet.ParameterSetName -eq 'Status')

if ($SCMStart) {                # The SCM tells us to start the service
  # Do whatever is necessary to start the service script instance
  Log "$scriptName -SCMStart: Starting script '$scriptFullName' -Service"
  Write-EventLog -LogName $logName -Source $serviceName -EventId 1001 -EntryType Information -Message "$scriptName -SCMStart: Starting script '$scriptFullName' -Service"
  Start-Process PowerShell.exe -ArgumentList ("-c & '$scriptFullName' -Service")
  return
}

if ($Start) {                   # The user tells us to start the service
  Write-Verbose "Starting service $serviceName"
  Write-EventLog -LogName $logName -Source $serviceName -EventId 1002 -EntryType Information -Message "$scriptName -Start: Starting service $serviceName"
  Start-Service $serviceName # Ask Service Control Manager to start it
  return
}

if ($SCMStop) {         #  The SCM tells us to stop the service
  # Do whatever is necessary to stop the service script instance
  Write-EventLog -LogName $logName -Source $serviceName -EventId 1003 -EntryType Information -Message "$scriptName -SCMStop: Stopping script $scriptName -Service"
  Log "$scriptName -SCMStop: Stopping script $scriptName -Service"
  # Send an exit message to the service instance
  Send-PipeMessage $pipeName "exit"
  return
}

if ($Stop) {                    # The user tells us to stop the service
  Write-Verbose "Stopping service $serviceName"
  Write-EventLog -LogName $logName -Source $serviceName -EventId 1004 -EntryType Information -Message "$scriptName -Stop: Stopping service $serviceName"
  Stop-Service $serviceName # Ask Service Control Manager to stop it
  return
}

if ($Restart) {                 # Restart the service
  & $scriptFullName -Stop
  & $scriptFullName -Start
  return
}

if ($Status) {                  # Get the current service status
  $spid = $null
  $processes = @(Get-WmiObject Win32_Process -filter "Name = 'powershell.exe'" | Where-Object {
    $_.CommandLine -match ".*$scriptCopyCname.*-Service"
  })
  foreach ($process in $processes) { # There should be just one, but be prepared for surprises.
    $spid = $process.ProcessId
    Write-Verbose "$serviceName Process ID = $spid"
  }
  # if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\services\$serviceName") {}
  try {
    $pss = Get-Service $serviceName -ea stop # Will error-out if not installed
  } catch {
    "Not Installed"
    return
  }
  $pss.Status
  if (($pss.Status -eq "Running") -and (!$spid)) { # This happened during the debugging phase
    Write-Error "The Service Control Manager thinks $serviceName is started, but $serviceName.ps1 -Service is not running."
    exit 1
  }
  return
}

if ($Setup) {                   # Install the service
  # Check if it's necessary
  try {
    $pss = Get-Service $serviceName -ea stop # Will error-out if not installed
    # Check if this script is newer than the installed copy.
    if ((Get-Item $scriptCopy -ea SilentlyContinue).LastWriteTime -lt (Get-Item $scriptFullName -ea SilentlyContinue).LastWriteTime) {
      Write-Verbose "Service $serviceName is already Installed, but requires upgrade"
      & $scriptFullName -Remove
      throw "continue"
    } else {
      Write-Verbose "Service $serviceName is already Installed, and up-to-date"
    }
    exit 0
  } catch {
    # This is the normal case here. Do not throw or write any error!
    Write-Debug "Installation is necessary" # Also avoids a ScriptAnalyzer warning
    # And continue with the installation.
  }
  if (!(Test-Path $installDir)) {											 
    New-Item -ItemType directory -Path $installDir | Out-Null
  }
  # Copy the service script into the installation directory
  if ($ScriptFullName -ne $scriptCopy) {
    Write-Verbose "Installing $scriptCopy"
    Copy-Item $ScriptFullName $scriptCopy
  }
  # Generate the service .EXE from the C# source embedded in this script
  try {
    Write-Verbose "Compiling $exeFullName"
    Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $exeFullName -OutputType ConsoleApplication -ReferencedAssemblies "System.ServiceProcess" -Debug:$false
  } catch {
    $msg = $_.Exception.Message
    Write-error "Failed to create the $exeFullName service stub. $msg"
    exit 1
  }
  # Register the service
  Write-Verbose "Registering service $serviceName"
  if ($UserName -and !$Credential.UserName) {
    $emptyPassword = New-Object -Type System.Security.SecureString
    switch ($UserName) {
      {"LocalService", "NetworkService" -contains $_} {
        $Credential = New-Object -Type System.Management.Automation.PSCredential ("NT AUTHORITY\$UserName", $emptyPassword)
      }
      {"LocalSystem", ".\LocalSystem", "${env:COMPUTERNAME}\LocalSystem", "NT AUTHORITY\LocalService", "NT AUTHORITY\NetworkService" -contains $_} {
        $Credential = New-Object -Type System.Management.Automation.PSCredential ($UserName, $emptyPassword)
      }
      default {
        if (!$Password) {
          $Credential = Get-Credential -UserName $UserName -Message "Please enter the password for the service user"
        } else {
          $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
          $Credential = New-Object -Type System.Management.Automation.PSCredential ($UserName, $securePassword)
        }
      }
    }
  }
  if ($Credential.UserName) {
    Log "$scriptName -Setup # Configuring the service to run as $($Credential.UserName)"
    $pss = New-Service $serviceName $exeFullName -DisplayName $serviceDisplayName -Description $ServiceDescription -StartupType Automatic -Credential $Credential
  } else {
    Log "$scriptName -Setup # Configuring the service to run by default as LocalSystem"
    $pss = New-Service $serviceName $exeFullName -DisplayName $serviceDisplayName -Description $ServiceDescription -StartupType Automatic
  }

  return
}

if ($Remove) {                  # Uninstall the service
  # Check if it's necessary
  try {
    $pss = Get-Service $serviceName -ea stop # Will error-out if not installed
  } catch {
    Write-Verbose "Already uninstalled"
    return
  }
  Stop-Service $serviceName # Make sure it's stopped
  # In the absence of a Remove-Service applet, use sc.exe instead.
  Write-Verbose "Removing service $serviceName"
  $msg = sc.exe delete $serviceName
  if ($LastExitCode) {
    Write-Error "Failed to remove the service ${serviceName}: $msg"
    exit 1
  } else {
    Write-Verbose $msg
  }
  # Remove the installed files
  if (Test-Path $installDir) {
    foreach ($ext in ("exe", "pdb", "ps1")) {
      $file = "$installDir\$serviceName.$ext"
      if (Test-Path $file) {
        Write-Verbose "Deleting file $file"
        Remove-Item $file
      }
    }
    if (!(@(Get-ChildItem $installDir -ea SilentlyContinue)).Count) {
      Write-Verbose "Removing directory $installDir"
      Remove-Item $installDir
    }
  }
  Log ""                # Insert one blank line to separate test sessions logs
  return
}

if ($Control) {                 # Send a control message to the service
  Send-PipeMessage $pipeName $control
}

if ($Service) {                 # Run the service
  Write-EventLog -LogName $logName -Source $serviceName -EventId 1005 -EntryType Information -Message "$scriptName -Service # Beginning background job"
  # Do the service background job
################################################
#FIRST TIME INSTALLATION
#Before installing as a service 
#
#1.) set the friendly names (Find with ctrl+f LocalFriendly). If you have multiple data feeds from the same 
#source that can't be differentiated label them 1,2,3,4 Example. "fbi1", "fbi2", "fbi3", "fbi4", "fbi5"
#
#As for destination, try to keep a naming convention like Example. cds_fbi, cds_coastguard, cds_nmec, cds_le,
#
#2.) ensure you have winscp, specify it's location under $Global:LocalFTPClient
#
#3.) if you wish to pass folders directly from C:\pfts\pulling\$Friendly\inbound to C:\pfts\pushing\$Friendly\outbound, name your friendly pulling the same as friendly pushing
#
################################################
#$Cronos = "1"
#while ($Cronos=1)
#{
try {
$Global:LocalFTPClient = "C:\Program Files (x86)\WinSCP"
$Parentfolder = "C:\pfts"
$Loggingfolder = "C:\pfts\log"
$Global:LoggingfolderPulling = "C:\pfts\log\pulling"
$LoggingfolderPushing = "C:\pfts\log\pushing"

$LocalFriendlyPulling = "ice", "coastguard", "dhs", "faa"
$LocalParentFolderPulling = "C:\pfts\pulling"
$Global:LocalChildFolderPulling = "$LocalParentFolderPulling\originators"
$Global:LocalConfFolderPulling = "$LocalParentFolderPulling\conf"

$LocalFriendlyPushing = "ice", "coastguard", "dhs", "faa"
$LocalParentFolderPushing = "C:\pfts\pushing"
$LocalChildFolderPushing =  "$LocalParentFolderPushing\destination"
$LocalConfFolderPushing = "$LocalParentFolderPushing\conf"

################################################
$Basename = $($MyInvocation.MyCommand.name)
$Basename = $Basename -replace ".{4}$"

if (!(Test-Path $ParentFolder))
    {
    mkdir $Parentfolder
    mkdir $Loggingfolder
    mkdir $LoggingfolderPulling
    mkdir $LoggingfolderPushing

    mkdir $LocalParentFolderPulling
    mkdir $LocalChildFolderPulling
    mkdir $LocalConfFolderPulling

    mkdir $LocalParentFolderPushing
    mkdir $LocalChildFolderPushing
    mkdir $LocalConfFolderPushing
    }
}

Catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0020 -EntryType Information -Message "Error: $Basename Can't find WinSCP installation. Use default installation path." -Category 1 -RawData 10,20
    Exit 1
    }

Try {
if (!(Test-Path $LocalFTPClient))
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0001 -EntryType Information -Message "Error: $Basename Can't find WinSCP installation. Use default installation path." -Category 1 -RawData 10,20
    Exit 1
    }

if ($LocalFriendlyPulling.length -le "1")
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 0002 -EntryType Information -Message "Info: No pulling datafeeds added" -Category 1 -RawData 10,20 
        }
            else
                {
                ForEach ($Friendly in $LocalFriendlyPulling) {
                    if (!(Test-path -Path $LocalChildFolderPulling\$Friendly))
                        {
                        mkdir "$LocalChildFolderPulling\$Friendly"
                        mkdir "$LoggingfolderPulling\$Friendly"
                        mkdir "$LocalChildFolderPulling\$Friendly\inbound"
                        mkdir "$LocalChildFolderPulling\$Friendly\working"
                        Start-Sleep -Milliseconds 500
                        $PullChildScriptBlock | Set-Content -Path "$LocalConfFolderPulling\$Friendly.ps1"
$PullChildScriptBlock = @'
##############################################################
##!!!!!REMOVE YO`UR PLAINTEXT PASSWORDS AFTER FIRST RUN!!!!!!##
##############################################################
######################
##Connection options##
######################
$OriginatorFTPType = "sftp"#required specify if you want to use scp sftp ftps Ex. "scp"
$OriginatorUsername = "pfts"#required username of account used to connect to data source
$OriginatorAuth = "password" #required valid values are "password", "sshkey" or "certificate"
$OriginatorSecurepassword = "12qwaszx!@QWASZX"#the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured), or a reboot will render all passwords unaccessable
$OriginatorSSHkey = #if using ssh keys, specify full path to key
$OriginatorSecureSSHkeyPassword = #password of ssh key, if used
$OriginatorFingerprint = "ssh-ed25519 256 hmk1czu5R0VTtjno/1fGeTMTQRaaMKg86nJZHsKnZpE="#required, you can obtain this using the winscp gui ex. '"ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"'
$OriginatorClientCert = #if using FTPS, and required you may specify a certificate here
$OriginatorTLSClientCert = #required full path to client certificate path
$OriginatorIP = "192.168.7.6"#required, ip address or hostname of data source
$OriginatorDir = "/home/pfts/pull/coastguard"#Required, directory path ex. "/home/pfts/pull/coastguard"
##########################
##Data formating options##
##########################
$OriginatorZip = "$True" #If you would have the originator zip files prior to sending. Encouraged for thousands of 'small' files, specify $True, else, $False ex. "$True"
$OriginatorZipQuantity = "500" #Required if $OriginatorZip is true Specify quantity of files to zip, suggested size of 500 ex. "500"
$OriginatorFiletype = "*.xml"#required this will collect only files of 'type' ex. "*.xml" "*.jpg" select "*" to collect regardless of filetype
$OriginatorOS = "Linux"#specify Linux or Windows, option not implemented don't use
$ConnectionSpeed = #how often should this script run in minutes ex. 5 #note, a time of 0 will never let the script end. #this does nothing right now
########################################################
##Don't go past here unless you know what you're doing##
########################################################
$BasenameArray = ($Args[0]).Split("\")
$Basename = $BasenameArray[$BasenameArray.Length - 1]
$Basename = $Basename -replace ".{4}$"
$timestamp = $(Get-Date -Format "o")
$Tab = [char]9

if ($OriginatorOS -eq "Linux")
{   
try {
    if (!(test-path "$Using:localConfFolderPulling\winscppass$Basename.txt"))
        {
        if ($OriginatorAuth -eq "password")
                {
                $OriginatorSecurepassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:localConfFolderPulling\winscppass$Basename.txt"
                $DecryptedSecurepassword = Get-Content "$Using:localConfFolderPulling\winscppass$Basename.txt" | ConvertTo-SecureString
                }
        }                
    elseif ($OriginatorAuth -eq "password")
        {
        $DecryptedSecurepassword = Get-Content "$Using:localConfFolderPulling\winscppass$Basename.txt" | ConvertTo-SecureString
        }

    if (!(test-path "$Using:localConfFolderPulling\winscpsshpass$Basename.txt"))
        {
        if ($OriginatorAuth -eq "sshkey")
            {
            $OriginatorSecureSSHkeyPassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:localConfFolderPulling\winscpsshpass$Basename.txt"
            $DecryptedSSHkeyPassword = Get-Content "$Using:localConfFolderPulling\winscpsshpass$Basename.txt" | ConvertTo-SecureString
            }
        }
    elseif ($OriginatorAuth -eq "sshkey")
        {
        $DecryptedSSHkeyPassword = Get-Content "$Using:localConfFolderPulling\winscpsshpass$Basename.txt" | ConvertTo-SecureString
        }
    }
    catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0007 -EntryType Information -Message "Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20
    }
    
try
{
    # Load WinSCP .NET assembly
    Add-Type -Path "$Using:LocalFTPClient\WinSCPnet.dll"

    if ($OriginatorAuth -eq "password")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$OriginatorFTPType
        HostName = $OriginatorIP
        UserName = $OriginatorUsername
        SecurePassword = $DecryptedSecurepassword
        SshHostKeyFingerprint = $Originatorfingerprint
                                                                      }
        }
    if ($OriginatorAuth -eq "sshkey")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$OriginatorFTPType
        HostName = $OriginatorIP
        UserName = $OriginatorUsername
        SshPrivateKeyPath = $OriginatorSSHkey
        SecurePrivateKeyPassphrase = $OriginatorSecureSSHkeyPassword
        SshHostKeyFingerprint = $Originatorfingerprint
                                                                      }
        }
    if ($OriginatorAuth -eq "certificate")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$OriginatorFTPType
        HostName = $OriginatorIP
        UserName = $OriginatorUsername
        TlsClientCertificatePath = $OriginatorSSHkey
        TlsHostCertificateFingerprint = $OriginatorSecureSSHkeyPassword
                                                                      }                        
        }
    
    if (!(test-path "$Using:localConfFolderPulling\winscpsshpass$Basename.txt") -and (!(test-path "$Using:localConfFolderPulling\winscpsshpass$Basename.txt")) -and ($OriginatorTLSClientCert.length -lt "1"))
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 0004 -EntryType Information -Message "Error: $basename No credentials input, halting" -Category 1 -RawData 10,20
        exit 1
        }
        
}
            
catch
{
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0005 -EntryType Information -Message "Error: $basename Credential error $($_.Exception.Message)" -Category 1 -RawData 10,20
    exit 1
}
#################################
##End of connection being built##
#################################
    
    try
    {
    $session = New-Object WinSCP.Session
    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.FileMask = "*>=2m", $OriginatorFiletype
    $session.Open($sessionOptions)
    }
    Catch
    {
    Write-EventLog SOMETHING WRONG WITH SESSION OPTIONS
    }
#################################
##Zip files with a filetype    ##
#################################
    try
    {  
      if ($OriginatorZip -eq $True)
        {
        if ($OriginatorFiletype.length -gt "3" -or $OriginatorFiletype.Length -eq "3")
            {
            $files = $session.EnumerateRemoteFiles($OriginatorDir, "$OriginatorFiletype", [WinSCP.EnumerationOptions]::None)
            while ($files.count -gt $OriginatorZipQuantity)
                {
                $ZipCommand = 'cd $OriginatorDir; timestamp=$(date --utc +%FT%T.%3NZ); files=$(find ./ +cmin 2 -type f -name "$OriginatorFiletype" | head -n $OriginatorZipQuantity); zip "$timestamp".zip -m $files'
                $session.ExecuteCommand($ZipCommand).Check()
                $currentzip = $session.EnumerateRemoteFiles($OriginatorDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                foreach ($zip in $currentzip)
                    {
                    $session.GetFiles(($OriginatorDir + "/" + "$zip"), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$zip"), $transferOptions).Check()
                    $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            }

                    "$timestamp" + $zip.name + $zip.length | Out-File -filepath "$Using:LoggingfolderPulling\$Basename\$currentdate.txt" -Append
                    $session.RemoveFiles("$OriginatorDir/" + $zip)
                    }
                }
            }
########################################
##Zip files with no filetype specified##
########################################
            else
            {
            $files = $session.EnumerateRemoteFiles($OriginatorDir, "*", [WinSCP.EnumerationOptions]::None)
            while ($files.count -gt $OriginatorZipQuantity)
                {
                $ZipCommand = 'cd $OriginatorDir; timestamp=$(date --utc +%FT%T.%3NZ); files=$(find ./ +cmin 2 -type f -name "[^_]*.zip" | head -n $OriginatorZipQuantity); zip "$timestamp".zip -m $files'
                $session.ExecuteCommand($ZipCommand).Check()
                $currentzip = $session.EnumerateRemoteFiles($OriginatorDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                foreach ($zip in $currentzip)
                    {
                    $session.GetFiles(($OriginatorDir + "/" + "$zip"), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$zip"), $transferOptions).Check()
                    $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            }
                    "$timestamp" + $Tab + $zip.name + $Tab + $zip.length | Out-File -filepath "$Using:LoggingfolderPulling\$Basename\$currentdate.txt" -Append
                    $session.RemoveFiles("$OriginatorDir/" + $zip)
                    }
                }
            }
        }
    }
    Catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0025 -EntryType Information -Message "Error: $basename something's broken with the zipping process $($_.Exception.Message)" -Category 1 -RawData 10,20
    }
#############################################
##No files being zipped, filetype specified##
#############################################
    else
    {
    try
        {
        if ($OriginatorZip -ne $True)
            {
            if ($OriginatorFiletype.length -gt "3" -or $OriginatorFiletype.Length -eq "3")
                {
                $files = $session.EnumerateRemoteFiles($OriginatorDir, "$OriginatorFiletype", [WinSCP.EnumerationOptions]::None)
                foreach ($file in $files) 
                    {
                    $session.GetFiles(($OriginatorDir + "/" + $file), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$file"), $transferOptions).Check()
                    $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file ########## make a logging dir
                            }
                        "$timestamp" + $Tab + $file.name + $Tab + $file.length | Out-File -filepath "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -Append
                        $session.RemoveFiles("$OriginatorDir/" + $file).Check()
                    }
                }
################################################
##No files being zipped, no filetype specified##
################################################ 
                else
                    {
                    $files = $session.EnumerateRemoteFiles($OriginatorDir, "*", [WinSCP.EnumerationOptions]::None)
                    foreach ($file in $files)
                        {
                        $session.GetFiles(($OriginatorDir + $file), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$filename"), $transferOptions).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file ########## make a logging dir
                            }
                        "$timestamp" + $Tab + $file.name + $Tab + $file.length | Out-File -filepath "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -Append
                        $session.RemoveFiles("$OriginatorDir/" + $file).Check()
                        }
                    }
            }
        }      

Catch
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 00024 -EntryType Information -Message "Error: $basename Something's wrong with non-zipping file transfers$($_.Exception.Message)" -Category 1 -RawData 10,20
        }
    }
<#            
        $files = $session.EnumerateRemoteFiles($OriginatorDir, "*.zip", [WinSCP.EnumerationOptions]::None)
        foreach ($file in $files)
            {
            $session.GetFiles(($OriginatorDir + "/" + $file), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$file")).Check()
            $currentdate = Get-Date -Format yyyyMMdd
            if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                {
                New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                }
            "$timestamp" + $file.name + $file.length | Out-File -filepath "$Using:LoggingfolderPulling\$Basename\$currentdate.txt" -Append
            $session.RemoveFiles("$OriginatorDir/" + $file)
            }
        
        else
            {
            $files = $session.EnumerateRemoteFiles($OriginatorDir, [WinSCP.EnumerationOptions]::None)
            foreach ($file in $files)
                {
                $session.GetFiles(($OriginatorDir + $file), ("$Using:LocalChildFolderPulling\$Basename\inbound\" + "$filename")).Check()
                $currentdate = Get-Date -Format yyyyMMdd
                if (!(Test-Path "$Using:LoggingfolderPulling\$basename\$currentdate.txt"))
                    {
                    New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file ########## make a logging dir
                    }
                "$timestamp" + $file.name + $file.length | Out-File -filepath "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -Append
                $session.RemoveFiles("$OriginatorDir/" + $file).Check()
                 }
            }
#>
    }

    finally
        {
        # Disconnect, clean up
        $session.Dispose()
        } 
        exit 0

catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0006 -EntryType Information -Message "Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20
    exit 1
    }

 #END OF LINUX STATEMENT if originator type = Windows else statement should go here

################################################################ End of linux if statement

<#if ($OriginatorOS -eq "Windows")
    try
    {
    robocopy
    }
#>
'@    
                        }
                    }
                }
}
Catch 
{
Write-EventLog -LogName "Application" -Source "pfts" -EventID 0021 -EntryType Information -Message "Info: Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20 
}

<# 
Try{
if ($LocalFriendlyPushing.length -le "1")
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 0002 -EntryType Information -Message "Info: No pulling datafeeds added" -Category 1 -RawData 10,20 
        }
            else
                {
                ForEach ($Friendly in $LocalFriendlyPushing) {
                    if (!(Test-path -Path $LocalChildFolderPushing\$Friendly))
                        {
                        mkdir "$LocalChildFolderPushing\$Friendly"
                        mkdir "$LoggingfolderPushing\$Friendly"
                        mkdir "$LocalChildFolderPushing\$Friendly\inbound"
                        mkdir "$LocalChildFolderPushing\$Friendly\working"
                        Start-Sleep -Milliseconds 500
                        $PushChildScriptBlock | Set-Content -Path "$LocalConfFolderPushing\$Friendly.ps1"
$PushChildScriptBlock = @'
asd
'@
                        }
                                                             }
                }
   }
      Catch 
      {
      Write-EventLog -LogName "Application" -Source "pfts" -EventID 0022 -EntryType Information -Message "Info: Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20 
      Exit 0
      }
#>
#########################
##Loop that starts jobs##
#########################
$ActivePulling = Get-ChildItem -name "$LocalConfFolderPulling\*.ps1"
$ActivePushing = Get-ChildItem -name "$LocalConfFolderPushing\*.ps1"
$ActivePulling = $ActivePulling -replace ".{4}$"
$ActivePushing = $ActivePushing -replace ".{4}$"

$ActivePulling | ForEach-Object {
        if ((Receive-Job -name "pulling$_").state -ne "Running")
                {
                $PassToJob = "$LocalConfFolderPulling\$_.ps1"
                Start-Job -name "pulling$_" -FilePath "$LocalConfFolderPulling\$_.ps1" -ArgumentList $PassToJob
                start-sleep -Seconds 1
                }
                                }
                                
<#
$ActivePushing | ForEach-Object {
        if ((Receive-Job -name "pulling$_" -Keep).state -ne "Running")
                {
                Try
                {
                $PassToJob = "$LocalConfFolderPulling\$_.ps1"
                Start-Job -name "pushing$_" -FilePath "$LocalConfFolderPushing\$_.ps1" -ArgumentList $PassToJob
                start-sleep -Seconds 1
                }
                Catch
                {
                Write-EventLog -LogName "Application" -Source "pfts" -EventID 0027 -EntryType Information -Message "Error: Job $_ broken, $($_.Exception.Message)" -Category 1 -RawData 10,20
                }
                }
                                }
}

            Catch
            {
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 0003 -EntryType Information -Message "Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20
            Exit 0
            }
#>
    ############### End of the service code example. ################
    # Terminate the control pipe handler thread
    Get-PSThread | Remove-PSThread # Remove all remaining threads
    # Flush all leftover events (There may be some that arrived after we exited the while event loop, but before we unregistered the events)
    $events = Get-Event | Remove-Event
    # Log a termination event, no matter what the cause is.
    Write-EventLog -LogName $logName -Source $serviceName -EventId 1006 -EntryType Information -Message "$script -Service # Exiting"
    Log "$scriptName -Service # Exiting"
  return
}