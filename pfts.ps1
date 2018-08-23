###############################################################################
#                                                                             #
#   File name       pfts.ps1                                                  #
#                                                                             #
#   Description     A Powershell & WinSCP based file transfer service         #
#   									      #
#   Dependencies    Powershell 3.0, .net 3.5, WinSCP 5.13          	      #
#                                                                             #
#   Notes           pfts (powershell file transfer service) is an extension   #
#		    of the WinSCP FTP client. Versioning is available at      #
#		    https://github.com/unix-bomber/Powershell.git             #
#		    pfts is heavily reliant on the PSService.ps1 JFLarvoire   #
#		    created. The most updated version of his code is at       #
#		    https://github.com/JFLarvoire/SysToolsLib/Powershell      #
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
#    2018-4-3  TWK tim@pueobusinesssolutions.com first push to master branch  #
#    2018-5-10  TWK tim@pueobusinesssolutions.com fixed memory leak, added s3 #
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

   5.) Observe pulling & pushing conf folders, (C:\pfts\pulling\conf) stop the service when all datafeeds are built
       C:\Temp\pfts.ps1 -stop

   6.) C:\pfts is the default root folder for data feed configurations, files entrance and exit, and transactional logs
       The file structure will depend based on the friendly names that you placed into
       $LocalFriendlyPulling/Pushing

   7.) Under C:\pfts\pulling\config, there will be a set of scripts based on the friendly
       names you input. Follow the instructions at the top of them, and edit the variables
       based on your needs.

   8.) Start the service, once datafeed configurations are set by using
       C:\Temp\pfts.ps1 -start
       MONITOR YOUR LOGS, AND DIRECTORIES FOR ANYTHING ABNORMAL.
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

$scriptVersion = "2018-3-22"

# This script name, with various levels of details
$argv0 = Get-Item $MyInvocation.MyCommand.Definition
$script = "pfts"               # Ex: PSService
$scriptName = "pfts.ps1"               # Ex: PSService.ps1
$scriptFullName = "C:\Temp\pfts.ps1"       # Ex: C:\Temp\PSService.ps1

# Global settings
$serviceName = $script                  # A one-word name used for net start commands
$serviceDisplayName = "Powershell File Transfer Service"
$ServiceDescription = "A Windows, Powershell, and WinSCP dependent file transfer service"
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
######### TO DO: Implement your own service code here. ##########
# Start pfts core logic
#-----------------------------------------------------------------------------#
#                                                                             #
#   Function        run-pfts                                                  #
#                                                                             #
#   Description     Core logic of the script                                  #
#                                                                             #
#   Arguments       See the Param() block                                     #
#                                                                             #
#   Notes                                                                     #
#                                                                             #
#   History                                                                   #
#    2018-04-03 TWK Created this function                                     #
#                                                                             #
#-----------------------------------------------------------------------------#

function Run-pfts {
$Global:LocalFTPClient = "C:\Program Files (x86)\WinSCP"
$Parentfolder = "C:\pfts"
$Loggingfolder = "C:\pfts\log"
$Global:LoggingfolderPulling = "C:\pfts\log\pulling"
$Global:LoggingfolderPushing = "C:\pfts\log\pushing"

$LocalFriendlyPulling = "coastguard"
$LocalParentFolderPulling = "C:\pfts\pulling"
$Global:LocalChildFolderPulling = "$LocalParentFolderPulling\originators"
$Global:LocalConfFolderPulling = "$LocalParentFolderPulling\conf"

$LocalFriendlyPushing = "coastguard"
$LocalParentFolderPushing = "C:\pfts\pushing"
$Global:LocalChildFolderPushing =  "$LocalParentFolderPushing\destination"
$Global:LocalConfFolderPushing = "$LocalParentFolderPushing\conf"

################################################
$Basename = $($MyInvocation.MyCommand.name)
$Basename = $Basename -replace ".{4}$"

try {
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
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 2000 -EntryType Information -Message "Info: Error: $basename problem creating folder structure: $($_.Exception.Message)" -Category 1 -RawData 10,20
    Exit 1
    }

if (!(Test-Path $LocalFTPClient))
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 2001 -EntryType Information -Message "Error: $Basename Can't find WinSCP .dll Ensure dll is present under C:\Program Files (x86)\WinSCP\WinSCPnet.dll $($_.Exception.Message)" -Category 1 -RawData 10,20
    Exit 1
    }


Try {
                ForEach ($Friendly in $LocalFriendlyPulling) {
                    if (!(Test-path -Path $LocalChildFolderPulling\$Friendly))
                        {
                        mkdir "$LocalChildFolderPulling\$Friendly"
                        mkdir "$LoggingfolderPulling\$Friendly"
                        mkdir "$LocalChildFolderPulling\$Friendly\inbound"
                        mkdir "$LocalChildFolderPulling\$Friendly\working"
                        Start-Sleep -Milliseconds 500
$PullChildScriptBlock = @'
##############################################################
##!!!!!REMOVE YOUR PLAINTEXT PASSWORDS AFTER FIRST RUN!!!!!!##
##############################################################
######################
##Connection options##
######################
$OriginatorFTPType = "sftp"#required specify if you want to use scp sftp ftps s3 Ex. "scp"
$OriginatorUsername = "pfts"#required username of account used to connect to data source Ex. "username" for s3 this is your public API key
$OriginatorAuth = "password"#required, valid values are "password", "sshkey" or "certificate" "apikey" Ex. "password
$OriginatorSecurepassword = "12qwaszx!@QWASZX"#use this for s3 secret api key, the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured), or a reboot will render all passwords unaccessable Ex. "Password
$OriginatorSSHkey = $null#if using ssh keys, specify full path to key
$OriginatorSecureSSHkeyPassword = $null#password of ssh key, if used
$OriginatorFingerprint = "ssh-ed25519 256 hmk1czu5R0VTtjno/1fGeTMTQRaaMKg86nJZHsKnZpE="#required unless s3 bucket, you can obtain this using the winscp gui Ex. "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
$OriginatorClientCert = $null#if using FTPS, and required you may specify a certificate here
$OriginatorTLSClientCert = $null#required if using certs full path to client certificate path
$OriginatorIP = "192.168.7.6"#required, ip address, hostname or bucket url of data source
$OriginatorDir = "/home/pfts/pull/coastguard"#required, directory path ex. "/home/pfts/pull/coastguard" also supports buckets
##########################
##Data formating options##
##########################
$OriginatorZip = $null #If you would have the originator zip files prior to sending. Encouraged for thousands of 'small' files, specify $True, else, $False ex. "$True"
$OriginatorZipQuantity = $null #Required if $OriginatorZip is true Specify quantity of files to zip, suggested size of 500 ex. "500"
$OriginatorFiletype = "*.xml"#required this will collect only files of 'type' ex. "*.xml" "*.jpg" select "*" to collect regardless of filetype
$OriginatorOS = "Linux"#Specify "Linux" for FTP variants. Specify "Windows" for SMB shares #windows not yet supported
########################################################
##Don't go past here unless you know what you're doing##
########################################################

$BasenameArray = ($Args[0]).Split("\")
$Basename = $BasenameArray[$BasenameArray.Length - 1]
$Basename = $Basename -replace ".{4}$"
$currentdate = Get-Date -Format yyyyMMdd
$timestamp = (Get-Date -Format o) | foreach{$_ -replace ":", "."}
$Tab = [char]9
Add-Type -assembly "system.io.compression.filesystem"
Remove-Item –path "C:\Windows\Temp\wscp*.tmp"
##############################
##compress any old translogs##
##############################

$toarchive = Get-ChildItem -Directory -Path "$Using:LoggingfolderPulling\$basename\" -Exclude "$currentdate"
    foreach ($archive in $toarchive.fullname) {
        if ((Get-ChildItem -path $archive | select -First 1) -like "*.txt")
            {
            Set-Variable -Name 'timestamp' -Option Readonly -Force
            [io.compression.zipfile]::CreateFromDirectory("$archive", "$archive\$timestamp.zip") 2>&1>$null
            Remove-Item –path "$archive\*.txt" -Recurse
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 3005 -EntryType Information -Message "pulling_$basename archived transaction logs" -Category 1 -RawData 10,20
            Set-Variable -Name 'timestamp' -Option Constant -Force
            }
    }

if ($OriginatorOS -eq "Linux")
{
try {
    if (!(test-path "$Using:LocalConfFolderPulling\pull_pass$Basename.txt"))
        {
        if ($OriginatorAuth -eq "password")
                {
                $OriginatorSecurepassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPulling\pull_pass$Basename.txt"
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPulling\pull_pass$Basename.txt" | ConvertTo-SecureString
                }
        }
        else
            {
            if ($OriginatorAuth -eq "password")
                {
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPulling\pull_pass$Basename.txt" | ConvertTo-SecureString
                }
            }

    if (!(test-path "$Using:LocalConfFolderPulling\pull_sshpass$Basename.txt"))
        {
        if ($OriginatorAuth -eq "sshkey")
            {
            $OriginatorSecureSSHkeyPassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPulling\pull_sshpass$Basename.txt"
            $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPulling\pull_sshpass$Basename.txt" | ConvertTo-SecureString
            }
        }

        else
            {
            if ($OriginatorAuth -eq "sshkey")
                {
                $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPulling\pull_sshpass$Basename.txt" | ConvertTo-SecureString
                }
            }
    }
catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 3000 -EntryType Information -Message "Error: pulling_$basename credential failure: $($_.Exception.Message)" -Category 1 -RawData 10,20
    Exit 1
    }

try {
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
        TlsClientCertificatePath = $OriginatorTLSClientCert
        TlsHostCertificateFingerprint = $Originatorfingerprint
                                                                      }
    if ($OriginatorAuth -eq "apikey")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$OriginatorFTPType
        HostName = $OriginatorIP
        PortNumber = 443
        UserName = $OriginatorUsername
        SecurePassword = $DecryptedSecurepassword
                                                                      }
        }

    if (!(test-path "$Using:LocalConfFolderPulling\pull_pass$Basename.txt") -and (!(test-path "$Using:LocalConfFolderPulling\pull_sshpass$Basename.txt")) -and ($OriginatorTLSClientCert.length -le "2"))
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 3001 -EntryType Information -Message "Error: pulling_$basename No credentials input, halting" -Category 1 -RawData 10,20
        exit 1
        }

}

catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 3002 -EntryType Information -Message "Error: pulling_$basename Credential error $($_.Exception.Message)" -Category 1 -RawData 10,20
    exit 1
    }
#################################
##End of connection being built##
#################################
#################################
##Zip files with a filetype    ##
#################################
try {
      if ($OriginatorZip -eq "$True")
        {
        if (!(Test-Path -Path "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt"))
            {
            if (!(Test-Path -Path "$Using:LoggingfolderPulling\$basename\$currentdate\"))
                {
                New-Item -Path "$Using:LoggingfolderPulling\$basename\$currentdate\" -ItemType directory
                }
            New-Item -Path "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt" -ItemType file
        }
        $session = New-Object WinSCP.Session
        $session.SessionLogPath = "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt"
        $transferOptions = New-Object WinSCP.TransferOptions
        $transferOptions.FileMask = "*<=15s; *>0"
        $session.Open($sessionOptions)
            $discoveredfiles = $session.EnumerateRemoteFiles("$OriginatorDir", "$OriginatorFiletype", [WinSCP.EnumerationOptions]::None)
            $discoveredfilecount = ($discoveredfiles | Measure-Object).count
            $discoveredzips = $session.EnumerateRemoteFiles("$OriginatorDir", "*.zip", [WinSCP.EnumerationOptions]::None)
            $discoveredzipcount = ($discoveredzips | Measure-Object).count
            while (($discoveredfilecount -ge "1") -or ($discoveredzipcount -ge "1")){
                if ($discoveredzipcount -lt "1" -and $OriginatorFiletype -ne "*.zip")
                    {
                    $ZipCommand = 'cd ' + "$OriginatorDir; timestamp=" + '$(' + 'date --utc +%FT%TZ); files=$(' + "find ./ -cmin +2 -type f -name " + '"' + "$OriginatorFiletype" + '"' + ' -and -not -name "*.zip"' + ' | head -n ' + "$OriginatorZipQuantity); zip " + '$timestamp' + '.zip -m $files'
                    $session.ExecuteCommand($ZipCommand).Check()
                    }
                    $session.GetFiles(("$OriginatorDir/*.zip"), ("$Using:LocalChildFolderPulling\$Basename\inbound\"),$True ,$transferOptions).Check()
                    $discoveredzipcount = ($discoveredzips | Measure-Object).count
            }
        $session.Dispose()
        exit 0
        }
    }
Catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 3003 -EntryType Information -Message "Info: Error with pulling_$basename zipping file transfer $($_.Exception.Message)" -Category 1 -RawData 10,20
    }
#########################
##No files being zipped##
#########################
try {
    if ($OriginatorZip -ne "$True")
    {
    if (!(Test-Path -Path "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt"))
        {
        if (!(Test-Path -Path "$Using:LoggingfolderPulling\$basename\$currentdate\"))
            {
            New-Item -Path "$Using:LoggingfolderPulling\$basename\$currentdate\" -ItemType directory
            }
            New-Item -Path "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt" -ItemType file
        }
    $session = New-Object WinSCP.Session
    $session.SessionLogPath = "$Using:LoggingfolderPulling\$basename\$currentdate\$timestamp.txt"
    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.FileMask = "*<=15s; *>0"
    $session.Open($sessionOptions)

        $discoveredfiles = $session.EnumerateRemoteFiles("$OriginatorDir", "$OriginatorFiletype", [WinSCP.EnumerationOptions]::None)
        $discoveredfilecount = ($discoveredfiles | Measure-Object).count
        while ($discoveredfilecount -ge "1") {
                    $session.GetFiles(("$OriginatorDir/$OriginatorFiletype"), ("$Using:LocalChildFolderPulling\$Basename\inbound\"),$True ,$transferOptions).Check()
                    $discoveredfilecount = ($discoveredfiles | Measure-Object).count
        }
        $session.Dispose()
        exit 0
    }
}

Catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 3004 -EntryType Information -Message "Info: Error with pulling_$basename non-zipping file transfer $($_.Exception.Message)" -Category 1 -RawData 10,20
    }
}
'@
                        $PullChildScriptBlock | Set-Content -Path "$LocalConfFolderPulling\$Friendly.ps1"
                        Write-EventLog -LogName "Application" -Source "pfts" -EventID 2002 -EntryType Information -Message "Info: pulling datafeed $Friendly added" -Category 1 -RawData 10,20
                        }
                    }
            }
Catch
{
Write-EventLog -LogName "Application" -Source "pfts" -EventID 2003 -EntryType Information -Message "Info: Error Creating file structure & child scripts pulling_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
}

################################
##End of pulling feed creation##
################################

##################################
##Start of pushing feed creation##
##################################

Try {
                ForEach ($Friendly in $LocalFriendlyPushing) {
                    if (!(Test-path -Path $LocalChildFolderPushing\$Friendly))
                        {
                        mkdir "$LocalChildFolderPushing\$Friendly"
                        mkdir "$LoggingfolderPushing\$Friendly"
                        mkdir "$LocalChildFolderPushing\$Friendly\outbound"
                        mkdir "$LocalChildFolderPushing\$Friendly\working"
                        Start-Sleep -Milliseconds 500
$PushChildScriptBlock = @'
##############################################################
##!!!!!REMOVE YOUR PLAINTEXT PASSWORDS AFTER FIRST RUN!!!!!!##
##############################################################
######################
##Connection options##
######################
$DestinationFTPType = "sftp"#required specify if you want to use scp sftp ftps s3 Ex. "scp" 
$DestinationUsername = "pfts"#required username of account used to connect to data source Ex. "username" s3 use your public api key
$DestinationAuth = "password"#required, valid values are "password", "sshkey" or "certificate" Ex. "password" s3 use password
$DestinationSecurepassword = "12qwaszx!@QWASZX" #for s3 use secret key the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured), or a reboot will render all passwords unaccessable Ex. "Password
$DestinationSSHkey = $null#if using ssh keys, specify full path to key
$DestinationSecureSSHkeyPassword = $null#password of ssh key, if used
$DestinationFingerprint = "ssh-ed25519 256 hmk1czu5R0VTtjno/1fGeTMTQRaaMKg86nJZHsKnZpE="#required, unless s3. You can obtain this using the winscp gui Ex. "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
$DestinationClientCert = $null#if using FTPS, and required you may specify a certificate here
$DestinationTLSClientCert = $null#required if using certs full path to client certificate path
$DestinationIP = "192.168.7.6"#required, ip address or hostname of data source, s3 use the full path to your bucket, do not use DestinationDir
$DestinationDir = "/home/pfts/push/coastguard"#required, directory path ex. "/home/pfts/push/coastguard"
##########################
##Data formating options##
##########################
$LocalZip = $null#zips files prior to sending. Encouraged for thousands of 'small' files, specify $True to use, else, $null ex. "$True"
$LocalZipQuantity = $null#required if $LocalZip is true. Specify quantity of files to zip, suggested size of 500 ex. "500"
$LocalUnzip = $null#this option unzips files prior to sending to the distant end, specify $True to use.
$LocalFiletype = "*.xml"#required this will collect only files by file extension ex. "*.xml" "*.jpg" select "*" to collect regardless of filetype
$LocalPassthrough = $True#this option allows one to pass files from the 'pulling' folder directly to the corresponding pushing folder. the only setup required is to name the friendly pushing the same as the friendly pulling, and to specify this value $True
$DestinationOS = "Linux"#specify Linux or Windows, option not implemented don't use
##############################
##Rudimentary Alert settings##
##############################
$SMTPAlert = $True #turns the alert on or off
$SMTPAlertTime = "60" #if data hasn't been transfered in 'x' minutes, send an email 
$SMTPServer = "192.168.0.2"#IP address or hostname of mail server
$SMTPPort = "25"#port to connect with
$SMTPFrom = "SMTPalert@gmail.com" #use the format x@domain
$SMTPTo = "SMTPReceive@gmail.com" #use the format x@domain
$SMTPPriority = "High" #use "High" "Medium" or "Low"
########################################################
##Don't go past here unless you know what you're doing##
########################################################
$BasenameArray = ($Args[0]).Split("\")
$Basename = $BasenameArray[$BasenameArray.Length - 1]
$Basename = $Basename -replace ".{4}$"
$currentdate = Get-Date -Format yyyyMMdd
$timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
$Tab = [char]9
Add-Type -assembly "system.io.compression.filesystem"
Remove-Item –path "C:\Windows\Temp\wscp*.tmp"
##############################
##compress any old translogs##
##############################

$toarchive = Get-ChildItem -Directory -Path "$Using:LoggingfolderPushing\$basename\" -Exclude "$currentdate"
    foreach ($archive in $toarchive.fullname) {
        if ((Get-ChildItem -path $archive | select -First 1) -like "*.txt")
            {
            Set-Variable -Name 'timestamp' -Option Readonly -Force
            [io.compression.zipfile]::CreateFromDirectory("$archive", "$archive\$timestamp.zip") 2>&1>$null
            Remove-Item –path "$archive\*.txt"
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 3005 -EntryType Information -Message "pushing_$basename archived transaction logs" -Category 1 -RawData 10,20
            Set-Variable -Name 'timestamp' -Option Constant -Force
            }
}

if ($DestinationOS -eq "Linux")
{
try {
    if (!(test-path "$Using:LocalConfFolderPushing\push_pass$Basename.txt"))
        {
        if ($DestinationAuth -eq "password")
                {
                $DestinationSecurepassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPushing\push_pass$Basename.txt"
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPushing\push_pass$Basename.txt" | ConvertTo-SecureString
                }
        }
        else
            {
            if ($DestinationAuth -eq "password")
                {
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPushing\push_pass$Basename.txt" | ConvertTo-SecureString
                }
            }

    if (!(test-path "$Using:LocalConfFolderPushing\pull_sshpass$Basename.txt"))
        {
        if ($DestinationAuth -eq "sshkey")
            {
            $DestinationSecureSSHkeyPassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPushing\push_sshpass$Basename.txt"
            $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPushing\push_sshpass$Basename.txt" | ConvertTo-SecureString
            }
        }

        else
            {
            if ($DestinationAuth -eq "sshkey")
                {
                $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPushing\push_sshpass$Basename.txt" | ConvertTo-SecureString
                }
            }
    }

catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 4000 -EntryType Information -Message "Error: pushing_$basename credential failure $($_.Exception.Message)" -Category 1 -RawData 10,20
    Exit 1
    }

try {
    # Load WinSCP .NET assembly
    Add-Type -Path "$Using:LocalFTPClient\WinSCPnet.dll"

    if ($DestinationAuth -eq "password")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$DestinationFTPType
        HostName = $DestinationIP
        UserName = $DestinationUsername
        SecurePassword = $DecryptedSecurepassword
        SshHostKeyFingerprint = $Destinationfingerprint
                                                                      }
        }
    if ($DestinationAuth -eq "sshkey")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$DestinationFTPType
        HostName = $DestinationIP
        UserName = $DestinationUsername
        SshPrivateKeyPath = $DestinationSSHkey
        SecurePrivateKeyPassphrase = $DestinationSecureSSHkeyPassword
        SshHostKeyFingerprint = $Destinationfingerprint
                                                                      }
        }
    if ($DestinationAuth -eq "certificate")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$DestinationFTPType
        HostName = $DestinationIP
        UserName = $DestinationUsername
        TlsClientCertificatePath = $OriginatorTLSClientCert
        TlsHostCertificateFingerprint = $Originatorfingerprint
                                                                      }
        }
    if ($DestinationAuth -eq "apikey")
        {
        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
        Protocol = [WinSCP.Protocol]::$DestinationFTPType
        HostName = $DestinationIP
        PortNumber = 443
        UserName = $DestinationUsername
        SecurePassword = $DecryptedSecurepassword
                                                                      }
        }

    if (!(test-path "$Using:LocalConfFolderPushing\push_pass$Basename.txt") -and (!(test-path "$Using:LocalConfFolderPushing\pull_sshpass$Basename.txt")) -and ($DestinationTLSClientCert.length -le "2"))
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 4001 -EntryType Information -Message "Error: pushing_$basename No credentials input, halting" -Category 1 -RawData 10,20
        exit 1
        }

}

catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 4002 -EntryType Information -Message "Error: pushing_$basename Credential error $($_.Exception.Message)" -Category 1 -RawData 10,20
    exit 1
    }

if ($LocalZip -and $LocalUnzip -eq "$True")
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 4003 -EntryType Information -Message "Error: pushing_$basename You can either zip, or unzip files. You can't do both. Change either $LocalZip or $LocalUnzip" -Category 1 -RawData 10,20
    exit 1
    }

#################################
##End of connection being built##
#################################

###################################
##Manifest of sent files handling##
###################################
    if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
        {
        if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
            {
            New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
            }
            New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
        }
############
##Alerting##
############
if ($SMTPAlert -eq "$True")
    {
    $lastlog = (Get-ChildItem -Path $Using:LoggingfolderPushing\$basename\$currentdate | select -Last 1).LastWriteTime
    if ($lastlog.count -lt "2")
        {
        $lastdir = Get-ChildItem -Path $Using:LoggingfolderPushing\$basename | select -Last 1
        $lastfile = Get-ChildItem -Path $lastdir.FullName | select -Last 1
            if ($lastfile -lt $(Get-Date).AddMinutes(-$SMTPAlertTime))
                {
                Send-MailMessage -Port $SMTPPort -From $SMTPFrom -To $SMTPTo -Priority $SMTPPriority -SmtpServer $SMTPServer -Body "Cross Domain feed $basename on server $env:Computername hasn't received any data in $SMTPAlertTime minutes"
                Write-EventLog -LogName "Application" -Source "pfts" -EventID 8888 -EntryType Information -Message "Error: $basename hasn't received any data in $SMTPAlertTime minutes" -Category 1 -RawData 10,20
                }
        }

    elseif ($lastlog -lt $(Get-Date).AddMinutes(-$SMTPAlertTime))
        {
        Send-MailMessage -Port $SMTPPort -From $SMTPFrom -To $SMTPTo -Priority $SMTPPriority -SmtpServer $SMTPServer -Body "Cross Domain feed $basename on server $env:Computername hasn't received any data in $SMTPAlertTime minutes"
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 8888 -EntryType Information -Message "Error: $basename hasn't received any data in $SMTPAlertTime minutes" -Category 1 -RawData 10,20
        }
    }

#####################
##Passthrough files##
#####################

if ($LocalPassthrough -eq "$True")
    {
    if (Test-Path (!("$Using:LocalChildFolderPulling\$Basename\inbound")))
        {
        Write-EventLog -LogName "Application" -Source "pfts" -EventID 4004 -EntryType Information -Message "Error: $basename Can't passthrough, there's no folder named $Using:LocalChildFolderPulling\$Basename\inbound" -Category 1 -RawData 10,20
        exit 1
        }
            
                if ($LocalZip -eq $True)
                    {
                    try {
                        if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1 ).count -ge 1)
                            {
                            if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                                {
                                if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                                    {
                                    New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                                    }
                                New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                                }
                            $session = New-Object WinSCP.Session
                            $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                            $transferOptions = New-Object WinSCP.TransferOptions
                            $transferOptions.FileMask = "*>0"
                            $session.Open($sessionOptions)
                            $suffix = "_part"
                            $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1 ).count
                            while ($currentbatchtotal -ge "1"){
                                $move = Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | where Length -gt 1 | select -Last $LocalZipQuantity  
                                $move.fullname | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                                $timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
                                [io.compression.zipfile]::CreateFromDirectory("$Using:LocalChildFolderPulling\$Basename\working", "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 2>&1>$null
                                Remove-Item –path "$Using:LocalChildFolderPulling\$Basename\working\*" -Recurse
                                $transferresult = $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir/" + "*.*" + "$suffix"), $True, $transferOptions)
                                $transferresult.check()
                                $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                                $session.ExecuteCommand($unpartcmdfull).Check()
                                $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | where Length -gt 1).count
                                }
                            $session.Dispose()
                            }
                        }
                    catch 
                        {
                        Write-EventLog -LogName "Application" -Source "pfts" -EventID 5001 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
                        exit 1
                        }
                    exit 0
                    }
                
                if ($LocalUnzip -eq $True)
                    {
                    try {
                            if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1).count -ge 1)
                                {
                                if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                                    {
                                    if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                                        {
                                        New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                                        }
                                    New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                                    }
                                $session = New-Object WinSCP.Session
                                $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                                $transferOptions = New-Object WinSCP.TransferOptions
                                $transferOptions.FileMask = "*>0"
                                $session.Open($sessionOptions)
                                $suffix = "_part"
                                $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound").count
                                    while ($currentbatchtotal -ge "1"){
                                            $move = Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound\*.zip" | where Length -gt 1
                                            $timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
                                            foreach ($m in $move.fullname){
                                                [System.IO.Compression.ZipFile]::ExtractToDirectory($m, "$Using:LocalChildFolderPushing\$Basename\outbound") 2>&1>$null
                                                Remove-Item -Path $m
                                                $transferresult = $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"), ("$DestinationDir/" + "*.*" + "$suffix"), $True, $transferOptions)
                                                $transferresult.check()
                                            }
                                            $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                                            $session.ExecuteCommand($unpartcmdfull).Check()
                                            $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | where Length -gt 1).count
                                    }
                                $session.Dispose()
                                }
                        }
                    catch
                        {
                        Write-EventLog -LogName "Application" -Source "pfts" -EventID 5002 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
                        exit 1
                        }
                    exit 0  
                    }

                if (($LocalZip -ne $True) -and ($LocalUnzip -ne $True))
                    {
                    try {
                            if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1 ).count -ge 1)
                                {
                                if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                                    {
                                    if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                                        {
                                        New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                                        }
                                    New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                                    }
                                $session = New-Object WinSCP.Session
                                $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                                $transferOptions = New-Object WinSCP.TransferOptions
                                $transferOptions.FileMask = "*>0"
                                $session.Open($sessionOptions)
                                $suffix = "_part"
                                $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound").count
                                while ($currentbatchtotal -ge "1"){
                                        $transferresult = $session.PutFiles(("$Using:LocalChildFolderPulling\$Basename\inbound\$LocalFiletype"), ("$DestinationDir/" + "*.*" + $suffix), $True, $transferOptions)
                                        $transferresult.check()
                                        $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                                        $session.ExecuteCommand($unpartcmdfull).Check()
                                        $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | where Length -gt 1 ).count
                                    }
                                $session.Dispose()
                                }
                        }
                    catch
                        {
                        Write-EventLog -LogName "Application" -Source "pfts" -EventID 5003 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
                        exit 1
                        }
                    exit 0
                    }
    }

################
##Direct files##
################

if ($LocalPassthrough -ne "$True")
    {
    if ($LocalZip -eq $True)
        {
        Try {
                if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\outbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1 ).count -ge 1)
                    {
                    if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                        {
                        if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                            {
                            New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                            }
                        New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                        }
                    $session = New-Object WinSCP.Session
                    $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                    $transferOptions = New-Object WinSCP.TransferOptions
                    $transferOptions.FileMask = "*>0"
                    $session.Open($sessionOptions)
                    $suffix = "_part"
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" -exclude "*.zip" | Sort-Object -Property Length | where Length -gt 1 ).count
                        while ($currentbatchtotal -ge "1"){
                                $move = Get-ChildItem "$Using:LocalChildFolderPushing\$Basename\outbound" -exclude "*.zip" | where Length -gt 1 | select -Last $LocalZipQuantity
                                $move.fullname | Move-Item -Destination "$Using:LocalChildFolderPushing\$Basename\working"
                                $timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
                                [io.compression.zipfile]::CreateFromDirectory("$Using:LocalChildFolderPushing\$Basename\working", "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 2>&1>$null
                                Remove-Item –path "$Using:LocalChildFolderPushing\$Basename\working\*" -Recurse
                                $transferresult = $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir/" + "*.*" + "$suffix"), $True, $transferOptions)
                                $transferresult.check()
                        $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                        $session.ExecuteCommand($unpartcmdfull).Check()
                        $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" | where Length -gt 1).count
                        }
                    $session.Dispose()
                    }
            }
        Catch
            {
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 5004 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
            exit 1
            }
        exit 0
        }

    if (($LocalZip -ne $True) -and ($LocalUnzip -ne $True))
        {
        Try {
                if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1).count -ge 1)
                    {
                    if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                        {
                        if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                            {
                            New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                            }
                        New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                        }
                    $session = New-Object WinSCP.Session
                    $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                    $transferOptions = New-Object WinSCP.TransferOptions
                    $transferOptions.FileMask = "*>0"
                    $session.Open($sessionOptions)
                    $suffix = "_part"
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" | Sort-Object -Property Length | where Length -gt 1 ).count
                        while ($currentbatchtotal -ge "1"){
                            $transferresult = $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"), ("$DestinationDir/" + "*.*" + $suffix), $True, $transferOptions)
                            $transferresult.check()
                            $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                            $session.ExecuteCommand($unpartcmdfull).Check()
                            $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" | Sort-Object -Property Length | where Length -gt 1).count
                            }
                        $session.Dispose()
                    }
            }
        Catch
            {
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 5005 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
            exit 1
            }
        exit 0
        }

    if ($LocalUnzip -eq $True)
        {
        Try {
                    if ((Get-ChildItem "$Using:LocalChildFolderPulling\$Basename\inbound" | Sort-Object -Property Length | select -Last 1 | where Length -gt 1).count -ge 1)
                        {
                        if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"))
                            {
                            if (!(Test-Path -Path "$Using:LoggingfolderPushing\$basename\$currentdate\"))
                                {
                                New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\" -ItemType directory
                                }
                            New-Item -Path "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt" -ItemType file
                            }
                        $session = New-Object WinSCP.Session
                        $session.SessionLogPath = "$Using:LoggingfolderPushing\$basename\$currentdate\$timestamp.txt"
                        $transferOptions = New-Object WinSCP.TransferOptions
                        $transferOptions.FileMask = "*>0"
                        $session.Open($sessionOptions)
                        $suffix = "_part"
                        $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" | Sort-Object -Property Length | where Length -gt 1 ).count
                            while ($currentbatchtotal -ge "1") {
                                $move = Get-ChildItem "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip" | where Length -gt 1
                                $timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
                                foreach ($m in $move.fullname){
                                    [System.IO.Compression.ZipFile]::ExtractToDirectory($m, "$Using:LocalChildFolderPushing\$Basename\outbound") 2>&1>$null
                                    Remove-Item -Path $m
                                    $transferresult = $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"), ("$DestinationDir/" + "*.*" + "$suffix"), $True, $transferOptions)
                                    $transferresult.check()
                                    }
                            $unpartcmdfull = 'cd ' + "$DestinationDir;" + 'for file in *_part ; do mv $file  $(echo $file |sed ' + "'" + 's/.....$//' + "'" + '); done'
                            $session.ExecuteCommand($unpartcmdfull).Check()
                            $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" | Sort-Object -Property Length | where Length -gt 1 ).count
                            }
                        $session.Dispose()
                        }
            }
        Catch
            {
            Write-EventLog -LogName "Application" -Source "pfts" -EventID 5006 -EntryType Information -Message "Error: pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
            exit 1
            }
        exit 0
        }
    }
}
'@
                        $PushChildScriptBlock | Set-Content -Path "$LocalConfFolderPushing\$Friendly.ps1"
                        Write-EventLog -LogName "Application" -Source "pfts" -EventID 2002 -EntryType Information -Message "Info: pushing datafeed $Friendly added" -Category 1 -RawData 10,20
                        }
                    }
               }
Catch
{
Write-EventLog -LogName "Application" -Source "pfts" -EventID 2003 -EntryType Information -Message "Info: Error Creating file structure & child scripts pushing_$basename $($_.Exception.Message)" -Category 1 -RawData 10,20
}


##################################
##End of pushing feed creation##
##################################

#########################
##Loop that starts jobs##
#########################
try {
$ActivePulling = Get-ChildItem -name "$LocalConfFolderPulling\*.ps1"
$ActivePushing = Get-ChildItem -name "$LocalConfFolderPushing\*.ps1"
$ActivePulling = $ActivePulling -replace ".{4}$"
$ActivePushing = $ActivePushing -replace ".{4}$"

$ActivePulling | ForEach-Object {
    if ((Get-Job -name "pulling_$_").state -ne "Running")
        {
        Receive-Job -name "pulling_$_"
        Remove-Job -name "pulling_$_"
        $PassToJob = "$LocalConfFolderPulling\$_.ps1"
        Start-Job -name "pulling_$_" -FilePath "$LocalConfFolderPulling\$_.ps1" -ArgumentList $PassToJob
        }
}

$ActivePushing | ForEach-Object {
    if ((Get-Job -name "pushing_$_").state -ne "Running")
        {
        Receive-Job -name "pushing_$_"
        Remove-Job -name "pushing_$_"
        $PassToJob = "$LocalConfFolderPushing\$_.ps1"
        Start-Job -name "pushing_$_" -FilePath "$LocalConfFolderPushing\$_.ps1" -ArgumentList $PassToJob
        }
}
}
Catch
{
Write-EventLog -LogName "Application" -Source "pfts" -EventID 2004 -EntryType Information -Message "Info: Error: With $basename, job handler: $($_.Exception.Message)" -Category 1 -RawData 10,20
Exit 1
}
}
    try {
    # Start the control pipe handler thread
    $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
    $timerName = "pfts"
    $period = 30 # seconds
    $timer = New-Object System.Timers.Timer
    $timer.Interval = ($period * 1000) # Milliseconds
    $timer.AutoReset = $true # Make it fire repeatedly
    Register-ObjectEvent $timer -EventName Elapsed -SourceIdentifier $timerName -MessageData "TimerTick"
    $timer.start() #Must be stopped in the finally block
    # Now enter the main service event loop
    do { # Keep running until told to exit by the -Stop handler
      $event = Wait-Event # Wait for the next incoming event
      $source = $event.SourceIdentifier
      $message = $event.MessageData
      $eventTime = $event.TimeGenerated.TimeofDay
      Write-Debug "Event at $eventTime from ${source}: $message"
      $event | Remove-Event # Flush the event from the queue
      switch ($message) {
        "ControlMessage" { # Required. Message received by the control pipe thread
          $state = $event.SourceEventArgs.InvocationStateInfo.state
          Write-Debug "$script -Service # Thread $source state changed to $state"
          switch ($state) {
            "Completed" {
              $message = Receive-PipeHandlerThread $pipeThread
              Log "$scriptName -Service # Received control message: $Message"
              if ($message -ne "exit") { # Start another thread waiting for control messages
                $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage"
              }
            }
            "Failed" {
              $error = Receive-PipeHandlerThread $pipeThread
              Log "$scriptName -Service # $source thread failed: $error"
              Start-Sleep 1 # Avoid getting too many errors
              $pipeThread = Start-PipeHandlerThread $pipeName -Event "ControlMessage" # Retry
            }
          }
        }
        "TimerTick" { # Example. Periodic event generated for this example
          Run-pfts
          [System.GC]::Collect()
        }
        default { # Should not happen
          Log "$scriptName -Service # Unexpected event from ${source}: $Message"
        }
      }
    } while ($message -ne "exit")
  } catch { # An exception occurred while runnning the service
    $msg = $_.Exception.Message
    $line = $_.InvocationInfo.ScriptLineNumber
    Log "$scriptName -Service # Error at line ${line}: $msg"
  } finally { # Invoked in all cases: Exception or normally by -Stop
    # Cleanup the periodic timer used in the above example
    Unregister-Event -SourceIdentifier $timerName
    ############### End of the service code example. ################
    # Terminate the control pipe handler thread
    Get-PSThread | Remove-PSThread # Remove all remaining threads
    # Flush all leftover events (There may be some that arrived after we exited the while event loop, but before we unregistered the events)
    $events = Get-Event | Remove-Event
    # Log a termination event, no matter what the cause is.
    Write-EventLog -LogName $logName -Source $serviceName -EventId 1006 -EntryType Information -Message "$script -Service # Exiting"
    Log "$scriptName -Service # Exiting"
  }
  return
}

#                                     You keeping us on course,
#                                       Little buddy?           \
#
#      Yes, Skipper \                       __________________________
#                   H                      |   ____     _____
#     ___           O                      |  |____|   |_____|
#    |\_ --------__,+-_____________________|____________________-------
#    \  `===#==__|__/\____|_____|_______|_______|_______|_____-------
#     \
#      |   ss. pueo
#       \
#    ~~~~-\_ /~~=._         ~~~~~~~~~~~             ~~~~~~~~~~~~~
#~~~~      =/       ~~~~~~~~ ~~~~~~    ~~~~~~~~~~~~~             ~~~~~
