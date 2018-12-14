##############################
##    Install Information   ##
##############################
$PShellmonInstallDir = "C:\PShellmon"
$PasswordLocation = "$PShellmonInstallDir\passwords" #Directory encrypted passwords are stored in
$ManifestLocation = "$PShellmonInstallDir\manifests" #Information on what occured durning monitoring

###############################
## Configuration Information ##
###############################
$MonSecurepassword = "whateverpassword" #Password to connect with (REMOVE AFTER FIRST RUN)
$MonRemoteUser = "addomain\someuser" #User to connect as
$Global:MonDirectory = "C:\directory1", "C:\directory2", "C:\directory3" #Directories to monitor
$MonClientServer = "192.168.0.1", "192.168.0.2" #Servers to monitor
$Global:MonRestartInterval = "10" #if files are older than 5 minutes restart pfts

##############################
##Rudimentary Alert settings##
##############################
$Global:SMTPAlert = $True #turns the alert on or off
$Global:SMTPServer = "192.168.0.1"#IP address or hostname of mail server
$Global:SMTPPort = "25"#port to connect with
$Global:SMTPFrom = "me@gmail.com" #use the format x@domain
$Global:SMTPTo = "me@gmail.com", "you@gmail.com", "someone@gmail.com" #use the format x@domain
$Global:SMTPSubject = "pfts feed down"
$Global:SMTPPriority = "High" #use "High" "Medium" or "Low"
$Global:SMTPAlertTime = "30" #if a check fails for longer than 30 minutes, e-mail the NOC

########################################################################################
##                              End of User settings                                  ##
########################################################################################
$currentdate = Get-Date -Format yyyyMMdd
$timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
New-EventLog -LogName PSmon -Source PSmon -ea SilentlyContinue

##################################
## Installation & Configuration ##
##################################
try {
    if (!(test-path "$PasswordLocation"))
        {
        New-Item -ItemType directory -Path $PasswordLocation, $ManifestLocation
        }
    }

catch {
      Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 2001 -EntryType Information -Message "Error: Installation error $($_.Exception.Message)" -Category 1 -RawData 10,20
      exit 1
      }

#########################
## Password Management ##
#########################
try {
    if (!(test-path "$PasswordLocation\mon_pass.txt"))
        {
            $MonSecurepassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$PasswordLocation\mon_pass.txt"
            $DecryptedSecurepassword = Get-Content "$PasswordLocation\mon_pass.txt" | ConvertTo-SecureString
        }
        else
            {
            if (test-path "$PasswordLocation\mon_pass.txt")
                {
                $DecryptedSecurepassword = Get-Content "$PasswordLocation\mon_pass.txt" | ConvertTo-SecureString
                }
            }
    }
catch
    {
    Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 2002 -EntryType Information -Message "Error: Credential error $($_.Exception.Message)" -Category 1 -RawData 10,20
    exit 1
    }

#########################################
## Check if monitored server is online ##
#########################################
try {
    $MonClientServer | ForEach-Object {
    if (!(Test-Connection -ComputerName $_ -Count 2))
        {
        Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 2003 -EntryType Information -Message "Error: PFTS Server $_ is not reachable!" -Category 1 -RawData 10,20
        }
    }
}
catch
    {
    Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 2004 -EntryType Information -Message "Error: Test connection logic failed $($_.Exception.Message)" -Category 1 -RawData 10,20
    }

######################################
## Check for old data, restart PFTS ##
######################################
$InvokeCommandCred = New-Object System.Management.Automation.PSCredential -ArgumentList $MonRemoteUser,$DecryptedSecurepassword

try {
    $MonClientServer | ForEach-Object {
    Invoke-Command -ComputerName $_ -Credential $InvokeCommandCred -ScriptBlock {
        $Using:MonDirectory | ForEach-Object {
            $OldestFile = Get-ChildItem -Path $_ | Sort-Object -Property LastWriteTime -Descending | select -First 1
            if ($OldestFile.LastWriteTime -lt $(Get-Date).AddMinutes(-$Using:MonRestartInterval))
                {
                Restart-Service -Name pfts -Force
                Start-Sleep -Seconds 300
                }
                if ($OldestFile.LastWriteTime -lt $(Get-Date).AddMinutes(-$Using:SMTPAlertTime))
                    {
                    Send-MailMessage -Port $Using:SMTPPort -From $Using:SMTPFrom -subject "$Using:SMTPSubject !contact admins!" -To $Using:SMTPTo -Priority $Using:SMTPPriority -SmtpServer $Using:SMTPServer -Body "Cross Domain feed Major Error on server $env:Computername hasn't transmit any data in $Using:SMTPAlertTime minutes ***CALL THE CROSS DOMAIN TEAM IMMEDIATELY***"
                    }
        }
    }
    }
}
catch
    {
    Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 2005 -EntryType Information -Message "Error: File Checking Failed $($_.Exception.Message)" -Category 1 -RawData 10,20
    }

############################
## Mail for failed checks ##
############################
$lastmail = Get-EventLog -LogName PSmon -InstanceId 3000 -Newest 1 -Message "*Something wrong, mailed admin*"
if ($SMTPAlert -eq "$True")
    {
    $lastlog = Get-EventLog -LogName PSmon -InstanceId 200* -Newest 1
        if ($lastlog.TimeGenerated -lt $(Get-Date).AddMinutes(-$SMTPAlertTime))
                {
                if ($lastmail.TimeGenerated -lt $(Get-Date).AddMinutes(-$SMTPAlertTime))
                    {
                    Send-MailMessage -Port $SMTPPort -From $SMTPFrom -subject "$SMTPSubject PFTS FAILURE !contact admins!" -To $SMTPTo -Priority $SMTPPriority -SmtpServer $SMTPServer -Body "Feeds on server $MonClientServer hasn't received any data in $SMTPAlertTime minutes ***CALL THE CROSS DOMAIN TEAM IMMEDIATELY***"
                    Write-EventLog -LogName "PSmon" -Source "PSmon" -EventID 3000 -EntryType Information -Message "Error: Something wrong, mailed admin" -Category 1 -RawData 10,20
                    }
                }
    }