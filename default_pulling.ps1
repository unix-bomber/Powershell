##############################################################
##!!!!!REMOVE YOUR PLAINTEXT PASSWORDS AFTER FIRST RUN!!!!!!##
##############################################################
######################
##Connection options##
######################
$DestinationFTPType = "sftp"#required specify if you want to use scp sftp ftps Ex. "scp"
$DestinationUsername = "pfts"#required username of account used to connect to data source Ex. "username"
$DestinationAuth = "password"#required, valid values are "password", "sshkey" or "certificate" Ex. "password
$DestinationSecurepassword = $null#the GPO setting Network Access: Do not allow storage of passwords and credentials for network authentication must be set to Disabled (or not configured), or a reboot will render all passwords unaccessable Ex. "Password
$DestinationSSHkey = $null#if using ssh keys, specify full path to key
$DestinationSecureSSHkeyPassword = $null#password of ssh key, if used
$DestinationFingerprint = "ssh-ed25519 256 hmk1czu5R0VTtjno/1fGeTMTQRaaMKg86nJZHsKnZpE="#required, you can obtain this using the winscp gui Ex. "ssh-rsa 2048 xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx"
$DestinationClientCert = $null#if using FTPS, and required you may specify a certificate here
$DestinationTLSClientCert = $null#required if using certs full path to client certificate path
$DestinationIP = "192.168.7.6"#required, ip address or hostname of data source
$DestinationDir = "/home/pfts/push/coastguard"#required, directory path ex. "/home/pfts/Push/coastguard"
##########################
##Data formating options##
##########################
$LocalZip = $null#zips files prior to sending. Encouraged for thousands of 'small' files, specify $True to use, else, $null ex. "$True"
$LocalZipQuantity = $null#required if $LocalZip is true. Specify quantity of files to zip, suggested size of 500 ex. "500"
$LocalUnzip = $null#this option unzips files prior to sending to the distant end, specify $True to use.
$LocalFiletype = $null#required this will collect only files by file extension ex. "*.xml" "*.jpg" select "*" to collect regardless of filetype
$LocalPassthrough = $null#this option allows one to pass files from the 'pulling' folder directly to the corresponding pushing folder. the only setup required is to name the friendly pushing the same as the friendly pulling, and to specify this value $True
$DestinationOS = "Linux"#specify Linux or Windows, option not implemented don't use
$ConnectionSpeed = $null #how often should this script run in minutes ex. 5 #note, a time of 0 will never let the script end. #this does nothing right now
########################################################
##Don't go past here unless you know what you're doing##
########################################################
$BasenameArray = ($Args[0]).Split("\")
$Basename = $BasenameArray[$BasenameArray.Length - 1]
$Basename = $Basename -replace ".{4}$"
function get-formattedtime {$timestamp = (Get-Date -Format o) | foreach{$_ -replace ":", "."}}
$Tab = [char]9

if ($DestinationOS -eq "Linux")
{   
try {
    if (!(test-path "$Using:LocalConfFolderPushing\winscppass$Basename.txt"))
        {
        if ($DestinationAuth -eq "password")
                {
                $DestinationSecurepassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPushing\winscppass$Basename.txt"
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPushing\winscppass$Basename.txt" | ConvertTo-SecureString
                }
        }               
        else 
            {
            if ($DestinationAuth -eq "password")
                {
                $DecryptedSecurepassword = Get-Content "$Using:LocalConfFolderPushing\winscppass$Basename.txt" | ConvertTo-SecureString
                }
            }

    if (!(test-path "$Using:LocalConfFolderPushing\winscpsshpass$Basename.txt"))
        {
        if ($DestinationAuth -eq "sshkey")
            {
            $DestinationSecureSSHkeyPassword | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "$Using:LocalConfFolderPushing\winscpsshpass$Basename.txt"
            $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPushing\winscpsshpass$Basename.txt" | ConvertTo-SecureString
            }
        }

        else
            {
            if ($DestinationAuth -eq "sshkey")
                {
                $DecryptedSSHkeyPassword = Get-Content "$Using:LocalConfFolderPushing\winscpsshpass$Basename.txt" | ConvertTo-SecureString
                }
            }
    }
catch
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 0007 -EntryType Information -Message "Error: $basename $($_.Exception.Message)" -Category 1 -RawData 10,20
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
        TlsClientCertificatePath = $DestinationSSHkey
        TlsHostCertificateFingerprint = $DestinationSecureSSHkeyPassword
                                                                      }                        
        }
    
    if (!(test-path "$Using:LocalConfFolderPushing\winscppass$Basename.txt") -and (!(test-path "$Using:LocalConfFolderPushing\winscpsshpass$Basename.txt")) -and ($DestinationTLSClientCert.length -lt "2" -or $DestinationFiletype.length -eq "2" -or $DestinationFiletype.length -eq "2"))
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

if ($LocalZip -and $LocalUnzip -eq "$True")
    {
    Write-EventLog -LogName "Application" -Source "pfts" -EventID 1005 -EntryType Information -Message "Error: $basename You can either zip, or unzip files. You can't do both. Change either $LocalZip or $LocalUnzip" -Category 1 -RawData 10,20
    exit 1
    }

#################################
##End of connection being built##
#################################
#######################
##Passthrough and Zip##
#######################

Add-Type -assembly "system.io.compression.filesystem"

        if ($LocalPassthrough -eq "$True")
            {
            if (Test-Path (!("$Using:LocalChildFolderPulling\$Basename\inbound")))
                {
                Write-EventLog -LogName "Application" -Source "pfts" -EventID 1006 -EntryType Information -Message "Error: $basename Can't passthrough, there's no file named $Using:LocalChildFolderPulling\$Basename\inbound" -Category 1 -RawData 10,20
                exit 1
                }
            if ($LocalZip -eq $True)
                {
                $session = New-Object WinSCP.Session
                $session.Open($sessionOptions)
                get-formattedtime

                $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                while ($currentbatchtotal -ge $LocalZipQuantity){
                    Get-formattedtime
                    $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $LocalZipQuantity)
                    $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                    $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                    [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                    $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                    
                    foreach ($zip in $SendingZips)
                            {
                            get-formattedtime
                            $session.PutFiles(($zip), ("$DestinationDir"),$True).Check()
                            $currentdate = Get-Date -Format yyyyMMdd
                            if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                {
                                New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                }
                            "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                            $currentbatchtotal = ($currentbatchtotal - $LocalZipQuantity)
                            }
               }
                    if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        get-formattedtime
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(($SendingZips), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        }
                        }
###########################
##Passthrough, No zipping##
###########################
                Else
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)

                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                    while ($currentbatchtotal -ge "1"){
                        get-formattedtime
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype") | select -first 1
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\outbound"
                        $Sending = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            get-formattedtime
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                            "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        $currentbatchtotal = ($currentbatchtotal - "1")
                    }
                    }
###########################
##Passthrough, un zipping##
###########################
                if ($LocalUnzip -eq $True)
                    {
                    get-formattedtime
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "*.zip" | Measure-Object).count
                    while ($currentbatchtotal -gt "1"){
                        get-formattedtime
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "*.zip") | select -first 1
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::ExtractToDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\") 
                        $SendingFiles = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" -Include "$LocalFiletype" -Exclude "*.zip"
                        foreach ($file in $SendingFiles)
                            {
                            get-formattedtime
                            $session.PutFiles(($file), ("$DestinationDir"),$True).Check()
                            $currentdate = Get-Date -Format yyyyMMdd
                            if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                {
                                New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                }
                            "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                            $currentbatchtotal = ($currentbatchtotal - $LocalZipQuantity)
                            }
                    }
                    }
                    }
###############################################
##No Passthrough, zipping, filetype specified##
###############################################        
                    Else
                        {
                        if ($LocalZip -eq $True)
                        {
                        $session = New-Object WinSCP.Session
                        $session.Open($sessionOptions)
                        get-formattedtime

                        $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" -Include "$LocalFiletype" | Measure-Object).count
                        while ($currentbatchtotal -ge $LocalZipQuantity){
                            get-formattedtime
                            $move = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound" -Include "$LocalFiletype" | select-object -last $LocalZipQuantity)
                            $move | Move-Item -Destination "$Using:LocalChildFolderPushing\$Basename\working"
                            $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\working" -Include "$LocalFiletype")
                            [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                            $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                            foreach ($zip in $SendingZips)
                                {
                                get-formattedtime
                                $session.PutFiles(("$zip"), ("$DestinationDir"),$True).Check()
                                $currentdate = Get-Date -Format yyyyMMdd
                                if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                    {
                                    New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                    "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                    }
                                "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                                }
                            $currentbatchtotal = ($currentbatchtotal - $LocalZipQuantity)
                        }   
                        if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                            {
                            get-formattedtime
                            $move = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $currentbatchtotal
                            $move | Move-Item -Destination "$Using:LocalChildFolderPushing\$Basename\working"
                            $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\working" -Include "$LocalFiletype")
                            [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                            $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                            foreach ($zip in $SendingZips)
                                {
                                get-formattedtime
                                $session.PutFiles(($zip), ("$DestinationDir"),$True).Check()
                                $currentdate = Get-Date -Format yyyyMMdd
                                if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                    {
                                    New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                    "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                    }
                                "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                                }
                            }
                        }
###########################
##Passthrough, No zipping##
###########################
                Else
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    get-formattedtime

                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                    while ($currentbatchtotal -ge "1"){
                        get-formattedtime
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype")
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\outbound"
                        $Sending = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        $currentbatchtotal = ($currentbatchtotal - "1")
                    }
                    }
###########################
##Passthrough, un zipping##
###########################
                if ($LocalUnzip -eq $True)
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    get-formattedtime

                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "*.zip" | Measure-Object).count
                    while ($currentbatchtotal -gt "1"){
                        get-formattedtime
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "*.zip")
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::ExtractToDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\") 
                        $SendingFiles = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\$LocalFiletype"
                        foreach ($file in $SendingFiles)
                            {
                            get-formattedtime
                            $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir"),$True).Check()
                            $currentdate = Get-Date -Format yyyyMMdd
                            if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                {
                                New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                }
                            "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                            $currentbatchtotal = ($currentbatchtotal - $LocalZipQuantity)
                            }
                    }
                    }
                        }


# Deliberately using an underscore instead of a dot,
        # as the dot has specific meaning in operation mask
        $suffix = "_filepart"
        $transferOptions = New-Object WinSCP.TransferOptions
        $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::Off
 
        # Upload all .txt files with temporary "_filepart" suffix
        $transferResult = $session.PutFiles(($file), ($remotePath + $suffix), $False, $transferOptions)
        $transferResult.Check()
 
        # Rename uploaded files
        foreach ($transfer in $transferResult.Transfers)
        {
            $finalName = $transfer.Destination.SubString(0, $transfer.Destination.Length - $suffix.Length)
            $session.MoveFiles($transfer.Destination, $finalName)
            Remove-Item $file
        }
    }

            if ($LocalZip -eq $True)
                {
                $session = New-Object WinSCP.Session
                $session.Open($sessionOptions)
                ####
                $suffix = "_filepart"
                $transferOptions = New-Object WinSCP.TransferOptions
                $transferOptions.ResumeSupport.State = [WinSCP.TransferResumeSupportState]::Off
                get-formattedtime

                $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                while ($currentbatchtotal -ge $LocalZipQuantity){
                    Get-formattedtime
                    $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $LocalZipQuantity)
                    $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                    $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                    [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                    $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                    
                    foreach ($zip in $SendingZips)
                            {
                            get-formattedtime
                            $transferresult = $session.PutFiles(($zip), ($DestinationDir + $suffix),$True)
                            $transferresult.Check()
                                foreach ($transfer in $transferresult.Transfers)
                                {
                                    $originalname = $transfer.Destination.SubString(0, $transfer.Destination.Length - $suffix.Length)
                                    $session.MoveFiles($transfer.Destination, $finalName)
                                    Remove-Item $zip
                                }
                            $currentdate = Get-Date -Format yyyyMMdd
                            if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                {
                                New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                                "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                }
                            "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                            $currentbatchtotal = ($currentbatchtotal - $LocalZipQuantity)
                            }
               }
                    if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        get-formattedtime
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(($SendingZips), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        }
                        }