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
$timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}
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
#########################################
##Passthrough and Zip, with a filetype ##
#########################################

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
                if ($LocalFiletype.length -ge "2")
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                    while ($currentbatchtotal -ge $LocalZipQuantity){
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $LocalZipQuantity)
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
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
                        if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        }

                    }
#########################################
##Passthrough and Zip, with no filetype##
#########################################
                if ($LocalFiletype.length -lt "2")
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | Measure-Object).count
                    while ($currentbatchtotal -ge $LocalZipQuantity){
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | select-object -last $LocalZipQuantity)
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
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
                        if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        }
                    }
                }
############################################
##Passthrough, No zipping, Files specified##
############################################
                Else
                    {
                    if ($LocalFiletype.length -ge "2")
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | Measure-Object).count
                    while ($currentbatchtotal -ge "1"){
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $LocalZipQuantity)
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
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
                        if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" -Include "$LocalFiletype" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        }

                    }
###############################################
##Passthrough, No zipping, No Files specified##
###############################################
                if ($LocalFiletype.length -lt "2")
                    {
                    $session = New-Object WinSCP.Session
                    $session.Open($sessionOptions)
                    $currentbatchtotal = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | Measure-Object).count
                    while ($currentbatchtotal -ge $LocalZipQuantity){
                        $move = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | select-object -last $LocalZipQuantity)
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working" -Include "$LocalFiletype")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
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
                        if (($currentbatchtotal -lt $LocalZipQuantity) -and ($currentbatchtotal -ne "0"))
                        {
                        $move = Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\inbound" | select-object -last $currentbatchtotal
                        $move | Move-Item -Destination "$Using:LocalChildFolderPulling\$Basename\working"
                        $currentbatch = (Get-ChildItem -Path "$Using:LocalChildFolderPulling\$Basename\working")
                        [io.compression.zipfile]::CreateFromDirectory($currentbatch, "$Using:LocalChildFolderPushing\$Basename\outbound\$timestamp.zip") 
                        $SendingZips = Get-ChildItem -Path "$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"
                        $session.PutFiles(("$Using:LocalChildFolderPushing\$Basename\outbound\*.zip"), ("$DestinationDir"),$True).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPulling\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        "$timestamp" + $Tab + $SendingZips.name + $Tab + $SendingZips.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        }
                    }
                }
############################################
##Passthrough, un zipping, Files specified##
############################################
                if ($LocalUnzip -eq $True








        }
        
        Else
        {
        Use files from "$Using:LocalChildFolderPushing\$Basename"
            if ($Zip)
                {
                if ($filetype)
                    {
                    Logic
                    }
                else #nofiletype
                    {
                    Logic
                    }
                }
            else #no zip
                {
                if ($filetype)
                    {
                    Logic
                    }
                else #nofiletype
                    {
                    Logic
                    }
                }
        }

        Add-Type -assembly "system.io.compression.filesystem"
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $destination)
        #unzips files ^^^




        $session = New-Object WinSCP.Session
        $transferOptions = New-Object WinSCP.TransferOptions
        $transferOptions.FileMask = ("<=15s")
        $session.Open($sessionOptions)
        if ($DestinationFiletype.length -gt "2" -or $DestinationFiletype.length -eq "2")
            {
            $files = $session.EnumerateRemoteFiles($DestinationDir, "$DestinationFiletype", [WinSCP.EnumerationOptions]::None)
            $discoveredfilecount = ($files | Measure-Object).count
            while ($discoveredfilecount -gt $DestinationZipQuantity -or $discoveredfilecount -eq $DestinationZipQuantity){
                $ZipCommand = 'cd ' + "$DestinationDir; timestamp=" + '$(' + 'date --utc +%FT%TZ); files=$(' + "find ./ +cmin 2 -type f -name " + '"' + "$DestinationFiletype" + '"' + '| head -n ' + "$DestinationZipQuantity); zip " + '$timestamp' + '.zip -m $files'
                $session.ExecuteCommand($ZipCommand).Check()
                $currentzip = $session.EnumerateRemoteFiles($DestinationDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                foreach ($zip in $currentzip){
                    $session.GetFiles(($zip), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                    $currentdate = Get-Date -Format yyyyMMdd
                    if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                        {
                        New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                        "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                        }
                    "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                    $discoveredfilecount = ($discoveredfilecount - $DestinationZipQuantity)
                                             }
                }
            if (($discoveredfilecount -le $DestinationZipQuantity) -and ($discoveredfilecount -ne 0)) 
                {
                $ZipCommand = 'cd ' + "$DestinationDir; timestamp=" + '$(' + 'date --utc +%FT%TZ); files=$(' + "find ./ +cmin 2 -type f -name " + '"' + "$DestinationFiletype" + '"' + '| head -n ' + "$discoveredfilecount); zip " + '$timestamp' + '.zip -m $files'
                $session.ExecuteCommand($ZipCommand).Check()
                $currentzip = $session.EnumerateRemoteFiles($DestinationDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                $session.GetFiles(($zip), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                $currentdate = Get-Date -Format yyyyMMdd
                if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                    {
                    New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                    "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                    }
                "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                }
            }
########################################
##Zip files with no filetype specified##
########################################
            else
                {
                if ($DestinationFiletype.length -lt "2" -or $DestinationFiletype.length -eq "2")
                    {
                    $filesall = $session.EnumerateRemoteFiles($DestinationDir, "*", [WinSCP.EnumerationOptions]::None)
                    $discoveredfilecount = ($filesall | Measure-Object).count
                    while ($discoveredfilecount -gt $DestinationZipQuantity -or $discoveredfilecount -eq $DestinationZipQuantity){
                        $ZipCommand = 'cd ' + "$DestinationDir; timestamp=" + '$(' + 'date --utc +%FT%TZ); files=$(' + "find ./ +cmin 2 -type f ! -name " + '"' + ".zip" +'"' + ' | head -n ' + "$DestinationZipQuantity); zip " + '$timestamp' + '.zip -m $files'
                        $session.ExecuteCommand($ZipCommand).Check()
                        $currentzip = $session.EnumerateRemoteFiles($DestinationDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                        foreach ($zip in $currentzip){
                            $session.GetFiles(($zip), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                            $currentdate = Get-Date -Format yyyyMMdd
                            if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                                {
                                New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                                "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                                }
                            "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                            $discoveredfilecount = ($discoveredfilecount - $DestinationZipQuantity)
                                                     }
                            }
                            }
                    if (($discoveredfilecount -le $DestinationZipQuantity) -and ($discoveredfilecount -ne 0 -or $discoveredfilecount -le 0)) 
                        {
                        $ZipCommand = 'cd ' + "$DestinationDir; timestamp=" + '$(' + 'date --utc +%FT%TZ); files=$(' + "find ./ +cmin 2 -type f -name " + '"' + ".zip" +'"' + ' | head -n ' + "$discoveredfilecount); zip " + '$timestamp' + '.zip -m $files'
                        $session.ExecuteCommand($ZipCommand).Check()
                        $currentzip = $session.EnumerateRemoteFiles($DestinationDir, "*.zip", [WinSCP.EnumerationOptions]::None)
                        $session.GetFiles(($zip), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                            "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        }
                    }
                    $session.Dispose()
                    exit 0
                }
#############################################
##No files being zipped, filetype specified##
#############################################
    if ($DestinationZip -ne $True)
    {
    $session = New-Object WinSCP.Session
    $transferOptions = New-Object WinSCP.TransferOptions
    $transferOptions.FileMask = ("<=2n")
    $session.Open($sessionOptions)
        if ($DestinationFiletype.length -gt "2" -or $DestinationFiletype.length -eq "2")
            {
            $filesall = $session.EnumerateRemoteFiles($DestinationDir, "$DestinationFiletype", [WinSCP.EnumerationOptions]::None)
            $discoveredfilecount = ($filesall | Measure-Object).count
            while ($discoveredfilecount -gt "1"){
                foreach ($file in $filesall){
                    $session.GetFiles(($file.FullName), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                    $currentdate = Get-Date -Format yyyyMMdd
                    if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                        {
                        New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                        "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                        }
                    "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                    $discoveredfilecount = ($discoveredfilecount - "1")
                                         }
            }
            }
################################################
##No files being zipped, no filetype specified##
################################################ 
            else
            {
                $filesall = $session.EnumerateRemoteFiles($DestinationDir, "*", [WinSCP.EnumerationOptions]::None)
                $discoveredfilecount = ($filesall | Measure-Object).count
                while ($discoveredfilecount -gt "1"){
                    foreach ($file in $filesall){
                        $session.GetFiles(($file.FullName), ("$Using:LocalChildFolderPushing\$Basename\inbound\"),$True ,$transferOptions).Check()
                        $currentdate = Get-Date -Format yyyyMMdd
                        if (!(Test-Path "$Using:LoggingfolderPushing\$basename\$currentdate.txt"))
                            {
                            New-Item "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -ItemType file
                            "Time" + $Tab + "Name" + $Tab + "Size (Kb)" + $Tab + "IP Address" + $Tab + "Directory" + $Tab + "FTP Type" + $Tab + "FileType" | Out-file -FilePath "$Using:LoggingfolderPushing\$basename\$currentdate.txt" -Append
                            }
                        "$timestamp" + $Tab + $zip.name + $Tab + $zip.length + "Kb" + $Tab + $DestinationIP + $Tab + $DestinationDir + $Tab + $DestinationFTPType + $Tab + $DestinationFiletype | Out-File -FilePath "$Using:LoggingfolderPushing\$Basename\$currentdate.txt" -Append
                        $discoveredfilecount = ($discoveredfilecount - "1")
                                                }
                }
            }
                $session.Dispose()
                exit 0
    }
}