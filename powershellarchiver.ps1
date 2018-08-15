#feel free to edit these variables
$foldersparent = "D:\backup" #don't include a trailing backslah, aka \
$folders = "examplefolder"#, "anotherexample", #an all option can be included here, but it's not implemented yet
$archiveparent = "D:\backup\archive" #don't include a trailing backslash, aka \
$makearchiveparent = "yes" #specify "yes", or "no" if the root directory 'archive parent' doesn't exist, will create for you

#edit at your peril
$currentdate = Get-Date -Format yyyyMMddHH
$timestamp = (Get-Date -Format o) | foreach {$_ -replace ":", "."}

Add-Type -assembly "system.io.compression.filesystem"

#register in eventlog
if (([System.Diagnostics.EventLog]::SourceExists("powershellarchiver") -ne "True"))
    {
    New-EventLog -Source "powershellarchiver" -LogName "Application"
    }

#archive initialization
try {
    #makearchive error checking
    if ($makearchiveparent -ne "yes" -and $makearchiveparent -ne "no")
        {
        Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2000 -EntryType Information -Message "You spelled 'yes' or 'no' wrong. Check the 'makearchive' variable" -Category 1 -RawData 10,20
        Exit 1
        }
    
    #if archiveparent doesn't exist, alert and create or fail
    if (!($archiveparent))
        {
            if ($makearchiveparent -eq "yes")
                {
                New-Item -ItemType Directory -Force -path $archiveparent
                Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2001 -EntryType Information -Message "Info: Created directory $archiveparent" -Category 1 -RawData 10,20
                }
            else 
                {
                Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2002 -EntryType Information -Message "Error: Archive parent directory not found, and not created" -Category 1 -RawData 10,20
                Exit 1
                }
        }
    #if archiveparent is found
    else 
        {
        Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2003 -EntryType Information -Message "$archiveparent located, using this archive directory" -Category 1 -RawData 10,20
        }
}

Catch
{
Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2004 -EntryType Information -Message "Error: $($_.Exception.Message)" -Category 1 -RawData 10,20
}
#archive initilization complete

#archive configuration & archive start
Try {
foreach ($folder in $folders) {
        New-Item -ItemType Directory -Force -path ($archiveparent + "\" + $folder)
        New-Item -ItemType Directory -Force -path ($archiveparent + "\" + $folder + "\" + $currentdate)

    $currentarchive = $archiveparent + "\" + $folder + "\" + $currentdate
    $currentfolder = $foldersparent + "\" + $folder
    $workingfolder = ($archiveparent + "\" + $folder + "\" + "working")
    if (!($currentfolder))
        {
        Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2005 -EntryType Information -Message "Error: $currentfolder not found, skipping" -Category 1 -RawData 10,20
        break
        }

#startarchive (core logic)
    foreach ($cfolder in $currentfolder) {
        #Set-variable -name 'timestamp' -Option Readonly -Force
        New-Item -ItemType Directory -Force -path $workingfolder
        Get-ChildItem -Path $cfolder -File | Move-Item -Destination $workingfolder
        [io.compression.zipfile]::CreateFromDirectory("$workingfolder", "$currentarchive\$timestamp.zip") 2>&1> $null
        Remove-Item -path "$workingfolder" -Recurse | Out-File -FilePath "$currentarchive\manifest_$timestamp.txt"
        Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 2006 -EntryType Information -Message "Info: $cfolder backed up to $currentarchive\$timestamp.zip" -Category 1 -RawData 10,20
        #Set-variable -name 'timestamp' -Option Constant -Force
    }
}
}

Catch 
{
Write-EventLog -LogName "Application" -source "powershellarchiver" -EventId 1000 -EntryType Information -Message "Error: $($_.Exception.Message)" -Category 1 -RawData 10,20
Exit 1
}
