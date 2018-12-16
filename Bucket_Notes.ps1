###############################
## Configuration Information ##
###############################
$NotesDir = "C:\Users\$env:USERNAME\Documents\bucket_notes"
$NotesHotDuration = "10" #Days to stay in bucket
$NotesWarmDuration = "20"
$NotesColdDuration = "30"
#Deletion always takes precedence over Archiving. Pick one or the other
$NotesArchive = $True #Set to true to archive data in cold bucket
$NotesDelete = $False #Set to true to delete data older than a certain date

########################################################################################
##                              End of User settings                                  ##
########################################################################################
$currentdate = Get-Date -Format yyyyMMdd
$timestamp = Get-Date -Format o | foreach {$_ -replace ":", "."}

##################################
## Installation & Configuration ##
##################################
try {
    if (!(test-path "$NotesDir"))
        {
        New-Item -ItemType directory -Path $NotesDir, "$NotesDir\hot", "$NotesDir\warm", "$NotesDir\cold", "$NotesDir\archive"
        }
    }
catch {
      $($_.Exception.Message) | Out-File -FilePath "C:\Users\$env:USERNAME\Documents\bucket_notes_error$timestamp.txt"
      exit 1
      }

########################
## Check for old data ##
########################

try {
    $BucketDirectories = Get-ChildItem -Path $NotesDir -Directory -Recurse 
    $BucketDirectories.Directory | ForEach-Object {
            $BucketnoteFiles = Get-ChildItem -Path $_ -File | Sort-Object -Property LastWriteTime -Descending
            $BucketnoteFiles | ForEach-Object {
                if ($_.Fullname -ilike 'hot' -and $_.LastWriteTime -lt $(Get-Date).AddDays(-$NotesHotDuration))
                    {
                    Move-Item -Path $_.FullName -Destination "$NotesDir\warm"
                    }
                
                if ($_.Fullname -ilike 'warm' -and $_.LastWriteTime -lt $(Get-Date).AddDays(-$NotesWarmDuration))
                    {
                    Move-Item -Path $_.FullName -Destination "$NotesDir\cold"
                    }
                
                if ($_.Fullname -ilike 'cold' -and $_.LastWriteTime -lt $(Get-Date).AddDays(-$NotesColdDuration))
                    {
                    if ($NotesArchive -eq "$True" -and $NotesDelete -eq "$True")
                        {
                        Remove-Item -Path $_.FullName
                        }
                    if ($NotesArchive -eq "$True" -and $NotesDelete -eq "$False")
                        {
                        $WorkingDir = "$NotesDir\archive\temp"
                        New-Item -Path $WorkingDir
                        Move-Item -Path $_.FullName -Destination "$NotesDir\archive\temp"
                        }
                    if ($NotesArchive -eq "$False" -and $NotesDelete -eq "$True")
                        {
                        echo "Am I a joke to you?"
                        }
                    }
            }
    }
    if (Test-Path -Path $WorkingDir)
        {
        Compress-Archive -Path "$WorkingDir\*" -DestinationPath "$NotesDir\archive\$timestamp.zip"
        Remove-Item -Path "$WorkingDir"
        }
}
catch
    {
    $($_.Exception.Message) | Out-File -FilePath "C:\Users\$env:USERNAME\Documents\bucket_notes_error$timestamp.txt"
    exit 1
    }