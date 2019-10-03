$directorytoflatten = Get-ChildItem -Recurse -path "C:\Users\tkaczynski\Pictures"
$directorykey = "C:\Users\tkaczynski\key.txt"
$flatteneddirectory = "C:\Users\tkaczynski\flatboi"

######################
## Begining of code ##
######################

############################
## Create Key Value Pairs ##
############################

#create a key if it doesn't exist
New-Item -ItemType file -Path $directorykey
New-Item -ItemType directory -Path $flatteneddirectory

#Read contents, save as file to be sent to distant end
$directorytoflatten.fullname | set-content -Path $directorykey

#Get number of lines, may allow us to iterate through file line by line
$File = Get-content $directorykey | Measure-Object –Line

For ($i=0; $i -lt $File.lines; $i++) {
echo $i

$DirectoryKeyContent = Get-Content $directorykey

$CurrentFileNumber = $i

#I use this because it's the fastest method to read lines from files. As far as I know.
$CurrentFile = ([System.IO.File]::ReadAllLines( $directorykey ))[$CurrentFileNumber]
echo $CurrentFile

$FileSHA = Get-Filehash $CurrentFile -Algorithm SHA256
$FileSHAHash = $FileSHA.hash

$DirectoryKeyContent[$CurrentFileNumber] += ";$FileSHAHash"
$DirectoryKeyContent | Set-Content $directorykey
}

########################
## Flatten everything ##
########################
#This doesn't work. I didn't even try to make it work yet 
For ($i=0; $i -lt $File.lines; $i++) {
echo $i

$DirectoryKeyContent = Get-Content $directorykey

$CurrentFileNumber = $i

#I use this because it's the fastest method to read lines from files. As far as I know.
$CurrentFile = ([System.IO.File]::ReadAllLines( $directorykey ))[$CurrentFileNumber]
echo $CurrentFile

Copy-Item $CurrentFile

$DirectoryKeyContent[$CurrentFileNumber] += ";$FileSHAHash"
$DirectoryKeyContent | Set-Content $directorykey
}
