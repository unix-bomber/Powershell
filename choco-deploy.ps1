$wsusserver = $env:Computername
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco feature enable -n usefipscompliantchecksums
choco install googlechrome -y
choco install github-desktop -y --force --params "'ALLUSERS=1'"
choco install atom -y --force --params "'ALLUSERS=1'"
choco upgrade all -y
}
}