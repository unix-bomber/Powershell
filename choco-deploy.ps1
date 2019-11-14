$wsusserver = $env:Computername
$adserver = $env:LOGONSERVER.substring(2)

$ServiceAccount = "domain\some-svc-acct" #service account needs to be domain admin
$Password = ConvertTo-SecureString -string "sanitizedpassword" -AsPlainText -force

$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ServiceAccount, $Password

#Import AD Module
$S = New-PSSession -ComputerName $adserver -Credential $Credential
$ComputerProperties = Invoke-Command $S -Scriptblock { Get-ADGroupmember -Identity "Domain Computers" }
#Get All Computers to update
$ComputerName = $ComputerProperties.Name

    foreach ($Computer in $Computername) 
        {
                Invoke-Command -Computername $computer -Credential $Credential -Scriptblock {

Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco feature enable -n usefipscompliantchecksums
choco install googlechrome -y
choco install github-desktop -y --force --params "'ALLUSERS=1'"
choco install atom -y --force --params "'ALLUSERS=1'"
choco upgrade all -y
}
}
