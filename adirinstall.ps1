$VMPermIP = 192.168.0.20#Active Directory IP
$VMLocalAdmin = "Administrator"
$VMLocalPassword = ConvertTo-SecureString -string 'SomePassword90)' -AsPlainText -force

$VMstaticIP = "150"
$VMNetPrefix = "24"
$VMGateway = "192.168.0.1"

$VMFeature = "AD-Domain-Services"#"Server" does no configuration "AD-Domain-Services","UpdateServices","Server","wds","SCVMM"
$NewDomainName = "domain"
$NewDomainNametld = ".com"
$ExternalDNS = "9.9.9.9"
$FirstDomainUser = "administrator"
$FirstDomainPassword = ConvertTo-SecureString -String "SomePassword90)" -AsPlainText -Force
$NewAdminUserName = "domainadmin"
$NewAdminPassword = ConvertTo-SecureString -String 'SufficientlyComplexPassword098)(*' -AsPlainText -Force
$SafeModeAdministratorPassword = ConvertTo-SecureString -string "acrazylongCOMPLEX47$&47$&" -AsPlainText -force

###############
## Constants ##
###############

$Bytes = [math]::pow( 2, 30 )

$FullDomainName = "$NewDomainName" + "$NewDomainNametld"
$NewDomainNametldraw = $NewDomainNametld.substring(1)
$FullHostLocalAdmin = "$env:computername" + "\" + "$HostLocalAdmin"
$FullExtDomainAdmin = "$ExtHostDomain" + "\" + "$ExtDomainAdmin"
$FullVMLocalAdmin = "$VMnamestemp" + "\" + "$VMLocalAdmin"
$FullFirstDomainUser =  "$FullDomainName" + "\" + "$FirstDomainUser"
$FullNewAdminUserName = "$FullDomainName" + "\" + "$NewAdminUserName"

$HostLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FullHostLocalAdmin, $HostLocalAdminPassword
$VMLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FullVMLocalAdmin, $VMLocalPassword
$FirstDomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FullFirstDomainUser, $FirstDomainPassword
$NewAdminDomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FullNewAdminUserName, $NewAdminPassword


$AdInstallState = Get-WindowsFeature -ComputerName $VMPermIP -credential $VMLocalCredential -name "AD-Domain-Services"
if ($ADInstallState.Installed -ne "Installed")
{
  Write-Verbose "Installing & Configuring $VMFeatureTemp on $VMnamestemp" -Verbose
  Invoke-Command -VMname $VMNamestemp -Credential $VMLocalCredential -ScriptBlock {
  param ($VMLocalCredential,$FullDomainName,$NewDomainName,$SafeModeAdministratorPassword)
  Install-WindowsFeature –Name AD-Domain-Services -Credential $VMLocalCredential -IncludeManagementTools
  Import-Module ADDSDeployment
  Install-ADDSForest -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName $FullDomainName -DomainNetbiosName $NewDomainName -InstallDns -NoDNSonNetwork -ForestMode "WinThreshold" -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force -SafeModeAdministratorPassword $SafeModeAdministratorPassword -NoRebootOnCompletion
  } -ArgumentList $VMLocalCredential,$FullDomainName,$NewDomainName,$SafeModeAdministratorPassword
}

Write-Verbose "Rebooting $VMnamestemp to apply $VMFeatureTemp" -Verbose
Stop-VM -name $VMNamestemp
Start-VM -name $VMNamestemp

# ----- This determines whether the VM is online and ready to receive commands after installing active directory.
Write-Verbose "Waiting for $VMnamestemp to respond..." -Verbose
while ((icm -VMName $VMNamesTemp -Credential $FirstDomainCredential {“Test”} -ea SilentlyContinue) -ne “Test”) {Sleep -Seconds 1}

Invoke-Command -VMName $VMNamestemp -Credential $FirstDomainCredential -ScriptBlock {
  param ($NewAdminUserName, $NewAdminPassword)
  $ADWebSvc = Get-Service ADWS | Select-Object *
  while($ADWebSvc.Status -ne 'Running')
          {
          Start-Sleep -Seconds 1
          }
  Do {
  Start-Sleep -Seconds 30
  Write-Verbose "Waiting for AD to be Ready for User Creation" -Verbose
  New-ADUser -Name $NewAdminUserName -AccountPassword $NewAdminPassword
  Enable-ADAccount -Identity $NewAdminUserName
  $ADReadyCheck = Get-ADUser -Identity $NewAdminUserName
  }
  Until ($ADReadyCheck.Enabled -eq "True")
  Add-ADGroupMember -Identity "Domain Admins" -Members "$NewAdminUserName"
  } -ArgumentList $NewAdminUserName, $NewAdminPassword

Invoke-Command -VMName $VMNamestemp -Credential $FirstDomainCredential -ScriptBlock {
param ($FullDomainName,$NewDomainName,$NewAdminPassword,$NewDomainNametldraw,$VMnames,$HostName,$VMNetworkPortion,$VMNetPrefix,$LiVMnames,$LiVMstaticIP,$WDSPhysicalHostHostname)
Write-Verbose "Creating custom AD environment & users" -Verbose
Import-Module ActiveDirectory
Enable-PSRemoting
# ----- Add Server Computer accounts
  ForEach ($Name in $VMnames) {
  New-ADComputer -Name "$Name" -SamAccountName "$Name"
  }
# ----- Add Local Hypervisor
  New-ADComputer -Name "$HostName" -SamAccountName "$HostName"

# ----- Add Cluster Hypervisors
  ForEach ($Name in $WDSPhysicalHostHostname) {
  New-ADComputer -Name "$Name" -SamAccountName "$Name"
  }

# ----- Configure NTP server
  $adfqdn = "$VMNamestemp" + "$FullDomainName"

  w32tm /config /manualpeerlist:$adfqdn /syncfromflags:MANUAL
  Stop-Service w32time
  Start-Service w32time

# ----- Creates Reverse lookup zone
# ----- DNS Configuration
  $VMNetworkFirstIP = $VMNetworkPortion + "0"
  Add-DnsServerPrimaryZone -NetworkID "$VMNetworkFirstIP/$VMNetPrefix" -ReplicationScope "Forest"

# ----- Reverse the $VMNetworkFirstIP, to get reverse dns
  $ipsplit = $VMNetworkFirstIP.split(".")
  $reverseip = $ipsplit[2] + "." + $ipsplit[1] + "." + $ipsplit[0]

  $ForwardZone = Get-DnsServerZone | where -Property ZoneName -match "$FullDomainName"
  $ReverseZone = Get-DnsServerZone | where -Property ZoneName -like "*$reverseip*"

  For ($i=0; $i -lt $LiVMnames.count; $i++) {
    $LiVMnamestemp = $LiVMnames[$i]
    $LiVMPermIP = $VMNetworkPortion + $LiVMstaticIP[$i]
    Add-DnsServerResourceRecordA -Name $LiVMnamestemp -IPv4Address $LiVMPermIP -ZoneName $ForwardZone.ZoneName
    Add-DnsServerResourceRecordPtr -Name $LiVMnamestemp -ZoneName $ReverseZone.ZoneName -PtrDomainName $FullDomainName
  }

} -ArgumentList $FullDomainName,$NewDomainName,$NewAdminPassword,$NewDomainNametldraw,$VMnames,$HostName,$VMNetworkPortion,$VMNetPrefix,$LiVMnames,$LiVMstaticIP,$WDSPhysicalHostHostname
}
