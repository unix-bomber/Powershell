#############################
## Hypervisor OS Variables ##
#############################
$HostName = "helio"
$HostTimeZone = "Eastern Standard Time"
$HostOSpartitionsize = "80"
$HostManagementIP = "192.168.0.7"
$HostNetPrefix = "24"
$HostManagementGateway = "192.168.0.1"
$HostDNS = "192.168.0.10"
$HostProductKey = "" #Put a product key here, if you want to apply it
$HostSwitchName = "HVSwitch"
$HostVMMountPath = "E:\VMStorage"
$HostConfigure = $True #If true, apply the above settings install&configure hyper-v

#############################
## Existing AD Credentials ##
#############################
$DomainAdmin = "domain_admin"
$DomainAdminPassword = "password" | ConvertTo-SecureString -AsPlainText -Force
$DomainName = "domain"
$HostLocalAdmin = "local_admin"
$HostLocalAdminPassword = "password" | ConvertTo-SecureString -AsPlainText -Force

################################
## Failover Cluster Variables ##
################################
$FailoverCluster = $True #If true, configure failover cluster variables

###############################
## Virtual Machine Variables ##
###############################

# ----- VM Location and Identification
$VMnames = "addc", "file", "wsus", "wds"
$VMTemplate = "E:\Hyper-V\windowsimage.vhdx"
$VMUnattend = "E:\Unattend.xml"
$VMProductKey = "key1", "key2", "key3", "key4"

# ----- VM Resource Allocation
$VMRAM = 6,6,14,6
$VMCPUCount = 2,2,4,2
$VMDataVHDSize = 0,2500,500,500

# ----- VM Network Information
$VMNetworkPortion = "192.168.0."
$VMIP = "8", "9", "10", "11"
$VMNetPrefix = "24"
$VMGateway = "192.168.0.1"
$VMFeature = "AD-Domain-Services", "FileServer", "UpdateServices", "WDS" #FileServer doesn't do any installation, only creates shared file structure

# ----- Credentials & Ownership
#Computer name is defined in 'VMnames'
$VMLocalAdminName = "xAdministrator"
$VMLocalAdminPassword = "GenericPassword" | ConvertTo-SecureString -AsPlainText -Force
$VMLocalOrganization = "Ghowstown"

#####################################################
## Active Directory Feature Installation Variables ##
#####################################################
$SafeModeAdministratorPassword = "password"  | ConvertTo-SecureString -AsPlainText -Force
$NewDomainName = "ghowstown"
$ExternalDNS = "9.9.9.9"

#############
##Constants##
#############
$Bytes = [math]::pow( 2, 30 )

############################
##Configure the Hypervisor##
############################

$DomCred = New-Object System.Management.Automation.PSCredential -ArgumentList $DomainAdmin,$DomainAdminPassword
$LocCred = New-Object System.Management.Automation.PSCredential -ArgumentList $HostLocalAdmin,$HostLocalAdminPassword

if ($HostConfigure -eq "$True")
    {
    # ----- I determine if the hypervisor needs configuration by if the hostname is correct or not
    if ($env:computername -ne $HostName)
        {
        TZUtil /s $HostTimeZone
        Rename-Computer -NewName $HostName -Confirm:$False
        # ----- Register product key
        if ($ProductKey.count -gt 1)
          {
          Dism /online /Set-Edition:ServerDatacenter /AcceptEula /ProductKey:$HostProductKey
          }
        Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Confirm:$False
        # ----- Join AD domain
        if ($env:userdomain -ne $HostDomain)
          {
          Add-Computer -ComputerName $HostName -LocalCredential "$LocCred" -DomainName "$DomainName" -Credential $Cred -Restart -Force
          }
        Restart-Computer -force
        }
###fixme### the new if statement below, has to be wrapped in 'if $FailoverCluster is true, DO NOT do this'
###fixme### this if statement needs to be replaced with 'if windows-feature hyper-v is present, DO NOT do this'
    # ----- If there's no partition for data storage and external facing 'stuff' we probably need hyper-v configuration
    if (!(Get-Partition -DriveLetter 'E' -ErrorAction SilentlyContinue))
        {
        Import-Module -Name netswitchteam
        $HostOSpartitionsize = $Bytes * $HostOSpartitionsize
        $VerifySwitch = Get-VMSwitch
        Resize-Partition -DriveLetter 'C' -Size $HostOSpartitionsize
        New-Partition -DiskNumber 0 -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Force
        New-Item -ItemType Directory -Path $HostVMMountPath
        # ----- If Virtual switch doesn't exist, create it & conigure
        if ($VerifySwitch.name -ne $HostSwitchName)
            {
            Import-Module -Name Hyper-V
            Set-Vmhost -VirtualHardDiskPath $HostVMMountPath -VirtualMachinePath $HostVMMountPath
            New-NetLbfoTeam -Name HVTeam -TeamMembers * -Confirm:$False -LoadBalancingAlgorithm HyperVPort -TeamingMode SwitchIndependent
            New-VMSwitch -Name $HostSwitchName -NetAdapterName HVTeam -AllowManagementOS $True -Confirm:$False
            New-NetIPAddress -InterfaceAlias "vEthernet ($HostSwitchName)" -IPAddress $HostManagementIP -PrefixLength $HostNetPrefix -DefaultGateway $HostManagementGateway
            Set-DnsClientServerAddress -InterfaceAlias "vEthernet ($HostSwitchName)" -ServerAddresses ($HostDNS,$ExternalDNS)
            Disable-NetAdapterBinding "vEthernet ($HostSwitchName)" -ComponentID ms_tcpip6 -PassThru
            }
        }

  if ($FailoverCluster -eq "$True")
    {

    }
}
###########################
##Create Virtual Machines##
###########################

For ($i=0; $i -lt $VMnames.count; $i++) {

# ----- Convert index to variable for programatic ease
    $VMnamestemp = $VMnames[$i]
    $DataVHDSizetemp = $VMDataVHDSize[$i]
    $RAMtemp = $VMRAM[$i]
    $CPUtemp = $VMCPUCount[$i]

# ----- Name drives in a standard format
    $VHDPath = ("$HostVMMountPath" + "\" + $VMnamestemp + ".vhdx")
    $DataVHDPath = ("$HostVMMountPath" + "\" + $VMnamestemp + "_data.vhdx")

# ----- Some quick math to convert from bytes to Gb
    $DataVHDSizeGB = $Bytes * $DataVHDSizetemp
    $RAMGB = $Bytes * $RAMTemp

        if (!(Get-Item $VHDPath -ErrorAction SilentlyContinue))
            {
                # ----- Copies sysprepped image
                Copy-Item -path $VMTemplate -Destination $VHDPath
                $MountedSysprepDrive = Mount-VHD -Path $VHDPath -Passthru | Get-Disk | Get-Partition | Get-Volume | where{$_.FileSystemLabel -ne "Recovery"} | select DriveLetter -ExpandProperty DriveLetter
                Copy-Item -Path $VMUnattend -Destination ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml = Get-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!ComputerName!', $VMNamesTemp } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!organization!', $VMLocalOrganization } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!password!', $VMLocalAdminPassword } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!administrator!', $VMLocalAdminName } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!productkey!', $VMProductKey } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                Dismount-Vhd -Path $VHDPath
                New-VM -Generation 2 -MemoryStartupBytes $RAMGB -Name $VMnamestemp -SwitchName $HostSwitchName
                Add-VMHardDiskDrive –ControllerType SCSI -ControllerNumber 0 -VMName $VMnamestemp -Path $VHDPath
                Set-VM -Name $VMnamestemp -StaticMemory -ProcessorCount $CPUtemp
                #$VMDvdDrive = Get-VMDvdDrive -VMName $VMnamestemp
                #Add-VMDvdDrive -VMName $VMnamestemp -Path $VMHostISOPath
                $Drivefirst = Get-VMHardDiskDrive -VMName $VMnamestemp # change
                Set-VMFirmware "$VMnamestemp" -FirstBootDevice $Drivefirst
                Disable-VMIntegrationService -Name 'Time Synchronization' -ComputerName $HostName -VMName $VMnamestemp
                # ----- Creates a second HDD for data & external facing stuff, configures VM for installation
                if ($DataVHDSizeGB -ge 1)
                    {
                    New-VHD -Path $DataVHDPath -SizeBytes $DataVHDSizeGB -Dynamic
                    Add-VMHardDiskDrive –ControllerType SCSI -ControllerNumber 0 -VMName $VMnamestemp -Path $DataVHDPath
                    }
                Start-VM -Name $VMnamestemp
            }
}

############################################
## Install and Configure Windows features ##
############################################

For ($i=0; $i -lt $VMnames.count; $i++) {

# ----- Convert index to variable for programatic ease
    $VMnamestemp = $VMnames[$i]
    $DataVHDSizetemp = $VMDataVHDSize[$i]
    $RAMtemp = $VMRAM[$i]
    $CPUtemp = $VMCPUCount[$i]
    $VMFeaturetemp = $VMFeature[$i]
    $VMIPtemp = $VMIP[$i]
    $VMIPSegment = $VMIP[$i]

$VMPermIP = "$VMNetworkPortion" + "$VMIPSegment"
$VMLocCred = New-Object System.Management.Automation.PSCredential -ArgumentList $VMLocalAdminName,$VMLocalAdminPassword
$TempIP = Get-VM -Name $VMnamestemp | Select-Object -ExpandProperty NetworkAdapters | Select-Object IPAddresses

# ----- Assign a Static IP
Invoke-Command -ComputerName $VMIPTemp -Credential $VMLocCred -Argumentlist $VMPermIP,$VMGateway,$VMNetPrefix -ScriptBlock {
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $VMPermIP -PrefixLength $VMNetPrefix -DefaultGateway $VMGateway
}

if ($VMFeaturetemp = "AD-Domain-Services")
  {
    Invoke-Command -ComputerName $VMPermIP -Credential $VMLocCred -Argumentlist $NewDomainName,$VMPermIP,$VMSubnet,$VMGateway,$SafeModeAdministratorPassword -ScriptBlock {
    Install-WindowsFeature –Name AD-Domain-Services -IncludeManagementTools -Confirm:$False
    Import-Module ADDSDeployment
    Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2016" -DomainName "$NewDomainName" + ".com" -DomainNetbiosName "$NewDomainName" -ForestMode "Win2016" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $SafeModeAdministratorPassword
    }
    # ----- Need to add connection logic for restart (Connecting & ensuring device is up)

$DefaultAdminPassword = "Password" | ConvertTo-SecureString -AsPlainText -Force
$DefaultUserPassword = "Password" | ConvertTo-SecureString -AsPlainText -Force
    Import-Module ActiveDirectory
<#
Reference Structure
    Sites
      Kaczynski
        Accounts
          Admin
            kdomad
            kentad
            hosad_kk
            hosad_ck
          Users
            kactw
            celie
          Service
            mailer

        Devices
          Servers
            helio
            wsus
            file
            wds
          Hosts
            laptopski
            desktopski
            laptopcelie
      Zwalker
      Pwalker
#>

# ----- Add OU structure
    New-ADOrganizationalUnit -Name "Sites"
      New-ADOrganizationalUnit -Name "Kaczynski" -Path "OU=SITES,DC=GHOWSTOWN,DC=COM"
        New-ADOrganizationalUnit -Name "Accounts" -Path "OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
          New-ADOrganizationalUnit -Name "Admin" -Path "OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
          New-ADOrganizationalUnit -Name "Users" -Path "OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
          New-ADOrganizationalUnit -Name "Service" -Path "OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"

        New-ADOrganizationalUnit -Name "Devices" -Path "OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
          New-ADOrganizationalUnit -Name "Servers" -Path "OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
          New-ADOrganizationalUnit -Name "Hosts" -Path "OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"

# ----- Add Groups
    New-ADGroup -Name "Kaczynski Users" -SamAccountName "KaczynskiUsers" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski Users" -Path "OU=USERS,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are Users at the Kaczynski site"
    New-ADGroup -Name "Kaczynski LocalAdmin" -SamAccountName "KaczynskiLocAdmin" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski LocAdmin" -Path "OU=ADMIN,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are Local Computers Admins at the Kaczynski site"
    New-ADGroup -Name "Kaczynski Hosts" -SamAccountName "KaczynskiHosts" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski Hosts" -Path "OU=HOSTS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are User Computers at the Kaczynski site"
    New-ADGroup -Name "Kaczynski Servers" -SamAccountName "KaczynskiServers" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski Servers" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are Servers at the Kaczynski site"
    New-ADGroup -Name "Kaczynski Physical" -SamAccountName "KaczynskiPhysical" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski Physical" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are Physical Servers at the Kaczynski site"
    New-ADGroup -Name "Kaczynski Virtual" -SamAccountName "KaczynskiVirtual" -GroupCategory Security -GroupScope Global -DisplayName "Kaczynski Virtual" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -Description "Members of this group are Virtual Servers at the Kaczynski site"

# ----- Add Users Accounts
    New-ADUser -Name "Kaczynski DomainAdmin" -SamAccountName "kdomad" -AccountPassword $DefaultAdminPassword -Path "OU=ADMIN,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" "//file/admins/%USERNAME%"
    New-ADUser -Name "Kaczynski EnterpriseAdmin" -SamAccountName "kentad" -AccountPassword $DefaultAdminPassword -Path "OU=ADMIN,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" "//file/admins/%USERNAME%"
    New-ADUser -Name "Kaczynski TimLocalAdmin" -SamAccountName "khosad_kk" -AccountPassword $DefaultAdminPassword -Path "OU=ADMIN,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADUser -Name "Kaczynski CeciliaLocalAdmin" -SamAccountName "khosad_ck" -AccountPassword $DefaultAdminPassword -Path "OU=ADMIN,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADUser -Name "Timothy Kaczynski" -SamAccountName "kactw" -AccountPassword $DefaultUserPassword -Path "OU=USERS,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -HomeDirectory "//file/users/%USERNAME%"
    New-ADUser -Name "Cecilia Brogdon" -SamAccountName "celie" -AccountPassword $DefaultUserPassword -Path "OU=USERS,OU=ACCOUNTS,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM" -HomeDirectory "//file/users/%USERNAME%"

# ----- Add Users to Groups
    Add-ADGroupMember -Identity "KaczynskiUsers" -Members kactw,celie
    Add-ADGroupMember -Identity "KaczynskiLocAdmin" -Members khosad_kk,khosad_ck
    Add-ADGroupMember -Identity "DomainAdministrators" -Members kdomad,kentad
    Add-ADGroupMember -Identity "EnterpriseAdministrators" -Members kentad

# ----- Add Computer accounts
    New-ADComputer -Name "helio" -SamAccountName "helio" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "wsus" -SamAccountName "wsus" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "file" -SamAccountName "file" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "wds" -SamAccountName "wds" -Path "OU=SERVERS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "laptopski" -SamAccountName "laptopski" -Path "OU=HOSTS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "desktopski" -SamAccountName "desktopski" -Path "OU=HOSTS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"
    New-ADComputer -Name "laptopbro" -SamAccountName "laptopbro" -Path "OU=HOSTS,OU=DEVICES,OU=KACZYNSKI,OU=SITES,DC=GHOWSTOWN,DC=COM"

# ----- Add Computers to Groups
    Add-ADGroupMember -Identity "KaczynskiServers" -Members addc,helio,wsus,file,wds
    Add-ADGroupMember -Identity "KaczynskiPhysical" -Members "helio"
    Add-ADGroupMember -Identity "KaczynskiVirtual" -Members addc,wsus,file,wds
    Add-ADGroupMember -Identity "KaczynskiHosts" -Members kactw,celie

# https://social.technet.microsoft.com/wiki/contents/articles/7833.how-to-make-a-domain-user-the-local-administrator-for-all-pcs.aspx ----- make a local user admin for hosts & servers
# addc https://www.dell.com/support/article/ch/de/chdhs1/how10253/installing-active-directory-domain-services-and-promoting-the-server-to-a-domain-controller?lang=en or https://blogs.technet.microsoft.com/uktechnet/2016/06/08/setting-up-active-directory-via-powershell/ ----- install addc and forest

  }

if ($VMService = "FileServer")
  {
    Invoke-Command -ComputerName $VMPermIP -Credential $VMLocCred -Argumentlist $NewDomainName,$VMPermIP,$VMSubnet,$VMGateway,$SafeModeAdministratorPassword -ScriptBlock {
    New-Item -Name "users" -path "E:\" -ItemType "Directory"
    New-Item -Name "admin" -path "E:\" -ItemType "Directory"
    New-Item -Name "public" -path "E:\" -ItemType "Directory"
    New-Item -Name "kactw" -path "E:\users" -ItemType "Directory"
    New-Item -Name "celie" -path "E:\users" -ItemType "Directory"

    # ----- pick up here
    New-SMBShare –Name "users" –Path "E:\users" –ContinuouslyAvailable –FullAccess $NewDomainName\domainadmin,$NewDomainName\domainusers
    $path = "E:\users\kactw","E:\users\celie" #Replace with whatever file you want to do this to.
    $user = "$NewDomainName\kactw","$NewDomainName\celie" #User account to grant permisions too.
    $Rights = "Full control" #Comma seperated list.
    $InheritSettings = "Containerinherit, ObjectInherit" #Controls how permissions are inherited by children
    $PropogationSettings = "None" #Usually set to none but can setup rules that only apply to children.
    $RuleType = "Allow" #Allow or Deny.

    For ($i=0; $i -lt $users.count; $i++) {

      $acl = Get-Acl $path[$i]
      $perm = $user[$i], $Rights, $InheritSettings, $PropogationSettings, $RuleType
      $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
      $acl.SetAccessRule($rule)
      $acl | Set-Acl -Path $path[$i]
      }
    }
  }

if ($VMService = "UpdateServices")
  {

  }

if ($VMService = "WDS")
  {
  Invoke-Command -ComputerName $VMPermIP -Credential $VMLocCred -Argumentlist $NewDomainName,$VMPermIP,$VMSubnet,$VMGateway -ScriptBlock {
  Install-WindowsFeature –Name WDS -IncludeManagementTools

  }

}
}

#Hash for my first sysprepped image
#F07793BC4B720E85B2B0BC7B82FF632D70D0F2F41F0706EDFF84440AC1F28978

#Get-VM -Name windowstest | Select-Object -ExpandProperty NetworkAdapters | Select-Object VMName,IPAddresses
#invoke-command -ComputerName "192.168.0.53" -Credential "windowstest1\Administrator" -ScriptBlock {shutdown -s -t 0}

########################
<#
AutoUnattend that works

<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserData>
                <AcceptEula>true</AcceptEula>
                <FullName></FullName>
                <Organization></Organization>
            </UserData>
            <EnableFirewall>true</EnableFirewall>
            <EnableNetwork>true</EnableNetwork>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ComputerName>!ComputerName!</ComputerName>
            <ProductKey>!productkey!</ProductKey>
            <RegisteredOrganization>!organization!</RegisteredOrganization>
            <RegisteredOwner>!organization!</RegisteredOwner>
        </component>
        <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <fDenyTSConnections>false</fDenyTSConnections>
        </component>
        <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <FirewallGroups>
                <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
                    <Active>true</Active>
                    <Group>Remote Desktop</Group>
                    <Profile>all</Profile>
                </FirewallGroup>
            </FirewallGroups>
        </component>
        <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <UserAuthentication>0</UserAuthentication>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
                <SkipUserOOBE>true</SkipUserOOBE>
                <SkipMachineOOBE>true</SkipMachineOOBE>
            </OOBE>
            <RegisteredOrganization>!organization!</RegisteredOrganization>
            <RegisteredOwner>!organization!</RegisteredOwner>
            <DisableAutoDaylightTimeSet>false</DisableAutoDaylightTimeSet>
            <TimeZone>GMT Standard Time</TimeZone>
            <AutoLogon>
                <Password>
                    <Value>!password!</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>2</LogonCount>
                <Username>!administrator!</Username>
            </AutoLogon>
            <UserAccounts>
                <AdministratorPassword>
                    <Value>!password!</Value>
                    <PlainText>true</PlainText>
                </AdministratorPassword>
            </UserAccounts>
        </component>
    </settings>
    <cpi:offlineImage cpi:source="wim:q:/install.wim#Windows Server 2012 R2 SERVERSTANDARD" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>

#https://4sysops.com/archives/powershell-remoting-over-https-with-a-self-signed-ssl-certificate/
#https://gist.github.com/Sauraus/6030714
#References for autounattend and https psremoting

else {
#Join the domain & restart the host server
Add-Computer -Credential $Domain\$User -DomainName $Domain -OUPath $OUPath
Restart-Computer
}
}?
#>

#wsus https://blogs.technet.microsoft.com/heyscriptingguy/2013/04/15/installing-wsus-on-windows-server-2012/
#addc https://www.dell.com/support/article/ch/de/chdhs1/how10253/installing-active-directory-domain-services-and-promoting-the-server-to-a-domain-controller?lang=en or https://blogs.technet.microsoft.com/uktechnet/2016/06/08/setting-up-active-directory-via-powershell/
#wds https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/jj648426(v=ws.11)
