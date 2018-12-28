########################
##Hypervisor Variables##
########################
$HostName = “helio”
$HostTimeZone = “Eastern Standard Time”
$HostOSpartitionsize = "80"
$HostManagementIP = "192.168.0.7"
$HostManagementGateway = "192.168.0.1"
$HostDNS = "192.168.0.10"
$HostSwitchName = "HVSwitch"
$HostVMMountPath = ”E:\VMStorage”
$HostConfigure = $True #If true, configure the hypervisor
$ProductKey = "PRODUCTKEY"
$AttachToExistingActiveDirectory = $True #If true, join to domain. If False, don't join to domain

################################
## Failover Cluster Variables ##
################################
$FailoverCluster = $True #If true, configure failover cluster variables


###############################
## Virtual Machine Variables ##
###############################

## VM Location and Identification
$VMnames = "addc","file","wsus"
$VMTemplate = "E:\Hyper-V\windowsimage.vhdx"
$VMUnattend = "E:\Unattend.xml"
$VMHostISOPath = "E:\VMControl\iso\Win2016.iso" #this iso needs autounattend.xml in its root

## VM Resource Allocation
$VMRAM = 6,6,14
$VMCPUCount = 2,2,4
$VMDataVHDSize = 0,2000,500

## VM Network Information
$VMNetworkPortion = "192.168.0."
$VMIP = "8", "9", "10"
$VMSubnet = "255.255.255.0"
$VMGateway = "192.168.0.1"
$VMFeature = "AD-Domain-Services", "", "UpdateServices"

## Credentials & Ownership
#Computer name is defined in 'VMnames'
$LocalAdminName = "xAdministrator"
$LocalAdminPassword = "GenericPassword"
$LocalOrganization = "Ghowstown"

#############
##Constants##
#############
$Bytes = [math]::pow( 2, 30 )

############################
##Configure the Hypervisor##
############################
if ($HostConfigure -eq "$True")
    {
    # ----- I determine if the hypervisor needs configuration by if the hostname is correct or not
    if ($env:computername -ne $HostName)
        {
        # ----- Set TimeZone
        TZUtil /s $HostTimeZone
        Rename-Computer -NewName $HostName -Confirm:$False
        # ----- Register product key
        Dism /online /Set-Edition:ServerDatacenter /AcceptEula /ProductKey:$ProductKey
        Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Confirm:$False Restart-Computer
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
            New-NetIPAddress -InterfaceAlias “vEthernet (HVSwitch)” -IPAddress $HostManagementIP -PrefixLength 24 -DefaultGateway $HostManagementGateway
            Set-DnsClientServerAddress -InterfaceAlias “vEthernet (HVSwitch)” -ServerAddresses $HostDNS
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

#----- Convert index to variable for programatic ease
    $VMnamestemp = $VMnames[$i]
    $DataVHDSizetemp = $VMDataVHDSize[$i]
    $RAMtemp = $VMRAM[$i]
    $CPUtemp = $VMCPUCount[$i]

#----- Name drives in a standard format
    $VHDPath = (“$HostVMMountPath" + "\" + $VMnamestemp + ".vhdx")
    $DataVHDPath = (“$HostVMMountPath" + "\" + $VMnamestemp + "_data.vhdx")

#----- Some quick math to convert from bytes to Gb
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
                $xml | Foreach-Object { $_ -replace '!organization!', $LocalOrganization } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!password!', $LocalAdminPassword } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
                $xml | Foreach-Object { $_ -replace '!administrator!', $LocalAdminName } | Set-Content ("$MountedSysprepDrive" + ":\Windows\Panther\unattend.xml")
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

For ($i=0; $i -lt $VMnames.count; $i++) {

#----- Convert index to variable for programatic ease
    $VMnamestemp = $VMnames[$i]
    $DataVHDSizetemp = $VMDataVHDSize[$i]
    $RAMtemp = $VMRAM[$i]
    $CPUtemp = $VMCPUCount[$i]
    $VMService = $VMFeature[$i]

if ($VMService = "AD-Domain-Services")
  {

  }

if ($VMService = "UpdateServices")
  {

  }

if ($VMService = "WDS")
  {
    Invoke-Command

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
            <ProductKey>CB7KF-BWN84-R7R2Y-793K2-8XDDG</ProductKey>
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
