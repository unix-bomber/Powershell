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
$HostVMMountPath = ”D:\VMStorage”

#############################
##Virtual Machine Variables##
#############################
$VMnames = "addc","file","wsus"
$VMHostISOPath = "D:\VMControl\iso\Win2016.iso" #this iso needs autounattend.xml in its root
$VMRAM = 6,6,14
$VMCPUCount = 2,2,4
$VMVHDSize = 80,80,80
$VMDataVHDSize = 0,2000,500
$VMNetworkPortion = "192.168.0."
$VMIP = "8", "9", "10"
$VMSubnet = "255.255.255.0"
$VMGateway = "192.168.0.1"
$VMFeature = "AD-Domain-Services", "", "UpdateServices"
$TemplateMode = $False #if true, turns template mode on. allows one better configuration in creating multiple vm's
$TemplatePath = #C:\wherever\your\template\is.txt

#############
##Constants##
#############
$Bytes = [math]::pow( 2, 30 )

############################
##Configure the Hypervisor##
############################
if ($env:computername -ne $HostName)
    {
    TZUtil /s $HostTimeZone
    Rename-Computer -NewName $HostName -Confirm:$False
    Dism /online /Set-Edition:ServerDatacenter /AcceptEula /ProductKey:
    Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Confirm:$False Restart-Computer
    }

if (!(Get-Partition -DriveLetter 'E' -ErrorAction SilentlyContinue))
    {
    Import-Module -Name netswitchteam
    $HostOSpartitionsize = $Bytes * $HostOSpartitionsize
    $VerifySwitch = Get-VMSwitch
    Resize-Partition -DriveLetter 'C' -Size $HostOSpartitionsize
    New-Partition -DiskNumber 0 -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -Force
    New-Item -ItemType Directory -Path $HostVMMountPath
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

###########################
##Create Virtual Machines##
###########################

For ($i=0; $i -lt $VMnames.count; $i++) {

#----- Convert index to variable for programatic ease
    $VMnamestemp = $VMnames[$i]
    $VHDSizetemp = $VMVHDSize[$i]
    $DataVHDSizetemp = $VMDataVHDSize[$i]
    $RAMtemp = $VMRAM[$i]
    $CPUtemp = $VMCPUCount[$i]
    
#----- Name drives in a standard format
    $VHDPath = (“$HostVMMountPath" + "\" + $VMnamestemp + ".vhdx")
    $DataVHDPath = (“$HostVMMountPath" + "\" + $VMnamestemp + "_data.vhdx")

#----- Some quick math to convert from bytes to Gb
    $VHDSizeGB = $Bytes * $VHDSizetemp
    $DataVHDSizeGB = $Bytes * $DataVHDSizetemp
    $RAMGB = $Bytes * $RAMTemp

        if (!(Get-Item $VHDPath -ErrorAction SilentlyContinue))
            {
                New-VM -NewVHDPath $VHDPath -NewVHDSizeBytes $VHDSizeGB -Generation 2 -MemoryStartupBytes $RAMGB -Name $VMnamestemp -SwitchName $HostSwitchName
                Set-VM -Name $VMnamestemp -StaticMemory -ProcessorCount $CPUtemp
                if ($DataVHDSizeGB -ge 1) 
                    {
                    New-VHD -Path $DataVHDPath -SizeBytes $DataVHDSizeGB -Dynamic
                    Add-VMHardDiskDrive –ControllerType SCSI -ControllerNumber 0 -VMName $VMnamestemp -Path $DataVHDPath
                    Add-VMDvdDrive -VMName $VMnamestemp -Path $HostISOPath
                    $VMDvdDrive = Get-VMDvdDrive -VMName $VMnamestemp
                    Set-VMFirmware "$VMnamestemp" -FirstBootDevice $VMDvdDrive
                    Disable-VMIntegrationService -Name 'Time Synchronization' -ComputerName $HostName -VMName $VMnamestemp
                    Start-VM -Name $VM
                    }
            }
}


########################
<#
$Unattended = @'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
            <InputLocale>en-US</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DiskConfiguration>
                <Disk wcm:action="add">
                    <CreatePartitions>
                        <CreatePartition wcm:action="add">
                            <Type>Primary</Type>
                            <Order>1</Order>
                            <Size>80</Size>
                        </CreatePartition>
                        <CreatePartition wcm:action="add">
                            <Order>2</Order>
                            <Type>Primary</Type>
                            <Extend>true</Extend>
                        </CreatePartition>
                    </CreatePartitions>
                    <ModifyPartitions>
                        <ModifyPartition wcm:action="add">
                            <Active>true</Active>
                            <Format>NTFS</Format>
                            <Label>boot</Label>
                            <Order>1</Order>
                            <PartitionID>1</PartitionID>
                        </ModifyPartition>
                        <ModifyPartition wcm:action="add">
                            <Format>NTFS</Format>
                            <Label>System</Label>
                            <Letter>C</Letter>
                            <Order>2</Order>
                            <PartitionID>2</PartitionID>
                        </ModifyPartition>
                    </ModifyPartitions>
                    <DiskID>0</DiskID>
                    <WillWipeDisk>true</WillWipeDisk>
                </Disk>
            </DiskConfiguration>
            <ImageInstall>
                <OSImage>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/NAME </Key>
                            <Value>Windows Server 2016 SERVERDATACENTER</Value>
                        </MetaData>
                    </InstallFrom>
                    <InstallTo>
                        <DiskID>0</DiskID>
                        <PartitionID>2</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
            <UserData>
                <!-- Product Key from http://technet.microsoft.com/en-us/library/jj612867.aspx -->
                <ProductKey>
                    <!-- Do not uncomment the Key element if you are using trial ISOs -->
                    <!-- You must uncomment the Key element (and optionally insert your own key) if you are using retail or volume license ISOs -->
                    <!--<Key>D2N9P-3P6X9-2R39C-7RTCD-MDVJX</Key>-->
                    <WillShowUI>OnError</WillShowUI>
                </ProductKey>
                <AcceptEula>true</AcceptEula>
                <FullName>Vagrant</FullName>
                <Organization>Vagrant</Organization>
            </UserData>
        </component>
    </settings>
    <settings pass="specialize">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <OEMInformation>
                <HelpCustomized>false</HelpCustomized>
            </OEMInformation>
            <ComputerName>defaultname</ComputerName>
            <TimeZone>Eastern Standard Time</TimeZone>
            <RegisteredOwner/>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-ServerManager-SvrMgrNc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DoNotOpenServerManagerAtLogon>true</DoNotOpenServerManagerAtLogon>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <IEHardenAdmin>false</IEHardenAdmin>
            <IEHardenUser>false</IEHardenUser>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-OutOfBoxExperience" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <DoNotOpenInitialConfigurationTasksAtLogon>true</DoNotOpenInitialConfigurationTasksAtLogon>
        </component>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Security-SPP-UX" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <AutoLogon>
                <Password>
                    <Value>singusasongyourethepianoman</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <Username>xadministrator</Username>
            </AutoLogon>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>cmd.exe /c powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Bypass"</CommandLine>
                    <Description>Set Execution Policy 64 Bit</Description>
                    <Order>1</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <CommandLine>C:\Windows\SysWOW64\cmd.exe /c powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Bypass"</CommandLine>
                    <Description>Set Execution Policy 32 Bit</Description>
                    <Order>2</Order>
                    <RequiresUserInput>false</RequiresUserInput>
                </SynchronousCommand>
        <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" name="Microsoft-Windows-LUA-Settings" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <EnableLUA>false</EnableLUA>
        </component>
    </settings>
    <cpi:offlineImage xmlns:cpi="urn:schemas-microsoft-com:cpi" cpi:source="wim:c:/wim/install.wim#Windows Server 2016 SERVERDATACENTER"/>
</unattend>
'@







Start-VM -Name $VM



#Set variables to join the domain
$Domain=”Company.local”
$User=”hvadmin”
$OUPath=”OU=Servers,DC=Company,DC=local”

if ($VM = addc)
{
}

else {
#Join the domain & restart the host server
Add-Computer -Credential $Domain\$User -DomainName $Domain -OUPath $OUPath
Restart-Computer
}
}?
#>

#wsus https://blogs.technet.microsoft.com/heyscriptingguy/2013/04/15/installing-wsus-on-windows-server-2012/
#addc https://www.dell.com/support/article/ch/de/chdhs1/how10253/installing-active-directory-domain-services-and-promoting-the-server-to-a-domain-controller?lang=en or https://blogs.technet.microsoft.com/uktechnet/2016/06/08/setting-up-active-directory-via-powershell/
