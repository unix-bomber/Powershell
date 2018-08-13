#----- Initialization

#----- Hypervisor Variables
$TimeZone= “Eastern Standard Time”
$HostName= “HELIO”
$OSpartition = "80"
$MgmtIP="192.168.0.7"
$MgmtGateway="192.168.0.1"
$DNS="192.168.0.10"
$SwitchName="HVSwitch"
$MountPath=”D:\VMStorage”

#----- Variables for VM creation
$VMnames="addc","file","wsus"
$ISOPath="D:\VMControl\iso\Win2016.iso"
$Unattend="D:\VMControl\autofiles\autounattend.xml"

#----- Resources to be assigned to virtual machines, in order of $VMnames
#-- All VM information is stored at D:\VirtualMachines, VM's with a second drive (DataVHD) will have a prefix of _data
$RAM = 6,6,14
$CPUCount = 2,2,4
$VHDSize = 80,80,80
$DataVHDSize = 0,2000,500

#----- Controlling logic variables
#-- if the desired hostname is set, a reboot has probably occured
$Currenthostname = $env:computername
$Bytes = [math]::pow( 2, 30 )
$OSpartition = $Bytes * $OSpartition
$ExternalStorage = "F:\ISO\Windows2016.iso"

#----- Hypervisor Configuration

if ($Currenthostname -ne $HostName) 
    {
    TZUtil /s $TimeZone
    Rename-Computer -NewName $HostName -Confirm:$False
    Dism /online /Set-Edition:ServerDatacenter /AcceptEula /ProductKey:YDJ2Q-CNPT3-JP8H9-K2KRM-2PRBF
    Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Confirm:$False Restart-Computer
    }

#----- Initialization
$VerifySwitch=Get-VMSwitch
Import-Module -Name Hyper-V

if (!(Get-Partition -DriveLetter 'D' -ErrorAction SilentlyContinue ))
    {
    Resize-Partition -DriveLetter 'C' -Size $OSpartition
    New-Partition -DiskNumber 0 -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS
    Import-Module -Name netswitchteam
    New-Item -ItemType Directory -Path $MountPath
    if ($VerifySwitch.name -ne $SwitchName) 
        {
        Set-Vmhost -VirtualHardDiskPath $MountPath -VirtualMachinePath $MountPath
        New-NetLbfoTeam -Name HVTeam -TeamMembers * -Confirm:$False -LoadBalancingAlgorithm HyperVPort -TeamingMode SwitchIndependent
        New-VMSwitch -Name $SwitchName -NetAdapterName HVTeam -AllowManagementOS $True -Confirm:$False
        New-NetIPAddress -InterfaceAlias “vEthernet (HVSwitch)” -IPAddress $MgmtIP -PrefixLength 24 -DefaultGateway $MgmtGateway
        Set-DnsClientServerAddress -InterfaceAlias “vEthernet (HVSwitch)” -ServerAddresses $DNS
        }
    }

#Copy-Item -Path $ExternalStorage -Destination $ISOPath

#----- Create Virtual Machines

For ($i=0; $i -lt $VMnames.count; $i++) {

    $VHDPath = (“$MountPath" + "\" + $VMnames[$i] + ".vhdx")
    $DataVHDPath = (“$MountPath" + "\" + $VMnames[$i] + "_data.vhdx")

    $VHDSizeGB = $Bytes * $VHDSize[$i]
    $DataVHDSizeGB = $Bytes * $DataVHDSize[$i]
    $RAMGB = $Bytes * $RAM[$i]

        if (!(Get-Item $VHDPath -ErrorAction SilentlyContinue))
            {
                New-VM -NewVHDPath $VHDPath -NewVHDSizeBytes $VHDSizeGB -Generation 2 -MemoryStartupBytes $RAMGB -Name $VMNames[$i] -SwitchName $SwitchName
                Set-VM -Name $VMNames[$i] -StaticMemory -ProcessorCount $CPUCount[$i]
                if ($DataVHDSizeGB -ge 1) 
                    {
                    New-VHD -Path $DataVHDPath -SizeBytes $DataVHDSizeGB -Dynamic
                    Add-VMHardDiskDrive –ControllerType SCSI -ControllerNumber 0 -VMName $VMNames[$i] -Path $DataVHDPath
                    }
            }

}

#Set-VMDvdDrive -VMName $VM -Path $ISOPath

#Disable-VMIntegrationService -name 'Time Synchronization' -VMName *

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
                            <Label>Windows 2016</Label>
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
            <ComputerName>vagrant-2012-r2</ComputerName>
            <TimeZone>Pacific Standard Time</TimeZone>
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