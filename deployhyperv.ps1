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
$HostConfigure = $True #If true, configure the hypervisor

#############################
##Virtual Machine Variables##
#############################
$VMnames = "addc","file","wsus"
$VMTemplate = "E:\Hyper-V\windowsimage.vhdx"
$VMUnattend = "E:\Unattend.xml"
$VMHostISOPath = "D:\VMControl\iso\Win2016.iso" #this iso needs autounattend.xml in its root
$VMRAM = 6,6,14
$VMCPUCount = 2,2,4
$VMVHDSize########################DELETE
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
if ($HostConfigure -eq "$True")
    {
    # ----- I determine if the hypervisor needs configuration by if the hostname is correct or not
    if ($env:computername -ne $HostName)
        {
        # ----- Set TimeZone
        TZUtil /s $HostTimeZone
        Rename-Computer -NewName $HostName -Confirm:$False
        # ----- Register product key
        Dism /online /Set-Edition:ServerDatacenter /AcceptEula /ProductKey:
        Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Confirm:$False Restart-Computer
        }

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
                $xml | Foreach-Object { $_ -replace '!ComputerName!', $serverName } | Set-Content $unattendedFileLocation
                Dismount-Vhd -Path $VHDPath
                New-VM -Generation 2 -MemoryStartupBytes $RAMGB -Name $VMnamestemp -SwitchName $HostSwitchName
                Add-VMHardDiskDrive –ControllerType SCSI -ControllerNumber 0 -VMName $VMnamestemp -Path $VHDPath
                Set-VM -Name $VMnamestemp -StaticMemory -ProcessorCount $CPUtemp
                $VMDvdDrive = Get-VMDvdDrive -VMName $VMnamestemp
                Add-VMDvdDrive -VMName $VMnamestemp -Path $VMHostISOPath
                Set-VMFirmware "$VMnamestemp" -FirstBootDevice "HardDiskDrive"
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

#Hash for my first sysprepped image
#F07793BC4B720E85B2B0BC7B82FF632D70D0F2F41F0706EDFF84440AC1F28978

########################
<#

else {
#Join the domain & restart the host server
Add-Computer -Credential $Domain\$User -DomainName $Domain -OUPath $OUPath
Restart-Computer
}
}?
#>

#wsus https://blogs.technet.microsoft.com/heyscriptingguy/2013/04/15/installing-wsus-on-windows-server-2012/
#addc https://www.dell.com/support/article/ch/de/chdhs1/how10253/installing-active-directory-domain-services-and-promoting-the-server-to-a-domain-controller?lang=en or https://blogs.technet.microsoft.com/uktechnet/2016/06/08/setting-up-active-directory-via-powershell/
