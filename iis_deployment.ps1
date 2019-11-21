#Reference https://4sysops.com/archives/install-and-configure-an-ftp-server-with-powershell/
#This was done for a 2012R2 server specifically. There's probably better ways to do this now, but I don't know them.
#!#!#!#!#!#!#!#!##!#!#!#!#!#!#!#!##!#!#!#!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!#
#!#!#!#!#!#!#!#!#IF YOU ONLY HAVE A SINGLE VARIABLE, ENCLOSE IT LIKE THIS @('something')#!#!#!#!#!#!#!#!#
#!#!#!#!#!#!#!#!##!#!#!#!#!#!#!#!##!#!#!#!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!##!#!#!#!#!#

#These configure websites. You must have the same number of variables for all three of these variables (I.E. if you need 3 sites, there should be three FTPSiteNames, FTPRootDirs and FTPPorts)
$FTPSiteName = @('PFTS Data')
$FTPRootDir = @('E:\FTPRoot')
$FTPPort = @("21")
$FirstInstall = $True #If true, check for second partition. If it doesn't exist, online it, modify timezone

#These configure FTP users. You must have the same number of variables for FTPUserName & Password (I.E. if you need 3 users, there should be three FTPUserNames and FTPPasswords)
$CreateFTPUsers = $True #if true, create local ftp users, if false, don't create ftp users. Usefull if you have a domain account alreadys
$FTPUserName = @("FTPUser") #"anotheruser", "anotheruser1"
$FTPPassword = @('123qwe!@#QWE') #"Password", "anotherPassword"
$CreateGroup = $True #if true, creates a local group. This is useful if you're using Active Directory. This is more useful if you have slow AD
$FTPUserGroupName = @("FTP Users") #assign active directory users/group memberships to this local group, and/or local users.

#authentication variables
$Authtypes = 'ftpServer.security.authentication.basicAuthentication.enabled'#list of auth types is below, don't think windowsAuthentication is required
#'ftpServer.security.authentication.basicAuthentication.enabled', 'ftpServer.security.authentication.windowsAuthentication.enabled'

#install FTP&IIS, import modules
Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature -IncludeManagementTools
Install-WindowsFeature Web-Server -IncludeAllSubFeature  -IncludeManagementTools

Import-Module WebAdministration

#create firewall rules for FTP
New-NetFirewallRule -DisplayName "Allow ftp" -Direction Inbound -LocalPort 21 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow Inbound ftp control channels" -Direction Inbound -LocalPort 1024-65535 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow Outbound ftp control channels" -Direction Outbound -LocalPort 1024-65535 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow ftp" -Direction Outbound -LocalPort 20 -Protocol TCP -Action Allow

#If there's no data drive, make one
if (!(Get-Partition -DriveLetter 'E' -ErrorAction SilentlyContinue ))
    {
    Initialize-Disk -Number 1 -PartitionStyle GPT
    New-Partition -DiskNumber 1 -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS
    TZUtil /s "Eastern Standard Time"
    }

#Create group
if ($CreateGroup = $True)
{
            #Create group
            if (!(Get-LocalGroup -Name $FTPUserGroupName))
                {
                $ADSI = [ADSI]"WinNT://$env:ComputerName"
                $FTPUserGroup = $ADSI.Create("Group", "$FTPUserGroupName")
                $FTPUserGroup.SetInfo()
                $FTPUserGroup.Description = "Members of this group can connect through FTP"
                $FTPUserGroup.SetInfo()
                }
}

#Create users, assign password, add to group
if ($CreateFTPUsers = $True)
{
For ($i=0; $i -lt $FTPUserName.count; $i++) {
        if (!(Get-LocalUser $FTPUserName[$i] -ErrorAction SilentlyContinue))
            {
            #Convert all incrementing variables to a static variable to avoid issues with quotes
            $FTPUserNameTemp = $FTPUserName[$i]
	        $FTPpasswordTemp = $FTPPassword[$i]

            #Create User, and set password
            $CreateUserFTPUser = $ADSI.Create("User", "$FTPUserNameTemp")
            $CreateUserFTPUser.SetInfo()
            $CreateUserFTPUser.SetPassword("$FTPPasswordTemp")
            $CreateUserFTPUser.SetInfo()

            #Add user to group
            $UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserNameTemp")
            $SID = $UserAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $Group = [ADSI]"WinNT://$env:ComputerName/$FTPUserGroupName,Group"
            $User = [ADSI]"WinNT://$SID"
            $Group.Add($User.Path)
            }
}
}

#Create multiple ftp sites
For ($i=0; $i -lt $FTPSiteName.count; $i++) {
        if (!(Get-Item $FTPRootDir[$i] -ErrorAction SilentlyContinue))
            {
	        $FTPRootDirTemp = $FTPRootDir[$i]
	        $FTPPortTemp = $FTPPort[$i]
	        $FTPSiteNameTemp = $FTPSiteName[$i]

	        New-Item -Path $FTPRootDirTemp -ItemType Directory
            New-WebFtpSite -Name $FTPSiteNameTemp -Port $FTPPortTemp -PhysicalPath $FTPRootDirTemp

            #Configure Basic Authentication for site
            $FTPSitePath = "IIS:\Sites\$FTPSiteNameTemp"

            #IIS portion of system access
            if ($AuthTypes.count -ge "1")
                {
                Set-ItemProperty -path "$FTPSitePath" -name 'ftpServer.security.authentication.basicAuthentication.enabled' -value $True
                Set-ItemProperty -path "$FTPSitePath" -name 'ftpServer.directoryBrowse.showFlags' -value 4
                #Add an authorization read rule for FTP Users.
                    $Param = @{
                    Filter   = "/system.ftpServer/security/authorization"
                        Value    = @{
                        accessType  = "Allow"
                        roles       = "$FTPUserGroupName"
                        permissions = "1,2"
                        }
                    PSPath   = 'IIS:\'
                    Location = $FTPSiteNameTemp
                    }
                }
                Add-WebConfiguration @param

            #If you want to configure SSL policy from require to accept
            $SSLPolicy = @(
            'ftpServer.security.ssl.controlChannelPolicy',
            'ftpServer.security.ssl.dataChannelPolicy'
            )
            Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value $false
            Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[1] -Value $false
            $UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserGroupName")
            $AccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($UserAccount,
            'Modify',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
            )

            #if ftpgroup doesn't have any permissions, give them modify permissions
            $accesscheck = Get-Acl -Path $FTPRootDirTemp
            $UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserGroupName")
                if ($Accesscheck.AccessToString -inotlike "*$UserAccount*")
                    {
                    if ($accesscheck.Group -notcontains $UserAccount)
                        {
                        $AccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($UserAccount,
                        'Modify',
                        'ContainerInherit,ObjectInherit',
                        'None',
                        'Allow'
                        )

                        $ACL = Get-Acl -Path $FTPRootDirTemp
                        $ACL.SetAccessRule($AccessRule)
                        $ACL | Set-Acl -Path $FTPRootDirTemp
                        }
                    }
            Restart-WebItem "IIS:\Sites\$FTPSiteNameTemp" -Verbose
                }
            }
