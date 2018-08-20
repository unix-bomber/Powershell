#Reference https://4sysops.com/archives/install-and-configure-an-ftp-server-with-powershell/

Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
Install-WindowsFeature Web-Server -IncludeAllSubFeature  IncludeManagementTools

Import-Module WebAdministration

#These configure websites. You must have the same number of variables for all three of these variables (I.E. if you need 3 sites, there should be three FTPSiteNames, FTPRootDirs and FTPPorts)
$FTPSiteName = 'Default FTP Site'
$FTPRootDir = 'D:\FTPRoot'
$FTPPort = 21

#These configure FTP users. You must have the same number of variables for FTPUserName & Password (I.E. if you need 3 users, there should be three FTPUserNames and FTPPasswords)
$FTPUserName = "FTPUser"
$FTPPassword = 'P@ssword123'
$FTPUserGroupName = "FTP Users"
$JustUsers = "no" #This feature doesn't work yet. At a later date, this would allow you to only generate FTP users, if required

#Create multiple users, give password, give permissions
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
            
            #Create group
            $ADSI = [ADSI]"WinNT://$env:ComputerName"
            $FTPUserGroup = $ADSI.Create("Group", "$FTPUserGroupName")
            $FTPUserGroup.SetInfo()
            $FTPUserGroup.Description = "Members of this group can connect through FTP"
            $FTPUserGroup.SetInfo()
            
            #Add user to group
            $UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserNameTemp")
            $SID = $UserAccount.Translate([System.Security.Principal.SecurityIdentifier])
            $Group = [ADSI]"WinNT://$env:ComputerName/$FTPUserGroupName,Group"
            $User = [ADSI]"WinNT://$SID"
            $Group.Add($User.Path)
            }
}

#Create multiple sites
For ($i=0; $i -lt $FTPSiteName.count; $i++) {
        if (!(Get-Item $FTPRootDir[$i] -ErrorAction SilentlyContinue))
            {
	        $FTPRootDirTemp = $FTPRootDir[$i]
	        $FTPPortTemp = $FTPPort[$i]
	        $FTPSiteNameTemp = $FTPSiteName[$i]            

	        New-Item -Path $FTPRootDirTemp -ItemType Folder
            New-WebFtpSite -Name $FTPSiteNameTemp -Port $FTPPortTemp -PhysicalPath $FTPRootDirTemp
            
            #Configure Basic Authentication for site
            $FTPSitePath = "IIS:\Sites\$FTPSiteNameTemp"
            $BasicAuth = 'ftpServer.security.authentication.basicAuthentication.enabled'
            Set-ItemProperty -Path $FTPSitePath -Name $BasicAuth -Value $True
            
            # Add an authorization read rule for FTP Users.
                $Param = @{
                Filter   = "/system.ftpServer/security/authorization"
                    Value    = @{
                    accessType  = "Allow"
                    roles       = "$FTPUserGroupName"
                    permissions = 1
                    }
                PSPath   = 'IIS:\'
                Location = $FTPSiteNameTemp
                }

            Add-WebConfiguration @param
            
            #Configure SSL policy from require to accept... if you're using regular FTP you're wrong...
            <#
            $SSLPolicy = @(
            'ftpServer.security.ssl.controlChannelPolicy',
            'ftpServer.security.ssl.dataChannelPolicy'
            )
            Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[0] -Value $false
            Set-ItemProperty -Path $FTPSitePath -Name $SSLPolicy[1] -Value $false
            $UserAccount = New-Object System.Security.Principal.NTAccount("$FTPUserGroupName")
            $AccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($UserAccount,
            'ReadAndExecute',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
            )
            $ACL = Get-Acl -Path $FTPRootDir
            $ACL.SetAccessRule($AccessRule)
            $ACL | Set-Acl -Path $FTPRootDir
            #>

            Restart-WebItem "IIS:\Sites\$FTPSiteNameTemp" -Verbose
            }
}