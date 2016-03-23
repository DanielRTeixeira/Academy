#Install .Net 3.5

Install-WindowsFeature Net-Framework-Core

#Setup SNMP

Import-Module ServerManager
Get-WindowsFeature -name SNMP* | Add-WindowsFeature -IncludeManagementTools
REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities /v public /t REG_DWORD /d 8 /f
REG DELETE HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers\ /f

#Setup FTP Server

Add-WindowsFeature Web-FTP-Server

Import-Module WebAdministration

New-WebFtpSite -Name "Default FTP Site" -Port "21"
cmd /c \Windows\System32\inetsrv\appcmd set SITE "Default FTP Site" "-virtualDirectoryDefaults.physicalPath:C:\"
Set-ItemProperty "IIS:\Sites\Default Ftp Site" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
Set-ItemProperty "IIS:\Sites\Default Ftp Site"-Name ftpServer.security.ssl.controlChannelPolicy -Value 0
Set-ItemProperty "IIS:\Sites\Default Ftp Site" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0
Add-WebConfiguration "/system.ftpServer/security/authorization" -value @{accessType="Allow";roles="";permissions="Read,Write";users="*"} -PSPath IIS:\ -location "Default Ftp Site"
Restart-WebItem "IIS:\Sites\Default FTP Site"


#Enable RDP

set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 0


#Setup Users

Import-Module ActiveDirectory

NEW-ADUSER Bob -AccountPassword (ConvertTo-SecureString "P4ssw0rd" -AsPlainText -force) -enabled $true 
NEW-ADUSER John -AccountPassword (ConvertTo-SecureString "C0mput3r" -AsPlainText -force) -enabled $true 
Add-ADGroupMember "Domain Admins" Bob
