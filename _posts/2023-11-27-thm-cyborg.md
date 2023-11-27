---
title: "TryHackMe - Cyborg"
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

This is a write-up for the [Cyborg](https://tryhackme.com/room/cyborgt8) room on [TryHackMe](https://tryhackme.com/). 

In addition to solving this CTF and providing my methodology, I will also use MITRE ATT&CK to map the attack.

# Reconnaissance
After deploying the machine, I began the process of information gathering with an `nmap` scan:
- `$ nmap -A <TARGET IP>`
    - `22-ssh`
    - `80-http`

Seeing that the `http` service is running, I navigated to the target IP in a browser. This yielded the Apache2 Ubuntu default page.

Next, I chose to run `feroxbuster` against the web server to see if there are any other pages or directories to view. This revealed two interesting directories:
- `$ feroxbuster -u http://10.10.28.207 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt`
    - `/admin`
    - `/etc/squid`

I navigated to `/admin` and walked through this page. My first finding, under the "Admins" section, is a conversation between users. The final comment from Alex reveals information regarding a squid proxy they are using, as well as a backup named "music_archive.

Next, I clicked the "Archive" drop-down button, then "Download", and downloaded `archive.tar`.

In order to view the contents of this archive, I used the `tar` command:

`tar -xf archive.tar`

This reveals a series of nested directories, leading to `/final_directory`, which contains a `README` file. I used `cat` to read `README`, which revealed that this is a Borg Backup repository.

At this point I downloaded Borg Backup Tool and read through the `man` page.

It appears the pertinent functions to this task will be `list`, to list the available archives, and `extract` to extract them. However, after running `borg list final_archive`, I was prompted for a password, which I do not have, yet.

At this point I turned back to the web server, this time navigating to `/etc/squid`. This directory yielded a `passwd` file and a `squid.conf` file. I downloaded both of these files.

Using `cat` to view the contents of `passwd` I found:

`music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.`

Before attempting to crack this hash, I used [hashcat's example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes), and found this to be:

`hashcat type 1600-Apache $apr1$ MD5, md5apr1, MD5 (APR)`

Next, I copied just the hash into a new text file I named `hash.txt`, and ran:

 `$ hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt`

This returned the password: `squidward`.

After obtaining the password, I tried using it with the Borg Backup:
- `$ borg list final_archive`
    - `music_archive                        Tue, 2020-12-29 09:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]`
Now I have the archive's name. I used `borg extract` to extract it:
- `$ borg extract final_archive`.

This extracted archive appears to be a `/home` directory for a user named "Alex." I examined the directories and came across: `/home/Alex/Documents/note.txt`

I used `cat` to read the contents of this file, and found `alex:S3cretP@s3`.

# Initial Access
With these credentials in hand I pivoted to the machine's `ssh` port:

`$ ssh alex@<TARGET IP>`

After entering the password that was found, I was granted access. I ran `whoami` and confirmed I am logged in as "Alex."

First I listed the contents of the home directory:

`$ ls -la`

This revealed the first flag: `user.txt`. I used `cat` to read the flag.

# Privilege Escalation
First, to check for any files Alex may have `sudo` privileges for, I ran the following command:

`$ sudo -l`

This revealed:

`(ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh`

This tells me that I have `sudo` privilege for running this shell script without needing to enter a password. I was able to use `cat` on this file to view the script. The script seems to be for backing up `mp3` files found on the system. 

I used `nano` to edit the script, and simply changed the first line to `sudo bash`. After saving and closing the file, I ran the following command:

`$ sudo ./etc/mp3backups/backup.sh`

After this I ran:
- `$ whoami`
    - `root`

For the final flag, I navigated to the `/root` directory using, and used `cat` to view the flag in `root.txt`.

# MITRE ATT&CK
I created the following layer in MITRE ATT&CK Navigator:
<a href="/projectpage/assets/images/cyborg-nav-layer.png"><img src="/projectpage/assets/images/cyborg-nav-layer.png"></a>

## Breakdown of Tactics and Techniques
Reconnaissance and discovery was accomplished on the host using `nmap` and `feroxbuster`. Account discovery was performed by exploiting the public-facing application, and obtaining unsecured credentials via the `final_archive` file. From this, the attacker was able to comprimise the valid account of user "Alex." The attacker was then able to use the remote service `ssh` in order to acquire persistent access to the system. Finally, the attacker was able to escalate their privilege to the `root` user, by abusing the elevation control mechanism.

# Mitigations
As illustrated by the ATT&CK mapping, there wer many points at which security controls were either not implemented, or were misconfigured. 
From the outside-in: 
- Enumeration of the web application's directories via `feroxbuster`
  - Implementing a WAF would be able to deny requests made by suspicious user-agents.
- Lack of security controls in accessing `/admin`, which contains sensitive data.
  - Configuring a login page would prevent unauthorized access to the `/admin` page. 
- Weak encryption of credentials found in `final_archive`.
  - Implementing a stronger hashing algorythm than MD5, and a more complex password policy.
- Remote access over `ssh` with username and password.
  - Disabling password login, and implement public key authentication.
- Misconfigured elevation control mechanism.
  - Auditing the `sudo` privileges of all users, removing this permission from files and users that do not require it, or requiring a password if they do.

  # Conclusion

  This was an enjoyable challenge. Reflecting on the attack, from a defender's perspective, it is interesting to consider how the attack may have played out if even one or two of the suggested mitigations had been implemented. While it may be nearly impossible to ensure the attacker would not have eventually found their way in, this illuminates why the concept of defense-in-depth is so important.