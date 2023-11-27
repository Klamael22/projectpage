---
title: "TryHackMe - Agent T"
categories:
  - Blog
tags:
  - TryHackMe
  - CTF
  - Training
---

This is a write-up for the [Agent T](https://tryhackme.com/room/agentt) room on [TryHackMe](https://tryhackme.com/). 

For additional learning and practice, I will map my process to the Cyber Kill Chain.

Scenario:
```
Agent T uncovered this website, which looks innocent enough, but something seems off about how the server responds...

After deploying the vulnerable machine attached to this task, please wait a couple of minutes for it to respond.
```

# Reconnaissance
First, I ran nmap on the target IP to see what ports and services are in use:
- `$ nmap -sV -sC <TARGET IP>`
    - `80-http`

This tells me the target is most likely a web server. I navigated to the target IP in a browser to see what is being served.

With the scenario in mind, I opened Burp Suite's Intercept, and enabled the the Firefox extension to catch the requests and responses to the server.

Upon accessing the site, I instructed Intercept to catch the response:
- Action > Do Intercept > Response to this request
- Then Forward the request.

When the response was captured, I inspected it for interesting information. I quickly noticed that the response included the version of PHP that the web server is using:
`X-Powered-By: PHP/8.1.0-dev`

# Weaponization
A quick search using `searchsploit` proved fruitful:
- `$ searchsploit php 8.1.0 dev`
    - `PHP 8.1.0-dev - 'User-Agentt' Remote CodeExecution | php/webapps/49933.py`

I used `cat` to read the script and determine how this exploit works. You can examine it yourself [here](https://www.exploit-db.com/exploits/49933).

The script exploits a vulnerability that was introduced to the PHP source code after a git.php.net server was compromised. Essentially, the attackers added code to execute arbitrary commands if the user agent making the request to the web server begins with `zerodium`. Read more about it [here](https://www.techzine.eu/news/devops/57715/hackers-added-backdoor-to-php-source-code/)

# Delivery
The method of delivery for this exploit is through an HTTP request. Simply running the script and providing the target URL will begin this process:
`$ python3 /usr/share/exploitdb/exploits/php/webapps/49933.py`

# Exploitation
When the web server receives the HTTP request with a user-agent header beginning with `zerdium`, a shell is provided to the attacker, allowing for arbitrary command execution.

Once the payload has executed, I verified the username I have access as:
- `$ whoami`
    - `root`

# Installation
Given the scope of this excercise, installation of a persistence mechanism is not necessary.

# Command and Control
Again, this phase is outside the scope of this CTF. 

# Action on Objectives
With access to the host, as `root` no less, I can now realize my objective of exfiltrating the flag. 

Because I am targeting one specific file on the system, I will start by issueing a `find` command to attempt to locate it:
`find / -name "*flag*"`

This reveals the file `/flag.txt`

I used `cat /flag.txt` to obtain the flag string, and complete the CTF.

# Conclussion
This was a quick CTF. I think the scenario given exposed the solution too easily. However, I believe the goal of this excercise - researching and executing a known vulnerability - was achieved. 