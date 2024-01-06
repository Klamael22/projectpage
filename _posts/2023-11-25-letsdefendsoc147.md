---
title: "Letsdefend - SOC147 - SSH Scan Activity"
categories:
  - Blog
tags:
  - Letsdefend
  - SOC
toc: true
toc_sticky: true
---

This is a walkthrough of "SOC147 - SSH Scan Activity" from [letsdefend.io](https://letsdefend.io/).

```
EventID: 94
Event Time: Jun, 13, 2021, 04:23 PM
Rule: SOC147 - SSH Scan Activity
Level: Security Analyst
Source Address: 172.16.20.5
Source Hostname: PentestMachine
File Name: nmap
File Hash: 3361bf0051cc657ba90b46be53fe5b36
File Size: 2.82 MB
Device Action: Allowed
```
First, I took ownership of the alert and opened a case.

I verified the file identified as nmap, via its file hash (`3361bf0051cc657ba90b46be53fe5b36`). I searched [VIRUSTOTAL](https://virustotal.com/), and confirmed the file is indeed nmap, and not malware.

# Investigation Outline:
## Log Management
- Beginning on June 13, 2021 at 4:23 PM, PentestMachine at IP 172.16.20.5 made connections to several clients over port 22.
	- 172.16.20.6
	- 172.16.20.4
	- 172.16.20.3
	- 172.16.20.2
	- 172.16.20.1

## Endpoint Security
- PentestMachin:
	- Terminal History: PentestMachine appears to be running a ping sweep of the /24 subnet, for the purpose of host discovery.
		- `nmap -sV -sP 172.16.20.0/24`
			- `-sV` option for version detection.
			- `-sP` option performs a ping scan.
- Hosts Identified:
	- SQLServer (172.16.20.6)
	- gitServer (172.16.20.4)
	- Exchange Server (172.16.20.3)
	- N/A (172.16.20.2)
	- N/A (172.16.20.1)

## Email Security
At this point, it finally occured to me that the hostname performing these scans is `PentestMachine`. I decided to check for any email correspondence indicating any known scanning activity or engagements. I found an email sent on June 11, 2021 from user Ellie, informing the SOC of planned network scanning on June 13. 2021, after 12:00.

# Closing Case
- Start Playbook
    - Define Threat Indicator: Other
    - Check if the malware is quarantined/cleaned: Not Quarantined
    - Analyze Malware: Non-malicious
- Close case
    - False Positive

# Conclusion
This was a quick investigation, and probably could have been a lot quicker had I connected the dots about it possibly being an internal engagement. 

After checking the results under Closed Alerts, it appears that I actually lost points for assessing nmap as non-malicious. I don't necessarily agree with this, as nmap is not inherently malicious, but I do understand that it can and often is used for malicious purposes.

This was my first activity on [letsdefend.io](https://letsdefend.io/), and I must say I enjoyed it. I look forward to using this platform more!