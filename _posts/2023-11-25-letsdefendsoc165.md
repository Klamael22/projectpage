---
title: "Letsdefend - SOC165 - Possible SQL Injection Payload"
categories:
  - Blog
tags:
  - Letsdefend
  - SOC
toc: true
toc_sticky: true
---

This is a walkthrough of "SOC165 - Possible SQL Injection Payload Detected" from [letsdefend.io](https://letsdefend.io/).

```
EventID: 115
Event Time: Feb, 25, 2022, 11:34 AM
Rule: SOC165 - Possible SQL Injection Payload Detected
Level: Security Analyst
Hostname: WebServer1001
Destination IP Address: 172.16.17.18
Source IP Address: 167.99.169.17
HTTP Request Method: GET
Requested URL: https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
Alert Trigger Reason: Requested URL Contains OR 1 = 1
Device Action: Allowed
```
First, I took ownership of the alert, and opened a case.

I began by doing some research on the attcker's IP address (`167.99.169.17`).

I searched on [who.is](who.is) for the IP. This revealed that the requests are coming from an IP owned by Digital Ocean. This is a cloud provider, meaning that the attacker is most likely using this IP to launch their attacks in hopes of masking their identity.

Next, I searched for the IP address on [VIRUSTOTAL](https://virustotal.com). The results show that 5 security vendors flagged this IP address as malicious.

# Investigation Outline:
## Log Management
First I checked the Log Management interface. I filtered the logs by the source IP (`167.99.169.17`). The attacker made a total of 6 requests to the target (`https://172.16.17.18/`). After the initial request to the target, the attacker made 5 requests with URL encoded payloads. I used cyberchef to decode the requests. 

### Sequence of events
- The attacker first accessed the target (`https://172.16.17.18/`) at 11:30 AM. 
- Next, at 11:32 AM the attacker tried two basic SQLi payloads
	- First, to check if the web app may be vulnerable, the attacker requested:
		- `https://172.16.17.18/search/?q=%27`
			- Decoded: `https://172.16.17.18/search/?q='`
            - HTTP Response Size: 948
			- HTTP Response Status: 500
				- To the attacker this confirms that the web app is most likely vulnerable to SQLi as the addition of a single quote appears to have broken the query syntax.
		- `https://172.16.17.18/search/?q=%27%20OR%20%271`
			- Decoded: `https://172.16.17.18/search/?q=' OR '1`
            - HTTP Response Size: 948
			- HTTP Response Status: 500
				- I believe the attacker is trying to figure out the structure of the underlying query. This request also produced a 500 Status Code, meaning the query syntax was broken by this query as well.
- At 11:33 AM the attacker made two requests, changing the payload to include an always true query, followed by an `ORDER BY` query:
	- `https://172.16.17.18/search/?q=%27%20OR%20%27x%27%3D%27x`
		- Decoded: ` https://172.16.17.18/search/?q=' OR 'x'='x`
        - HTTP Response Size: 948
		- HTTP Response Status: 500
			- The attacker again received a 500 Status Code.
	- `https://172.16.17.18/search/?q=1%27%20ORDER%20BY%203--%2B`
		- Decoded: `https://172.16.17.18/search/?q=1' ORDER BY 3--+`
        - HTTP Response Size: 948
		- HTTP Response Status: 500
- At 11:34 the attacker makes their final request to the target.
	- `https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-`
		- Decoded: `https://172.16.17.18/search/?q=" OR 1 = 1 -- -`
        - HTTP Response Size: 948
		- HTTP Response Code: 500
			- The attacker again changes up their payload, this time using a double quote (`"`) followed by an always true query, `1 = 1`

## Endpoint Security
I searched by the target IP (`172.16.17.18`) but was not able to gather any additional data from here. There were no pertinent network traffic or commands executed found.

I also searched for the attacker IP, but nothing was found, confirming the attacker is outside of the organization.

## Email Security
To confirm that this was not a planned engagement, checked for any emails that may indicate this. These searches yielded no results, though.

# Closing Case
- Start Playbook
	- Traffic marked as malicious
	- Attack Type: SQL injection
	- Not Planned
	- Direction of traffic: Internet -> Company Network
	- Attack was Unsuccessful
	- Do not escalate to Tier 2
- Close case:
	- True Positive

# Conclusion
After analyzing the firewall logs, I determined this was an attempted SQL injection attack. It does not appear that the attack was successful, as every payload returned a response code of 500, and every response size was 948. The response size is an important data point, as any variance in this could point to insecure error handling by the web server.

All in all another great excercise by [letsdefend.io](https://letsdefend.io/). I'm really enjoying this platform for understanding incident investigation in a practical, more realistic, way.