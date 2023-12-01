---
title: "Homelab Project: Active Directory Setup"
categories:
  - Blog
tags:
  - Homelab
  - Proxmox
  - Active Directory
toc: true
toc_label: Table of Contents
toc_sticky: true
---

Now that all VMs are created, and before installing Windows 10 on any clients, let's install AD and setup a domain for them to join. In the past I have install ADDS through the Server Manager interface, but have opted to try installing with Powershell this time.

# Before Installing Active Directory
## Rename Computer
First, I will rename to computer to something more logical:
Settings > System > About:
- Rename this PC
- Enter name: DOMCON

Restart the computer when prompted.

## Setting A Static IP
Now let's configure the network settings on this machine:
- Navigate to Settings > Network & Internet > Change Adapter Options 
- Right-click Ethernet Network adapter > Properties
- Select Internet Protocol Version 4 (TCP/IPv4)
- Click "Use the following IP address:"
	- IP address: 10.0.0.2
	- Subnet mask: 255.255.255.192
	- Default gateway: 10.0.0.1

Now I will proceed with the installation and configuration of Active Directory.

# Installing Active Directory Domain Services
- Open Server Manager and click Manage > Add Roles and Features
- Select "Role-based or feature-based installation"
- Select "Active Directory Domain Services"
- Make sure Group Policy Management, Active Directory module for Windows PowerShell, Active Directory Administrative Center, and AD DS Snap-ins and Command-Line Tools are installed

## Promoting to Domain Controller and Creating a new forest
- In Server Manager, click on the flag in the top right corner, and click "Promote this server to a domain controller
- Select "Add a new forest"
- Name the domain: someorg.local
- Click through the rest of the process and restart when prompted to

# Configuring Active Directory
## Creating Groups OU
- Open Active Directory Users and Computers
	- Right-click `someorg.local` > New > Organizatioinal Units
		- Name: Groups
	- Next I moved all users, except for `Administrator` and `Guest` from the `Users` directory to the `Groups` directory.

## Creating Users
I will be adding two accounts, one as a member of the "Domain Users" group, and the other will be in the "Domain Admins" group.
- Under the `Users` directory.
	- Right-click > New > User:
		- Name: Ben Horne
		- User logon name: b.horne
		- Password: *******
	- Repeat these steps, for the Domain Admin:
		- Name: Dale Cooper
		- User logon name: d.cooper
		- Password: *******

### Adding User to Domain Admin Group
- Right-click the user Dale Cooper
- Click Member Of tab > Add
- Type "Domain Admins" > OK

## Adding Computers
Now, switch to the Computers directory. 
- Right-click in the right panel > New > Computer
- Computer name: BHORNE-PC

Then repeat this process to create a computer named: DCOOPER-PC

# Windows 10 Client Setup
On the Windows 10 clients select time-zone and keyboard layout. At the "Sign in with Microsoft" screen, click "Domain join instead" in  the bottom left corner, enter a username and password for the local account and proceed.

## Joining the domain
After the setup is complete navigate to:
- Settings > Network & Internet > Change adapter options. 
- Right-click on Ethernet network > Properties
- Internet Protocol Version 4 (TCP/IPv4)
- Set the DNS server to the domain controller's IP address: 10.0.0.2

Now navigate to Settings > System > About > Rename this PC (advanced)

Click "Change" to rename this computer or change its domain or workgroup. Name the computer "BHORNE-PC," then select "Domain" under the "Member of" section. Enter the domain name "someorg.local" and click OK.

Enter the username created in AD, "b.horne," and its password. Then restart the computer when prompted.

Now that the user Ben Horne is joined, repeat these steps for the user Dale Cooper.

## Installing AD Users and Groups on Domain Admin
Realistically, administering Active Directory should not be done from the domain controller, so I will install AD Users and Groups on the domain admin account.
- Navigate to Settings > Apps & features > Optional features.
- Add a feature
- Check RSAT: Active Directory Domain Services and Lightweight Directory Services
- Install

## Installing PuTTY on WinAdmin
As I have plans to expand this homelab, I imagine I will need an SSH client at some point. PuTTY is the SSH client for Windows that I am most familiar with.

Download and install from here:
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html

# Conclusion
Now I have a basic Active Directory domain with two clients. 