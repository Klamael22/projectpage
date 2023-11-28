
# Setting up Active Directory
Before installing any clients, let's install AD and setup a domain for them to join. In the past I have install ADDS through the Server Manager interface, but have opted to try installing with Powershell this time.

## Rename Computer
First, I will rename to computer to something more logical:
Settings > System > About:
- Rename this PC
- Enter name: DOMCON

## Setting Static IP
First I'll set a static IP for Windows Server.
- `> Get-NetIPInterface`
	- `ifIndex: 14`
- `> Set-NetIPAddress -InterfaceIndex 6 -IPAddress 10.0.0.2 -PrefixLength 26`

## Installing Active Directory Domain Services
- `> Add-WindowsFeature AD-Domain-Services`

## Create a new AD forest and domain,  Install DNS, and promote to Domain Controller
- `Install-ADDSForest -DomainName someorg.local -InstallDNS`
- Enter `SafeModeAdministratorPassword`
- Type `A` to configure this server as a domain controller and restart when complete.

## Install AD Users and Computers
`> Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`

