## Table of contents
* [Cybersecurity](#Cybersecurity)
* [Firewall](#Firewall)
* [VPN](#VPN)
* [Proxy](#Proxy)
* [DHCP](#DHCP)
* [DMZ](#DMZ )
* [DNS](#DNS )
* [WAF](#WAF)
* [IDS-IPS](#IDS-IPS)
* [HIDS-NIDS](#HIDS-NIDS)
* [Firewall-Deny-and-Drop](#Firewall-Deny-and-Drop)
* [TCP and UDP](#TCP-UDP)
* [TCP Three Way Handshake](#Handshake)
* [CIA](#CIA)
* [Encryption](#Encryption)
* [Hashing](#Hashing)
* [Threat-Vulnerability-Risk](#Threat-Vulnerability-Risk)
* [SIEM](#SIEM)
* [SOC](#SOC)
* [L1-L2](#L1-L2)
* [False Positive](#False-Positive)
* [False Negative](#False-Negative)
* [SOC Runbook](#Runbook)
* [Cyber Kill Chain](#Cyber-Kill-Chain)
* [Risk Assessment](#Risk-Assessment)
* [Vulnerability Assessment](#Vulnerability-Assessment)
* [ARP](#ARP)
* [RDP](#RDP)
* [SQL](#SQL)
* [XSS](#XSS)
* [RFI](#RFI)
* [LFI](#LFI)
* [CSRF](#CSRF)
* [IDOR](#IDOR)
* [Buffer overflow](#Buffer-overflow)
* [Login-in-Windows](#Login-in-windows)
* [Malicious Behavior](#Malicious-Behavior)
* [Signature-Behavioural](#Signature-Behavioural)
* [Incident response](#Incident-response)
* [Ports](#Ports)
* [What can you offer to customer](#Offer-Customer)

## Cybersecurity
Cybersecurity is the protection of internet-connected systems, including hardware, software and data from cyberattacks to prevent unauthorized access to data
The goal of cybersecurity is to limit risk and protect IT assets from attackers with malicious intent.  maintain the confidentiality, integrity and availability (CIA) of data

## Firewall
firewall is a device that allows or blocks traffic as per the defined set of rules. These are placed on the boundary of trusted and untrusted networks.
So firewall purpose is to create safety barriers between private networks and public internet

## VPN
A VPN secures the private network, using encryption and other security mechanisms to ensure that only authorized users can access the network and that the data cannot be intercepted.      
VPN: not only hide your IP address but encrypt the date that being transferred over the internet
	
## Proxy
Proxy is server that retrieves date out on the internet, such as a web page on behalf of the user
For example: The proxy server receives the request from your computer and will directly retrieve the web page on your behalf and then send it to your computer

## DHCP
is a network management protocol that is used to dynamically assigns an IP address configuration
to each host on the network so that they can communicate efficiently


## DMZ 
DMZ is used to improve the security of an organizations network by segregating devices such as computers and servers on the opposite of the firewall
So when people access these servers they are not going to be accessing them behind the company firewall

## DNS 
stand for domain name system and DNS resolve names to numbers, to be more specific it resolves domain names to IP address

1. The pc will check for the website in the hosts file.
2. If it’s not existed in hosts file. It will check the browser cache.
3. If it's not existed in the browser cache. It will query the DNS server.
4. If it's not existed in the DNS server. The DNS server will query the parent DNS server 


## WAF 
WAF stands for web application firewall. It is used to protect the application by filtering legitimate traffic from malicious traffic.
WAF can be either a box type or cloud-based.
It typically protects web applications from attacks such as cross-site forgery, cross-site-scripting (XSS), file inclusion, and SQL injection


## IDS-IPS
IDS is an intrusion detection system whereas an IPS is an intrusion prevention system,
the key deference here is one is detecting, while the other is preventing, 
so one is aware of the problem, and the other one is stopping the problem


## HIDS-NIDS
HIDS: HIDS means Host Intrusion Detection System. HIDS is located on each host.
NIDS: NIDS means Network Intrusion Detection System. NIDS is located in the network.

## Firewall-Deny-and-Drop

DENY RULE: If the firewall is set to deny rule, it will block the connection and send a reset packet back to the requester.
The requester will know that the firewall is deployed.

DROP RULE: If the firewall is set to drop rule, it will block the connection request 
without notifying the requester.

It is best to set the firewall to deny the outgoing traffic and drop the incoming traffic so that attacker will not know whether the firewall is deployed or not.

## TCP-UDP
TCP is a connection-oriented protocol. - UDP is a datagram oriented protocol.
TCP is reliable - UDP is not reliable
TCP is slower - UDP IS faster than TCP

Example: HTTP, SSH, HTTPS, SMTP -   Example: VoIP, online multiplayer games


## Handshake
The TCP three-way handshake is the method used in a TCP/IP network to create a connection between a local host, client and server. 
It is a three-step method that requires both the client and server to exchange SYN and ACK packets before actual data communication begins.

## CIA
confidentiality, integrity and availability, also known as the CIA triad, is a model designed to guide policies for information security within an organization

Confidentiality -- ensuring that only authorized parties can read a message

Integrity -- ensuring that any changes to data will be detected and rejected

Availability --  ensuring that data should be available to authorized users whenever they require it. 
This means keeping systems, networks, and devices up and running.

## Encryption
Encryption is the process of converting a normal readable message known as plaintext into unreadable message
known as Cipher text. The cipher text obtained from the encryption can easily be transformed into plaintext using the encryption key. 

## Hashing
Hashing is the process of converting the information into a key using a hash function.
The original information cannot be retrieved from the hash key by any means. 

## Threat-Vulnerability-Risk
Threat: is Someone with the potential to cause harm by damaging or destroying the official data to a system or organization

Vulnerability: It refers to weaknesses in a system that makes threat outcomes more possible and even more dangerous

Risk: It refers to a combination of threat probability and impact/loss. In simple terms, it is related to potential damage or loss when threat exploits the vulnerability

## SIEM
SIEM software works by collecting log and event data generated by an organizations 
application, security devices and host systems and bringing it together into a single centralized 
platform to search in them. For example, Splunk and Qradar.

## SOC
SOC stand for Security Operation Center and they are responsible for monitoring, detection, analysis, response, to any activities

## L1-L2

L1 Monitors SIEM alerts, manages and configures security monitoring tools. Prioritizes and triages alerts or issues to determine whether real security incident is taking place.

L2 Receives incidents and performs deep analysis; correlates with threat intelligence to identify the threat actor

## False-Positive
When the device generated an alert for an intrusion that has actually not happened

## False-Negative
if the device has not generated any alert and the intrusion has actually happened, this is the case of a false negative.

## Runbook
A run book in SOC is a set of conditional procedures that are used to automatically perform actions,
including data enrichment, threat containment, and notification as part of the incident response or security operations process.

## Cyber-Kill-Chain
The cyber kill chain is a series of steps that trace stages of a cyberattack from the early reconnaissance stages to the exfiltration of data.

## Risk-Assessment 
refers to detecting the information assets that are prone to cyber-attacks (including customer data, hardware, laptop,) and evaluates various risks that could affect those assets

## Vulnerability-Assessment 
is to Identify security weaknesses in your IT infrastructure
prioritize the vulnerabilities in computer systems, network, applications. and gives the organization with the required information to fix the flaws.


## ARP
The Address Resolution Protocol (ARP) is a communication protocol used for discovering
the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address

## RDP
Remote desktop protocol (RDP) is a secure network communications protocol developed by Microsoft.
It enables network administrators to remotely control users

## SQL
SQL injection is a famous vulnerability in the web application that allows Hackers to inject
malicious code input into the SQL statement to compromise the SQL database. 

SQL Prevent it?
Using parameterized queries
Validating the inputs
Deploying a web application firewall


## XSS
Cross-site scripting attack, the attacker executes the malicious scripts on a web page 
and can steal the user’s sensitive information. With XSS vulnerability, the attacker can inject Trojan, 
read out user information, and perform specific actions such as the website’s defacement.

XSS Prevent it?
Encoding the output
Applying filters at the point where input is received
Deploying a web application firewall

## RFI
Remote File Inclusion (RFI), is the security vulnerability that occurs when a file on 
different server is included without sanitizing the data obtained from a user.


## LFI
Local File Inclusion (LFI), is the security vulnerability that occurs when 
local file is included without sanitizing the data obtained from a user.

## CSRF
Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted 
actions on a web application in which they’re currently authenticated. With a little help of social engineering

## IDOR
IDOR is a vulnerability caused by the lack of an authorization mechanism or because it is not used properly. 
It enables a person to access an object that belongs to another.


##  Buffer-overflow
A buffer overflow occurs when a program or process attempts to write more data to a fixed-length block of memory,
or buffer, than the buffer is allocated to ...


## Login-in-windows
Application events (ex. any running application)
• System events (ex. Load a driver)
• Security events (ex. Failed and success login)
• Sysmon and PowerShell logs we can enable them.

Success login through event ID 4624 
Failed login through event ID 4625

 Sysmon logs

• Event id 1→for process creation
• Event id 3→for network connection
• Event id 7→image loaded
• Event id 11→file creation

## Malicious-Behavior
• RDP or SSH sessions during non-working hours.
• DNS queries to IP addresses.
• Process creation (Sysmon event id 1)
• Scheduled tasks (event id 4698 in windows & crontabs in Linux)
• Remote login with admin & root accounts. (they should login remotely by normal account 
 then they switch to admin or root accounts if needed)

## Signature-Behavioural
Signature based will compare the signature to a list of signatures and if there is a match it will 
be blocked, also it's called static analysis. 

Behavioural based will run the code or program in isolated environment and monitor the 
behavior for suspicious behavior (ex. The chrome browser will try to access the CMD). Also it's
called dynamic analysis or sandboxing.


## Incident-response
Preparation: means prepare the infrastructure to handle incidents by placing all security 
controls (ips, ids, firewall) and create process and procedures to handle incidents.

• Detection & Analysis: analyze the incidents and make sure it is not a false positive. What are 
the signs of incidents and sources of indicators(alert,logs,pepole), and incident documentation.

• Containment &Recovery: contain the incidents from spreading or increasing damage. An 
essential part of containment is decision-making (e.g., shut down a system, disconnect it from a 
network, disable certain functions).

• Post-Incident Activity: learning and improving phase. To learn about the incident and modify 
our security controls (ips, ids, firewall) to prevent it in future.

## Ports
20	File Transfer Protocol (FTP) Data Transfer
21	File Transfer Protocol (FTP) Command Control
22	Secure Shell (SSH)
23	Telnet - Remote login service, unencrypted text messages
25	Simple Mail Transfer Protocol (SMTP) E-mail Routing
53	Domain Name System (DNS) service
80	Hypertext Transfer Protocol (HTTP) used in World Wide Web
110	Post Office Protocol (POP3) used by e-mail clients to retrieve e-mail from a server
119	Network News Transfer Protocol (NNTP)
123	Network Time Protocol (NTP)
143	Internet Message Access Protocol (IMAP) Management of Digital Mail
161	Simple Network Management Protocol (SNMP)
194	Internet Relay Chat (IRC)
443	HTTP Secure (HTTPS) HTTP over TLS/SSL


## Offer-Customer
ensure and manage to keep your business safe from any cyber security attack by real-time monitoring
and will protect your assets your date your software and hardware and prevent and mitigate any risk 
