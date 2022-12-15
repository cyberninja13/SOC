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
* [TCP Three Way Handshake](#Handshake)
* [CIA](#CIA)
* [Threat-Vulnerability-Risk](#Threat-Vulnerability-Risk)
* [SOC](#SOC)
* [L1-L2](#L1-L2)
* [False Positive](#False-Positive)
* [False Negative](#False-Negative)
* [Risk Assessment](#Risk-Assessment)
* [Vulnerability Assessment](#Vulnerability-Assessment)


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


## Handshake
The TCP three-way handshake is the method used in a TCP/IP network to create a connection between a local host, client and server. 
It is a three-step method that requires both the client and server to exchange SYN and ACK packets before actual data communication begins.

## CIA
confidentiality, integrity and availability, also known as the CIA triad, is a model designed to guide policies for information security within an organization

Confidentiality -- ensuring that only authorized parties can read a message

Integrity -- ensuring that any changes to data will be detected and rejected

Availability --  ensuring that data should be available to authorized users whenever they require it. 
This means keeping systems, networks, and devices up and running.

## Threat-Vulnerability-Risk
Threat: is Someone with the potential to cause harm by damaging or destroying the official data to a system or organization

Vulnerability: It refers to weaknesses in a system that makes threat outcomes more possible and even more dangerous

Risk: It refers to a combination of threat probability and impact/loss. In simple terms, it is related to potential damage or loss when threat exploits the vulnerability

## SOC
SOC stand for Security Operation Center and they are responsible for monitoring, detection, analysis, response, to any activities

## L1-L2

L1 Monitors SIEM alerts, manages and configures security monitoring tools. Prioritizes and triages alerts or issues to determine whether real security incident is taking place.

L2 Receives incidents and performs deep analysis; correlates with threat intelligence to identify the threat actor

## False-Positive
When the device generated an alert for an intrusion that has actually not happened

## False-Negative
if the device has not generated any alert and the intrusion has actually happened, this is the case of a false negative.

## Risk-Assessment 
refers to detecting the information assets that are prone to cyber-attacks (including customer data, hardware, laptop,) and evaluates various risks that could affect those assets

## Vulnerability-Assessment 
is to Identify security weaknesses in your IT infrastructure
prioritize the vulnerabilities in computer systems, network, applications. and gives the organization with the required information to fix the flaws.

