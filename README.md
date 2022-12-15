## Table of contents
* [Firewall](#Firewall)
* [VPN](#VPN)
* [Proxy](#Proxy)
* [DHCP](#DHCP)
* [DMZ](#DMZ )
* [DNS](#DNS )
* [WAF](#WAF)
* [IDS-IPS](#IDS-IPS)
* [HIDS-NIDS](#HIDS-NIDS)
* [TCP Three-Way Handshake](#TCP Three-Way Handshake)

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


## TCP Three-Way Handshake
The TCP three-way handshake is the method used in a TCP/IP network to create a connection between a local host, client and server. 
It is a three-step method that requires both the client and server to exchange SYN and ACK packets before actual data communication begins.

