### Stateful vs. stateless firewalls

#### Stateless

Stateless firewalls watch network traffic, and restrict or block packets based on source and destination addresses or other static values. They are not "aware" of traffic patterns or data flows. A stateless firewall uses simple rule-sets that do not account for the possibility that a packet might be received by the firewall "pretending" to be something you asked for. 

#### Stateful

Stateful firewalls can watch traffic streams from end to end. They are are aware of communication paths and can implement various IP Security (IPsec) functions such as tunnels and encryption. In technical terms, this means that stateful firewalls can tell what stage a TCP connection is in (open, open sent, synchronized, synchronization acknowledge or established), it can tell if the MTU has changed, whether packets have fragmented etc.

Neither is really superior and there are good arguments for both types of firewalls. Stateless firewalls are typically faster and perform better under heavier traffic loads. Stateful firewalls are better at identifying unauthorized and forged communications.

### Rules based vs. policy based firewalls

#### Rules based firewalls

Rules based firewall systems use rules to control communication between hosts inside and outside the firewall. These rules are a single line of text information containing network addresses and virtual port numbers of services that are permitted or denied. These rules are stored together in one or more text files which are read when the firewall starts up. Rules based systems are static in that they cannot do anything they haven't been expressly configured to do. There must be a line in one of their configuration files somewhere that tells them exactly what to do with each packet that flows through the device. This makes the system more straight-forward to configure, but less flexible and less adaptive to changing circumstances.

#### Policy based firewalls

Policy-based systems are more flexible than rules based systems. They allow the administrator to define conditions under which general types of communication are permitted, as well as specifying what functions and services will be performed to provide that communication. A policy-based system can dynamically set up permitted communication to random IP addresses. Any system that supports IPsec Authentication Header and Encapsulating Security Payload is considered a policy based system.

### Packet filtering vs. packet inspecting firewalls

#### Packet filtering firewalls

Packet Filtering firewalls watch the following fields in an IP datagram it receives:

* Source IP address

* Destination IP address

* Source port number

* Destination port number

* Protocol type

Using these fields, the packet filtering firewall can either permit or drop the packet in either direction. Routers with access control lists can also perform packet filtering, however a purely packet filtering firewall cannot recognize dynamic connections such as that used by FTP.

#### Packet inspecting firewalls

Packet inspection involves opening IP packets, looking beyond the basic network protocol information such as source and destination IP address and other packet header information. Using TCP/IP as an example, a packet inspecting firewall can tell the difference between a web request (TCP port 80), a Telnet request (TCP port 23) and a DNS lookup (UDP port 53). It can tell the difference between the web request, and the web server's response and will only permit the proper response . "Deep" inspection firewalls can see the Web URL that is being retrieved and in some cases, can see the Java Applets, JavaScript and cookies contained within the web page. Such "deep inspection" firewalls can remove the offending Java Applets and block the cookies based on the URL of the web server delivering the page or other criterion.

### Stateful packet inspection

Stateful packet inspection requires keeping track of the state of the communications channel between the endpoints in the communication. The firewall monitors the IP, TCP and UDP header information passing between client and server. By monitoring this information, the firewall knows who inside the protected zone is opening connections and whom outside the firewall they are communicating with. Thus, any unsolicited connection request from outside or any random packet sent from outside will be recognized as not being part of any permitted or ongoing communications.

Stateful inspection firewalls can even permit return traffic from a server which is not explicitly permitted by the firewall's ruleset. Because the client protected by the firewall initiated the connection, the firewall can permit the return response from the server, even if no rule exists to explicitly permit this. For example, smart stateful packet inspecting firewalls will know when a protected host is opening an FTP connection and will know to permit the returning connection for the data channel on a different TCP port. 

### Proxy firewall

Proxy firewalls watch (primarilly) the following fields:

* Source port number

* Destination port number

Some proxy firewalls also perform network address translation (NAT) in addition to proxy address translation (PAT).

Proxy firewalls provide protection by performing all outside connections on behalf of the host, literally translating internal TCP and UDP port addresses to outside port addresses. Many proxy firewalls are *stateless*, and are therfore more easilly tricked into permitting connections they should not. Moreover, since the proxy firewall typically does not inspect the contents of the packet, it is not capable of supporting IPsec functions (VPN/tunnels and encryption).

### Network Address Translation (NAT)

Firewalls have low security areas (the outside) and high security areas (the inside) attached to their network interfaces. Network Address Translation (NAT) is a protocol that firewalls use to translate publicly routable IP addresses on the 'outside' to private IP addresses which are not routable on the Internet on the inside. This makes it more difficult for attackers to connect to a host protected by the firewall. A firewall providing NAT will receive a request from a protected host, strip the non-routable private IP address from the IP datagram and replace that address with a public IP address that is routable on the Internet. Thus, external hosts cannot directly connect to protected hosts as the private IP addresses are blocked within the architecture of the Internet itself.

#### NAT with overload (Port Address Translation)

When an outside IP address is used by multiple hosts on different virtual ports, the NAT process is often referred to as *NAT with Overload*. This allows multiple hosts to use one outside address and to share the virtual port numbers available to the firewall. TCP /IP supports up to 64,000 virtual ports so many hosts can easily share the single external IP address. This is sometimes called Proxy Address Translation or Port Address Translation. 

### Virtual Private Networking (VPN)

A Virtual Private Networking (VPN) connection is an encrypted connection that allow secure access to a local network from a remote location. This is typically done using IP Security tunnels and encryption protocols such as DES. A VPN user will use special software to open a connection to the VPN network access server, provide authentication credentials and then after validating the user's identity, be permitted to access network resources.
