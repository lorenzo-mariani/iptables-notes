# Logging transport layer headers with iptables

### Logging the TCP header

The TCP header is defined in RFC 793, and the length of the header for any particular TCP segment varies depending on the number of options that are included. The length of the header, excluding the options, is always 20 bytes. The TCP header is composed of several fields:

* **Source port (SPT), Destination port (DPT), Reserved (RES), ECN (CWR, ...), Flags (SYN, ...), Window (WINDOW), Urgent pointer (URGP)** - fields that are always logged by iptables
* **Sequence number (SEQ** , requires *--log-tcp-sequence* **), Acknowledgment number (ACK**, requires *--log-tcp-sequence* **), Options (OPT**, requires *--log-tcp-options* **)** - fields that are logged only if the specified command-line argumeny is given to iptables 
* **Data offset, Checksum** -  fields that are not logged by iptables under any circumstances

To have iptables include TCP sequence and acknowledgment values, use the *--log-tcp-sequence* argument:

	[iptablesfw]# iptables -I INPUT 1 -p tcp --dport 15104 -j LOG --log-tcp-options --log-tcp-sequence

### Logging the UDP header

The UDP header is defined in RFC 768. It is only eight bytes long and has no variable length fields. Since there are no special command-line arguments to influence how a UDP header is represented by the LOG target, iptables always logs UDP headers in the same way.

* **Source port (SPT), Destination port (DPT), Length (LEN)** - fields that are always logged by iptables
* **Checksum** - field that is not logged by iptables under any circumstances

# Transport layer attack definitions

A transport layer attacks is a packet or series of packets that abuses the fields of the transport layer header in order to exploit either a vulnerability or error condition in the transport stack implementation of an end host. Transport layer attacks fall into one of the following three categories:

* **Connection resource exhaustion:** packets that are designed to saturate all available resources for servicing new connections on a targeted host or set of hosts.
* **Header abuses:** packets that contain maliciously constructed, broken, or falsified transport layer headers.
* **Transport stack exploits:** packets that contain transport layer stack exploits for vulnerabilities in the stack of an end host. That is, the kernel code dedicated to the processing of transport layer information is itself the target.

# Abusing the transport layer

### Port scans

A port scan is a technique used to interrogate a host in order to see what TCP or UDP services are accessible from a particular IP address.

### TCP port scans techinques

Port scans of TCP ports can be accomplished using a different number of techniques. One of the most powerful port-scanning tools is Nmap:

* **TCP connect() scan** - (Nmap -sT)
* **TCP SYN or half-open scan** - (Nmap -sS)
* **TCP FIN, XMAS, and NULL scans** - (Nmap -sF, -sX, -sN)
* **TCP ACK scan** - (Nmap -sA)
* **TCP idle scan** - (Nmap -sI)
* **UDP scan** - (Nmap -sU)

From Nmap’s perspective, each scanned port can be in one of three states:

* **Open:** there is a server bound to the port, and it is accessible.
* **Close:** there is no server bound to the port.
* **Filtered:** there may be a server bound to the port, but attempts to communicate with it are blocked, and Nmap cannot determine if the port is open or closed.

### TCP connect() scans

When a normal client application attempts to communicate over a network to a server that is bound to a TCP port, the local TCP stack interacts with the remote stack on behalf of the client. Before any application layer data is transmitted, the two stacks must negotiate the parameters that govern the conversation that is about to take place between the client and server. This negotiation is the standard TCP *three-way handshake* and requires three packets. The first packet, SYN, is sent by the client to the server. This packet advertises the desired initial sequence number used for tracking data transmission across the TCP session to the server. If the SYN packet reaches an open port, the server TCP stack responds with a SYN/ACK to acknowledge the receipt of the initial sequence value from the client and to declare its own sequence number back to the client. The client receives the SYN/ACK and responds with an acknowledgment (ACK) to the server. At this point, both sides have agreed on the connection parameters, and the connection state is defined as established and ready to transfer data. In the context of the TCP *connect()* scan, the scanner sends both the SYN and the ending ACK packet for each scanned port. Any normal user can scan a remote system in this mode with Nmap.

### TCP SYN or half-open scans

A SYN or half-open scan is similar to a *connect()* scan in that the scanner sends a SYN packet to each TCP port in an effort to get  a SYN/ACK or RST/ACK response that will show if the targeted port is open or closed. However, the scanning system never completes the three-way handshake because it deliberately fails to return the ACK packet to any open port that responds with a SYN/ACK. Therefore, a SYN scan is also known as a half-open scan because three-way handshakes are never given a chance to complete. A SYN or half-open scan is similar to a *connect()* scan in that the scanner sends a SYN packet to each TCP port in an effort to elicit a SYN/ACK or RST/ACK response that will show if the targeted port is open or closed. However, the scanning system never completes the three-way handshake because it deliberately fails to return the ACK packet to any open port that responds with a SYN/ACK. Therefore, a SYN scan is also known as a half-open scan because three-way handshakes are never given a chance to gracefully complete. A SYN scan cannot be accomplished with the *connect()* system call because that call invokes the vanilla TCP stack code, which will respond with an ACK for each SYN/ACK received from the target. Hence, every SYN packet sent in a SYN scan must be crafted by a mechanism that bypasses the TCP stack altogether.

NOTE:  If the remote host responds with a SYN/ACK, then the local TCP stack on the scanning system receives the SYN/ACK, but the outbound SYN packet did not come from the local stack, so the SYN/ACK is not part of a legitimate TCP handshake as far as the stack is concerned. Hence, the scanner’s local stack sends a RST back to the target system, because the SYN/ACK appears to be unsolicited. You can stop this behavior on the scanning system by adding the following iptables rule to the OUTPUT chain before starting a scan with the command:

	[ext_scanner]# iptables -I OUTPUT 1 -d target -p tcp --tcp-flags RST RST -j DROP

Nmap uses a raw socket to manually build the TCP SYN packets used within its SYN scan mode (-sS). Because the characteristics of these packets are determined by Nmap directly, they differ from TCP SYN packets that the stack would normally have generated. Unlike the SYN packets generated by the real TCP stack, Nmap doesn’t care about negotiating a real TCP session. The only thing Nmap is interested in is whether the port is *open* (Nmap receives a SYN/ACK), *closed* (Nmap receives a RST/ACK), or *filtered* (Nmap receives nothing) on the remote host.

### TCP FIN, XMAS and NULL scans

The FIN, XMAS, and NULL scans operate on the principle that any TCP stack should respond in a particular way if a surprise TCP packet that does not set the SYN, ACK, or RST control bits is received on a port. If the port is closed, then TCP responds with a RST/ACK, but if the port is open, TCP does not respond with any packet at all.

Because a surprise FIN packet is not part of any legitimate TCP connection, all of the FIN packets (even those to open ports) are matched against the INVALID state rule in the iptables policy and subsequently logged and dropped.

### TCP ACK scans

The TCP ACK scan sends a TCP ACK packet to each scanned port and looks for RST packets (not RST/ACK packets, in this case) from both open and closed ports. If no RST packet is returned by a target port, then Nmap infers that the port is filtered. The goal of the ACK scan is not to determine whether a port is open or closed, but whether a port is filtered by a stateful firewall. Because the iptables firewall is stateful whenever the Netfilter connection tracking subsystem is used (via the state match), no surprise ACK packets make it into the TCP stack on the iptablesfw system. Therefore, no RST packets are returned to the scanner.

### TCP idle scans

The TCP idle scan is an advanced scanning mode that requires three systems:

* System to launch the scan
* Scan target
* Zombie host running a TCP server that is not heavily utilized (the "idle" part of the scan's name)

The idle scan exploits the fact that IP increments the IP ID value by one for every packet that is sent through the IP stack. The scan combines this fact with the requirement that a TCP stack send a SYN/ACK in response to a SYN packet to an open port, or a RST/ACK packet in response to a SYN packet to a closed port. In addition, all TCP stacks are required to ignore unsolicited RST/ACK packets. Taken together, these facts allow the scanner to watch how the zombie host increments the IP ID values during a TCP session that is maintained from scanner to the zombie host, while the scanner spoofs SYN packets with the zombie host’s IP address at the target system. As a result, the scanner is able to monitor IP ID values in the IP header of packets coming from the zombie system, and from this information it is able to extrapolate whether ports are open or closed on the target. When a SYN packet is sent from the scanner to an open port on the target with the source IP address spoofed as the zombie’s IP address, the target responds with a SYN/ACK (to the zombie system). Because the SYN packet that the zombie receives is actually unsolicited (it was spoofed from the scanner), it responds with a RST to the target system, thereby incrementing the IP ID counter by one. If a SYN packet is sent from the scanner to a closed port on the target (again with the source IP address spoofed), the target responds to the zombie with a RST/ACK, and the zombie ignores this unsolicited packet. Because in this case no packet is sent from the zombie, the IP ID value is not incremented. By monitoring how the IP ID values are incremented (by one for open ports on the target, and not at all for closed ports), the scanner can infer which ports are open on the target system.

### UDP scans

Since UDP does not implement control messages for establishing a connection, scans for UDP services are accomplished by sending data to a UDP port and then seeing if anything comes back within a reasonable amount of time. Because a UDP packet to an unfiltered port where no server is listening will give an ICMP Port Unreachable messagge, it is easy for a scanner to determine whether a UDP port is closed. In contrast, a UDP packet to an open port may be met even if the packet is not filtered. This is because a UDP server is not obligated to respond with a packet; whether it responds is entirely at the discretion of the particular server application that is bound to the port. If a firewall blocks a UDP packet to a particular port from a scanner, the scanner’s receiving nothing looks to the scanner like a UDP application bound to the port had nothing to say (this is why ports that are filtered are reported as *open|filtered* by Nmap).

### Port sweeps

A port sweep is a reconnaissance method similar to a port scan. However, instead of enumerating accessible services on a single host, a port sweep checks for the availability of a single service on multiple hosts. From a security perspective, port sweeps can give cause for greater concern than port scans since they frequently imply that a system has been compromised by a worm and is looking for other targets to infect. Nmap can easily apply all of its scanning abilities to sweep entire networks for particular services. For example, if an attacker has an exploit for an SSH daemon, Nmap can find all accessible instances of this service in the entire 10.0.0.0/8 subnet as follows:

	[ext_scanner]# nmap -P0 -p 22 -sS 10.0.0.0/8

### TCP sequence prediction attacks

TCP does not build in a layer of strong authentication or encryption; this task is left to the application layer. As a result, TCP sessions are vulnerable to a variety of attacks designed to inject data into a TCP stream, hijack a session, or force a session to close. In order to inject data into an established TCP connection, the attacker must know (or guess) the current sequence number used to track data delivery, which depends on the initial sequence number that each side of the connection chose before any data was transmitted. Significant work has gone into some TCP stacks to ensure that initial sequence numbers are randomly chosen, and the size of the sequence number field in the TCP header (32 bits) also provides some resistance to guessing when a TCP connection cannot be sniffed by an attacker. Whenever a network gateway is running iptables, one of the best ways to hinder someone on an internal network from using sequence-guessing attacks against external TCP sessions is to build in rules that drop spoofed packets that originate from the internal network. That is, for such attacks to be successful, an attacker must spoof packets past iptables and into the connection from either the external TCP client or server IP address. With iptables, it’s easy to stop spoofed packets from being forwarded by dropping any packet that hits an internal interface with a source address that lies outside the internal network.

### SYN floods

A SYN flood creates massive numbers of TCP SYN packets from spoofed source addresses and directs them toward a particular TCP server. The goal is to overwhelm the server by forcing the targeted TCP stack to commit all of its resources to sending out SYN/ACK packets and wait around for ACK packets that will never come. A SYN flood is purely a Denial of Service attack. Some protection from SYN floods is offered by iptables with the *limit* match:

	[iptablesfw]# iptables -I FORWARD 1 -p tcp --syn -m limit --limit 1/s -j ACCEPT

# Transport layer responses

Firewalls or other filtering devices can implement filtering operations based on transport layer headers, manufacture TCP RST or RST/ACK packets to tear down TCP connections, or throttle rates of incoming packets (such as the number of TCP SYN packets in a given period of time). 

### TCP responses

In the context of TCP, the transport layer has a built-in response mechanism for terminating a connection. This ability is implemented in the form of a TCP RST (Reset) or RST/ACK (Reset/Acknowledgment) packet. This packet informs the receiving TCP stack that no more data can be sent and that the connection is to be terminated, regardless of its current state. The RST flag is one of the elements in the 6-bit-wide control bits field in the TCP header. It is used whenever an untenable condition is encountered by either a TCP client or server, and either side of the connection may issue a RST.

### RST vs RST/ACK

Many firewalls and intrusion detection systems can send TCP RST packets to knock down malicious connections, but the implementation details for sending such packets vary greatly. According to RFC 793, there are only 3 circumstances in which a TCP stack should generate a RST/ACK; the rest of the time, a RST packet is sent without the ACK bit set. Further, there is an inverse relationship between the ACK flag in the last packet seen in the TCP session and a RST packet used to tear down the connection. That is, if the last packet contained the ACK flag, a RST packet should not contain the flag. Conversely, if the last packet did not contain the ACK flag, a RST should. For example, if a TCP SYN packet is sent to a port where no server is listening (i.e., the port is in the CLOSED state), a RST/ACK is sent back to the client. But if a SYN/ACK packet is sent to a CLOSED port, then a RST packet with no ACK bit is sent back to the client.

Example:

Any client is allowed to talk directly to the Linux TCP stack on the iptablesfw system via port 5001.

	[iptablesfw]# iptables -I INPUT 1 -p tcp --dport 5001 -j ACCEPT

A standard Nmap SYN scan is sent against port 5001 on the iptablesfw system.

	[ext_scanner]# nmap -P0 -sS -p 5001 71.157.X.X

The *tcpdump* command is used to watch what happens. The local TCP stack sends a RST (R flag in the example below) back to the client, and this RST has a non-zero acknowledgment value; the ACK bit is set because the SYN packet from Nmap did not contain the ACK bit.

	[iptablesfw]# tcpdump -i eth0 -l -nn port 5001
	tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
	listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
	17:10:24.693292 IP 144.202.X.X.33736 > 71.157.X.X.5001: S
	522224616:522224616(0) win 2048 <mss 1460>
	17:10:24.693413 IP 71.157.X.X.5001 > 144.202.X.X.33736: R 0:0(0) ack 522224617 win 0 

Another Nmap scan is sent against port 5001: an ACK scan.

	[ext_scanner]# nmap -P0 -sA -p 5001 71.157.X.X

The local TCP stack sends a RST back to the client, with no acknowledgment number and the ACK bit unset. This is because the packet from Nmap contained an acknowledgment number and had the ACK bit set.

	[iptablesfw]# tcpdump -i eth0 -l -nn port 5001
	tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
	17:11:03.985446 IP 144.202.X.X.62669 > 71.157.X.X.5001: . ack 1406759780 win 1024
	17:11:03.985477 IP 71.157.X.X.5001 > 144.202.X.X.62669: R 1406759780:1406759780(0) win 0

The iptables REJECT target implements the inverse relationship between the ACK flag on a matched TCP packet and the RST that it generates. If the original TCP packet contained the ACK bit, then the acknowledgment value is set to zero. If the original TCP packet did not contain the ACK bit, the acknowledgment value is derived from the original packet.

Example:

Let's take a look at how iptables tear down an established TCP connection after it has gone into the established state and when the string "tester" is sent across from the client to the server.

We start by including a rule to ACCEPT connections to TCP port 5001, followed by a rule to terminate connections that contain the "tester" string.

	[iptablesfw]# iptables -I INPUT 1 -p tcp --dport 5001 -j ACCEPT

	[iptablesfw]# iptables -I INPUT 1 -p tcp --dport 5001 -m string --string "tester" --algo bm -j REJECT --reject-with tcp-reset

We invoke "tcpdump" with the *-s 0* argument to make sure all application layer data s captured, and with *-X*, to dump the application layer data to the display.

	[iptablesfw]# tcpdump -i eth0 -l -nn -s 0 -X port 5001

The result of the tcpdump command is therefore the following:

	22:33:25.826122 IP 144.202.X.X.54922 > 71.157.X.X.5001: S 741951920:
	741951920(0) win 5840 <mss 1460,sackOK,timestamp 842078832 0,nop,wscale 6>
	22:33:25.826161 IP 71.157.X.X.5001 > 144.202.X.X.54922: S 264203278:
	264203278(0) ack 741951921 win 5792 <mss 1460,sackOK,timestamp 647974503
	842078832,nop,wscale 5>
	22:33:25.826263 IP 144.202.X.X.54922 > 71.157.X.X.5001: . ack 1 win 92
	<nop,nop,timestamp 842078832 647974503>
	22:33:25.826612 IP 144.202.X.X.54922 > 71.157.X.X.5001: P 1:8(7) ack 1 win
	92 <nop,nop,timestamp 842078832 647974503>
	      0x0000:  4500 003b 53c2 4000 4006 1d94 0000 0000  E..;S.@.@...G..5
	      0x0010:  0000 0000 d68a 1389 2c39 49b1 0fbf 6c0f  G..3....,9I...l.
	      0x0020:  8018 005c b82a 0000 0101 080a 3231 1a70  ...\.*......21.p
	      0x0030:  269f 4e67 7465 7374 6572 0a              &.Ng tester.
	22:33:25.826665 IP 71.157.X.X.5001 > 144.202.X.X.54922: R 
	264203279:264203279(0) win 0

As you can see, in the first few lines the three-way handshake begins and you can see that the packet before the RST is sent has the ACK bit set (*ack 1* at line 8) and contains the string "tester" (*tester* at line 13). Finally, the RST (*R* at line 14) is generated (Note that after the RST there is a sequence number, but that the ACK control bit is not set, because the previous packet contained the ACK bit).

### SYN cookies

An interesting method for enabling a TCP stack to perform well under a SYN flood attack is to enable SYN cookies. While a passive IDS cannot implement SYN cookies as a response to an attack, SYN cookies are easily enabled on Linux systems via the */proc* filesystem if the kernel is compiled with CONFIG_SYN_COOKIES support, simply by executing the following command:

	echo 1 > /proc/sys/net/ipv4/tcp_syncookies

The SYN cookie provides a way to build the server sequence number during the TCP handshake so that it can be used to reconstruct initial sequence numbers of legitimate clients after they return the final ACK. This allows the server to reuse kernel resources that would otherwise be reserved in order to create a connection after receiving a SYN packet from a client. Because the server does not know if the client will ever respond with an ACK after the server sends the SYN/ACK, using SYN cookies can provide an effective defense against SYN flood attack.

### UDP responses

The lack of structure in UDP makes data transfers fast because UDP lacks the overhead of a data acknowledgment scheme like the one in TCP. But that lack of structure also means that UDP has no built-in mechanism for convincing a system to stop sending UDP packets. UDP stacks do, however, utilize ICMP as a response mechanism: if a UDP packet is sent to a port where no UDP server is listening, then an ICMP Port Unreachable message is usually sent in return.

Example:

	[iptablesfw]# iptables -I INPUT 1 -p udp --dport 5001 -j ACCEPT

	[ext_scanner]$ echo -n "aaaa" | nc -u 71.157.X.X 5001

	[iptablesfw]# tcpdump -i eth0 -l -nn port 5001
	tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
	listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
	15:12:30.119336 IP 144.202.X.X.40503 > 71.157.X.X.5001: UDP, length 4
	15:12:30.119360 IP 71.157.X.X > 144.202.X.X: ICMP 71.157.X.X udp port 5001 unreachable, length 40

As you can see, if you allow UDP packets to port 5001 through the iptables firewall but do not bind a UDP server to this port, an ICMP Port Unreachable message is returned to the UDP client.

Intrusion detection systems and firewalls can also generate ICMP Port Unreachable messages in response to UDP traffic. The iptables REJECT target supports this response with the *--reject-with icmp-port-unreachable* command-line argument.

Example:

	[iptablesfw]# iptables -I INPUT 1 -p udp --dport 5001 -j REJECT –-reject-with icmp-port-unreachable

	[iptablesfw]# nc -l -u -p 5001 &
	[1] 12001

	[ext_scanner]$ echo -n "aaaa" | nc -u 71.157.X.X 5001

	[iptablesfw]# tcpdump -i eth0 -l -nn port 5001
	tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
	listening on eth0, link-type EN10MB (Ethernet), capture size 96 bytes
	15:28:55.949157 IP 144.202.X.X.31726 > 71.157.X.X.5001: UDP, length 4
	15:28:55.949264 IP 71.157.X.X > 144.202.X.X: ICMP 71.157.X.X udp port 5001 unreachable, length 40

### Firewall rules and router ACLs

Transport layer responses such as tearing down a suspicious TCP connection with a RST or sending ICMP Port Unreachable messages after detecting an attack in UDP traffic can be useful in some circumstances. However, these responses only apply to individual TCP connections or UDP packets; there is no persistent blocking mechanism that can prevent an attacker from trying a new attack. Fortunately, sending TCP RST or ICMP Port Unreachable messages can also be combined with dynamically created blocking rules in a firewall policy or router ACL for an attacker’s IP address and the service that is under attack  (hence, using both network layer and transport layer criteria as a part of the blocking rule). For example, if an attack is detected against a webserver from the IP address 144.202.X.X, the following iptables rule would restrict the ability of this IP address to communicate with a webserver via the FORWARD chain:

	[iptablesfw]# iptables -I FORWARD 1 -s 144.202.X.X -p tcp --dport 80 -j DROP
