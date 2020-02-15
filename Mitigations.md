## Block ping request

A ping request is an ICMP packet sent to the destination address to ensure connectivity between the devices. If your network works well, you can safely block all ping requests. It is important to note that this does not actually hide your computer — any packet sent to you is rejected, so you will still show up in a simple nmap "ping scan" of an IP range.

The most simple method to block ping command on Linux systems is by adding an iptables rule, as shown below:

	# iptables -A INPUT --proto icmp -j DROP

Another general method of blocking ICMP messages in Linux systems is to add the below kernel variable that will drop all ping packets:

	# echo “1” > /proc/sys/net/ipv4/icmp_echo_ignore_all

In order to make the above rule permanent, append following line to */etc/sysctl.conf* file and, subsequently, apply the rule with *sysctl* command:

	# echo “net.ipv4.icmp_echo_ignore_all = 1” >> /etc/sysctl.conf 
	# sysctl -p

In Debian-based Linux distributions that ship with UFW application firewall, you can block ICMP messages by adding the following rule to */etc/ufw/before.rules* file, as shown below:

	-A ufw-before-input -p icmp --icmp-type echo-request -j DROP

Restart UFW firewall to apply the rule, by issuing the below commands:

	# ufw disable && ufw enable

In CentOS or Red Hat Enterprise Linux distribution that use Firewalld interface to manage iptables rules, add the below rule to drop ping messages:

	# firewall-cmd --zone=public --remove-icmp-block={echo-request,echo-reply,timestamp-reply,timestamp-request} --permanent	
	# firewall-cmd --reload

In order to test if the firewall rules had been successfully applied in all the cases discussed above, try to ping your Linux machine IP address from a remote system. In case ICMP messages are blocked to your Linux box, you should get a *“Request timed out”* or *“Destination Host unreachable”* messages on the remote machine.

## Block IPs

Say for example, you’ve noticed the IP 59.45.175.62 continuously trying to attack your server, and you’d like to block it. We need to simply block all incoming packets from this IP. So, we need to add this rule to the INPUT chain of the filter table. You can do so with:

	iptables -t filter -A INPUT -s 59.45.175.62 -j REJECT

The *-t* specifies the table in which our rule would go into — in our case, it’s the filter table. The *-A* tells iptables to “append” it to the list of existing rules in the INPUT chain. The *-s* simply sets the source IP that should be blocked. Finally, the *-j* tells iptables to “reject” traffic by using the REJECT target. If you want iptables to not respond at all, you can use the DROP target instead.

Filter table is used by default. So you can leave it out, which saves you some typing:

	iptables -A INPUT -s 59.45.175.62 -j REJECT

You can also block IP ranges by using the CIDR notation. If you want to block all IPs ranging from 59.145.175.0 to 59.145.175.255, you can do so with:

	iptables -A INPUT -s 59.45.175.0/24 -j REJECT

If you want to block output traffic to an IP, you should use the OUTPUT chain and the *-d* flag to specify the destination IP:

	iptables -A OUTPUT -d 31.13.78.35 -j DROP

#### Block traffic from an IP on a specific NIC

	iptables -A INPUT -s 11.22.33.44 -i eth0 -j DROP

#### Block traffic from an IP on a specific port

	iptables -A INPUT -s 11.22.33.44 -p tcp -dport 22 -j DROP

## Block traffic from a specific MAC address

Suppose you want to block traffic some a MAC address instead of an IP address. This is handy if a DHCP server is changing the IP of the maching you want to protect from:

	iptables -A INPUT -m mac --mac-source 00:11:2f:8f:f8:f8 -j DROP

## Block a specific port

#### Block incoming traffic to a port

Suppose we need to block port 21 for incoming traffic:

	iptables -A INPUT -p tcp --destination-port 21 -j DROP

But if you have two-NIC server, with one NIC facing the Internet and the other facing your local private Network, and you only one to block FTP access from outside world.

	iptables -A INPUT -p tcp -i eth1 -p tcp --destination-port 21 -j DROP

In this case I'm assuming *eth1* is the one facing the Internet.

#### Block outgoing traffic to a port

If you want to forbid outgoing traffic to port 25, this is useful, in the case you are running a Linux firewall for your office, and you want to stop virus from sending emails.

	iptables -A FORWARD -p tcp --dport 25 -j DROP

Instead of FORWARD, you can use OUTPUT too, to block server self traffic.

## Avoid IP spoofing and bad addresses attacks

Spoofing and bad address attack tries to fool the server and try to claim that packets had come from local address/network.

Bad incoming address from following ranges:

* 0.0.0.0/8
* 127.0.0.0/8
* 10.0.0.0/8
* 172.16.0.0/12
* 192.168.0.0/16
* 192.168.0.0/16
* 224.0.0.0/3
* Your own internal server/network ip address/ranges.

Following small shell script tries to prevent this kind of attacks:

	#!/bin/bash
 
	INT_IF="eth1" # connected to internet
	SERVER_IP="202.54.10.20" # server IP
	LAN_RANGE="192.168.1.0/24" # your LAN IP range
 
	# Add your spoofed IP range/IPs here
	SPOOF_IPS="0.0.0.0/8 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/3"
 
	IPT="/sbin/iptables" # path to iptables
 
	# default action, can be DROP or REJECT
	ACTION="DROP"
 
	# Drop packet that claiming from our own server on WAN port
	$IPT -A INPUT -i $INT_IF -s $SERVER_IP -j $ACTION
	$IPT -A OUTPUT -o $INT_IF -s $SERVER_IP -j $ACTION
 
	# Drop packet that claiming from our own internal LAN on WAN port
	$IPT -A INPUT -i $INT_IF -s $LAN_RANGE -j $ACTION
	$IPT -A OUTPUT -o $INT_IF -s $LAN_RANGE -j $ACTION
 
	## Drop all spoofed
	for ip in $SPOOF_IPS
	do
	 $IPT -A INPUT -i $INT_IF -s $ip -j $ACTION
	 $IPT -A OUTPUT -o $INT_IF -s $ip -j $ACTION
	done
	## add or call your rest of script below to customize iptables ##

Save and close the file. Call above script from your own iptables script. Add following line to your */etc/sysctl.conf* file:

	net.ipv4.conf.all.rp_filter=1
	net.ipv4.conf.all.log_martians=1
	net.ipv4.conf.default.log_martians=1

The *net.ipv4.conf.all.rp_filter=1* entry enables source address verification which is inbuilt into Linux kernel itself and last two lines logs all such spoofed packets in log file.

## Avoid LAND attacks

LAND stands for Local Area Network Denial. In this attack, a packet is spoofed with source address as the address of the target itself, i.e., the source and destination addresses are the same. The target machine ends up replying to itself continuously.

To block all packets from your own IP (assuming 47.156.66.17 as IP of the machine), do the following:

	# iptables -A INPUT -s 47.156.66.17/32 -j DROP

With the *-s* option in the above command, source IP address is specified. Further, to block any packet from local network (self IP):

	# iptables -A INPUT -s 127.0.0.0/8 -j DROP

## Avoid XMAS packet

A Christmas tree packet is a packet in which all the flags in any protocol are set. The FIN, URG and PSH bits in the TCP header of this kind of packet are set. This packet is called Christmas Tree packet because all the fields of header are "lightened up" like a Christmas tree. This type of packet requires much more processing than the usual packets, so the server allocates a large number of resources for this packet. Hence, this can be used to perform a DOS attack on the server. These type of packets can be blocked with:

	# iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

Here, *-p* option specifies the protocol for which the rule is applicable. The *--tcp-flags* is used to specify the flags of TCP header. It requires two options, the 1st option is 'mask', in which we specify what flags should be examined (ALL), and the 2nd option is "comp" i.e. the flags that must be set. So here we want to examine ALL flags of which FIN, PSH and URG must be set.

Another method of blocking XMAS packets is by adding this iptables rule:

	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

## Drop all NULL packets

One method of blocking NULL packets is by adding this iptables rule:

	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

## Avoid Smurf attack

The attacker in this attack sends a large number of ICMP echo broadcast packet, with source IP address spoofed to that of target's IP address. All the machines in the network recieve this broadcast message and reply to the target with echo reply packet. One way to block this attack is to block all the ICMP packets, but if that can't be done, a limit may be applied to the icmp packets allowed.

For limiting the number of ICMP packets:

	# iptables -A INPUT -p icmp -m limit --limit 2/second --limit-burst 2 -j ACCEPT

To block all the ICMP packets:

	# iptables -A INPUT -p icmp -j DROP

## Avoid SYN floods

SYN flood is a type of DOS (Denial Of Service) attack.

The attacker can create a large number of forged SYN requests that have their source IP addresses spoofed, and send it to the target. The target replies with SYN/ACK, and allocates its resources for the connection, but never gets back ACK reply. The target machine’s resources are exhausted and it stops serving any further requests from any legitimate machine.

This attack and some other form of DOS/DDOS attacks can be blocked by limiting the incoming TCP connection request packets. A point to be noted here is that, we should not put a limit to requests from established connections. For avoiding this type of attack, only new connection requests need to be controlled. Moreover, the number of requests a server can handle depends on the server's available resources. So in the example below, the limit on the TCP connection must be changed according to the capacity of the server:

	# iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 2/second --limit-burst 2 -j ACCEPT
	# iptables -A INPUT –p tcp –m state --state NEW –j DROP

## Bruteforce attacks

One way to protect the services against bruteforce attacks is the use of appropriate iptables rules which activate and blacklist an IP after a set number of packets attempt to initiate a connection.

The following rules give an example configuration to mitigate SSH bruteforce attacks using iptables.

	# iptables -N IN_SSH
	# iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -j IN_SSH
	# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 3 --seconds 10 -j DROP
	# iptables -A IN_SSH -m recent --name sshbf --rttl --rcheck --hitcount 4 --seconds 1800 -j DROP 
	# iptables -A IN_SSH -m recent --name sshbf --set -j ACCEPT

The first rule allows for a maximum of 3 connection packets in 10 seconds and drops further attempts from this IP. The next rule adds a quirk by allowing a maximum of 4 hits in 30 minutes. This is done because some bruteforce attacks are actually performed slow and not in a burst of attempts.
