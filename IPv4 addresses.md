### What is an "IP" or an "IP address"?

An "IP" is an "Internet Protocol" address. IP addresses must be unique. All computers that use the Internet use only these unique IP addresses to talk to each other. Names such as www.yahoo.com are just for human convenience and are never used for computer communication. Computers use Domain Name Service (DNS) to turn the names humans understand into IP addresses computers understand. That is, they turn "www.yahoo.com" into "216.109.118.79". When you connect to Yahoo.com, your computer communicates with "216.109.118.79", not "www.yahoo.com". 

An IP address is not part of the hardware of the computer. An IP address is something you can configure on the computer and is a *unique* address that is stored in the computer's software. This property of being unique makes it easy to find a specific computer using the IP address. The fact that the IP address does not come from the computer's hardware means that a computer can be replaced and the IP address it was using goes to the new computer instead of being thrown away with the old computer. This also allows you to change the address of the computer when you move the computer to another network. IP addresses are often referred to as *logical* addresses whereas MAC addresses are referred to as *physical* addresses.

### What are IP addresses used for?

IP addresses are used to *uniquely* identify any device connected to a network running Internet Protocol. IP addresses are used when information is transmitted back and forth between computers. The transmitter is referred to as the source and the receiver is referred to as the the *destination*. Groups of all the addresses in a specific range are called *networks* or *subnets*.

### Classful IPv4 addressing

Classful addressing divides the entire IP address space (0.0.0.0 to 255.255.255.255) into "classes", or special ranges of contiguous IP addresses (no addresses missing between the first and last address in the range). Classful addressing makes it posible to determine the network portion of the IP address by looking at the first four bits of the first octet in the IP address. The first four bits are referred to as the "most significant bits" of the first octet and are used to determin what class of IP address is being used. The value of the first four bits determines the range of actual numerical values of the first octet of the IP addresses in that class. From this information, a receiving host can determine which part of the IP address is being used to identify the specific network on which the host resides, and which portion of the IP address is used to identify the host.

The different classes of IP addresses (Class A, Class B, Class C, Class D & Class E) were created to allow for carving up the entire set of all IP addresses into chunks of different sizes that would "fit" the number of hosts on the network for which the IP address space was being supplied. The chart below gives you a breakdown of how the Classful system breaks up the IP address space.

N = Network | h = Host

Most Significant BITS | Value Ranges | Addr. Class | Network vs. Host | #NETWORKS | #HOSTS
--- |
0000 | 0-126 | A | N.h.h.h | 127 | 16,777,214
-- | 127 | - | - | Special - Local Loopback | Special - Local Loopback
1000 | 128-191 | B | N.N.h.h | 65,536 | 65,534
1100 | 192-223 | C | N.N.N.h | 16,777,216 | 254
1110 | 224 - 239 | D | Special | N/A | N/A
1111 | 240 + | E |Special | N/A | N/A

### Classless IPv4 addressing

All IP addresses have a network and host portion. In classful addressing, the network portion ends on one of the separating dots in the address (on an octet boundary). Classless addressing uses a variable number of bits for the network and host portions of the address.

Classful addressing divides an IP address into the Network and Host portions along octet boundaries. Classless addressing treats the IP address as a 32 bit stream of ones and zeroes, where the boundary between network and host portions can fall anywhere between bit 0 and bit 31. The network portion of an IP address is determined by how many 1's are in the subnet mask. Again, this can be a variable number of bits, and although it can fall on an octet boundary, it does not necessarilly need to. A subnet mask is used locally on each host connected to a network, and masks are never carried in IPv4 datagrams. All hosts on the same network are configured with the same mask, and share the same pattern of network bits. The host portion of each host's IP address will be unique.g

### Public IPv4 addresses

Public IP addresses sometimes called "routable" addresses are addresses that are used when communicating with or connecting to the Internet. These addresses are designated by the Internet Assigned Numbers Authority for use in web servers, e-mail servers, firewalls and other devices that are directly connected to the Internet.

All addresses are managed by ICANN and allocated to organizations by IANA, so you cannot arbitrarilly add the IP addresses to your computers and connect them to the Internet as they may be in use elsewhere on the Internet.

Public addresses |
--- |
1.0.0.0 - 9.255.255.255 |
11.x.x.x - 126.255.255.255 |
129.0.0.0 - 169.253.255.255 |
169.255.0.0 - 172.15.255.255 |
172.32.0.0 - 191.0.1.255 |
192.0.3.0 - 192.88.98.255 |
192.88.100.0 - 192.167.255.255 |
192.169.0.0 - 198.17.255.255 |
198.20.0.0 - 223.255.255.255 |

### Private address ranges

Private IPv4 addresses are special addresses set aside by the Internet Assigned Numbers Authority (IANA) for use within networks that will not be seen by or communicate directly with the Internet. These private addresses cannot be used on the Internet or used to communicate with the Internet (unless the address is NAT'd behind a firewall with a public address). All major ISP's filter out and delete packets using private IP addresses. Any organization that uses private IP addresses on computers that communicate with the Internet *must* use a device that performs Network Address Translation (NAT).

However, anyone can use private IP addresses and because IP addresses must be unique, networks using private addresses should not talk to each other or to the Internet unless their addresses do not overlap, or they are using NAT or NAT with overload (Port Address Translation or "PAT"). 

There are several blocks of private addresses that were set aside by IANA specifically for this purpose. 

Private address ranges | |
--- |
Private Class A range | 10.0.0.0 - 10.255.255.255 |
Private Class B range | 172.16.0.0 - 172.31.255.255 |
Private Class C range | 192.168.0.0 - 192.168.255.255 |
Loopback Addresses | 127.0.0.0 - 127.255.255.255 |

The **Private Class A range** provides for up to 16,777,214 hosts on one network. In practice, most organizations that use the Class A range of addresses usually subnet this range of addresses into smaller sets of hosts called subnetworks (or just "subnets" for short). Still, even with the subnetting, it makes for a conveniently large number of addresses.

The **Private Class B range** of IP addresses fall into 16 subnets. These were provided so that an organization could have up to 65,534 hosts on a network and have up to 16 networks.

The **Private Class C range** of IP addresses is designed to support 254 networks of up to 65,534 hosts.

### Special IP addresses

#### Network address (0.0.0.0)

A network address is an address where all host bits in the IP address are set to zero (0). In every subnet there is a network address. This is the first and lowest numbered address in the range because the address is always the address where all host bits are set to zero. The network address is defined in the RFC's as as the address that contains all zeroes in the host portion of the address and is used to communicate with devices that maintain the network equipment. Today it is rare to see the network address in use.

#### Broadcast address (255.255.255.255)

A broadcast address is an address where all host bits in the IP address are set to one (1). This address is the last address in the range of addresses, and is the address whose host portion is set to all ones. All hosts are to accept and respond to the broadcast address. This makes special services possible. 

#### Loopback address (127.0.0.1)

The 127.0.0.0 class 'A' subnet is used for special local addresses, most commonly the loopback address 127.0.0.1. This address is used to test the local network interface device's functionality. All network interface devices should respond to this address from the command line of the local host. If you ping 127.0.0.1 from the local host, you can be assured that the network hardware is functioning and that the network software is also functioning. The addresses in the 127.0.0.0 - 127.255.255.255 range cannot be reached from outside the host, and so cannot be used to build a LAN. 

#### Private IP addresses

RFC 1918 defines a number of IP blocks which were set aside by the American Registry of Internet Numbers (ARIN) for use as private addresses on private networks that are not directly connected to the Internet. The private addresses are:

Class | Start | End
--- |
A | 10.0.0.0 | 10.255.255.255
B | 172.16.0.0 | 172.31.255.255
C | 192.168.0.0 | 192.168.255.255

#### Multicast IP addresses

There are a number of addresses that are set aside for special purposes, such as the IP's used in OSPF, Multicast, and experimental purposes that cannot be used on the Internet.

Class | Start | End
--- |
D | 224.0.0.0 | 239.255.255.255

#### Special use addresses

Address Block | CIDR Mask | Used for |
--- |
0.0.0.0 | /8 | Used to communicate with "This" network
10.0.0.0 | /8 | Private-Use Networks
14.0.0.0 | /8 | Public-Data Network
24.0.0.0 | /8 | Cable TV Networks
39.0.0.0 | /8 | Previously Reserved. Available for Regional Allocation
127.0.0.0 | /8 | Loopback address
128.0.0.0 | /16 | Previously Reserved. Available for Regional Allocation
169.254.0.0 | /16 | Link Local (eg. Microsoft XP systems use Automatic Private IP Addressing (APIPA) which selects addresses in this range.) 	
172.16.0.0 | /12 | Private-Use Networks
192.0.0.0 | /24 | IETF Protocol Assignments
192.88.99.0 | /24 | Used for IPv6 to IPv4 relay
192.168.0.0 | /16 | Private-Use Networks
