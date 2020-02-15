# Application layer string matching with iptables

One of the most important features for any IDS is the ability to search application layer data for telltale sequences of malicious bytes. However, because the structure of applications is generally much less strictly defined than that of network or transport layer protocols, intrusion detection systems must be flexible when it comes to inspecting application layer data. For example, when inspecting application layer communications, if an IDS assumes that certain sequences of bytes are inviolate, then changes in the application layer protocol might invalidate this assumption and cause the IDS to miss attacks that are delivered in unexpected ways. The ability to perform string matching against the entire application payload in network traffic is provided by the iptables string match extension.

### Observing the string match extension in action

In order to test the iptables string matching feature, we construct a simple iptables rule that uses the string match extension to verify that it functions as advertised. The following rule uses the iptables LOG target to generate a syslog message when the string "tester" is sent to a Netcat server that is listening on TCP port 5001:

	iptables -I INPUT 1 -p tcp --dport 5001 -m string --string "tester" --algo bm -m state --state ESTABLISHED -j LOG --log-prefix "tester"
	iptables -I INPUT 2 -p tcp --dport 5001 -j ACCEPT

The *--algo bm* command-line argument selects the pattern matching strategy (bm = Boyer-Moore. This algorithm is also commonly used by intrusion detection systems). The *-m state --state ESTABLISHED* command-line arguments restrict the string match operation to packets that are part of established TCP connections, and this means that someone cannot cause the iptables rule to match on a spoofed packet from an arbitrary source address - a bidirectional connection must be established.

Now we use Netcat to spawn a TCP server that listens locally on TCP port 5001, and then we use it again from the ext_scanner system as a client to send the string "tester" to the server:

	[iptablesfw]$ nc -l -p 5001

	[ext_scanner]$ echo "tester" | nc 71.157.X.X 5001

Now we examine the system logfile for evidence that the string match rule generated the appropriate syslog message:

	[iptablesfw]# tail /var/log/messages | grep tester
	Jul 11 04:19:14 iptablesfw kernel: tester IN=eth0 OUT=
	MAC=00:13:d3:38:b6:e4:00:30:48:80:4e:37:08:00 SRC=144.202.X.X DST=71.157.X.X
	LEN=59 TOS=0x00 PREC=0x00 TTL=64 ID=41843 DF PROTO=TCP SPT=55363 DPT=5001
	WINDOW=92 RES=0x00 ACK PSH URGP=0

Notice the log prefix *tester* above. By examining the remaining portion of the log message, we can confirm that the associated packet was sent from the ext_scanner system to our Netcat server listening on TCP port 5001.

### Matching non-printable application layer data

When running as a client, Netcat can interact with UDP servers just as easily as it can with those that listen on TCP sockets. When combined with a little Perl, Netcat can send arbitrary bytes across the wire, including ones that cannot be represented as printable ASCII characters. This feature is important because many exploits utilize non-printable bytes that cannot be represented by printable ASCII characters; in order to simulate such exploits as they are sent across the wire, we need the ability to generate the same bytes from our client. For example, suppose that you need to send a string of 10 characters that represent the Japanese yen to a UDP server listening on port 5002, and that you want iptables to match on these characters. According to the ISO 8859-9 character set, the hex code A7 represents the yen sign, and so the commands below will do the trick. We first execute iptables with the *--hex-string* argument to iptables, along with the bytes specified in hex between | characters like so:

	iptables -I INPUT 1 -p udp --dport 5002 -m string --hex-string "|a7a7a7a7a7a7a7a7a7a7|" --algo bm -j LOG --log-prefix "YEN "

Next, we spawn a UDP server on port 5002. Finally, we use a Perl command to generate a series of 10 hex A7 bytes, and we pipe that output through Netcat to send it over the network to the UDP server:

	nc -u -l -p 5002
	perl -e 'print "\xa7"x10' | nc -u 71.157.X.X 5002

Iptables matches the traffic, as you can see by the syslog log messagge (note the YEN log prefix):

	tail /var/log/messages | grep YEN

	Jul 11 04:15:14 iptablesfw kernel: YEN IN=eth0 OUT= 
	MAC=00:13:d3:38:b6:e4:00:30:48:80:4e:37:08:00 SRC=144.202.X.X DST=71.157.X.X
	LEN=38 TOS=0x00 PREC=0x00 TTL=64 ID=37798 DF PROTO=UDP SPT=47731 DPT=5002 LEN=18

# Application layer attack definitions

We define an application layer attack as an effort to subvert an application, an application user, or data managed by an application for purposes other than those sanctioned by the application owner or administrator. Application layer attacks fall into one of three categories:

* **Exploits for programming bugs:** often, programming errors are made during the development of an application. These bugs can cause serious vulnerabilities that are remotely accessible over the network. Good examples include a buffer overflow vulnerability derived from the usage of an unsafe C library function, web-centric vulnerabilities such as a webserver that passes unsanitized queries to a back-end database (which can result in an SQL injection attack), and sites that post unfiltered content derived from users (which can result in Cross-Site Scripting or XSS attacks).
* **Exploits for trust relationships:** some attacks exploit trust relationships instead of attacking application programming bugs. Such attacks look completely legitimate as far as the interaction with the application itself is concerned, but they target the trust people place on the usage of the application. Phishing attacks are a good example; the target is not a web application or mail server - it is the person interpreting a phishing website or email message.
* **Resource exhaustion:** like network or transport layer DoS attacks, applications can sometimes suffer under mountains of data input. Such attacks render applications unusable for everyone.

# Abusing the application layer

### Snort signatures

Consider the following Snort signature:

	alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB-ATTACKS /etc/shadow access"; content:"/etc/shadow"; flow:to_server,established; nocase; classtype:w eb-application-activity; sid:1372; rev:5;)

This signature detects when the string */etc/shadow* is transferred from a web client to a webserver. The webserver most likely runs as a user without sufficient permissions to read the */etc/shadow* file, but an adversary doesn’t necessarily know this before trying to request the file. Snort is looking for the *attempt* to read the file. In order to make iptables generate a log message when the */etc/shadow* string is seen over an established TCP connection on port 80 in the FORWARD chain, you can use the following rule:

	iptables -I FORWARD 1 -p tcp --dport 80 -m state --state ESTABLISHED -m string --string "/etc/shadow" --algo bm -j LOG --log-prefix "ETC_SHADOW "

### Buffer overflow exploit

A *buffer overflow exploit* is an attack that exploits a programming error made in an application’s source code whereby the size of a buffer is insufficient to accommodate the amount of data copied into it; hence the term *overflow* is used when adjacent memory locations are overwritten. For stack-based buffer overflows, a successful exploit overwrites the function return address (which is on the stack) so that it points into code provided by the attacker. This, in turn, allows the attacker to control the execution of the process thenceforth. Another class of buffer overflow attacks applies to memory regions that are dynamically allocated from the heap. Buffer overflow vulnerabilities are commonly introduced into C or C++ applications through improper use of certain library functions that do not automatically implement bounds checking. Example of such function include *strcpy(), strcat(), sprintf(), gets(), scanf(), malloc() and calloc()*.

In the context of network-based attacks, there is no generic way to detect buffer overflow attempts.

Sometimes the size alone of data supplied as arguments to certain application commands indicates an overflow attack.

Example:

The following is a signature for an overflow against the *chown* command in an FTP server. It looks for at least 100 bytes of data following the *chown* command in an FTP session.

	alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"FTP SITE CHOWN overflow attempt";
	flow:to_server,established; content:"SITE"; nocase; content:"CHOWN"; distance:0; nocase;
	isdataat:100,relative; pcre:"/^SITE\s+CHOWN\s[^\n]{100}/smi"; reference:bugtraq,2120;
	reference:cve,2001-0065; classtype:attempted-admin; sid:1562; rev:11;)

Although there is no regular expression engine available to iptables, we can produce a good iptables approximation of this Snort signature. For example, the iptables rule below searches for the *site* and *chown* strings and uses the length match to search for at least 140 byte packets (because the length match begins at the network layer header instead of at the application layer, we allow 20 bytes for the IP header and 20 bytes for the TCP header).

	[iptablesfw]# iptables -I FORWARD 1 -p tcp --dport 21 -m state --state ESTABLISHED -m string --string "site" --algo bm -m string --string "chown" --algo bm -m length --length 140 -j LOG --log-prefix "CHOWN OVERFLOW "

### SQL injection attacks

An SQL injection attack exploits a condition in an application where user input is not validated or filtered correctly before it is included within a database query. A clever attacker can use the nesting ability of the SQL language to build a new query and potentially modify or extract information from the database.

It is difficult to detect a generic SQL injection, but some Snort rules come fairly close for certain attacks.

Example:

Here is a Bleeding Snort signature that detects when an attacker attempts to truncate a section of an SQL query by supplying a closing single quote (*content: "'|00|";*) along with two - characters (*content: "-|00|-|00|";*). The two - characters comment out the remainder of the SQL query, and this can be used to remove restrictions that may have been placed on the query through additional joins on other fields.

	alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg: "BLEEDING-EDGE
	EXPLOIT MS-SQL SQL Injection closing string plus line comment"; flow:
	to_server,established; content: "'|00|"; content: "-|00|-|00|";
	reference:url,www.nextgenss.com/papers/more_advanced_sql_injection.pdf;
	reference:url,www.securitymap.net/sdm/docs/windows/mssql-checklist.html;
	classtype: attempted-user; sid: 2000488; rev:5; )

This Snort rule translates relatively cleanly into iptables, including the NULL characters through the use of the *--hex-string* command-line argument:

	[iptablesfw]# iptables -I FORWARD 1 -p tcp --dport 1433 -m state --state ESTABLISHED -m string --hex-string "'|00|" --algo bm -m string --hex-string "-|00|-|00|" --algo bm -j LOG --log-prefix "SQL INJECTION COMMENT "

One wrinkle both in the SQL Snort signature above and its iptables equivalent is that the ordering of the two content strings is not respected by either Snort or iptables. If a packet that is part of an established TCP connection contains the two strings in reverse order (with NULLs represented in Snort’s hex notation), for example, *-|00|-|00| foo bar '|00|* instead of *'|00| foo bar -|00|-|00|*, then both the Snort signature and the iptables rule would trigger. For some signatures, this can increase the false positive rate if there is any chance that legitimate data can emulate malicious data but in reverse.

### Gray matter hacking

Some of the most problematic attacks on the Internet today are those that target people directly via the applications they use. These attacks circumvent the best encryption algorithms and authentication schemes by exploiting people’s tendency to trust certain pieces of information. For example, if an attacker gets a person to trust the source of certain malicious software, or false passwords or encryption keys, the attacker can bypass even the most sophisticated security mechanisms.

### Phishing

Phishing is an attack whereby a user is tricked into providing authentication credentials for an online account, such as for a bank, to an untrusted source. Typically this is accomplished by sending an official-looking email to users requesting that they access their online account and perform some “urgent” task in the interest of security, such as changing their password. A web link is provided that appears legitimate but is subtly crafted to point the user to a website controlled by the attacker that closely mimics the authentic website. Once phished users visit the site and enter their credentials, the attacker steals their account credentials. For example, here is a portion of a phishing email that you can receive from the email address *support@citibank.com* with the subject *Citibank Online Security Message*:

	When signing on to Citibank Online, you or somebody else have made several login attempts and 
	reached your daily attempt limit. As an additional security measure your access to Online
	Banking has been limited. This Web security measure does not affect your access to phone
	banking or ATM banking. Please verify your information <a href="http://196.41.X.X/sys/"
	onMouseMove="window.status='https://www.citibank.com/us/cards/index.jsp';return true;"
	onMouseout="window.status=''">here</a>, before trying to sign on again. You will be able
	to attempt signing on to Citibank Online within twenty-four hours after you verify your
	information. (You do not have to change your Password at this time.)

The link contains a bit of embedded JavaScript that instructs a web browser to display a legitimate link to the Citibank website if the user puts the mouse pointer over the link text here in the email message. However, the real destination of the link is to the URL *http&#58;//196.41.X.X/sys*, which is a webserver controlled by the attacker. Fortunately, iptables can detect this particular phishing email when it is viewed over a web session with the following rule:

	iptables -I FORWARD 1 -p tcp --dport 25 -m state --state ESTABLISHED -m string --string "http://196.41.X.X/sys/" --algo bm -m string --hex-string "window.status=|27|https://www.citibank.com" -j LOG --log-prefix "CITIBANK PHISH "

The rule performs a multistring match against the strings *http&#58;//196.41.X.X/sys/* and *window.status=https&#58;//www.citibank.com* within established TCP connections to the SMTP port. The first string in the signature requires a match against the particular malicious webserver setup by the attacker. The second string looks or the Citibank website used as the argument to the window.status JavaScript window object property. While the real Citibank website might also use this construct for legitimate purposes, the combination of the two strings together in an email message is highly suspicious and has a low chance of triggering a false positive either within Snort or iptables.

### Backdoors and keystroke logging

A *backdoor* is an executable that contains functionality exposed to an attacker but not to a legitimate user. The goal of a backdoor is to stealthily grant an attacker the ability to do anything on a remote machine, from collecting keystrokes that reveal passwords to remotely controlling the system. The FsSniffer backdoor is an example of a backdoor. It is detected with the following Snort rule:

	alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"BACKDOOR FsSniffer
	connection attempt"; flow:to_server,established; content:"RemoteNC
	Control Password|3A|"; reference:nessus,11854; classtype:trojan-activity;
	sid:2271; rev:2;)

The FsSniffer Snort rule inspects packets that are part of established TCP connections and that are destined for the server side of a connection (*flow* command-line argument), and looks for application layer content that uniquely identifies attempts by an attacker to authenticate to the FsSniffer backdoor (*content* ommand-line argument). Recasting this Snort rule into iptables space yields the following iptables rule. (The iptables ESTABLISHED state matching requirement ensures that the rule matches against packets that are part of established TCP connec-tions, and the *--hex-string* command-line argument ensures that the hex code \x3A in the original content field is properly translated.)

	iptables -I FORWARD 1 -p tcp -m state --state ESTABLISHED -m string --hex-string "RemoteNC Control Password|3A|" --algo bm  -j LOG --log-ip-options --log-tcp-options --log-prefix "FSSNIFFER BACKDOOR "

# Encryption and application encodings

Two factors make it difficult to detect application layer attacks: encryption and application encoding schemes. Encryption is particularly problematic because it is designed to make decryption computationally infeasible in the absence of the encryption keys, and normally IDS, IPS, and firewall devices do not have access to these keys. 80Chapter 4Encoding techniques can also be hard for an IDS to deal with. For example, many web browsers support gzip encoding in order to reduce the size of data transferred over the network. If an attack is combined with a bit of random data and then compressed with gzip, an IDS must uncompress the resulting data as it is transferred across the network in order to detect the attack. The random data ensures that the compressed attack is different every time; without this randomization, the IDS could just look for the compressed string itself in order to identify the attack. On a busy network, it is computationally impractical to uncompress every web session in real time, because there are lots of web sessions that download large compressed files that are not malicious.

# Application layer response

Technically, a purely application layer response to an application layer attack should only involve constructs that exist at the application layer. For example, if users are abusing an application, their accounts should simply be disabled, or if an attacker attempts an SQL injection attack, the query should be discarded and an HTTP error code should be returned to the client. Such a response does not require manipulation of packet header information that exists below the application layer. However, strictly application layer responses are impractical for firewalls and network intrusion prevention systems because they are not usually tightly integrated with the applications themselves. Further, if a highly malicious attack is discovered from a particular IP address over a TCP session it may be more useful to disallow all subsequent communications from the attacker’s IP address anyway. This is a network layer response to an application layer attack.
