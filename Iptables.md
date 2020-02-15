## Introduction

With the term **firewall**, most people think of a product that inspects network traffic at the network and transport layers of the OSI Reference Model and makes pass or filter decisions. In terms of products, dozens of firewall types exist. They are differentiated by the data source they inspects (e.g., network traffic, host processes, or system calls) and the depth to which they inspect those sources. Almost any device that inspects communication and decides whether to pass or filter it could be considered a firewall product.

The job of detecting intrusions is usually left to special systems that are designed for this purpose and that have a broad view of the local network. There is no substitute for having a dedicated network **Intrusion Detection System (IDS)** as a part of the security infrastructure charged with protecting a network. Without an IDS to call attention to suspicious activity, an analyst might never even suspect that a system is under attack. Iptables (the firewall running on Linux systems) is used to supplement existing intrusion detection infrastructures. **The main focus of iptables is applying policy restrictions to network traffic, not detecting network attacks.** However, iptables offers powerful features that allow it to emulate a significant portion of the capabilities that traditionally lie within the purview of intrusion detection systems. For example, the iptables logging format provides detailed data on nearly every field of the network and transport layer headers (including IP and TCP options), and the iptables string matching capability can perform byte sequence matches against application layer data. Such abilities are critical for providing the ability to detect attempted intrusions. Intrusion detection systems are usually passive devices that are not configured to automatically take any punitive action against network traffic that appears to be malicious. In general, this is for good reason because of the risk of misidentifying benign traffic as something more sinister (known as a false positive). However, some IDSes can be deployed inline to network traffic, and when deployed in this manner such a system is typically referred to as a network **Intrusion Prevention System (IPS)**. Because iptables is a firewall, it is always inline to network traffic, which allows many attacks to be filtered out before they cause significant damage.

## Iptables

The iptables firewall is developed by the Netfilter Project. The iptables firewall allows the user to instrument a high degree of control over IP packets that interact with a Linux system. An iptables policy is built from an ordered set of rules, which describe to the kernel the actions that should be taken against certain classes of packets. Each iptables rule is applied to a chain within a table. An iptables chain is a collection of rules that are compared, in order, against packets that share a common characteristic.

#### Tables

A table is an iptables construct that delineates broad categories of functionality, such as packet filtering or Network Address Translation (NAT). There are four tables:

* **Filter table:** allows you to make decisions on packets and manage packets traffic.
* **NAT table:** allows packets to be routed to different hosts on NAT (Network Address Translation) networks by changing the source and destination addresses.
* **Mangle table:** allows you to modify the headers of the packets.
* **Raw table:** allows you to inspects packets based on their status.

The filter table is the default table used by iptables.

#### Chains

Each table has its own set of built-in chains. There are several types of chains:

* **PREROUTING chain:** the rules in this chain are applied when the packet arrives at the network interface.
* **INPUT chain:** the rules in this chain are applied just before the packet is delivered to a process. The INPUT chain is that part of iptables that decides whether the packets destined for the local system can communicate with a local socket.
* **FORWARD chain:** the rules in this chain are applied only if the packet arrives at a host that is not the receiver. The packet in question is simply forwarded.
* **OUTPUT chain:** the rules in this chain are applied when the packet is out of a process and is about to arrive at the network interface to be sent to the outside.
* **POSTROUTING chain:** the rules in this chain are applied just before the packet is sent from the network interface to the outside.

Therefore, the situation is the following:

* Filter table - INPUT, FORWARD and OUTPUT chains
* NAT table - PREROUTING, OUTPUT and POSTROUTING chains
* Mangle table - PREROUTING, INPUT, FORWARD, OUTPUT and POSTROUTING chains
* Raw table - PREROUTING and OUTPUT chains

#### Rules

The following are the key points to remember for the iptables rules:

* Rules contain a criteria and a target.
* If the criteria is matched, it goes to the rules specified in the target (or) executes the special values mentioned in the target.
* If the criteria is not matched, it moves on to the next rule.

#### Targets

Iptables supports a set of targets that trigger an action when a packet matches a rule. Some targets are called **terminating targets** as they can immediately decide what to do with that packet, without having to check other rules. The most used terminating targets are:

* **ACCEPT:** it accepts the packet.
* **DROP:** it discards the packet.
* **REJECT:** the same as DROP, but will also return an error message to the originating host which sent the packet.

There are also other types of targets, called **non-terminating targets**, which, unlike the previous ones, although they are executed, iptables continues to perform checks on the match of other rules. An example of these non-terminating targets is:

* **LOG:** the packet information is logged (syslog) and iptables continues processing the next rule in a table.

## Basic commands

Do the following to view a table:

	# iptables -t [table name] --list

NOTE: If you don’t specify the *-t* option, it will display the default filter table. So, both of the following commands are the same:

	# iptables -t filter --list
	(or)
	# iptables --list

Typing

	sudo iptables -L

lists your current rules in iptables. if you have just set up your server, you will have no rules, and you should see:

	Chain INPUT (policy ACCEPT)
	target     prot opt source               destination

	Chain FORWARD (policy ACCEPT)
	target     prot opt source               destination

	Chain OUTPUT (policy ACCEPT)
	target     prot opt source               destination

## Basic iptables options

1. **-A** - Append this rule to a rule chain. Valid chains for what we're doing are INPUT, FORWARD and OUTPUT.

2. **-L** - List the current filter rules.

3. **-m conntrack** - Allow filter rules to match based on connection state. Permits the use of the *--ctstate* option.

4. **--ctstate** - Define the list of states for the rule to match on. Valid states are:

     1. **NEW** - The connection has not yet been seen.

     2. **RELATED** - The connection is new, but is related to another connection already permitted.

     3. **ESTABLISHED** - The connection is already established.

     4. **INVALID** - The traffic couldn't be identified for some reason.

5. **-m limit** - Require the rule to match only a limited number of times. Allows the use of the *--limit* option. Useful for limiting logging rules.

     1. **--limit** - The maximum matching rate, given as a number followed by *"/second"*, *"/minute"*, *"/hour"*, or *"/day"* depending on how often you want the rule to match.

6. **-p** - The connection protocol used.

7. **--dport** - The destination port(s) required for this rule. A single port may be given, or a range may be given as start:end, which will match all ports from start to end, inclusive.

8. **-j** - Jump to the specified target. By default, iptables allows four targets:

     1. **ACCEPT** - Accept the packet and stop processing rules in this chain.

     2. **REJECT** - Reject the packet and notify the sender that we did so, and stop processing rules in this chain.

     3. **DROP** - Silently ignore the packet, and stop processing rules in this chain.

     4. **LOG** - Log the packet, and continue processing more rules in this chain. Allows the use of the *--log-prefix* and *--log-level* options.

9. **--log-prefix** - When logging, put this text before the log message. Use double quotes around the text to use.

10. **--log-level** - Log using the specified syslog level. 7 is a good choice unless you specifically need something else.

11. **-i** - Only match if the packet is coming in on the specified interface.

12. **-I** - Inserts a rule. Takes two options, the chain to insert the rule into, and the rule number it should be.

     1. *-I INPUT 5* would insert the rule into the INPUT chain and make it the 5th rule in the list.

13. **-v** - Display more information in the output. Useful for if you have rules that look similar without using *-v*.

14. **-s --source** - address[/mask] source specification.

15. **-d --destination** - address[/mask] destination specification.

16. **-o --out-interface** - output name[+] network interface name ([+] for wildcard)

## Allowing established sessions

We can allow established sessions to receive traffic:

        sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

NOTE: The above rule has no spaces either side of the comma in ESTABLISHED,RELATED

If the line above doesn't work, you may be on a castrated VPS whose provider has not made available the extension, in which case an inferior version can be used as last resort:

        sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

## Allowing incoming traffic on specific ports

You could start by blocking traffic, but you might be working over SSH, where you would need to allow SSH before blocking everything else.

To allow incoming traffic on the default SSH port (22), you could tell iptables to allow all TCP traffic on that port to come in.

        sudo iptables -A INPUT -p tcp --dport ssh -j ACCEPT

Referring back to the list above, you can see that this tells iptables:

1. append this rule to the input chain (-A INPUT) so we look at incoming traffic
2. check to see if it is TCP (-p tcp)
3. if so, check to see if the input goes to the SSH port (--dport ssh)
4. if so, accept the input (-j ACCEPT)

Let's check the rules (only the first few lines shown, you will see more):

        sudo iptables -L

        Chain INPUT (policy ACCEPT)
        target     prot opt source               destination
        ACCEPT     all  --  anywhere             anywhere            state RELATED,ESTABLISHED
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:ssh

Now, let's allow all incoming web traffic:

        sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT

Checking our rules, we have:

        sudo iptables -L

        Chain INPUT (policy ACCEPT)
        target     prot opt source               destination
        ACCEPT     all  --  anywhere             anywhere            state RELATED,ESTABLISHED
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:ssh
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:www

We have specifically allowed tcp traffic to the ssh and web ports, but as we have not blocked anything, all traffic can still come in.

## Blocking traffic

Once a decision is made to accept a packet, no more rules affect it. As our rules allowing ssh and web traffic come first, as long as our rule to block all traffic comes after them, we can still accept the traffic we want. All we need to do is put the rule to block all traffic at the end.

        sudo iptables -A INPUT -j DROP
        sudo iptables -L

        Chain INPUT (policy ACCEPT)
        target     prot opt source               destination
        ACCEPT     all  --  anywhere             anywhere            state RELATED,ESTABLISHED
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:ssh
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:www
        DROP       all  --  anywhere             anywhere

Because we didn't specify an interface or a protocol, any traffic for any port on any interface is blocked, except for web and ssh.

## Editing iptables

The only problem with our setup so far is that even the loopback port is blocked. We could have written the drop rule for just eth0 by specifying *-i eth0*, but we could also add a rule for the loopback. If we append, it will come too late - after all the traffic has been dropped. We need to insert this rule before that. Since this is a lot of traffic, we'll insert it as the first rule so it's processed first.

        sudo iptables -I INPUT 1 -i lo -j ACCEPT
        sudo iptables -L

        Chain INPUT (policy ACCEPT)
        target     prot opt source               destination
        ACCEPT     all  --  anywhere             anywhere
        ACCEPT     all  --  anywhere             anywhere            state RELATED,ESTABLISHED
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:ssh
        ACCEPT     tcp  --  anywhere             anywhere            tcp dpt:www
        DROP       all  --  anywhere             anywhere

The first and last lines look nearly the same, so we will list iptables in greater detail.

        sudo iptables -L -v

        Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
         pkts bytes target     prot opt in     out     source               destination
            0     0 ACCEPT     all  --  lo     any     anywhere             anywhere
            0     0 ACCEPT     all  --  any    any     anywhere             anywhere            state RELATED,ESTABLISHED
            0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere            tcp dpt:ssh
            0     0 ACCEPT     tcp  --  any    any     anywhere             anywhere            tcp dpt:www
            0     0 DROP       all  --  any    any     anywhere             anywhere

You can now see a lot more information. This rule is actually very important, since many programs use the loopback interface to communicate with each other. If you don't allow them to talk, you could break those programs!

## Logging

In the above examples none of the traffic will be logged. If you would like to log dropped packets to syslog, this would be the quickest way:

        sudo iptables -I INPUT 5 -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

## Saving iptables

If you were to reboot your machine right now, your iptables configuration would disappear. Rather than type this each time you reboot, however, you can save the configuration, and have it start up automatically. To save the configuration, you can use *iptables-save* and *iptables-restore*.

## Configuration on startup

NOTE: Iptables and NetworkManager can conflict. Also if you are concerned enough about security to install a firewall you might not want to trust NetworkManager. Also note NetworkManager and iptables have opposite aims.  Iptables aims to keep any questionable network traffic out. NetworkManager aims to keep you connected at all times. Therefore if you want security all the time, run iptables at boot time. If you want security some of the time then NetworkManager might be the right choice.

NOTE: If you use NetworkManager these steps will leave you unable to use NetworkManager for the interfaces you modify.

Save your firewall rules to a file

        sudo sh -c "iptables-save > /etc/iptables.rules"

At this point you have several options. You can make changes to */etc/network/interfaces* or add scripts to */etc/network/if-pre-up.d/* and */etc/network/if-post-down.d/* to achieve similar ends.

#### Solution 1 - /etc/network/interfaces

NOTE: Be careful - entering incorrect configuration directives into the interface file could disable all interfaces, potentially locking you out of a remote machine.

Modify the */etc/network/interfaces* configuration file to apply the rules automatically. You will need to know the interface that you are using in order to apply the rules - if you do not know, you are probably using the interface *eth0*, although you should check with the following command first to see if there are any wireless cards:

        iwconfig

When you have found out the interface you are using, edit (using sudo) your */etc/network/interfaces*:

	sudo nano /etc/network/interfaces

When in the file, search for the interface you found, and at the end of the network related lines for that interface, add the line:

	pre-up iptables-restore < /etc/iptables.rules

You can also prepare a set of down rules, save them into second file */etc/iptables.downrules* and apply it automatically using the above steps:

        post-down iptables-restore < /etc/iptables.downrules

A fully working example using both from above:

        auto eth0
        iface eth0 inet dhcp
          pre-up iptables-restore < /etc/iptables.rules
          post-down iptables-restore < /etc/iptables.downrules

You may also want to keep information from byte and packet counters.

        sudo sh -c "iptables-save -c > /etc/iptables.rules"

The above command will save the whole rule-set to a file called */etc/iptables.rules* with byte and packet counters still intact.

#### Solution 2 /etc/network/if-pre-up.d and ../if-post-down.d

NOTE: This solution uses *iptables-save -c* to save the counters. Just remove the *-c* to only save the rules.

Alternatively you could add the *iptables-restore* and *iptables-save* to the *if-pre-up.d* and *if-post-down.d* directories in the */etc/network* directory instead of modifying */etc/network/interface* directly.

NOTE: Scripts in *if-pre-up.d* and *if-post-down.d* must not contain dot in their names.

The script */etc/network/if-pre-up.d/iptablesload* will contain:

        #!/bin/sh
        iptables-restore < /etc/iptables.rules
        exit 0

and */etc/network/if-post-down.d/iptablessave* will contain:

        #!/bin/sh
        iptables-save -c > /etc/iptables.rules
        if [ -f /etc/iptables.downrules ]; then
           iptables-restore < /etc/iptables.downrules
        fi
        exit 0

Then be sure to give both scripts execute permissions:

        sudo chmod +x /etc/network/if-post-down.d/iptablessave
        sudo chmod +x /etc/network/if-pre-up.d/iptablesload

#### Solution 3 iptables-persistent

Install and use the *iptables-persistent* package.

## Configuration on startup for NetworkManager

NetworkManager includes the ability to run scripts when it activates or deactivates an interface. To save iptables rules on shutdown, and to restore them on startup, we are going to create such a script.

        gksudo gedit /etc/NetworkManager/dispatcher.d/01firewall

Then, paste this script into your editor, save, and exit the editor.

        if [ -x /usr/bin/logger ]; then
                LOGGER="/usr/bin/logger -s -p daemon.info -t FirewallHandler"
        else
                LOGGER=echo
        fi

        case "$2" in
                up)
                        if [ ! -r /etc/iptables.rules ]; then
                                ${LOGGER} "No iptables rules exist to restore."
                                return
                        fi
                        if [ ! -x /sbin/iptables-restore ]; then
                                ${LOGGER} "No program exists to restore iptables rules."
                                return
                        fi
                        ${LOGGER} "Restoring iptables rules"
                        /sbin/iptables-restore -c < /etc/iptables.rules
                        ;;
                down)
                        if [ ! -x /sbin/iptables-save ]; then
                                ${LOGGER} "No program exists to save iptables rules."
                                return
                        fi
                        ${LOGGER} "Saving iptables rules."
                        /sbin/iptables-save -c > /etc/iptables.rules
                        ;;
                *)
                        ;;
        esac

Finally, we need to make sure NetworkManager can execute this script. In a terminal window, enter this command:

        sudo chmod +x /etc/NetworkManager/dispatcher.d/01firewall

## Tips

#### If you manually edit iptables on a regular basis

The above steps go over how to setup your firewall rules and presume they will be relatively static. But if you do a lot of development work, you may want to have your iptables saved everytime you reboot. You could add a line like this one in */etc/network/interfaces*:

        pre-up iptables-restore < /etc/iptables.rules
        post-down iptables-save > /etc/iptables.rules

The line *post-down iptables-save > /etc/iptables.rules* will save the rules to be used on the next boot.

#### Using iptables-save/restore to test rules

If you edit your iptables beyond this tutorial, you may want to use the *iptables-save* and *iptables-restore* feature to edit and test your rules. To do this open the rules file a text editor.

        sudo sh -c "iptables-save > /etc/iptables.rules"
        gksudo gedit /etc/iptables.rules

You will have a file that appears similiar to:

        # Generated by iptables-save v1.3.1 on Sun Apr 23 06:19:53 2006
        *filter
        :INPUT ACCEPT [368:102354]
        :FORWARD ACCEPT [0:0]
        :OUTPUT ACCEPT [92952:20764374]
        -A INPUT -i lo -j ACCEPT
        -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
        -A INPUT -i eth0 -p tcp -m tcp --dport 80 -j ACCEPT
        -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
        -A INPUT -j DROP
        COMMIT
        # Completed on Sun Apr 23 06:19:53 2006

Notice that these are iptables commands minus the *iptable* command. Feel free to edit this to file and save when complete. Then to test simply:

        sudo iptables-restore < /etc/iptables.rules

NOTE: With iptables 1.4.1.1-1 and above, a script allow you to test your new rules without risking to brick your remote server. If you are applying the rules on a remote server, you should consider testing it with:

        sudo iptables-apply /etc/iptables.rules

After testing, if you have not added the *iptables-save* command above to your */etc/network/interfaces* remember not to lose your changes:

        sudo sh -c "iptables-save > /etc/iptables.rules"

#### More detailed logging

For further detail in your syslog you may want create an additional chain. This is an example of */etc/iptables.rules* showing how you can setup your iptables to log to syslog:

        # Generated by iptables-save v1.3.1 on Sun Apr 23 05:32:09 2006
        *filter
        :INPUT ACCEPT [273:55355]
        :FORWARD ACCEPT [0:0]
        :LOGNDROP - [0:0]
        :OUTPUT ACCEPT [92376:20668252]
        -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        -A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT
        -A INPUT -i eth0 -p tcp -m tcp --dport 80 -j ACCEPT
        -A INPUT -i lo -j ACCEPT
        -A INPUT -j LOGNDROP
        -A LOGNDROP -p tcp -m limit --limit 5/min -j LOG --log-prefix "Denied TCP: " --log-level 7
        -A LOGNDROP -p udp -m limit --limit 5/min -j LOG --log-prefix "Denied UDP: " --log-level 7
        -A LOGNDROP -p icmp -m limit --limit 5/min -j LOG --log-prefix "Denied ICMP: " --log-level 7
        -A LOGNDROP -j DROP
        COMMIT
        # Completed on Sun Apr 23 05:32:09 2006

Note a new CHAIN called LOGNDROP at the top of the file. Also, the standard DROP at the bottom of the INPUT chain is replaced with LOGNDROP and add protocol descriptions so it makes sense looking at the log. Lastly we drop the traffic at the end of the LOGNDROP chain. The following gives some idea of what is happening:

1. *--limit* sets the number of times to log the same rule to syslog

2. *--log-prefix "Denied..."* adds a prefix to make finding in the syslog easier

3. *--log-level 7* sets the syslog level to informational

#### Disabling the firewall

If you need to disable the firewall temporarily, you can flush all the rules using

        sudo iptables -P INPUT ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -F

or create a script using text editor such as nano

        sudo nano -w /root/fw.stop

        echo "Stopping firewall and allowing everyone..."
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT

Make sure you can execute the script

        sudo chmod +x /root/fw.stop

You can run the script

        sudo /root/fw.stop
