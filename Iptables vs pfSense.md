# Iptables vs pfSense

### Small introduction

- **iptables:** program that allows the configuration of the tables provided by the Linux Kernel and the chains and rules it stores. It requires elevated priviliges to operate and must be executed by user root.
- **pfSense:** open source FreeBSD appliance firewall distribution. It can be configured through a web-based interface.

### Main differences

* pfSense has a configuration file in which you can easily modify the rule set. Once the file has been modified you can just call *pfctl -f /etc/pf.conf* and the rule set will be loaded and start filtering. On the other hand, iptables does not have a configuration file. The rule set mainly modified from the command line. You can use *iptables-save* and *iptables-restore* to save and load iptables rules from a file or write a bash script that loads the iptables rules one by one.

* iptables has different tables, each with different chains. Packets are processed by these chains (PREROUTING, INPUT, FORWARD, OUTPUT, POSTROUTING). When a packet matches a rule description an action (target) is taken. If the target is terminating (ACCEPT, DROP, REJECT), processing on that chain stops immmediately and the action is performed. If the target is non-terminating (LOG, RETURN, ...) it performs an action and continues evaluation within the chain, looking for other matches. On the other hand, pfSense processes packets in the configuration file. Even if a packet matches a rule, it continues to process the packet until the end of the configuration file. Only if a rule contains the "quick" option does pfSense stop processing and take action before hitting the end of the rule set. If a packet reaches the end of the configuration file, the last action specified from a rule that matched that packet is taken.

* from the point of view of packet filtering iptalbes provides better solutions tha pfSense. Both of them can filter based on protocol, TCP flags, source/destination IP, interface, port, ... . However iptables allows you to filter packets based on state, time, statistics, ToS, ... .

**Note!** Saying that pfSense can't filter packets based on their state does not means that it is not a stateful firewall. It recognizes state, as it passes packets that are part of an established connection without even processing them, but the majority of packets skip firewall rules entirely; this guarantees higher speed. Even iptables behaves the same way, since most iptables rulesets pass packets that are part of an established state anyway, but the difference with pfSense is that here packets pass through all rules. So, the result is the same but the speed is considerably lower, especially when thre is a complicated rulesets.
