# BETA-Packet-Sniffer
**THIS IS ONLY A BETA VERSION OF THE SCRIPT : I STILL HAVE MUCH WORK TO DO WITH IT , THEREFORE IT MAY SEEM INCOMPLETE , AND YOU MAY ENCOUNTER FREQUENT ERRORS **

A python packet-sniffing script that uses the scapy module in order to sniff packets on a LAN.

# How it works#

-The script runs in a loop untill the user exirts to program
-The script uses scapy's "sniff" method in order to sniff a single packet on the LAN
-The script then processes all of the layers in the given packet and appends them to an array
-The script then checks the contents of the network layer in order to find the source and destination IP addresses
-The script then checks the contntents of the transport layer in order to find the source and destination ports
-The script then checks the packet to check if it contains a particular protocol (ie DNS , DHCP , TCP )
-The script then process the headers for that particular layer and decodes any data it needs to , in order to generate a suitable output string
-The output string is then appended to an output array 
-The time the packet was captured , source IP , destination IP , data link protocol , network protocol , transport protocol and application protocol , are printed , as well as any of the extra info we have found
