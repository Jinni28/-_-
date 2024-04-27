from scapy.all import *
from rich import print  #textformat for texts
from tabulate import tabulate #for tables

def packet_callback(packet): #callback function to handle each packet 
    #if with ethernet shows ethernet with source and destination  and 
    #if Ip shows source and destination of protocols
    data = []
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        data.append(["IP", src_ip, dst_ip, proto])
    elif packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        data.append(["Ethernet", src_mac, dst_mac, ""])

    table = tabulate(data, headers=["Layer", "Source", "Destination", "Protocol"], tablefmt="pretty")
    print("[green]Packet Information:[/]\n" + table)

# Start sniffing packets
sniff(prn=packet_callback, count=10)  # Capture 10 packets


# sniff by scappy is similar to callback and irretrating it again to capture packets 

Explaination : 
# 'packet _callback' is a function that will be called
# every time a new packet arrives at the network interface.
# The function receives as argument the captured packet.
# If the packet has an IP layer (most common) / Ethernet, it prints
# its source and destination addresses along with the protocol.
# Tabulate : used for representing in tabular form.
# Rich : used for colors.
# Note: Scapy is not meant to be run directly under Windows.
# We have installed nping for windows which can be used instead of Scapy.