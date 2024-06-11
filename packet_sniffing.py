from scapy.all import *

def packet_sniffer(packet):
    """
    Packet sniffer function that prints the src & dest IPs of each packet.
    Default of packets return amount - 10.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip} --> Destination IP: {dst_ip}")

# Sniffing packets and calling packet_sniffer for each packet
sniff(prn=packet_sniffer, filter="ip", count=10)
