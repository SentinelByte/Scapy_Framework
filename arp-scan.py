from scapy.all import *

def arp_scan(network):
    """
    ARP scanner function that performs an ARP scan on the specified network
    and displays the IP and MAC addresses of active hosts.
    """
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_request
    answered_list = srp(arp_broadcast, timeout=2, verbose=False)[0]

    print("[IP] IP Address\t\t[MAC] MAC Address")
    print("-----------------------------------------")

    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

# Scanning the network and displaying results
# change this CIDR as needed
arp_scan("192.168.1.0/24")
