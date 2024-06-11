from scapy.all import *

# Make sure to have some sort of sniffing tool installed (wireshark, etc.)

def tcp_port_scan(target_ip, ports):
    """
    TCP port scanner function that scans the specified ports on the target IP address.
    """
    open_ports = []

    # Iterate over each port in the list of ports to scan
    for port in ports:
        src_port = RandShort()  # Generate a random source port
        # Craft a TCP SYN packet with the specified source and destination ports
        tcp_syn_scan = sr1(IP(dst=target_ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=False)

        # Check if a response was received and it is a TCP packet
        if tcp_syn_scan and tcp_syn_scan.haslayer(TCP):
            # Check if the TCP packet has the SYN/ACK flags set (indicating an open port)
            if tcp_syn_scan[TCP].flags == 18:  # TCP flags 18 indicate a SYN/ACK packet
                open_ports.append(port)  # Add the open port to the list
                print(f"Port {port} is open.")

    return open_ports

# Example usage
# Change the IP and Ports as your need 
target_ip = "192.168.1.1"
ports_to_scan = [21, 22, 80, 443, 3389]
open_ports = tcp_port_scan(target_ip, ports_to_scan)
print("Open ports:", open_ports)
