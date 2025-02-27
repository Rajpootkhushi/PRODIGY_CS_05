from scapy.all import sniff, IP, TCP, UDP

def handle_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine the transport layer protocol (TCP/UDP)
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"
        else:
            src_port = dst_port = "N/A"
            protocol_name = "Other"

        # Print the captured packet information
        print(f"Protocol: {protocol_name} | Source: {src_ip}:{src_port} | Destination: {dst_ip}:{dst_port}")

def main(interface):
    print(f"Starting packet sniffer on interface: {interface}")
    # Start sniffing packets
    sniff(iface=interface, prn=handle_packet, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with your network interface (e.g., 'wlan0' for Wi-Fi on Linux)
    main("Wi-Fi")