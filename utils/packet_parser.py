from scapy.all import IP, TCP, UDP, ICMP

def parse_packet(packet):
    """Parse packet information into a dictionary."""
    packet_info = {
        "Source IP": None,
        "Destination IP": None,
        "Protocol": None,
        "Source Port": None,
        "Destination Port": None,
        "Raw Data": None
    }

    if packet.haslayer(IP):
        packet_info["Source IP"] = packet[IP].src
        packet_info["Destination IP"] = packet[IP].dst

    if packet.haslayer(TCP):
        packet_info["Protocol"] = "TCP"
        packet_info["Source Port"] = packet[TCP].sport
        packet_info["Destination Port"] = packet[TCP].dport
    elif packet.haslayer(UDP):
        packet_info["Protocol"] = "UDP"
        packet_info["Source Port"] = packet[UDP].sport
        packet_info["Destination Port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        packet_info["Protocol"] = "ICMP"

    # Include raw data if available
    if packet.haslayer("Raw"):
        packet_info["Raw Data"] = packet["Raw"].load.decode(errors="ignore")

    return packet_info
  
