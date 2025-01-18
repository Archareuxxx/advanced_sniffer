import argparse
from scapy.all import sniff, Raw
from utils.packet_parser import parse_packet
from utils.stats_tracker import update_stats, display_stats
from utils.geoip_lookup import get_geoip_info
from utils.signature_detector import load_signatures, detect_signatures
import pandas as pd
import os

LOG_DIR = "logs"
CSV_FILE = os.path.join(LOG_DIR, "packets.csv")
ALERT_FILE = os.path.join(LOG_DIR, "alerts.log")
SIGNATURE_HIT_FILE = os.path.join(LOG_DIR, "signature_hits.log")
os.makedirs(LOG_DIR, exist_ok=True)

SIGNATURES = load_signatures()

def log_packet(packet_info):
    """Save packet info to CSV for further analysis."""
    df = pd.DataFrame([packet_info])
    if not os.path.exists(CSV_FILE):
        df.to_csv(CSV_FILE, index=False, mode='w')
    else:
        df.to_csv(CSV_FILE, index=False, mode='a', header=False)

def alert(packet_info, reason):
    """Log alerts for suspicious activity."""
    with open(ALERT_FILE, 'a') as alert_file:
        alert_file.write(f"ALERT: {reason}\n")
        alert_file.write(str(packet_info) + "\n\n")

def log_signature_hit(signature, packet_info):
    """Log detected signatures to a separate file."""
    with open(SIGNATURE_HIT_FILE, 'a') as log_file:
        log_file.write(f"Signature Detected: {signature['name']}\n")
        log_file.write(f"Description: {signature['description']}\n")
        log_file.write(str(packet_info) + "\n\n")

def packet_callback(packet):
    """Callback function to handle each packet."""
    packet_info = parse_packet(packet)
    log_packet(packet_info)
    update_stats(packet_info)

    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")  # Decode raw payload
        signature = detect_signatures(payload, SIGNATURES)
        if signature:
            log_signature_hit(signature, packet_info)
            print(f"[!] Signature Detected: {signature['name']} - {signature['description']}")

    if packet_info.get("Source IP"):
        geo_info = get_geoip_info(packet_info["Source IP"])
        print(f"GeoIP Info: {geo_info}")

    print(packet_info)

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer with Signature Detection")
    parser.add_argument("--filter", type=str, default=None, help="Filter packets by protocol (e.g., tcp, udp, icmp)")
    args = parser.parse_args()

    print("[*] Starting packet sniffer with signature detection...")
    try:
        sniff(filter=args.filter, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet sniffer.")
        print("[*] Saving statistics...")
        display_stats()
        exit(0)

if __name__ == "__main__":
    main()
