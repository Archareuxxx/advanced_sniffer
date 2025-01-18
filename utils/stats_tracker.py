from collections import defaultdict
import matplotlib.pyplot as plt

stats = defaultdict(int)

def update_stats(packet_info):
    """Update statistics based on packet info."""
    protocol = packet_info.get("Protocol", "Unknown")
    stats[protocol] += 1

def display_stats():
    """Display a bar chart of packet statistics."""
    protocols = list(stats.keys())
    counts = list(stats.values())

    plt.bar(protocols, counts, color='skyblue')
    plt.xlabel("Protocols")
    plt.ylabel("Number of Packets")
    plt.title("Packet Statistics")
    plt.show()
  
