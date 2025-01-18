### Advanced sniffer
#### Advanced Packet Sniffer with Signature Detection

_This program is a packet sniffer equipped with signature-based detection features to detect attack patterns in network packets. This program is designed to help network administrators and security researchers analyze network traffic, monitor suspicious activity, and detect signature-based threats such as SQL injection, XSS, and others._

**Main Feature**
__Packet Sniffing:__
- Capture and analyze live network packets using Scapy.

- Supports common protocols such as TCP, UDP, and ICMP.
*Signature-Based Detection:*
- Supports attack pattern detection through JSON-based signature files.

- Detects attacks such as SQL Injection, XSS, Command Injection, and Directory Traversal.
**GeoIP Lookup:**
- Displays the geographic location of the source IP address
**Logging:**
- Logs all packets to a CSV file for further analysis.
- Suspicious packets are logged to the [alerts.log] file and [signature_hits.log].
**Network Statistics:**
•Track real-time network traffic statistics (packet count, protocols, etc.).
**Protocol Filters:**
•Supports protocol-based filters (**example:** _filter tcp to monitor only TCP packets_).
**Function**
  ***Packet Capture:***
- The program captures all network packets using Scapy and analyzes them layer by layer.

- Signature Matching: The packet payload is checked against the signature patterns from the attack_signatures.json file. If a match is found, the program logs the attack.
**Logging and Statistics:**
- All packets are logged in a CSV file for auditing.
- Suspicious packets are logged separately.
**GeoIP Integration:**
- Displays geographic information of the source IP for further analysis.
***Program advantages***
**Real-Time Threat Detection:**
- The program not only sniffs packets, but also detects signature-based threats.
**Easy to Customize:**
- Signatures can be updated by adding new patterns in the attack_signatures.json file.
**Comprehensive Logging:**
- All logs are recorded in detail, making it easy to investigate after network analysis.
**GeoIP Integration:**
- The ability to know the geographic location of the packet origin adds context to the analysis.
**Lightweight and Portable:**
- The program only requires lightweight dependencies such as Scapy and Python, making it easy to run on a variety of systems.
***Installation requirements:***
- Python 3.8 or later
- Scapy
- Additional modules such as pandas (for CSV logging)




  **Installation Steps:**
  git clone https://github.com/<username>/advanced-packet-sniffer.git
cd advanced-packet-sniffer
pip install -r requirements.txt
**run**
  sudo python advanced_sniffer.py
  
