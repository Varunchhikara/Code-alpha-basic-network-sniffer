# Network Packet Sniffer

A Python-based network packet sniffer built with Scapy for educational purposes. Captures, analyzes, and displays live network traffic with protocol-level detail.

## Features

- Real-time packet capture on any network interface
- Protocol detection: TCP, UDP, ICMP, ARP, DNS, IPv6
- Source/destination IP and port display
- TCP flag analysis (SYN, ACK, FIN, RST, PSH, URG)
- DNS query and response inspection
- ICMP type/code decoding
- Raw payload preview (truncated and sanitized)
- BPF filter support (e.g., `tcp port 80`, `icmp`, `dns`)
- Save captures to `.pcap` for Wireshark analysis
- Live traffic statistics on exit

## Requirements

- Python 3.7+
- Scapy (`python3-scapy`)
- Linux with root privileges (for raw socket access)

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/network-sniffer.git
cd network-sniffer
sudo apt install python3-scapy -y
chmod +x network_sniffer.py
