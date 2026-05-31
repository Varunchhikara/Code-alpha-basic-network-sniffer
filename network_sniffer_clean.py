#!/usr/bin/env python3
#!/usr/bin/env python3
"""
network_sniffer.py — Educational Packet Capture & Protocol Analyzer
Author: [Varun Chhikara]
Date: May 2026
License: MIT

DISCLAIMER:
- This tool is for authorized security testing and educational purposes ONLY.
- The author is not responsible for misuse.
- All captured data stays local — no exfiltration, no logging to external servers.
- MAC addresses and IPs shown in screenshots should be anonymized.
"""

# ... rest of the code below ...


import argparse
import signal
import sys
import time
from collections import defaultdict
from datetime import datetime

# Core scapy imports — minimal footprint
from scapy.all import conf, sniff, IP, IPv6, TCP, UDP, ICMP, DNS, Raw, Ether, ARP

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
conf.verb = 0          # Suppress scapy's verbose output entirely
conf.sniff_promisc = 1 # Enable promiscuous mode

# ──────────────────────────────────────────────
# PROTOCOL MAP — O(1) lookup, zero branching overhead
# ──────────────────────────────────────────────
PROTO_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    2:  "IGMP",
    132: "SCTP",
}

# ──────────────────────────────────────────────
# STATISTICS (thread-safe via simple atomic ops)
# ──────────────────────────────────────────────
stats = {
    "total": 0,
    "by_proto": defaultdict(int),
    "by_size": {"<64": 0, "64-127": 0, "128-511": 0, "512-1023": 0, "1024-1518": 0, ">1518": 0},
    "start_time": None,
}

# ──────────────────────────────────────────────
# HELPER: Protocol name resolution
# ──────────────────────────────────────────────
def proto_name(pkt):
    """Return protocol name from IP layer — fastest path."""
    if IP in pkt:
        return PROTO_MAP.get(pkt[IP].proto, f"IP-{pkt[IP].proto}")
    if IPv6 in pkt:
        return PROTO_MAP.get(pkt[IPv6].nh, f"IPv6-{pkt[IPv6].nh}")
    return "OTHER"

# ──────────────────────────────────────────────
# HELPER: Pretty-print payload (truncated + sanitized)
# ──────────────────────────────────────────────
def safe_payload(raw_bytes, max_len=64):
    """Return printable payload, truncating and escaping non-printables."""
    if not raw_bytes:
        return "(no payload)"
    printable = []
    for b in raw_bytes[:max_len]:
        if 32 <= b < 127:
            printable.append(chr(b))
        else:
            printable.append(f"\\x{b:02x}")
    snippet = "".join(printable)
    if len(raw_bytes) > max_len:
        snippet += f" ... [+{len(raw_bytes) - max_len} bytes]"
    return snippet

# ──────────────────────────────────────────────
# HELPER: TCP flags as readable string
# ──────────────────────────────────────────────
def tcp_flags_str(tcp_layer):
    """Return human-readable TCP flags."""
    flags = []
    if tcp_layer.flags & 0x01: flags.append("FIN")
    if tcp_layer.flags & 0x02: flags.append("SYN")
    if tcp_layer.flags & 0x04: flags.append("RST")
    if tcp_layer.flags & 0x08: flags.append("PSH")
    if tcp_layer.flags & 0x10: flags.append("ACK")
    if tcp_layer.flags & 0x20: flags.append("URG")
    return "|".join(flags) if flags else "NONE"

# ──────────────────────────────────────────────
# CORE: Packet classification by size
# ──────────────────────────────────────────────
def classify_size(length):
    """Bucket packet length for statistics."""
    if length < 64:          return "<64"
    if length <= 127:        return "64-127"
    if length <= 511:        return "128-511"
    if length <= 1023:       return "512-1023"
    if length <= 1518:       return "1024-1518"
    return ">1518"

# ──────────────────────────────────────────────
# CORE: Packet handler — called per-packet, zero delay
# ──────────────────────────────────────────────
def handle_packet(pkt):
    """Process a single captured packet — fast path."""
    stats["total"] += 1

    # ── Layer 2 ──
    if Ether in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        eth_type = pkt[Ether].type
    else:
        src_mac = dst_mac = "N/A"
        eth_type = 0

    # ── Layer 3 ──
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        p_len = pkt[IP].len
        proto = proto_name(pkt)
        stats["by_proto"][proto] += 1
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        ttl = pkt[IPv6].hlim
        p_len = pkt[IPv6].plen + 40  # IPv6 fixed header
        proto = proto_name(pkt)
        stats["by_proto"][proto] += 1
    elif ARP in pkt:
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        ttl = 0
        p_len = 42  # ARP fixed size
        proto = "ARP"
        stats["by_proto"]["ARP"] += 1
    else:
        src_ip = dst_ip = "N/A"
        ttl = 0
        p_len = len(pkt)
        proto = "OTHER"
        stats["by_proto"]["OTHER"] += 1

    # Size classification
    stats["by_size"][classify_size(p_len)] += 1

    # ── Layer 4 ──
    src_port = dst_port = 0
    tcp_flags = udp_len = ""

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        tcp_flags = tcp_flags_str(pkt[TCP])
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        udp_len = pkt[UDP].len

    # ── Application layer (DNS / Raw / ICMP) ──
    app_info = ""
    if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
        try:
            qname = pkt[DNS].qd.qname.decode(errors="replace")
            app_info = f"  DNS Query: {qname}"
        except Exception:
            app_info = "  DNS Query"
    elif DNS in pkt and pkt[DNS].qr == 1:  # DNS response
        app_info = "  DNS Response"
    elif ICMP in pkt:
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        type_names = {0: "Echo Reply", 3: "Dest Unreach", 8: "Echo Request", 11: "TTL Exceeded"}
        app_info = f"  ICMP: {type_names.get(icmp_type, f'Type-{icmp_type}')} (code={icmp_code})"
    elif Raw in pkt:
        payload = safe_payload(bytes(pkt[Raw]))
        app_info = f"  Payload: {payload}"

    # ── Assemble display line ──
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = (
        f"[{timestamp}] {proto:6s} | "
        f"{src_ip:15s}:{src_port:<5d} → {dst_ip:15s}:{dst_port:<5d} | "
        f"TTL={ttl:<3d} | Size={p_len:<5d}"
    )
    if tcp_flags:
        line += f" | Flags={tcp_flags:15s}"
    line += app_info

    # Atomic write to stdout (GIL-protected in CPython)
    print(line, flush=True)

# ──────────────────────────────────────────────
# DISPLAY: Live statistics (called on Ctrl+C)
# ──────────────────────────────────────────────
def show_stats():
    """Print summary statistics."""
    elapsed = time.time() - stats["start_time"]
    print("\n" + "=" * 60)
    print(f"  CAPTURE SUMMARY")
    print(f"  Duration: {elapsed:.2f}s")
    print(f"  Total packets: {stats['total']}")
    if elapsed > 0:
        print(f"  Avg rate: {stats['total']/elapsed:.1f} pkt/s")
    print(f"\n  ── Per Protocol ──")
    for proto, count in sorted(stats["by_proto"].items(), key=lambda x: -x[1]):
        print(f"    {proto:6s}: {count}")
    print(f"\n  ── Packet Size Distribution ──")
    for bucket, count in sorted(stats["by_size"].items()):
        bar = "█" * min(count, 60)
        print(f"    {bucket:10s}: {count:5d}  {bar}")
    print("=" * 60)

# ──────────────────────────────────────────────
# SIGNAL: Graceful shutdown
# ──────────────────────────────────────────────
def signal_handler(sig, frame):
    print("\n[!] Capture interrupted. Generating summary...")
    show_stats()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="High-performance network packet sniffer (Scapy-based)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 %(prog)s -i eth0
  sudo python3 %(prog)s -i wlan0 -c 500
  sudo python3 %(prog)s -i any -f "tcp port 80"
  sudo python3 %(prog)s -i eth0 -o capture.pcap
        """,
    )
    parser.add_argument("-i", "--interface", default=conf.iface,
                        help="Network interface to sniff on (default: %(default)s)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter (e.g., 'tcp port 80', 'udp', 'icmp')")
    parser.add_argument("-o", "--output", default="",
                        help="Save packets to .pcap file")
    parser.add_argument("--no-stats", action="store_true",
                        help="Skip final statistics display")
    args = parser.parse_args()

    # Validate interface
    from scapy.all import get_if_list
    available = get_if_list()
    if args.interface not in available and args.interface != "any":
        print(f"[!] Interface '{args.interface}' not found.")
        print(f"    Available: {', '.join(available)}")
        sys.exit(1)

    print(f"[*] Network Sniffer — Kali Linux")
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Filter:    {args.filter or '(none)'}")
    print(f"[*] Count:     {args.count if args.count else 'infinite'}")
    print(f"[*] Output:    {args.output or '(none)'}")
    print(f"[*] Promiscuous mode: ON")
    print(f"[*] Press Ctrl+C to stop\n")

    stats["start_time"] = time.time()

    # ── Sniff with or without count ──
    kwargs = {
        "iface": args.interface,
        "prn": handle_packet,
        "store": False,           # Don't keep packets in memory — zero overhead
    }
    if args.filter:
        kwargs["filter"] = args.filter
    if args.count:
        kwargs["count"] = args.count

    try:
        pkts = sniff(**kwargs)
    except PermissionError:
        print("[!] Permission denied. Run with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Capture error: {e}")
        sys.exit(1)

    # ── Save to pcap if requested ──
    if args.output:
        from scapy.all import wrpcap
        wrpcap(args.output, pkts)
        print(f"[*] Saved {len(pkts)} packets to {args.output}")

    # ── Show stats ──
    if not args.no_stats:
        show_stats()

if __name__ == "__main__":
    main()
