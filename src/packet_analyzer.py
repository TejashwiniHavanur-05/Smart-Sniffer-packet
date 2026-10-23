"""
packet_analyzer.py
--------------------
Extracts useful, header-only information from a raw Scapy packet:
    - Time of capture
    - Source IP
    - Destination IP
    - Protocol (TCP / UDP / ICMP / OTHER)
    - Packet size (bytes)

This module intentionally does NOT read or store any payload or application data
— only header metadata needed for traffic and protocol analysis.
"""

from datetime import datetime

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
except ImportError:
    IP = TCP = UDP = ICMP = None

try:
    from scapy.layers.inet6 import IPv6
except ImportError:
    IPv6 = None


def extract_packet_info(packet):
    """
    Extract Time, Source IP, Destination IP, Protocol, and Size from a
    single captured Scapy packet.

    Args:
        packet: Scapy raw packet object.

    Returns:
        dict with keys: time, src_ip, dst_ip, protocol, size
        or None if the packet should be skipped (e.g. non-IP packets).
    """
    if IP is None:
        return None

    try:
        # Check for IPv4 or IPv6 layer
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        elif IPv6 is not None and IPv6 in packet:
            ip_layer = packet[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
        else:
            # Skip non-IP packets (e.g. raw ARP, spanning tree, etc.)
            return None

        # Determine transport/network protocol
        if TCP is not None and TCP in packet:
            protocol = "TCP"
        elif UDP is not None and UDP in packet:
            protocol = "UDP"
        elif ICMP is not None and ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "OTHER"

        capture_time = datetime.now().strftime("%H:%M:%S")
        size = len(packet)

        return {
            "time": capture_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "size": size,
        }
    except Exception:
        # Protect against malformed or truncated packets
        return None


def format_row_for_table(packet_info: dict) -> tuple:
    """
    Format a packet_info dictionary into a tuple suitable for display in
    the Tkinter Treeview table.

    Args:
        packet_info: dict with time, src_ip, dst_ip, protocol, size.

    Returns:
        tuple: (Time, Source IP, Destination IP, Protocol, Size String)
    """
    if not packet_info:
        return ("", "", "", "", "")

    size_val = packet_info.get("size", 0)
    return (
        str(packet_info.get("time", "")),
        str(packet_info.get("src_ip", "")),
        str(packet_info.get("dst_ip", "")),
        str(packet_info.get("protocol", "")),
        f"{size_val} Bytes",
    )
