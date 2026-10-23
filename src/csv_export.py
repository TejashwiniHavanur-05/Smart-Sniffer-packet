"""
csv_export.py
---------------
Handles saving captured packet data to a CSV report in the reports/ folder.
"""

import os
from datetime import datetime

REPORTS_DIR = "reports"


def generate_default_filename(directory: str = REPORTS_DIR) -> str:
    """
    Generate a non-colliding timestamped CSV filepath inside the specified directory.
    Format: packet_report_YYYYMMDD_HHMMSS.csv

    Args:
        directory: Destination folder path (defaults to 'reports').

    Returns:
        str: Absolute or relative filepath for the new CSV report.
    """
    os.makedirs(directory, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"packet_report_{timestamp}.csv"
    target_path = os.path.join(directory, base_name)

    counter = 1
    while os.path.exists(target_path):
        target_path = os.path.join(directory, f"packet_report_{timestamp}_{counter}.csv")
        counter += 1

    return target_path


def export_to_csv(packets: list, filepath: str = None) -> str:
    """
    Save a list of packet_info dictionaries to a CSV file.

    Args:
        packets: List of dicts, each with keys (time, src_ip, dst_ip, protocol, size).
        filepath: Optional custom destination path. If None, a timestamped path is used.

    Returns:
        str: The saved filepath.

    Raises:
        ValueError: If the packet list is empty.
        IOError: If saving the file fails.
    """
    if not packets:
        raise ValueError("No captured packets to export. Please capture packets or load demo data first.")

    if filepath is None:
        filepath = generate_default_filename()
    else:
        target_dir = os.path.dirname(filepath)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)

    # Standardized column mapping
    # Accepts both lowercase and capitalized keys from packet dicts
    rows = []
    for pkt in packets:
        rows.append({
            "Time": pkt.get("time", pkt.get("Time", "")),
            "Source IP": pkt.get("src_ip", pkt.get("Source IP", "")),
            "Destination IP": pkt.get("dst_ip", pkt.get("Destination IP", "")),
            "Protocol": pkt.get("protocol", pkt.get("Protocol", "OTHER")),
            "Size": pkt.get("size", pkt.get("Size", 0)),
        })

    try:
        import pandas as pd
        df = pd.DataFrame(rows, columns=["Time", "Source IP", "Destination IP", "Protocol", "Size"])
        df.to_csv(filepath, index=False)
    except Exception:
        # Fallback to standard library csv module if pandas fails
        import csv
        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Time", "Source IP", "Destination IP", "Protocol", "Size"])
            writer.writeheader()
            writer.writerows(rows)

    return filepath
