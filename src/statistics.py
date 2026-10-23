"""
statistics.py
--------------
Maintains running protocol statistics (Total / TCP / UDP / ICMP / OTHER counts)
for captured packets, and provides distribution data formatted for charts.
"""


class PacketStatistics:
    """Tracks packet counts per network protocol."""

    def __init__(self):
        self.counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}

    def add_packet(self, protocol: str):
        """
        Increment the counter for the given protocol.
        Falls back to 'OTHER' for anything not TCP/UDP/ICMP.

        Args:
            protocol: Protocol string (e.g. 'TCP', 'UDP', 'ICMP', 'OTHER').
        """
        proto_clean = str(protocol).strip().upper() if protocol else "OTHER"
        if proto_clean in ("TCP", "UDP", "ICMP"):
            self.counts[proto_clean] += 1
        else:
            self.counts["OTHER"] += 1

    def reset(self):
        """Reset all protocol counters back to zero."""
        for key in self.counts:
            self.counts[key] = 0

    def total(self) -> int:
        """Return the sum of all captured packet counts."""
        return sum(self.counts.values())

    def as_dict(self) -> dict:
        """
        Return a summary dictionary including 'Total' plus each protocol count.
        Example: {'Total': 10, 'TCP': 6, 'UDP': 2, 'ICMP': 1, 'OTHER': 1}
        """
        data = {"Total": self.total()}
        data.update(self.counts)
        return data

    def get_protocol_distribution(self) -> tuple[list[str], list[int]]:
        """
        Return parallel lists of labels and count values suitable for plotting.

        Returns:
            tuple: (['TCP', 'UDP', 'ICMP', 'OTHER'], [counts...])
        """
        labels = ["TCP", "UDP", "ICMP", "OTHER"]
        counts = [self.counts[label] for label in labels]
        return labels, counts
