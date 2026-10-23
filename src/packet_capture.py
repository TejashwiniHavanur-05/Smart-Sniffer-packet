"""
packet_capture.py
------------------
Handles live packet capture using Scapy, running on a background daemon thread
so the Tkinter GUI remains completely responsive.

Educational use only: only capture traffic on networks/interfaces you are
authorized to monitor. This module only reads packet header metadata
(IPs, protocol, size, time) — it never inspects or stores payload data.
"""

import sys
import threading

try:
    from scapy.all import sniff
    from scapy.config import conf
except ImportError:
    sniff = None
    conf = None

from src.packet_analyzer import extract_packet_info


def is_live_capture_available() -> tuple[bool, str]:
    """
    Check if live packet capture is supported on the current host.
    On Windows, Scapy requires Npcap (or WinPcap API compatibility).

    Returns:
        tuple[bool, str]: (is_available, error_message_if_not)
    """
    if sniff is None or conf is None:
        return (
            False,
            "Scapy library is not installed or not available. "
            "You can use Offline Demo Mode with the sample dataset.",
        )

    # On Windows, check if pcap provider is available
    if sys.platform.startswith("win"):
        if hasattr(conf, "use_pcap") and not conf.use_pcap:
            return (
                False,
                "Live packet capture is unavailable because Npcap is not installed. "
                "You can use Offline Demo Mode with the sample dataset.",
            )

    return True, ""


class PacketCaptureEngine:
    """
    Wraps Scapy's sniff() in a background daemon thread and reports parsed
    packet info back to the GUI via callbacks.
    """

    def __init__(self, on_packet_captured, on_error=None, iface=None):
        """
        Args:
            on_packet_captured: callback(packet_info: dict) -> None
                Called once per captured packet with fields like
                {"time": ..., "src_ip": ..., "dst_ip": ..., "protocol": ..., "size": ...}
            on_error: callback(message: str) -> None
                Called if capture cannot start/continue (e.g. permissions, missing Npcap).
            iface: Optional network interface name to sniff on.
        """
        self.on_packet_captured = on_packet_captured
        self.on_error = on_error
        self.iface = iface

        self._stop_event = threading.Event()
        self._thread = None
        self.is_running = False

    def start(self):
        """
        Start sniffing on a background thread.
        Verifies prerequisites and starts capture without freezing the GUI.
        """
        if self.is_running:
            return

        available, reason = is_live_capture_available()
        if not available:
            if self.on_error:
                self.on_error(reason)
            return

        self._stop_event.clear()
        self.is_running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="PacketCaptureThread")
        self._thread.start()

    def stop(self):
        """Signal the sniff loop to stop safely."""
        self._stop_event.set()
        self.is_running = False

    def _run(self):
        """The actual capture loop running on the background thread."""
        if sniff is None:
            if self.on_error:
                self.on_error("Scapy is not installed or not available on this system.")
            self.is_running = False
            return

        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda pkt: self._stop_event.is_set(),
            )
        except PermissionError:
            if self.on_error:
                self.on_error(
                    "Permission denied. Packet capture requires elevated privileges. "
                    "Please run your terminal or Python as Administrator."
                )
        except (RuntimeError, OSError) as e:
            err_str = str(e).lower()
            if "winpcap" in err_str or "npcap" in err_str or "pcap" in err_str or "layer 2" in err_str:
                msg = (
                    "Live packet capture is unavailable because Npcap is not installed. "
                    "You can use Offline Demo Mode with the sample dataset."
                )
            else:
                msg = f"Network interface error: {e}. You can use Offline Demo Mode with the sample dataset."
            if self.on_error:
                self.on_error(msg)
        except Exception as e:
            err_str = str(e).lower()
            if "winpcap" in err_str or "npcap" in err_str or "pcap" in err_str:
                msg = (
                    "Live packet capture is unavailable because Npcap is not installed. "
                    "You can use Offline Demo Mode with the sample dataset."
                )
            else:
                msg = f"Packet capture stopped due to an error: {e}"
            if self.on_error:
                self.on_error(msg)
        finally:
            self.is_running = False

    def _handle_packet(self, packet):
        """
        Process a single raw packet, extract header metadata,
        and notify the listener callback.
        """
        try:
            info = extract_packet_info(packet)
            if info is not None:
                self.on_packet_captured(info)
        except Exception:
            # Protect thread from crashing on single malformed packet
            pass
