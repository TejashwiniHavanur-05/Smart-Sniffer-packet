"""
Smart Packet Sniffer and Protocol Analyzer
--------------------------------------------
Application Entry Point.

Educational use only: run this only on your own computer/network or a
network you are explicitly authorized to monitor.
"""

import sys
import tkinter as tk

from src.gui import PacketSnifferApp


def main():
    """Launch the Smart Packet Sniffer desktop application."""
    root = tk.Tk()
    root.title("Smart Packet Sniffer and Protocol Analyzer")
    root.geometry("1020x680")

    app = PacketSnifferApp(root)
    app.pack_or_grid()

    root.mainloop()


if __name__ == "__main__":
    main()
