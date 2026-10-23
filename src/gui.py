"""
gui.py
-------
Tkinter GUI for the Smart Packet Sniffer and Protocol Analyzer.

Provides:
  - Top header with project title and purpose
  - Control area: Start Capture, Stop Capture, Load Demo Data, Clear, Save CSV, Show Graph
  - Protocol filter dropdown (ALL, TCP, UDP, ICMP, OTHER)
  - Main packet table (scrollable Treeview): Time, Source IP, Destination IP, Protocol, Size
  - Live statistics display cards (Total, TCP, UDP, ICMP, OTHER)
  - Status bar tracking live capture, offline demo, and error states
  - Integrated Matplotlib protocol distribution chart popup
"""

import csv
import os
import tkinter as tk
from tkinter import ttk, messagebox

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from src.packet_capture import PacketCaptureEngine, is_live_capture_available
from src.packet_analyzer import format_row_for_table
from src.statistics import PacketStatistics
from src.csv_export import export_to_csv

# Resolve project root path reliably
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SAMPLE_PATH = os.path.join(PROJECT_ROOT, "data", "sample_packets.csv")


class PacketSnifferApp:
    """Main Application GUI controller."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Smart Packet Sniffer and Protocol Analyzer")
        self.root.geometry("1020x680")
        self.root.minsize(850, 550)

        # State management
        self.captured_packets = []          # List of packet dicts
        self.stats = PacketStatistics()      # Protocol counters
        self.capture_engine = None          # PacketCaptureEngine instance
        self.current_filter = tk.StringVar(value="ALL")
        self.status_var = tk.StringVar(value="Status: Ready | Select 'Start Capture' or 'Load Demo Data'")

        self._configure_styles()
        self._build_layout()
        self._bind_events()

    def _configure_styles(self):
        """Configure ttk visual styles for a clean, modern desktop presentation."""
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Color palette
        self.bg_color = "#f4f6f9"
        self.header_bg = "#1e293b"
        self.card_bg = "#ffffff"
        self.primary_blue = "#2563eb"
        self.accent_green = "#059669"
        self.accent_red = "#dc2626"
        self.accent_amber = "#d97706"
        self.text_dark = "#0f172a"
        self.text_muted = "#64748b"

        self.root.configure(bg=self.bg_color)

        # Treeview styling
        self.style.configure(
            "Treeview",
            background="#ffffff",
            foreground=self.text_dark,
            fieldbackground="#ffffff",
            rowheight=26,
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Treeview.Heading",
            background="#e2e8f0",
            foreground=self.text_dark,
            font=("Segoe UI", 9, "bold"),
            padding=4,
        )
        self.style.map("Treeview", background=[("selected", "#bfdbfe")], foreground=[("selected", "#1e3a8a")])

        # Button styling
        self.style.configure("TButton", font=("Segoe UI", 9, "bold"), padding=6)

    def _build_layout(self):
        """Construct the overall layout structure."""
        self._build_title_area()
        self._build_control_area()
        self._build_filter_area()
        self._build_table_area()
        self._build_statistics_area()
        self._build_status_bar()

    def _build_title_area(self):
        """Top banner with project title and description."""
        title_frame = tk.Frame(self.root, bg=self.header_bg, padx=16, pady=12)
        title_frame.pack(fill="x")

        main_title = tk.Label(
            title_frame,
            text="SMART PACKET SNIFFER & PROTOCOL ANALYZER",
            font=("Segoe UI", 15, "bold"),
            fg="#ffffff",
            bg=self.header_bg,
        )
        main_title.pack(anchor="w")

        subtitle = tk.Label(
            title_frame,
            text="Computer Networks Mini Project • Real-Time & Offline Protocol Monitoring (Header Inspection Only)",
            font=("Segoe UI", 9),
            fg="#cbd5e1",
            bg=self.header_bg,
        )
        subtitle.pack(anchor="w", pady=(2, 0))

    def _build_control_area(self):
        """Button controls for capturing, loading demo, clearing, saving, and charting."""
        control_frame = tk.Frame(self.root, bg=self.bg_color, pady=8, padx=12)
        control_frame.pack(fill="x")

        # Action Buttons
        self.start_button = tk.Button(
            control_frame,
            text="▶ Start Capture",
            command=self.on_start_capture,
            bg=self.accent_green,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="raised",
            cursor="hand2",
        )
        self.start_button.grid(row=0, column=0, padx=(0, 6), pady=2)

        self.stop_button = tk.Button(
            control_frame,
            text="⏹ Stop Capture",
            command=self.on_stop_capture,
            bg="#94a3b8",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            state=tk.DISABLED,
            relief="raised",
            cursor="hand2",
        )
        self.stop_button.grid(row=0, column=1, padx=6, pady=2)

        self.demo_button = tk.Button(
            control_frame,
            text="📁 Load Demo Data",
            command=self.on_load_demo,
            bg=self.primary_blue,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="raised",
            cursor="hand2",
        )
        self.demo_button.grid(row=0, column=2, padx=6, pady=2)

        self.clear_button = tk.Button(
            control_frame,
            text="🧹 Clear",
            command=self.on_clear,
            bg="#64748b",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="raised",
            cursor="hand2",
        )
        self.clear_button.grid(row=0, column=3, padx=6, pady=2)

        self.save_button = tk.Button(
            control_frame,
            text="💾 Save CSV",
            command=self.on_save_csv,
            bg="#475569",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="raised",
            cursor="hand2",
        )
        self.save_button.grid(row=0, column=4, padx=6, pady=2)

        self.graph_button = tk.Button(
            control_frame,
            text="📊 Show Graph",
            command=self.on_show_graph,
            bg=self.accent_amber,
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=4,
            relief="raised",
            cursor="hand2",
        )
        self.graph_button.grid(row=0, column=5, padx=6, pady=2)

    def _build_filter_area(self):
        """Dropdown filter controls."""
        filter_frame = tk.Frame(self.root, bg=self.bg_color, padx=14, pady=2)
        filter_frame.pack(fill="x")

        lbl = tk.Label(
            filter_frame,
            text="Filter by Protocol:",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_color,
            fg=self.text_dark,
        )
        lbl.pack(side="left", padx=(0, 8))

        self.filter_dropdown = ttk.Combobox(
            filter_frame,
            textvariable=self.current_filter,
            values=["ALL", "TCP", "UDP", "ICMP", "OTHER"],
            state="readonly",
            width=12,
            font=("Segoe UI", 9),
        )
        self.filter_dropdown.pack(side="left")
        self.filter_dropdown.bind("<<ComboboxSelected>>", self.on_filter_changed)

        self.filter_info_label = tk.Label(
            filter_frame,
            text="(Showing all captured packets)",
            font=("Segoe UI", 8, "italic"),
            bg=self.bg_color,
            fg=self.text_muted,
        )
        self.filter_info_label.pack(side="left", padx=(10, 0))

    def _build_table_area(self):
        """Scrollable packet table display."""
        table_container = tk.Frame(self.root, bg=self.bg_color, padx=12, pady=6)
        table_container.pack(fill="both", expand=True)

        columns = ("time", "src_ip", "dst_ip", "protocol", "size")
        self.table = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = {
            "time": "Time",
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "protocol": "Protocol",
            "size": "Size",
        }
        col_widths = {
            "time": 130,
            "src_ip": 220,
            "dst_ip": 220,
            "protocol": 140,
            "size": 130,
        }

        for col in columns:
            self.table.heading(col, text=headings[col], anchor="center")
            self.table.column(col, width=col_widths[col], anchor="center", stretch=True)

        # Alternating row tag colors
        self.table.tag_configure("even", background="#ffffff")
        self.table.tag_configure("odd", background="#f8fafc")
        self.table.tag_configure("tcp", foreground="#1e40af")
        self.table.tag_configure("udp", foreground="#065f46")
        self.table.tag_configure("icmp", foreground="#9a3412")
        self.table.tag_configure("other", foreground="#475569")

        # Scrollbars
        vsb = ttk.Scrollbar(table_container, orient="vertical", command=self.table.yview)
        hsb = ttk.Scrollbar(table_container, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        table_container.rowconfigure(0, weight=1)
        table_container.columnconfigure(0, weight=1)

    def _build_statistics_area(self):
        """Protocol statistics badges."""
        stats_outer = tk.LabelFrame(
            self.root,
            text=" Protocol Statistics ",
            font=("Segoe UI", 9, "bold"),
            bg=self.bg_color,
            fg=self.text_dark,
            padx=12,
            pady=6,
        )
        stats_outer.pack(fill="x", padx=12, pady=(0, 6))

        stats_inner = tk.Frame(stats_outer, bg=self.bg_color)
        stats_inner.pack(fill="x")

        def make_stat_badge(parent, label_text, fg_color):
            badge = tk.Frame(parent, bg="#ffffff", bd=1, relief="solid", padx=10, pady=4)
            badge.pack(side="left", padx=8, expand=True, fill="x")
            lbl = tk.Label(badge, text=label_text, font=("Segoe UI", 10, "bold"), fg=fg_color, bg="#ffffff")
            lbl.pack()
            return lbl

        self.total_label = make_stat_badge(stats_inner, "Total: 0", self.text_dark)
        self.tcp_label = make_stat_badge(stats_inner, "TCP: 0", "#2563eb")
        self.udp_label = make_stat_badge(stats_inner, "UDP: 0", "#059669")
        self.icmp_label = make_stat_badge(stats_inner, "ICMP: 0", "#d97706")
        self.other_label = make_stat_badge(stats_inner, "OTHER: 0", "#64748b")

    def _build_status_bar(self):
        """Bottom status bar displaying current operational state."""
        status_bar = tk.Frame(self.root, bg="#e2e8f0", bd=1, relief="sunken", padx=8, pady=4)
        status_bar.pack(side="bottom", fill="x")

        status_lbl = tk.Label(
            status_bar,
            textvariable=self.status_var,
            font=("Segoe UI", 8),
            bg="#e2e8f0",
            fg=self.text_dark,
            anchor="w",
        )
        status_lbl.pack(side="left", fill="x")

    def _bind_events(self):
        """Ensure clean shutdown when window is closed."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def pack_or_grid(self):
        """Lifecycle hook called after construction to finalize initial UI state."""
        self._refresh_stats_labels()

    # ------------------------------------------------------------------
    # Button Actions
    # ------------------------------------------------------------------
    def on_start_capture(self):
        """Handle Start Capture action with graceful Npcap and permission handling."""
        if self.capture_engine and self.capture_engine.is_running:
            return

        available, reason = is_live_capture_available()
        if not available:
            messagebox.showwarning("Live Capture Unavailable", reason)
            self.status_var.set("Notice: Npcap not installed. Use 'Load Demo Data' for offline evaluation.")
            return

        try:
            self.capture_engine = PacketCaptureEngine(
                on_packet_captured=self._on_packet_captured,
                on_error=self._on_capture_error,
            )
            self.capture_engine.start()

            # Update button states
            self.start_button.config(state=tk.DISABLED, bg="#94a3b8")
            self.stop_button.config(state=tk.NORMAL, bg=self.accent_red)
            self.demo_button.config(state=tk.DISABLED)
            self.status_var.set("Status: Capturing live network packets in real time...")
        except Exception as e:
            self._handle_capture_error(f"Failed to start packet capture: {e}")

    def on_stop_capture(self):
        """Safely halt the background capture engine."""
        if self.capture_engine and self.capture_engine.is_running:
            self.capture_engine.stop()

        self.start_button.config(state=tk.NORMAL, bg=self.accent_green)
        self.stop_button.config(state=tk.DISABLED, bg="#94a3b8")
        self.demo_button.config(state=tk.NORMAL)
        self.status_var.set(f"Status: Capture stopped | Total packets captured: {self.stats.total()}")

    def on_load_demo(self):
        """
        Load offline demonstration records from sample_packets.csv.
        Allows testing all features without Npcap or elevated privileges.
        """
        if self.capture_engine and self.capture_engine.is_running:
            messagebox.showinfo("Capture in Progress", "Please stop live capture before loading demo data.")
            return

        if not os.path.exists(DEFAULT_SAMPLE_PATH):
            messagebox.showerror(
                "Demo File Missing",
                f"Could not locate sample dataset at:\n{DEFAULT_SAMPLE_PATH}\n\n"
                "Please verify the data/sample_packets.csv file exists.",
            )
            return

        try:
            loaded_count = 0
            with open(DEFAULT_SAMPLE_PATH, mode="r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for raw_row in reader:
                    # Normalize keys (handle both Title Case and lowercase)
                    row_clean = {k.strip().lower(): v.strip() for k, v in raw_row.items() if k}
                    pkt_info = {
                        "time": row_clean.get("time", ""),
                        "src_ip": row_clean.get("source ip", row_clean.get("src_ip", "")),
                        "dst_ip": row_clean.get("destination ip", row_clean.get("dst_ip", "")),
                        "protocol": row_clean.get("protocol", "OTHER").upper(),
                        "size": int(row_clean.get("size", 0)) if row_clean.get("size", "0").isdigit() else 0,
                    }
                    self.captured_packets.append(pkt_info)
                    self.stats.add_packet(pkt_info["protocol"])
                    loaded_count += 1

            # Refresh table display with current filter
            self._render_table()
            self._refresh_stats_labels()
            self.status_var.set(
                f"Status: Offline Demo Mode active | Loaded {loaded_count} packets from sample dataset"
            )
            messagebox.showinfo(
                "Offline Demo Loaded",
                f"Successfully loaded {loaded_count} educational sample packets!\n\n"
                "You can now test Protocol Filtering, Statistics, Graphs, and CSV Export.",
            )
        except Exception as e:
            messagebox.showerror("Error Reading Demo File", f"Failed to load sample dataset:\n{e}")

    def on_clear(self):
        """Reset captured records, counters, table, and active filters."""
        if self.capture_engine and self.capture_engine.is_running:
            messagebox.showinfo("Capture in Progress", "Please stop live capture before clearing data.")
            return

        self.captured_packets.clear()
        self.stats.reset()
        for item in self.table.get_children():
            self.table.delete(item)

        self.current_filter.set("ALL")
        self.filter_info_label.config(text="(Showing all captured packets)")
        self._refresh_stats_labels()
        self.status_var.set("Status: Ready | Data cleared")

    def on_save_csv(self):
        """Export captured session to a timestamped CSV report in reports/."""
        if not self.captured_packets:
            messagebox.showwarning(
                "No Data to Export",
                "There are no captured packets to save.\n\n"
                "Please capture live packets or click 'Load Demo Data' first.",
            )
            return

        try:
            saved_path = export_to_csv(self.captured_packets)
            self.status_var.set(f"Status: Report saved successfully to {os.path.basename(saved_path)}")
            messagebox.showinfo(
                "Export Complete",
                f"Packet report successfully exported!\n\nLocation:\n{saved_path}\n\n"
                f"Total Records: {len(self.captured_packets)}",
            )
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to save CSV report:\n{e}")

    def on_show_graph(self):
        """Open a Matplotlib visualization dialog displaying protocol distribution."""
        if self.stats.total() == 0:
            messagebox.showwarning(
                "No Data Available",
                "No packet statistics available to plot.\n\n"
                "Please capture packets or load demo data first.",
            )
            return

        try:
            labels, counts = self.stats.get_protocol_distribution()
            # Filter non-zero categories for pie chart if desired, or show bar chart
            chart_window = tk.Toplevel(self.root)
            chart_window.title("Protocol Distribution Analysis")
            chart_window.geometry("640x520")
            chart_window.minsize(500, 400)
            chart_window.configure(bg=self.bg_color)

            # Matplotlib figure
            fig, (ax_bar, ax_pie) = plt.subplots(1, 2, figsize=(8, 4.5), dpi=100)
            fig.patch.set_facecolor("#f8fafc")

            colors = ["#2563eb", "#059669", "#d97706", "#64748b"]

            # Bar Chart
            bars = ax_bar.bar(labels, counts, color=colors, edgecolor="#0f172a", width=0.6)
            ax_bar.set_title("Packet Counts by Protocol", fontsize=11, fontweight="bold", pad=10)
            ax_bar.set_ylabel("Number of Packets", fontsize=9)
            ax_bar.set_facecolor("#ffffff")
            ax_bar.grid(axis="y", linestyle="--", alpha=0.5)

            for bar in bars:
                height = bar.get_height()
                ax_bar.annotate(
                    f"{height}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                    fontweight="bold",
                )

            # Pie Chart
            total_pkts = sum(counts)
            if total_pkts > 0:
                ax_pie.pie(
                    counts,
                    labels=labels,
                    autopct=lambda pct: f"{pct:.1f}%" if pct > 0 else "",
                    colors=colors,
                    startangle=140,
                    textprops={"fontsize": 9, "fontweight": "bold"},
                )
                ax_pie.set_title("Protocol Share (%)", fontsize=11, fontweight="bold", pad=10)
            else:
                ax_pie.text(0.5, 0.5, "No Data", ha="center", va="center")

            fig.tight_layout()

            # Embed figure inside Tkinter Toplevel
            canvas = FigureCanvasTkAgg(fig, master=chart_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

            # Close button
            close_btn = tk.Button(
                chart_window,
                text="Close Window",
                command=chart_window.destroy,
                font=("Segoe UI", 9, "bold"),
                bg="#475569",
                fg="#ffffff",
                padx=12,
                pady=4,
            )
            close_btn.pack(pady=(0, 10))
        except Exception as e:
            messagebox.showerror("Graph Error", f"Failed to generate protocol graph:\n{e}")

    def on_filter_changed(self, event=None):
        """Filter table view by protocol without modifying recorded session data."""
        filter_val = self.current_filter.get().strip().upper()
        if filter_val == "ALL":
            self.filter_info_label.config(text="(Showing all captured packets)")
        else:
            self.filter_info_label.config(text=f"(Showing only {filter_val} packets)")

        self._render_table()

    # ------------------------------------------------------------------
    # Capture Engine Callbacks (Thread-Safe)
    # ------------------------------------------------------------------
    def _on_packet_captured(self, packet_info: dict):
        """
        Invoked from the background sniffing thread.
        Dispatches processing to the Tkinter event loop using root.after().
        """
        self.root.after(0, self._process_captured_packet, packet_info)

    def _process_captured_packet(self, packet_info: dict):
        """Runs safely on the Tkinter main thread."""
        self.captured_packets.append(packet_info)
        proto = packet_info.get("protocol", "OTHER")
        self.stats.add_packet(proto)

        # Check if visible under current filter
        active_filter = self.current_filter.get().strip().upper()
        if active_filter == "ALL" or proto.upper() == active_filter:
            row_data = format_row_for_table(packet_info)
            row_idx = len(self.table.get_children())
            tag_name = proto.lower() if proto.lower() in ("tcp", "udp", "icmp", "other") else "other"
            parity_tag = "even" if row_idx % 2 == 0 else "odd"
            item_id = self.table.insert("", "end", values=row_data, tags=(parity_tag, tag_name))
            # Auto-scroll to latest
            self.table.see(item_id)

        self._refresh_stats_labels()
        self.status_var.set(
            f"Status: Live Capturing... | Total: {self.stats.total()} (TCP: {self.stats.counts['TCP']}, "
            f"UDP: {self.stats.counts['UDP']}, ICMP: {self.stats.counts['ICMP']}, OTHER: {self.stats.counts['OTHER']})"
        )

    def _on_capture_error(self, message: str):
        """Invoked from background thread upon capture error."""
        self.root.after(0, self._handle_capture_error, message)

    def _handle_capture_error(self, message: str):
        """Reset button states and alert user with friendly explanation."""
        self.start_button.config(state=tk.NORMAL, bg=self.accent_green)
        self.stop_button.config(state=tk.DISABLED, bg="#94a3b8")
        self.demo_button.config(state=tk.NORMAL)
        self.status_var.set(f"Notice: {message}")
        messagebox.showwarning("Capture Notice", message)

    # ------------------------------------------------------------------
    # Rendering Helpers
    # ------------------------------------------------------------------
    def _render_table(self):
        """Repopulate the Treeview table with packets matching current filter."""
        for item in self.table.get_children():
            self.table.delete(item)

        active_filter = self.current_filter.get().strip().upper()
        row_idx = 0
        for pkt in self.captured_packets:
            proto = str(pkt.get("protocol", "OTHER")).upper()
            if active_filter == "ALL" or proto == active_filter:
                row_data = format_row_for_table(pkt)
                tag_name = proto.lower() if proto.lower() in ("tcp", "udp", "icmp", "other") else "other"
                parity_tag = "even" if row_idx % 2 == 0 else "odd"
                self.table.insert("", "end", values=row_data, tags=(parity_tag, tag_name))
                row_idx += 1

    def _refresh_stats_labels(self):
        """Update protocol counts on the statistics banner."""
        data = self.stats.as_dict()
        self.total_label.config(text=f"Total: {data.get('Total', 0)}")
        self.tcp_label.config(text=f"TCP: {data.get('TCP', 0)}")
        self.udp_label.config(text=f"UDP: {data.get('UDP', 0)}")
        self.icmp_label.config(text=f"ICMP: {data.get('ICMP', 0)}")
        self.other_label.config(text=f"OTHER: {data.get('OTHER', 0)}")

    def on_closing(self):
        """Cleanly terminate background thread before closing window."""
        if self.capture_engine and self.capture_engine.is_running:
            self.capture_engine.stop()
        self.root.destroy()
