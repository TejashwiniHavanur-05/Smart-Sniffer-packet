# Development Notes & Architectural Guide

This document provides a technical walkthrough of the architectural flows, threading model, and implementation design for the **Smart Packet Sniffer and Protocol Analyzer**.

---

## 1. Packet Capture Flow (`src/packet_capture.py`)

1. **Prerequisite Verification:**
   - Before starting capture, `is_live_capture_available()` verifies that Scapy is imported and, on Windows hosts, verifies that `conf.use_pcap` is active.
   - If Npcap or Scapy is absent, the capture engine gracefully triggers the `on_error` callback and aborts startup without throwing an unhandled exception or freezing the application.

2. **Sniffing Loop:**
   - Packet capture is initiated via `scapy.sendrecv.sniff()`.
   - Arguments used:
     - `iface=self.iface`: Targets the default or selected network adapter.
     - `prn=self._handle_packet`: Per-packet handler callback.
     - `store=False`: Prevents accumulating raw packet objects in memory, eliminating memory bloat over prolonged capture sessions.
     - `stop_filter=lambda pkt: self._stop_event.is_set()`: Allows clean termination as soon as `stop()` signals the stop event.

3. **Termination:**
   - Invoking `engine.stop()` signals `self._stop_event.set()`.
   - The Scapy sniff loop detects the condition on the next evaluation and exits cleanly.
   - The `finally` block in `_run()` guarantees `is_running` is reset to `False`.

---

## 2. Packet Analysis Flow (`src/packet_analyzer.py`)

1. **Layer Filtering:**
   - When a packet arrives, `extract_packet_info(packet)` checks for an IP layer (`IP in packet` or `IPv6 in packet`).
   - Non-IP frames (such as raw ARP or LLDP) are safely ignored by returning `None`.

2. **Metadata Extraction:**
   - Header metadata is extracted directly from the Scapy layer:
     - `time`: Generated at reception using `datetime.now().strftime("%H:%M:%S")`.
     - `src_ip`: String representation of `packet[IP].src`.
     - `dst_ip`: String representation of `packet[IP].dst`.
     - `size`: Length of the entire packet frame (`len(packet)`).

3. **Protocol Classification:**
   - Transport layers are checked in order:
     - If `TCP in packet`: protocol is classified as `"TCP"`.
     - If `UDP in packet`: protocol is classified as `"UDP"`.
     - If `ICMP in packet`: protocol is classified as `"ICMP"`.
     - Otherwise: classified as `"OTHER"` (e.g. IGMP, OSPF, GRE, ESP).

4. **Safety Scope:**
   - Payload data (`Raw` or application layers) is never inspected, decoded, or persisted.

---

## 3. Statistics Flow (`src/statistics.py`)

1. **State Tracking:**
   - `PacketStatistics` encapsulates a dictionary of protocol counters:
     `{"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}`.

2. **Incrementation:**
   - When `add_packet(protocol)` is called, the protocol name is normalized to uppercase.
   - If the protocol matches one of the tracked keys, its counter is incremented; otherwise, the `"OTHER"` counter is incremented.

3. **Summary & Distribution:**
   - `total()` returns the sum of all protocol counters.
   - `as_dict()` returns a dictionary containing `"Total"` plus individual protocol counts for updating UI labels.
   - `get_protocol_distribution()` outputs parallel lists `(labels, counts)` ready for Matplotlib charting.

4. **Reset:**
   - `reset()` zeroes all counters upon user request (e.g. "Clear" button).

---

## 4. Threading & Thread Safety Model

Tkinter's GUI event loop is single-threaded and not thread-safe. Modifying Tkinter widgets from a secondary thread causes race conditions, visual glitches, or interpreter crashes.

1. **Worker Thread:**
   - `PacketCaptureEngine` launches `scapy.sniff()` inside a `threading.Thread(target=self._run, daemon=True, name="PacketCaptureThread")`.
   - Being a daemon thread, it will not prevent application exit if the main window is closed.

2. **Cross-Thread Dispatch (`root.after`):**
   - When `PacketCaptureEngine` receives a packet on the sniffing thread, it invokes `self.on_packet_captured(packet_info)`.
   - In `PacketSnifferApp`, `_on_packet_captured()` marshals the work onto the Tkinter main thread:
     ```python
     self.root.after(0, self._process_captured_packet, packet_info)
     ```
   - Tkinter's main loop executes `_process_captured_packet` synchronously on the UI thread, ensuring safe widget updates.

---

## 5. GUI Flow (`src/gui.py`)

1. **Modular Layout:**
   - **Header:** Project title and educational scope banner.
   - **Controls:** Command buttons (`Start Capture`, `Stop Capture`, `Load Demo Data`, `Clear`, `Save CSV`, `Show Graph`).
   - **Filter:** Combobox bound to `<<ComboboxSelected>>` to dynamically filter rows.
   - **Table:** Scrollable `ttk.Treeview` with alternating row colors and protocol-specific text colors.
   - **Statistics:** Live metric cards showing real-time totals.
   - **Status Bar:** Real-time feedback bar at the bottom.

2. **Non-Destructive Filtering:**
   - All captured records are retained in `self.captured_packets`.
   - Changing the filter dropdown clears the visible `Treeview` items and re-populates only the rows matching the filter (`ALL`, `TCP`, `UDP`, `ICMP`, `OTHER`).
   - Protocol statistics cards continuously reflect the entire session's metrics, avoiding distortion during filtering.

3. **Graphing Integration:**
   - `on_show_graph()` queries `self.stats.get_protocol_distribution()`.
   - Spawns a `tk.Toplevel` modal window embedding a Matplotlib figure using `FigureCanvasTkAgg`.
   - Displays side-by-side bar charts and pie charts with clean labels and percentages.

---

## 6. Offline Demo Flow

To ensure complete demonstrability regardless of Npcap availability:
1. `DEFAULT_SAMPLE_PATH` points to `data/sample_packets.csv`.
2. When the user clicks **"Load Demo Data"**:
   - The file is read via Python's `csv.DictReader`.
   - Rows are normalized and converted into packet dictionaries.
   - Each dictionary is added to `self.captured_packets` and passed to `self.stats.add_packet()`.
   - `_render_table()` and `_refresh_stats_labels()` refresh the UI instantly.
3. The demo data can be filtered, plotted, cleared, and exported identically to live captured traffic.

---

## 7. CSV Export Flow (`src/csv_export.py`)

1. **Validation:**
   - Verifies that `packets` is non-empty; displays a friendly warning if empty.

2. **Timestamped Naming:**
   - `generate_default_filename()` constructs `reports/packet_report_YYYYMMDD_HHMMSS.csv`.
   - If a collision occurs within the same second, it appends an index suffix (`_1`, `_2`).

3. **Writing Data:**
   - Normalized columns: `Time`, `Source IP`, `Destination IP`, `Protocol`, `Size`.
   - Uses `pandas.DataFrame.to_csv(filepath, index=False)`.
   - Includes automatic fallback to standard library `csv.DictWriter` if pandas encounters an environment issue.

---

## 8. Error Handling & Resilience Matrix

| Scenario | Handled By | Behavior |
| :--- | :--- | :--- |
| **Npcap Not Installed (Windows)** | `is_live_capture_available()` & `PacketCaptureEngine._run()` | Displays a friendly warning dialog directing the user to Offline Demo Mode; GUI does not crash. |
| **Missing Root/Admin Privileges** | `PacketCaptureEngine._run()` (`PermissionError`) | Catches permission error and alerts user to run with elevated privileges. |
| **Network Interface Missing/Down** | `PacketCaptureEngine._run()` (`OSError`) | Reports interface error without terminating GUI. |
| **Malformed/Corrupt Packets** | `extract_packet_info()` & `_handle_packet()` | Wrapped in `try-except`; silently skips corrupted packets without stopping sniff thread. |
| **Empty CSV Export Request** | `on_save_csv()` & `export_to_csv()` | Shows a warning dialog informing user to capture packets or load demo data first. |
| **Empty Graph Request** | `on_show_graph()` | Shows a friendly warning dialog instead of attempting to plot an empty chart. |
| **Missing Sample Data File** | `on_load_demo()` | Checks `os.path.exists()` and shows clear file path error if missing. |
| **Double-Clicking Start Capture** | `on_start_capture()` | Checks `self.capture_engine.is_running` and ignores redundant clicks; Start button is disabled while running. |
| **Window Closed While Capturing** | `on_closing()` handler on `WM_DELETE_WINDOW` | Automatically halts background capture thread before destroying the window. |
