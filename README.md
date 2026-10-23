# Smart Packet Sniffer and Protocol Analyzer using Python

A desktop-based network packet sniffer and protocol analyzer developed using Python, Scapy, Tkinter, Pandas, and Matplotlib. Created as an educational Computer Networks mini project.

> ⚠️ **Educational & Ethical Use Only:** This application is designed exclusively for educational network monitoring and protocol analysis on your own system or local network interfaces where you have explicit authorization. It captures **header-level metadata only** (timestamps, IP addresses, transport protocol, and packet size). It **does NOT** inspect or store application payloads, passwords, credentials, messages, or sensitive information, and contains zero interception, spoofing, or decryption capabilities.

---

## 1. Project Title
**Smart Packet Sniffer and Protocol Analyzer using Python**

## 2. Project Description
When a computer communicates across a network—such as accessing websites, streaming media, or querying DNS servers—data is transmitted in structured units called packets. This desktop software monitors network interfaces, analyzes incoming and outgoing packets in real time, extracts fundamental protocol header information, summarizes protocol metrics, and provides graphical visualization along with CSV reporting.

The software features a dual-mode operational architecture:
- **Live Capture Mode:** Captures live packets from the computer's network adapters using Scapy's packet-sniffing engine.
- **Offline Demo Mode:** Loads an educational sample dataset (`data/sample_packets.csv`) to demonstrate table filtering, statistics, graphing, and CSV export without requiring packet capture drivers or elevated privileges.

---

## 3. Main Objective
- Monitor and analyze IP network traffic in real time and offline.
- Extract and display essential packet header fields:
  - **Capture Time** (HH:MM:SS)
  - **Source IP Address**
  - **Destination IP Address**
  - **Protocol** (TCP, UDP, ICMP, OTHER)
  - **Packet Size** (Bytes)
- Track dynamic protocol counts and visualize traffic distribution.
- Enable protocol-specific filtering for traffic inspection.
- Generate timestamped CSV reports for documentation and offline analysis.

---

## 4. Key Features
- **Real-Time Packet Capture:** Multithreaded sniffing via Scapy on a background daemon thread ensuring the GUI never freezes.
- **Offline Demo Mode:** One-click evaluation using sample datasets for environments without Npcap or root permissions.
- **Interactive Packet Table:** Scrollable `ttk.Treeview` table displaying Time, Source IP, Destination IP, Protocol, and Size with alternating row styling and color-coded protocol tags.
- **Protocol Identification:** Explicit categorization of TCP, UDP, ICMP, and OTHER IP protocols.
- **Dynamic Protocol Statistics:** Real-time counters showing Total, TCP, UDP, ICMP, and OTHER packet totals.
- **Non-Destructive Protocol Filtering:** Instant dropdown filtering (ALL, TCP, UDP, ICMP, OTHER) that filters visible rows without altering the underlying captured session.
- **Graphical Protocol Analytics:** Integrated Matplotlib visualization window displaying side-by-side bar charts and pie charts of protocol distribution.
- **CSV Report Export:** Timestamped report generation with Pandas and collision prevention, saved into the `reports/` folder.
- **Data Reset (Clear):** Resets packet storage, statistics counters, and table view back to initial state.
- **Graceful Error Handling:** Friendly graphical dialogues for missing drivers (Npcap), permission denials, or empty exports.

---

## 5. Technologies Used
- **Programming Language:** Python 3.9+ (Tested on Python 3.11 and Python 3.14)
- **Packet Sniffing & Parsing:** [Scapy](https://scapy.net/) (`scapy.all.sniff`, `scapy.layers.inet`)
- **Desktop Graphical User Interface:** Tkinter & `ttk` (Python Standard Library)
- **Data Analysis & Table Management:** [Pandas](https://pandas.pydata.org/) (`pandas.DataFrame`)
- **Data Visualization & Plotting:** [Matplotlib](https://matplotlib.org/) (`matplotlib.pyplot`, `FigureCanvasTkAgg`)
- **Concurrency & Multithreading:** Python `threading.Thread` (daemon thread) & `threading.Event`

---

## 6. Computer Networks Concepts Covered
- **The OSI Reference Model & TCP/IP Protocol Suite:**
  - Network/Internet Layer (IPv4 / IPv6 addressing, ICMP)
  - Transport Layer (TCP connection-oriented protocol, UDP connectionless protocol)
  - Data Link Layer (Frame encapsulation, packet length)
- **IP Addressing:** Source and destination host identification, loopback addresses, local private subnets (e.g. `192.168.x.x`, `10.x.x.x`), and public DNS/web addresses.
- **Protocol Analysis:** Distinguishing between stream-based reliable communication (TCP), datagram broadcast/query traffic (UDP), network diagnostics/ping (ICMP), and multicast (OTHER / IGMP).
- **Traffic Monitoring Metrics:** Packet throughput, protocol ratios, and network packet sizing.

---

## 7. Project Structure
```
Smart_Packet_Sniffer/
│
├── main.py                      # Application entry point
├── README.md                    # Comprehensive project documentation
├── PROJECT_SPECIFICATION.md     # Architectural specifications and scope constraints
├── requirements.txt             # Third-party Python dependencies
│
├── data/
│   └── sample_packets.csv       # Educational dataset for Offline Demo Mode
│
├── docs/
│   └── DEVELOPMENT_NOTES.md     # Architectural flows, threading, and developer guide
│
├── reports/
│   └── .gitkeep                 # Output directory for exported CSV session reports
│
└── src/
    ├── __init__.py              # Package marker
    ├── packet_capture.py        # Background Scapy sniffing engine with Npcap detection
    ├── packet_analyzer.py       # Header extraction logic for IP, TCP, UDP, ICMP, OTHER
    ├── statistics.py            # Protocol counters, ratios, and summary metrics
    ├── csv_export.py            # Timestamped report generation with Pandas
    └── gui.py                   # Desktop Tkinter GUI with Matplotlib chart integration
```

---

## 8. Installation Requirements

### Prerequisites
- Python 3.9 or higher installed on your system.
- Standard libraries: `tkinter`, `threading`, `csv`, `datetime`, `os`, `sys`.

### Step 1: Install Python Dependencies
Open your command terminal in the project directory and install the required packages:
```bash
pip install -r requirements.txt
```

*(Alternatively, on systems with multiple Python versions installed, you can use:)*
```bash
python -m pip install -r requirements.txt
```

---

## 9. How to Run the Application

Launch the desktop application:
```bash
python main.py
```

- On Linux or macOS, live raw socket capture may require elevated privileges:
  ```bash
  sudo python main.py
  ```

---

## 10. Offline Demo Mode (No Driver or Admin Privileges Required)
Offline Demo Mode guarantees that the project can be demonstrated anytime, anywhere—including on university lab computers, classroom projectors, or virtual machines where Npcap cannot be installed:

1. Launch `python main.py`.
2. Click the **"Load Demo Data"** button.
3. The application loads realistic educational packet samples from `data/sample_packets.csv`.
4. You can immediately test and demonstrate:
   - Live population of the packet table.
   - Dynamic protocol counters (TCP, UDP, ICMP, OTHER).
   - Filtering by specific protocols via the dropdown.
   - Generating protocol distribution bar and pie charts (**Show Graph**).
   - Exporting the data to CSV (**Save CSV**).
   - Resetting the session (**Clear**).

---

## 11. Live Capture Mode
When running on a machine equipped with network capture drivers:
1. Launch `python main.py`.
2. Click **Start Capture**.
3. The background thread invokes Scapy's sniffing engine and listens on the system's active network adapter.
4. Incoming and outgoing packets are captured and displayed in real time in the table.
5. The statistics counters increment dynamically with every arriving packet.
6. Click **Stop Capture** to safely halt capture.

---

## 12. Npcap Requirement for Windows
- On Windows operating systems, raw packet sniffing requires a low-level packet capture driver: **[Npcap](https://npcap.com/)**.
- **Important:** If Npcap is **not** installed, the application **will not crash**. Instead, it displays a helpful notification:
  > *"Live packet capture is unavailable because Npcap is not installed. You can use Offline Demo Mode with the sample dataset."*
- To enable Live Capture on Windows:
  1. Download and install Npcap from [npcap.com](https://npcap.com/).
  2. During installation, select **"Install Npcap in WinPcap API-compatible Mode"**.
  3. Restart the application.

---

## 13. How the Project Works Step-by-Step

```
[ User Launches main.py ]
          │
          ▼
[ Tkinter Desktop GUI Opens ]
          │
    ┌─────┴────────────────────────┐
    ▼                              ▼
[ Live Capture Mode ]     [ Offline Demo Mode ]
(Scapy sniff on thread)   (Read sample_packets.csv)
    │                              │
    └──────────────┬───────────────┘
                   ▼
        [ Packet Analyzer ]
        - Check IP layer (IPv4 / IPv6)
        - Extract Time, Src IP, Dst IP, Size
        - Classify Protocol: TCP / UDP / ICMP / OTHER
                   │
                   ▼
       [ Thread-Safe UI Dispatch ]
       (root.after marshals to main thread)
                   │
                   ▼
        [ Statistics Engine ]
        - Increment Total & Protocol counters
        - Update GUI Statistic Badges
                   │
                   ▼
         [ Main Packet Table ]
         - Display row according to active Filter
                   │
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
[ Filter ]    [ Show Graph ]  [ Save CSV ]
(ALL/TCP/UDP) (Matplotlib)   (reports/ folder)
```

1. **Initialization:** `main.py` initializes the Tkinter window and loads `PacketSnifferApp`.
2. **Ingestion:** Packets are acquired either via real-time Scapy sniffing on a worker thread or parsed from `data/sample_packets.csv`.
3. **Header Parsing:** `src/packet_analyzer.py` extracts metadata and categorizes the packet.
4. **Thread-Safe Dispatch:** Background worker thread posts packet metadata back to the Tkinter UI event loop via `root.after()`.
5. **Metrics & Table Display:** The table displays rows formatted with alternating row colors, while `src/statistics.py` maintains session counters.
6. **Analytics & Output:** The user can filter records, launch graphical charts, or export session logs.

---

## 14. CSV Report Export
- Clicking **"Save CSV"** exports the currently captured session into the `reports/` folder.
- Uses Pandas with an automatic fallback to Python's standard `csv` module.
- Generates unique, non-colliding timestamped filenames: `reports/packet_report_YYYYMMDD_HHMMSS.csv`.
- Columns exported: `Time`, `Source IP`, `Destination IP`, `Protocol`, `Size`.
- Prevents saving empty datasets with friendly warning dialogs.

---

## 15. Graph and Protocol Statistics
- Clicking **"Show Graph"** opens an integrated Matplotlib visualization window (`Toplevel` modal):
  - **Bar Chart:** Displays exact counts for TCP, UDP, ICMP, and OTHER.
  - **Pie Chart:** Displays percentage protocol share of the current traffic session.
- Seamlessly integrates with the Tkinter event loop using `FigureCanvasTkAgg`.

---

## 16. Limitations
- **Header-Level Only:** Designed strictly for educational monitoring; payload inspection, deep packet inspection (DPI), and decryption (TLS/HTTPS) are deliberately excluded.
- **Windows Driver Dependency:** Live capture requires Npcap on Windows due to OS socket architecture restrictions (addressed via Offline Demo Mode).
- **Interface Selection:** Currently monitors the default network adapter; multi-interface selection dropdown can be added in future iterations.

---

## 17. Future Enhancements
- Adapter selection dropdown to allow sniffing on specific virtual, Wi-Fi, or Ethernet adapters.
- Port-level protocol classification (e.g. mapping port 80 to HTTP, 443 to HTTPS, 53 to DNS).
- Packet rate velocity graphs (packets per second over time).
- Custom Berkeley Packet Filter (BPF) input box for advanced filtering (e.g. `tcp and port 80`).
- GeoIP lookup integration to identify geographical server endpoints.
