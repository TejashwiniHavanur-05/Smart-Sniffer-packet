# PROJECT SPECIFICATION

## Project Title
Smart Packet Sniffer and Protocol Analyzer using Python

## Project Description
A desktop-based Smart Packet Sniffer and Protocol Analyzer. The application
captures network packets in real time from the computer's network interface
and displays useful information about each packet, helping the user
understand network traffic and basic networking protocols.

Example: When a user opens Google, watches YouTube, or uses a web
application, the computer sends and receives network packets. This
application captures those packets and displays important information
about them.

## Main Objective
Monitor and analyze network traffic in real time by capturing packets and
displaying:
- Source IP Address
- Destination IP Address
- Protocol
- Packet Size
- Time of Capture

The application must also provide protocol statistics and allow the
captured information to be saved as a CSV report.

## Technologies
- Language: Python
- Libraries:
  - Scapy — packet capturing and packet analysis
  - Tkinter — GUI
  - Pandas — data handling
  - Matplotlib — graphs/statistics
  - csv (standard library) — saving reports

Code should be simple and beginner-friendly.

## Main Features
1. Real-time packet capture
2. Start Capture button
3. Stop Capture button
4. Display captured packets in a GUI table
5. Display Source IP
6. Display Destination IP
7. Identify protocols such as: TCP, UDP, ICMP
8. Display packet size
9. Display capture time
10. Count packets according to protocol
11. Search/filter packets by protocol
12. Display basic network statistics
13. Show graphs using Matplotlib
14. Save captured packet information to CSV
15. Clear/reset captured data
16. User-friendly GUI
17. Proper error handling
18. Gracefully handle cases where packet capture permissions are unavailable

## Example Output (illustrative only, not hardcoded)

```
Time        Source IP     Destination IP      Protocol   Size
10:15:30    192.168.1.5   142.250.183.14      TCP        66 Bytes
10:15:31    192.168.1.5   8.8.8.8             UDP        78 Bytes
10:15:32    192.168.1.5   1.1.1.1             ICMP       64 Bytes
```

## Working Flow
1. Start the application.
2. The user clicks "Start Capture".
3. The application begins monitoring the selected network interface.
4. When a packet arrives, Scapy captures it.
5. The application extracts: Time, Source IP, Destination IP, Protocol, Size.
6. The information is displayed in the GUI table.
7. Protocol statistics are updated continuously.
8. The user can filter/search the packets.
9. The user can view basic graphs/statistics.
10. The user clicks "Stop Capture" to stop packet capturing.
11. The user can save the captured information as a CSV report.

## Networking Concepts Covered
- OSI Model
- TCP/IP Model
- IP Addressing
- TCP
- UDP
- ICMP
- Packet Structure
- Network Monitoring
- Network Traffic
- Protocol Analysis

## GUI Requirements
Clean, simple desktop GUI using Tkinter.

- TOP: Project title
- CONTROL AREA: Start Capture, Stop Capture, Clear, Save CSV
- FILTER AREA: Protocol filter/search
- MAIN AREA: Packet table (Time, Source IP, Destination IP, Protocol, Size)
- STATISTICS AREA: Total packets, TCP count, UDP count, ICMP count
- GRAPH AREA: Simple protocol distribution graph using Matplotlib

The GUI should be easy for a college student to demonstrate during a
project presentation.

## Project Structure
```
Smart_Packet_Sniffer/
│
├── README.md
├── PROJECT_SPECIFICATION.md
├── requirements.txt
├── main.py
│
├── src/
│   ├── __init__.py
│   ├── packet_capture.py
│   ├── packet_analyzer.py
│   ├── gui.py
│   ├── statistics.py
│   └── csv_export.py
│
├── data/
│   └── sample_packets.csv
│
├── reports/
│   └── .gitkeep
│
└── docs/
    └── DEVELOPMENT_NOTES.md
```

## Important Development Requirements
- Must be a real working Python desktop application (not a fake/demo-only interface).
- Packet information must come from Scapy when capture is running.
- Do not hardcode packet results.
- Keep packet capture logic separate from GUI logic.
- Keep CSV export logic separate.
- Keep statistics logic separate.
- Use functions/classes where appropriate.
- Add comments for important parts of the code.
- Use beginner-friendly code (college mini project level).
- Avoid unnecessary advanced frameworks.
- Do not use Flask, Django, React, Node.js, or a web server.
- Use Tkinter for the desktop GUI.
- Do not freeze the GUI while capturing packets — use threading.
- Include basic exception handling.
- Make the project easy for another AI coding assistant to understand and extend.

## Safety / Privacy Scope
This project is intended strictly for **educational network monitoring on
the user's own computer or a network the user is explicitly authorized to
monitor** (e.g. a home lab, a personal router, or a classroom lab
environment set up for this purpose).

The project must NOT include, and no contributor (human or AI) should add:
- Credential stealing / sniffing plaintext passwords
- Decrypting private/encrypted traffic
- Bypassing network security or authentication
- Unauthorized interception of third-party traffic
- ARP spoofing / MITM / packet injection features

The application only reads packet **metadata** (headers: IPs, protocol,
size, time) for learning purposes — it does not inspect or store payload
contents, and it must only ever be run against traffic the user is
authorized to capture.
