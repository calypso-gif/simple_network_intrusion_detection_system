# Simple Network Intrusion Detection System (NIDS)

A lightweight, desktop-based Network Intrusion Detection System built with **Python**, **Scapy**, and **Tkinter**. It monitors TCP traffic on a selected network interface and raises heuristic alerts for port-scan-like activity and SYN-flood-like bursts.

> **Academic project:** This is an educational prototype for learning about packet capture, TCP flags, traffic monitoring, and basic intrusion-detection logic. It is not a replacement for a production IDS/IPS or a network firewall.

## Features

- Live TCP packet monitoring using Scapy's `AsyncSniffer`
- Detection of TCP port-scan-like activity using distinct destination ports per source IP
- Detection of SYN-flood-like bursts using SYN packets without the ACK flag
- Tkinter dashboard with live packet statistics and a 30-second activity graph
- Network-interface selection and local IPv4 address display
- Editable detection thresholds and per-alert cooldown
- Trusted-IP whitelist
- Alert filtering by type and source IP
- Automatic CSV alert logging and manual CSV export
- **Demo Mode** that generates synthetic events locally; it does not send attack traffic

## How detection works

The application captures TCP packets from the selected interface. For detection, it considers IPv4/TCP packets addressed to the selected interface's local IPv4 address and identifies SYN-only packets (SYN set, ACK not set).

| Detection | Default condition | Default time window |
|---|---:|---:|
| Port-scan-like activity | 15 or more distinct destination ports from one source IP | 5 seconds |
| SYN-flood-like activity | 100 or more SYN-only packets from one source IP | 3 seconds |
| Alert cooldown | 10 seconds per source IP and alert type | — |

These are configurable starting values, not universal security rules. Normal traffic may sometimes trigger an alert, and suspicious activity may not cross the configured thresholds.

## Requirements

- Python 3.8 or later (recommended)
- Scapy (`scapy`)
- Tkinter (usually included with desktop Python; on some Linux distributions it is installed separately)
- Packet-capture privileges for **Live Monitoring**
- On Windows, Npcap is required for live packet capture with Scapy

## Installation and use

### Linux / Kali Linux

Install Python, Tkinter, and virtual-environment support:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-tk
```

Clone the repository and enter its folder 

```bash
git clone https://github.com/calypso-gif/simple_network_intrusion_detection_system.git
cd simple_network_intrusion_detection_system
```

Create and activate a virtual environment, then install the Python dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Start the application:

```bash
python simple_nids_interactive.py
```

You can use **Demo Mode** without capturing live network traffic. Live packet capture may require elevated permissions. On a typical Linux setup, you can launch it with the virtual-environment interpreter as follows:

```bash
sudo .venv/bin/python simple_nids_interactive.py
```

### Windows 10 / 11

1. Install Python 3.8 or later and Npcap. Tkinter is normally included with the standard Windows Python installer.
2. Open PowerShell in the project folder.
3. Create and activate a virtual environment, then install the dependency:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

4. Start the application:

```powershell
python simple_nids_interactive.py
```

Demo Mode does not need live packet capture. For Live Monitoring on Windows, use an Administrator terminal and make sure Npcap is installed and working.

## Runtime files

The application may create these files in the directory from which it is launched:

- `nids_alerts.csv` — automatically recorded alerts
- `nids_whitelist.txt` — trusted IP addresses

These files are intentionally excluded from version control because they contain machine-specific runtime data. The `.gitignore` file also excludes virtual environments and Python cache files.

## Project structure

```text
simple-network-intrusion-detection-system/
├── simple_nids_interactive.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Limitations

- Detection is threshold-based and heuristic; an alert is not proof that an attack occurred.
- The current detector focuses on IPv4/TCP and SYN-only traffic. It does not analyze UDP, ICMP, or IPv6 traffic.
- Detection is limited to packets visible on the selected interface and addressed to that interface's selected local IPv4 address.
- Low-rate or distributed activity may not cross the per-source thresholds.
- The application raises alerts and records them; it does not block traffic or automatically stop connections.

## Responsible use

Use Live Monitoring only on devices and networks you own or are explicitly authorized to monitor. Demo Mode is provided for classroom demonstrations and testing without generating attack traffic.

## License

No license has been added yet. Add a license if you decide how others may use, modify, and distribute this project.
