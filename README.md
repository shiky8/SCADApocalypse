# SCADApocalypse Toolkit

## Overview

SCADApocalypse Toolkit is a comprehensive offensive security framework written in Python, designed to scan, brute-force, fuzz, and exploit a wide array of SCADA (Supervisory Control and Data Acquisition) systems. It is tailored for red teamers, penetration testers, and security researchers targeting industrial control systems (ICS).

---

## Features

- **Multi-Protocol Scanning**: TCP/UDP port scanning, SCADA service detection, and protocol-specific scanners (Modbus, DNP3, S7Comm, IEC-104, BACnet, EtherNet/IP, OPC, MQTT, SNMP, and more).
- **Brute Force Modules**: HTTP, FTP, SSH, Telnet, SNMP, and VNC brute force with default/wordlist credentials.
- **Fuzzing**: Protocol fuzzers for Modbus, DNP3, S7Comm, IEC-104, BACnet, EtherNet/IP, OPC, MQTT, and more.
- **Exploits**: Dozens of ready-to-use exploits for real-world SCADA/ICS vulnerabilities.
- **Payload Management**: Built-in payloads for fuzzing and brute force, easily extendable.
- **CVE Matching**: (Partially implemented) Code exists to match service banners to known CVEs using the CIRCL CVE API, but this feature is not yet fully integrated into the scanning or reporting workflow.
- **Reporting**: Generates detailed JSON and HTML reports.
- **Plugin System**: Modular architecture for scanners, fuzzers, and exploits. Easily add your own.
- **Web UI**: Modern Flask/SocketIO web interface for managing plugins, running scans, fuzzers, exploits, and viewing live logs.
- **Live Logs**: Real-time log streaming in the web UI.
- **Marketplace**: Web-based plugin management and execution.
- **Docker Support**: Run the toolkit in a container for easy deployment.
- **Extensible Architecture**: Easily add new scanners, fuzzers, exploits, and payloads.
- **Wordlist & Credential Management**: Use built-in or custom wordlists for brute force modules.
- **Automated & Targeted Attacks**: Run all modules or target specific protocols/systems.
- **Comprehensive Output**: Results and logs are available in both CLI and web UI.

---

## Note

### It's still in the testing version, so there may be some bugs. 

---

## Demo

### CLI Example

```bash
# list all payloads
python3 __main__.py  --target 192.168.1.100 --list_payloads

# list all scanners
python3 __main__.py  --target 192.168.1.100 ---list_scan

# list all fuzzers
python3 __main__.py  --target 192.168.1.100 --list_fuzz

# list all exploits
python3 __main__.py  --target 192.168.1.100 --list_exploit

# Run TCP port scan
python3 __main__.py --target 192.168.1.100 --tcp_port_scan

# Run UDP port scan
python3 __main__.py --target 192.168.1.100 --udp_port_scan

# Detect scada system via defualt ports
python3 __main__.py --target 192.168.1.100 --detect_scada_scan

# Run all scannners
python3 __main__.py --target 192.168.1.100 --scan all

# Run a scan for Modbus
python3 __main__.py --target 192.168.1.100 --scan modbus_tcp_scanner

# Run all fuzzers
python3 __main__.py --target 192.168.1.100 --fuzz all

# Run a fuzzer for Modbus
python3 __main__.py --target 192.168.1.100 --fuzz modbus_fuzzer

python3 __main__.py --target 192.168.1.100 --fuzz modbus_fuzzer --payload modbus2_payloads.txt

# Brute force HTTP login
# when login use user=^USER^&pass=^PASS^
python3 __main__.py --target 192.168.1.100 --brute_http --brute_dir "/login" --brute  --brute_requ '-----------------------------305651727416383242032691890489
Content-Disposition: form-data; name="user"

^USER^
-----------------------------305651727416383242032691890489
Content-Disposition: form-data; name="pass"

^PASS^
-----------------------------305651727416383242032691890489
Content-Disposition: form-data; name="auth_enter"

Enter
-----------------------------305651727416383242032691890489--
' --brute_invaled_mass "Wrong authentication" --brute_wordlist wordlist2.txt



# Brute force SSH login

python3 __main__.py --target 192.168.1.100 --brute_ssh --port 10010  --brute_wordlist wordlist2.txt

# Brute force VNC login

python3 __main__.py --target 192.168.1.100 --brute_vnc --port 10010  --brute_wordlist wordlist2.txt

# Brute force SNMP login

python3 __main__.py --target 192.168.1.100 --brute_snmp --port 10010  --brute_wordlist wordlist2.txt --scada-system openscada

# Brute force Telnet login

python3 __main__.py --target 192.168.1.100 --brute_telnet --port 10010  --brute_wordlist wordlist2.txt

# Brute force FTP login

python3 __main__.py --target 192.168.1.100 --brute_ftp --port 10010  --brute_wordlist wordlist2.txt

# Run CVE Search 
python3 __main__.py --target 192.168.1.100 --cve  --scada-system openscada

# Run all exploits
python3 __main__.py --target 192.168.1.100 --exploit all

# Run a exploit for Netbiter Read
python3 __main__.py --target 192.168.1.100 --exploit exploit_34794_netbiter_read_cgi

python3 __main__.py --target 192.168.1.100 --exploit exploit_34794_netbiter_read_cgi --user USER --pwd PWD  --lhost 127.0.0.1 --lport 4444        



```

### Web UI Example

```bash
# Start the web UI
python3 -m marketplace.app
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

- Run scanners, fuzzers, exploits, and brute force attacks from the browser
- View live logs and results

> ![Web UI Screenshot Placeholder](docs/webui_screenshot.png)

### Docker Usage

Build the image:
```bash
docker build -t scadapocalypse .
```

#### Run CLI (default):
```bash
docker run -it scadapocalypse --target 192.168.1.100 --scan all
```

#### Run Web UI:
```bash
docker run -p 5000:5000 -e MODE=web scadapocalypse
```

---

## Demo video

https://github.com/user-attachments/assets/b18a53c3-022b-460a-b094-b9359f23f4b9

---

## Installation

### Requirements
- Python 3.8+
- Linux (Kali, Parrot, Ubuntu 20.04+ recommended)

### Install with pip
```bash
pip install -r requirements.txt
```

### Or use Docker (recommended for easy setup)
See Docker section above.

---

## Usage

### CLI
```bash
python3 __main__.py --target <IP> [OPTIONS]
```

**Main Options:**
- `--scan`           Run all or specific scanners
- `--brute_http`     Run HTTP brute force
- `--brute_ftp`      Run FTP brute force
- `--brute_ssh`      Run SSH brute force
- `--brute_telnet`   Run Telnet brute force
- `--brute_snmp`     Run SNMP brute force
- `--brute_vnc`      Run VNC brute force
- `--fuzz`           Run all or specific fuzzers
- `--exploit`        Run all or specific exploits
- `--scada-system`   Specify SCADA system for targeted brute forcing
- `--tcp_port_scan`  TCP port scan
- `--udp_port_scan`  UDP port scan
- `--detect_scada_scan` Detect SCADA system via default port

### Web UI
```bash
python3 -m marketplace.app
```
- Access at [http://localhost:5000](http://localhost:5000)
- Run scans, fuzzers, exploits, brute force, and view live logs

### Docker
- CLI: `docker run -it scadapocalypse --target <IP> --scan all`
- Web: `docker run -p 5000:5000 -e MODE=web scadapocalypse`

---

## Project Structure

```
SCADApocalypse_toolkit/
├── __main__.py           # Main CLI entry point
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── utils/                # Utility modules (logging, reporting, payloads, CVE matching)
├── plugins/              # Modular scanners, exploits, fuzzers
│   ├── scanners/         # Protocol-specific scanners
│   ├── exploits/         # Exploit modules
│   └── fuzzers/          # Fuzzer modules
├── brute_force/          # Brute force modules (HTTP, FTP, SSH, Telnet, SNMP, VNC)
├── marketplace/          # Flask web UI for plugin management
│   └── templates/        # Web UI HTML templates
├── payloads/             # Payload files for fuzzing and brute forcing
├── reports/              # Generated reports (JSON, HTML)
└── Dockerfile            # Docker container definition
```

---

## Extending the Toolkit

- **Add a Scanner**: Drop a new Python file in `plugins/scanners/` and register it in the plugin manager.
- **Add a Fuzzer**: Drop a new Python file in `plugins/fuzzers/`.
- **Add an Exploit**: Drop a new Python file in `plugins/exploits/`.
- **Add Payloads**: Place new payload files in `payloads/`.
- **Web UI**: New plugins appear automatically in the web interface.

---
## Credits

**Special thanks to the following authors for their contributions to exploit modules:**

- **Eugene Salov**
  - plugins/exploits/exploit_34794_netbiter_read_cgi.py
  - plugins/exploits/exploit_34798_its_scada_sqli.py
- **Dillon Beresford**
  - plugins/exploits/exploit_15957_kingview_heap.py
- **Nin3**
  - plugins/exploits/exploit_23132_advantech_studio_traversal.py
- **James Fitts**
  - plugins/exploits/exploit_42885_laquis_traversal.py
  - plugins/exploits/exploit_42724_kingview_alarmserver.py
  - plugins/exploits/exploit_42691_zscada_modbus.py
- **t4rkd3vilz** (CVE Author)
  - plugins/exploits/exploit_44734_honeywell_infoleak.py
- **Emre ÖVÜNÇ**
  - plugins/exploits/exploit_48620_myscada_hardcoded.py
- **Chris Lyne (@lynerc)** (Pythonized by SCADApocalypse Team)
  - plugins/exploits/exploit_45774_webaccess_rce.py

---

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bugs and feature requests.

---

## Disclaimer

Use this toolkit only on systems you have explicit permission to test. Unauthorized access or attacks are illegal and unethical.

---

Happy testing and stay safe!
