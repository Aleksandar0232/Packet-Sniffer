Packet Sniffer:  simple HTTP request & credential detector
A small Scapy-based packet sniffer that prints HTTP requests (Host + Path) and looks for possible login/credential data in packet payloads (POST bodies / form fields).
This is a learning / auditing tool — only use it on networks and systems where you have explicit permission.

Features
Prints HTTP requests (Host + Path).

Checks packet payloads for common credential-related keywords (username, password, token, etc.).

Minimal, easy-to-read Python script using Scapy.

Files
packet_sniffer.py — main script (single-file).

README.md — this file.

Requirements
Python 3.8+ (tested on Python 3.9+)

scapy (install with pip install scapy)

Root/Administrator privileges to capture packets (e.g. sudo on Linux)

A network interface name that can capture traffic (e.g. eth0, wlan0, enp3s0)

Installation
Clone the repo:

bash
Copy code
git clone <your-repo-url>
cd <your-repo-folder>
Create a virtualenv (optional but recommended):

bash
Copy code
python3 -m venv venv
source venv/bin/activate
Install dependencies:

bash
Copy code
pip install scapy
Usage
Run the sniffer with root privileges and pass the interface name (defaults to eth0 if omitted):

bash
Copy code
sudo python3 packet_sniffer.py                # uses eth0 by default
sudo python3 packet_sniffer.py wlan0         # specify interface
Example output:

css
Copy code
[+] HTTP Request >>> testphp.vulnweb.com/login.php
[!] Possible username/password > FORM_FIELDS
    username -> ['admin']
    password -> ['supersecret']
Notes on Python 3 / bytes vs str
You may see an error like:

python
Copy code
WARNING: Socket <scapy.arch.linux.L2ListenSocket object at 0x...> failed with 'a bytes-like object is required, not 'str''
or

vbnet
Copy code
TypeError: a bytes-like object is required, not 'str'
Why: Scapy's HTTP fields (Host, Path, Raw.load, etc.) are sometimes bytes objects and sometimes str. Comparing str to bytes or calling .decode() on a str causes errors.

Fix (recommended): convert bytes to str safely before doing joins, comparisons or printing. Example helper:

python
Copy code
def safe_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)
Use safe_text(packet[http.HTTPRequest].Host) and safe_text(packet[http.HTTPRequest].Path) in get_url() and use safe_text(packet[scapy.Raw].load) inside get_login_info().

Example get_url() / process_sniffed_packet() (safe for Python 3)
python
Copy code
def safe_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)

def get_url(packet):
    host = safe_text(packet[http.HTTPRequest].Host)
    path = safe_text(packet[http.HTTPRequest].Path)
    return host + path

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>> " + url)
        # look for login info in Raw payload (also decoded via safe_text)
        # ...
Security & Legal
Only run this software on networks and systems you own or where you have explicit written permission to capture traffic.

Sniffing network traffic can capture sensitive personal data (credentials, tokens, credit-card numbers). Treat any captured data responsibly and delete any sensitive captures you do not need.

Do not use this tool for malicious activity.

Troubleshooting
Permission denied or capture socket warnings: run with sudo or run as Administrator, and ensure the interface name exists (ip a or ifconfig).

ValueError or TypeError about bytes/str: use the safe_text helper everywhere you transform or compare packet fields.

If you get Scapy import problems: ensure you installed scapy in the active Python environment (pip show scapy).
