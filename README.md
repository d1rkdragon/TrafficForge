# <h1 align="center">TrafficForge</h1>

TrafficForge is a research-focused tool that replays HTTP traffic captured in PCAP files. It works by reconstructing user-side requests, including headers, and forwarding them through a specified proxy or Web Application Firewall (WAF). By doing so, it enables researchers and security teams to simulate real-world traffic patterns and assess how applications, proxies, or WAFs respond under realistic conditions. This makes it particularly useful for testing security defenses, analyzing behavior, and evaluating system performance against both normal and potentially malicious traffic.
## ✨ Features

- Parse PCAP files and extract HTTP requests  
- Reconstruct real user-side requests with headers  
- Replay traffic through a proxy or WAF  
- Useful for web security testing, behavior analysis, and research  

# ⚙️ Installation

First, clone the repository:

```bash
git clone https://github.com/your-username/TrafficForge.git
cd TrafficForge
```
### 1. Create and activate a Virtual Environment

🔹 On Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

🔹 On Windows (PowerShell):
```bash
python -m venv .venv
.\.venv\Scripts\activate
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

▶️ Usage:
TrafficForge is run using pcap.py. You can provide either a single PCAP file (-d) or a directory of PCAPs (-D).
You also specify the proxy/WAF URL with -p.

## Arguments

- `-d <file>` — Single PCAP file to parse/replay.  
  **Usage:** `-d ./pcap/sample.pcap`

- `-D <dir>` — Directory of PCAPs (non-recursive).  
  **Usage:** `-D ./pcap/`

- `-p <proxy>` / `--proxy <proxy>` — Send reconstructed requests via a proxy/WAF. Accepts `http://host:port` or `host:port` (defaults to `http`).  
  **Usage:** `-p 127.0.0.1:8080`

- `--speed <N>` — Timing scale factor (1.0 = original, >1 = faster, <1 = slower).  
  **Usage:** `--speed 2.0`

- `--max-req <N>` — Max requests to replay per file (useful for smoke-tests).  
  **Usage:** `--max-req 10`

- `--dry-run` — Print reconstructed requests (headers/body preview) without sending.


## Example Commands
 Replay traffic from one PCAP
```bash 
python pcap.py -d ./pcap/sample.pcap -p http://127.0.0.1:8080
```

Replay traffic from a directory of PCAPs
```bash
python pcap.py -D ./pcap/ -p http://127.0.0.1:8080
```

Replay with speed and max arguments
```bash
python pcap.py -d ./pcap/sample.pcap -p http://127.0.0.1:8080 --speed 5 --max 50
```
## 📌 Notes

- Ensure your proxy / WAF server is running before replaying requests.  
- Use a virtual environment to avoid dependency conflicts.  
- Only use TrafficForge in authorized test environments — intended for research and security testing.

