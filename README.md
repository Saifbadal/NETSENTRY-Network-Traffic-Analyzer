# NETSENTRY — Network Traffic Analyzer

A local-first educational network monitoring application built with Flask, Scapy and scikit-learn. It supports a local analyst account, packet metadata capture, PCAP/PCAPNG import, rule-based observations, an Isolation Forest training baseline, CSV export and PDF summaries.

## Features
- First-run local analyst account creation and sign-in
- Dashboard auto-refreshes packet totals, charts, IP statistics and alerts every 2 seconds while open
- Dashboard with packet totals, protocol distribution, top IPs and recent records
- Live packet metadata capture through Scapy (Npcap recommended on Windows)
- Demo Lab with 180-record synthetic dataset and additional 60-record synthetic batches (no packets sent)
- PCAP and PCAPNG import (32 MB upload cap; up to 100,000 packets per import)
- Rule-based observations for large packets, long DNS names and selected service ports
- Isolation Forest model training on packet metadata
- CSV export and PDF security summary
- SQLite persistence and CSRF-protected forms

## Windows 11 setup

1. Install Python 3.10–3.12 (recommended for broad library compatibility).
2. Extract this project folder.
3. Open the folder in VS Code.
4. Open PowerShell in the project directory and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If PowerShell blocks virtual-environment activation, use the current-terminal-only bypass:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

5. Open http://127.0.0.1:5000
6. On first run, create the local analyst account. Use a unique password of at least 10 characters.

## Live capture on Windows
- Install Npcap from https://npcap.com/#download.
- Restart VS Code after installation.
- Select a network interface on the Live Capture page.
- If access is denied, reopen VS Code as Administrator.
- If live capture is unavailable, PCAP upload can still be used.

## Safe use
Only capture traffic on your own device or networks for which you have explicit authorization. This project stores packet metadata (addresses, ports, protocol, length, timestamps and DNS query names) rather than intentionally saving packet payloads. PCAP files can still contain sensitive metadata. Do not upload captures you are not authorized to inspect.

## ML note
The Isolation Forest model is an unsupervised baseline trained on packet length, source port, destination port and a basic protocol encoding. Outlier scores are not proof of malicious activity. After training, the model scores the training sample and scores newly collected packets. Packets captured before model training are not automatically rescored except for the training sample used at that time. Use it as a learning and investigation aid, and validate detections with context.

## Important deployment note
This starter is intended for local use on 127.0.0.1. Do not expose the Flask development server or this application directly to the public internet. Before any shared deployment, add production hosting, secure secret management, HTTPS, stronger authorization, upload isolation and operational hardening. Set `NTA_SECRET_KEY` to a long random secret before use outside local development.

## Troubleshooting
- `TemplateNotFound`: make sure the `templates` folder is at the same level as `app.py`.
- `No libpcap provider available`: install Npcap and restart the terminal.
- `Access is denied`: run VS Code as Administrator only when needed for capture.
- Port 5000 busy: stop the other Flask process or change the port at the bottom of `app.py`.
- Python compatibility: if dependency installation fails under a very new Python release, use Python 3.11 or 3.12 and recreate `.venv`.

## Project structure
```text
analyzer project
├── app.py
├── config.py
├── requirements.txt
├── templates/
├── static/css/
├── instance/       # generated SQLite database
├── uploads/        # temporary PCAP uploads
├── reports/
└── ml_models/
```

## License
For educational and authorized defensive monitoring use.
