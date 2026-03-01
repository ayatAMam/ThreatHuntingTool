# Threat Hunting Tool – Python-based Security Analysis
# Threat Hunting Tool 🛡️

**Threat Hunting Tool** Python-based Threat Hunting Tool driven by Threat Intelligence (TIP). Detects suspicious IPs, domains, and other indicators in JSON logs using pre-defined threat intelligence lists.

<img width="913" height="827" alt="image" src="https://github.com/user-attachments/assets/05b149eb-f68d-4368-9453-ce2febb2d2bd" />


## ⚡ Features

- Analyze JSON logs from any security controls.
- Supports threat intelligence JSON files (TIP) such as:
  - `apt_list.json` – known APT indicators
  - `c2_list.json` – Command & Control servers
  - `botnet_list.json` – botnet IPs
  - Or any custom JSON file containing IPs/domains classified by type.
- Indicators can have a **score** to prioritize high-risk threats.
- Fully **customizable**: add new classifications like IPs, Domains, or any other type.
- Produces actionable output for **incident response** and **proactive threat hunting**.

---

## 🛠️ Requirements

- Python 3.x
- JSON log files
- Optional: pre-defined TIP JSON files (`apt_list.json`, `c2_list.json`, `botnet_list.json`, etc.)

---

## 🚀 Usage

```bash
python3 threat_hunting.py <json_logs>
