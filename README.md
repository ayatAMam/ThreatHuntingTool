# Threat Hunting Tool – Python-based Security Analysis
# Threat Hunting Tool 🛡️

**Threat Hunting Tool** is a Python-based tool for proactive **threat detection** using structured JSON logs. It helps security analysts identify suspicious activity by correlating logs with known threat indicators.

<img width="1032" height="526" alt="image" src="https://github.com/user-attachments/assets/85ae3d6e-c8e2-44bd-a115-79efbf248fe8" />



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
