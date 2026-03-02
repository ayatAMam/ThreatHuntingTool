# Threat Hunting Tool 🛡️

## Threat Hunting Tool – Intelligence-Driven Security Analysis

**Threat Hunting Tool** is a Python-based CLI tool designed for proactive threat detection using multiple Threat Intelligence (TIP) feeds.

It analyzes structured JSON logs and correlates IP addresses against one or more external threat intelligence files (JSON or CSV), automatically classifying and scoring detected threats.

---


<img width="869" height="856" alt="image" src="https://github.com/user-attachments/assets/01a651de-322a-4e0c-87f6-628dc509626d" />

## ⚡ Key Features

- 🔍 Analyze JSON logs from any security control (Firewall, EDR, IDS, etc.)
- 📂 Supports multiple Threat Intelligence feeds at once
- 📄 Accepts both **JSON and CSV** feed formats
- 🧠 Automatic classification based on feed filename  
  - `apt_list.json` → APT
  - `c2_list.csv` → C2
  - `botnet_feed.json` → BOTNET
- 🎯 Built-in Risk Scoring system
- 🎨 Color-coded output based on severity
- 📊 Sorted results by highest risk score
- 🖥️ Clean and professional CLI interface
- 🆘 Built-in `--help` option

---

## 🛠️ Requirements

- Python 3.x
- JSON log file
- One or more Threat Intelligence feed files (JSON or CSV)

---

## 📂 Supported Feed Formats

### JSON Format
```json
[
  {"ip": "185.243.115.10"},
  {"ip": "45.67.89.200"}
]
