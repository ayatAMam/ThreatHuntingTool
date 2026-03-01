#!/usr/bin/env python3
import os
import json
from collections import defaultdict
import sys

import sys
import time
import os

# ====== CONFIG ======
USER_NAME = "0xayat"   

# ====== CLEAR SCREEN ======
def clear():
    os.system("cls" if os.name == "nt" else "clear")

# ====== LOADING ANIMATION ======
def loading_animation():
    print("Initializing Threat Hunting Engine", end="")
    for _ in range(5):
        time.sleep(0.5)
        print(".", end="")
        sys.stdout.flush()
    print("\n")

# ====== BANNER ======
def show_banner():
    banner = r"""
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   

        Threat Hunting Tool
    """
    print(banner)
    print(f"👩‍💻 Developer: {USER_NAME}")
    print("🚀 Version: 1.0")
    print("=" * 60)
    time.sleep(1.5)

# ====== START SCREEN ======
def startup():
    clear()
    loading_animation()
    show_banner()

startup()



######### Base directory (same folder as script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

######### Threat feeds with score
threat_feeds = {
    "C2": (os.path.join(BASE_DIR, "c2_list.json"), 5),
    "Botnet": (os.path.join(BASE_DIR, "botnet_list.json"), 4),
    "APT": (os.path.join(BASE_DIR, "apt_list.json"), 6)
}

######### Loader function
def load_ip_list(filename):
    with open(filename, "r") as f:
        data = json.load(f)
    return set(item["ip"] for item in data)

######### Load all feeds automatically
loaded_feeds = {}
for threat_name, (filename, score) in threat_feeds.items():
    loaded_feeds[threat_name] = {
        "ips": load_ip_list(filename),
        "score": score
    }

######### Load Logs from argument
if len(sys.argv) < 2:
    print("Usage: python3 script.py /path/to/Firewall_logs.json")
    sys.exit(1)

logs_path = sys.argv[1]

if not os.path.exists(logs_path):
    print(f"Error: Logs file not found at {logs_path}")
    sys.exit(1)

with open(logs_path, "r") as f:
    logs = json.load(f)

######### Threat Matching Engine
ip_scores = defaultdict(lambda: {"score": 0, "reasons": []})

for log in logs:
    ip = log["ip_address"]

    for threat_name, feed_data in loaded_feeds.items():
        # Score counted once per feed per IP
        if ip in feed_data["ips"]:
            if threat_name not in ip_scores[ip]["reasons"]:
                ip_scores[ip]["score"] += feed_data["score"]
                ip_scores[ip]["reasons"].append(threat_name)

######### ALERT
# ANSI color codes
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"

# Table header with borders
header = f"| {'IP Address':<15} | {'Risk Score':<10} | {'Threats':<20} |"
separator = "-" * len(header)
print(separator)
print(header)
print(separator)

for ip, data in ip_scores.items():
    if data["score"] > 0:
        # Determine color based on score
        if data["score"] > 5:
            color = RED
        elif data["score"] >= 4:
            color = YELLOW
        else:
            color = GREEN
        
        threats = ", ".join(data["reasons"])
        print(f"| {color}{ip:<15} | {data['score']:<10} | {threats:<20}{RESET} |")

print(separator)
