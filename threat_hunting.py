#!/usr/bin/env python3

import os
import sys
import json
import csv
import time
import argparse
from collections import defaultdict

# =========================
# CONFIG
# =========================
USER_NAME = "0xayat"

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

# =========================
# UI FUNCTIONS
# =========================
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def loading_animation():
    print(f"{CYAN}Initializing Threat Hunting Engine", end="")
    for _ in range(5):
        time.sleep(0.4)
        print(".", end="")
        sys.stdout.flush()
    print(RESET + "\n")

def show_banner():
    banner = f"""
{GREEN}
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
   ██║   ███████║██████╔╝█████╗  ███████║   ██║   
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   

        Threat Hunting Tool
{RESET}
"""
    print(banner)
    print(f"👩‍💻 Developer: {USER_NAME}")
    print("🚀 Version: 2.0")
    print("=" * 65)
    time.sleep(1)

# =========================
# ARGUMENT PARSER
# =========================
parser = argparse.ArgumentParser(
    description="Threat Hunting Tool - Detect malicious IPs using multiple Threat Intelligence feeds"
)

parser.add_argument(
    "logs",
    help="Path to JSON logs file"
)

parser.add_argument(
    "feeds",
    nargs="+",
    help="One or more Threat Intelligence feed files (JSON or CSV)"
)

args = parser.parse_args()

# =========================
# START SCREEN
# =========================
clear()
loading_animation()
show_banner()

# =========================
# VALIDATE LOG FILE
# =========================
if not os.path.exists(args.logs):
    print(f"{RED}Error: Logs file not found.{RESET}")
    sys.exit(1)

# =========================
# LOAD LOGS
# =========================
with open(args.logs, "r") as f:
    logs = json.load(f)

# =========================
# LOAD FEEDS (JSON / CSV)
# =========================
def load_feed_file(filepath):
    extension = filepath.split(".")[-1].lower()
    ips = set()

    if extension == "json":
        with open(filepath, "r") as f:
            data = json.load(f)
            for item in data:
                if "ip" in item:
                    ips.add(item["ip"])

    elif extension == "csv":
        with open(filepath, "r") as f:
            reader = csv.reader(f)
            for row in reader:
                if row:
                    ips.add(row[0])

    else:
        print(f"{YELLOW}Unsupported file format skipped: {filepath}{RESET}")

    return ips

# =========================
# BUILD THREAT FEEDS
# =========================
threat_feeds = {}

for feed_path in args.feeds:

    if not os.path.exists(feed_path):
        print(f"{RED}Feed file not found: {feed_path}{RESET}")
        continue

    # Classification based on file name
    feed_name = os.path.basename(feed_path).split("_")[0].upper()

    threat_feeds[feed_name] = {
        "ips": load_feed_file(feed_path),
        "score": 5   # default score 
    }

if not threat_feeds:
    print(f"{RED}No valid threat feeds loaded.{RESET}")
    sys.exit(1)

# =========================
# THREAT MATCHING ENGINE
# =========================
ip_scores = defaultdict(lambda: {"score": 0, "reasons": []})

for log in logs:
    ip = log.get("ip_address")
    if not ip:
        continue

    for threat_name, feed_data in threat_feeds.items():
        if ip in feed_data["ips"]:
            if threat_name not in ip_scores[ip]["reasons"]:
                ip_scores[ip]["score"] += feed_data["score"]
                ip_scores[ip]["reasons"].append(threat_name)

# =========================
# OUTPUT TABLE
# =========================
header = f"| {'IP Address':<15} | {'Risk Score':<10} | {'Threats':<25} |"
separator = "-" * len(header)

print(separator)
print(header)
print(separator)

for ip, data in sorted(ip_scores.items(), key=lambda x: x[1]["score"], reverse=True):

    if data["score"] == 0:
        continue

    if data["score"] >= 10:
        color = RED
    elif data["score"] >= 5:
        color = YELLOW
    else:
        color = GREEN

    threats = ", ".join(data["reasons"])
    print(f"| {color}{ip:<15} | {data['score']:<10} | {threats:<25}{RESET} |")

print(separator)
