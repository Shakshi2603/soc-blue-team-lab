#!/usr/bin/env python3
# ==============================================================================
# File Identity: alert_notifier.py
# Objective: Real-time NDJSON parsing & high-severity SOAR escalation alerts
# Usage: sudo python3 alert_notifier.py
# ==============================================================================

import os
import sys
import json
import time
import requests

# --- SOAR INTERFACE BOUNDARIES ---
TELEGRAM_TOKEN = "8916363390:AAF1v7Cf3QXX3MvEVwyWpHNTAxtyZcqWvjU"
CHAT_ID = "8937596428"
ALERT_LOG_PATH = "/var/ossec/logs/alerts/alerts.json" 
SEVERITY_THRESHOLD = 10  # Match or exceed Level 10 Alerts 

#!/usr/bin/env python3
# ==============================================================================
# File Identity: alert_notifier.py
# Objective: Real-time NDJSON parsing & high-severity SOAR escalation alerts
# Usage: sudo python3 alert_notifier.py
# ==============================================================================

import os
import sys
import json
import time
import requests

# --- SOAR INTERFACE BOUNDARIES ---
TELEGRAM_TOKEN = "PASTE_YOUR_TELEGRAM_BOT_TOKEN_HERE"
CHAT_ID = "PASTE_YOUR_PERSONAL_CHAT_ID_HERE"
ALERT_LOG_PATH = "/var/ossec/logs/alerts/alerts.json" 
SEVERITY_THRESHOLD = 10  # Match or exceed Level 10 Alerts 

def send_notification(alert_json):
    """Dispatches extracted incident fields to Telegram Channel"""
    # Parse critical fields cleanly out of the raw nested JSON structure 
    rule_id = alert_json.get("rule", {}).get("id", "Unknown")
    description = alert_json.get("rule", {}).get("description", "No Description")
    level = alert_json.get("rule", {}).get("level", 0) 
    agent_name = alert_json.get("agent", {}).get("name", "Wazuh-Manager")
    
    # Construct an easy-to-read triage message block for the analyst
    message_payload = (
        f"🚨 *CRITICAL SIEM SECURITY ALERT*\n"
        f"=============================\n"
        f"• *Severity Level*: {level}\n"
        f"• *Rule ID*: {rule_id}\n"
        f"• *Affected Node*: {agent_name}\n"
        f"• *Incident Summary*:\n_{description}_\n"
        f"============================="
    )
    
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message_payload,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"[-] Discord/Telegram Hook Failure: Status {response.status_code}")
    except Exception as e:
        print(f"[-] Network Notification Failure: {str(e)}")

def tail_wazuh_alerts(path):
    """Main log tailing function with file verification logic"""
    if not os.path.exists(path):
        print(f"[-] Ingestion Error: Target file path '{path}' does not exist.")
        sys.exit(1)
        
    print(f"[+] Ingestion Active! Tailing '{path}' for alerts >= Level {SEVERITY_THRESHOLD}...")
    
    with open(path, "r") as f:
        # Move the system pointer straight to the current end of the file 
        f.seek(0, 2) 
        
        while True:
            line = f.readline() 
            if not line:
                # If no new line has been written, sleep briefly to preserve CPU 
                time.sleep(0.5) 
                continue
                
            try:
                # Parse the raw line string into a searchable JSON dictionary object 
                alert_data = json.loads(line)
                alert_level = alert_data.get("rule", {}).get("level", 0) 
                
                # Check if the alert matches or exceeds our severity threshold 
                if alert_level >= SEVERITY_THRESHOLD: 
                    send_notification(alert_data) 
                    
            except json.JSONDecodeError:
                # Handle rare incomplete lines gracefully without crashing the script
                continue

if __name__ == "__main__":
    # Ensure the script runs with root privileges to read system logs
    if os.geteuid() != 0:
        print("[-] Permission Denied! This script must be executed using sudo.")
        sys.exit(1)
    tail_wazuh_alerts(ALERT_LOG_PATH)

def tail_wazuh_alerts(path):
    """Main log tailing function with file verification logic"""
    if not os.path.exists(path):
        print(f"[-] Ingestion Error: Target file path '{path}' does not exist.")
        sys.exit(1)
        
    print(f"[+] Ingestion Active! Tailing '{path}' for alerts >= Level {SEVERITY_THRESHOLD}...")
    
    with open(path, "r") as f:
        # Move the system pointer straight to the current end of the file 
        f.seek(0, 2) 
        
        while True:
            line = f.readline() 
            if not line:
                # If no new line has been written, sleep briefly to preserve CPU 
                time.sleep(0.5) 
                continue
                
            try:
                # Parse the raw line string into a searchable JSON dictionary object 
                alert_data = json.loads(line)
                alert_level = alert_data.get("rule", {}).get("level", 0) 
                
                # Check if the alert matches or exceeds our severity threshold 
                if alert_level >= SEVERITY_THRESHOLD: 
                    send_notification(alert_data) 
                    
            except json.JSONDecodeError:
                # Handle rare incomplete lines gracefully without crashing the script
                continue

if __name__ == "__main__":
    # Ensure the script runs with root privileges to read system logs
    if os.geteuid() != 0:
        print("[-] Permission Denied! This script must be executed using sudo.")
        sys.exit(1)
    tail_wazuh_alerts(ALERT_LOG_PATH)
