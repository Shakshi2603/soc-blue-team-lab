#!/usr/bin/env python3
# ==============================================================================
# File Identity: ioc_enrichment.py
# Objective: Programmatic CTI Enrichment via VirusTotal & AbuseIPDB APIs
# Usage: python3 ioc_enrichment.py <TARGET_IP_ADDRESS>
# ==============================================================================

import sys
import json
import requests

# --- SYSTEM API CONFIGURATION BOUNDARIES ---
VT_API_KEY = "18aa43a4b7bf7be0264c48a98ccbdfe883c87358c2a8901368ab60b54ab69b71"
ABUSE_API_KEY = "76ab1b3b51a2fd64f12fcfb7688ae22f2f751e365b56081ac8e78a1ecb665df31020c86c596ea180"

def check_virus_total(ip_address):
    """Queries VirusTotal v3 IP Analysis API Endpoint"""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Extract key security scanning vendor verdict tallies
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        else:
            return {"error": f"HTTP Error Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_abuse_ipdb(ip_address):
    """Queries AbuseIPDB v2 IP Check API Endpoint"""
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        if response.status_code == 200:
            data = response.json()
            res = data['data']
            return {
                "abuse_score": res.get("abuseConfidenceScore", 0),
                "total_reports": res.get("totalReports", 0),
                "country": res.get("countryCode", "Unknown"),
                "isp": res.get("isp", "Unknown")
            }
        else:
            return {"error": f"HTTP Error Status {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def main():
    # Enforce basic command-line usage controls
    if len(sys.argv) != 2:
        print("[-] Target missing! Usage: python3 ioc_enrichment.py <IP_ADDRESS>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    print(f"\n[+] Executing CTI Enrichment Protocol against: {target_ip}")
    print("=" * 60)
    
    # Run queries across both enrichment pipelines
    vt_results = check_virus_total(target_ip)
    abuse_results = check_abuse_ipdb(target_ip)
    
    # --- VISUAL PRESENTATION FRAMEWORK FOR ANALYSTS ---
    print("[🛡️ VIRUSTOTAL REPUTATION METRICS]")
    if "error" in vt_results:
        print(f"  [-] Query Failure: {vt_results['error']}")
    else:
        print(f"  Malicious Verdicts : {vt_results['malicious']} vendors")
        print(f"  Suspicious Verdicts: {vt_results['suspicious']} vendors")
        print(f"  Harmless Verdicts  : {vt_results['harmless']} vendors")
        
    print("\n[☣️ ABUSEIPDB HISTORICAL RECORDFILES]")
    if "error" in abuse_results:
        print(f"  [-] Query Failure: {abuse_results['error']}")
    else:
        print(f"  Abuse Confidence Score: {abuse_results['abuse_score']}%")
        print(f"  Total Historical Reports: {abuse_results['total_reports']}")
        print(f"  Geo IP Origin Location  : {abuse_results['country']}")
        print(f"  Registered ISP Entity   : {abuse_results['isp']}")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
