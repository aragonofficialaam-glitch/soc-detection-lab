"""
IOC Enrichment Script
Enriches a list of IP addresses using AbuseIPDB and VirusTotal APIs.
Part of SOC Detection & Response Lab - Phase 4
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

print("AbuseIPDB key loaded:", ABUSEIPDB_KEY[:10] if ABUSEIPDB_KEY else "NOT FOUND")
print("VirusTotal key loaded:", VIRUSTOTAL_KEY[:10] if VIRUSTOTAL_KEY else "NOT FOUND")

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "is_tor": data.get("isTor")
        }
    except Exception as e:
        return {"error": str(e)}

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "reputation": data.get("reputation")
        }
    except Exception as e:
        return {"error": str(e)}

import csv
from datetime import datetime

def enrich_ip(ip):
    print(f"\n{'='*60}")
    print(f"IOC: {ip}")
    print(f"{'='*60}")

    abuse = check_abuseipdb(ip)
    print("\n[AbuseIPDB]")
    if "error" in abuse:
        print(f"  Error: {abuse['error']}")
    else:
        print(f"  Abuse Confidence Score: {abuse['abuse_score']}%")
        print(f"  Country: {abuse['country']}")
        print(f"  ISP: {abuse['isp']}")
        print(f"  Total Reports: {abuse['total_reports']}")
        print(f"  Tor Exit Node: {abuse['is_tor']}")

    vt = check_virustotal(ip)
    print("\n[VirusTotal]")
    if "error" in vt:
        print(f"  Error: {vt['error']}")
    else:
        print(f"  Malicious detections: {vt['malicious']}")
        print(f"  Suspicious detections: {vt['suspicious']}")
        print(f"  Harmless detections: {vt['harmless']}")
        print(f"  Reputation score: {vt['reputation']}")

    return {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "abuse_score": abuse.get("abuse_score", "N/A"),
        "abuse_country": abuse.get("country", "N/A"),
        "abuse_isp": abuse.get("isp", "N/A"),
        "abuse_reports": abuse.get("total_reports", "N/A"),
        "is_tor": abuse.get("is_tor", "N/A"),
        "vt_malicious": vt.get("malicious", "N/A"),
        "vt_suspicious": vt.get("suspicious", "N/A"),
        "vt_harmless": vt.get("harmless", "N/A"),
        "vt_reputation": vt.get("reputation", "N/A")
    }

def export_to_csv(results, filename="ioc_enrichment_results.csv"):
    fieldnames = ["ip", "timestamp", "abuse_score", "abuse_country", "abuse_isp",
                  "abuse_reports", "is_tor", "vt_malicious", "vt_suspicious",
                  "vt_harmless", "vt_reputation"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] Results exported to {filename}")

if __name__ == "__main__":
    # IOCs from Investigation #3 (BOTS v1 - Website Defacement scenario)
    iocs = [
        "40.80.148.42",   # Acunetix scanner source
        "23.22.63.114"    # Brute-force attack source
    ]

    all_results = []
    for ip in iocs:
        result = enrich_ip(ip)
        all_results.append(result)

    export_to_csv(all_results)