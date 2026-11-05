"""
Risk-Based Alerting Script
Cross-references SOC alerts with known vulnerability findings to
dynamically adjust alert priority. Part of SOC Detection & Response Lab - Phase 5.

Design note: this lab's identity environment (soclab.local) and the
Vulnerability Management Pipeline project (Metasploitable2-based) use
separate, non-overlapping hosts. For demonstration purposes, a manual
asset mapping is used below to simulate how a CMDB or shared asset
inventory would link the two systems in a production environment.
"""

# Manual asset mapping (simulates a CMDB lookup in production)
# Maps SOC lab hostnames -> vulnerability scan asset_name
ASSET_MAPPING = {
    "WServer": "nginx:1.14",
    "DC01": "nginx:1.14"
}

# Known critical vulnerability findings from vuln-mgmt-pipeline
# (pulled from findings_scored.csv, in_kev=yes entries)
VULNERABILITY_DB = {
    "nginx:1.14": {
        "cve": "CVE-2020-15999",
        "severity": "Critical",
        "in_kev": True,
        "title": "freetype: Heap-based buffer overflow due to integer truncation in Load_SBit_Png"
    }
}

# Severity escalation order
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


def get_asset_risk(host):
    """Look up whether a SOC lab host has an associated critical vulnerability."""
    asset_name = ASSET_MAPPING.get(host)
    if not asset_name:
        return None
    return VULNERABILITY_DB.get(asset_name)


def escalate_severity(current_severity, asset_risk):
    """
    If the host has a KEV-listed Critical vulnerability, escalate the
    alert severity to Critical, regardless of its original level.
    """
    if asset_risk and asset_risk.get("in_kev") and asset_risk.get("severity") == "Critical":
        return "Critical"
    return current_severity


def process_alert(alert_name, host, original_severity):
    print(f"\n{'='*65}")
    print(f"ALERT: {alert_name}")
    print(f"Host: {host}")
    print(f"Original Severity: {original_severity}")
    print(f"{'='*65}")

    asset_risk = get_asset_risk(host)

    if asset_risk:
        print(f"\n[+] Asset risk context found for {host}:")
        print(f"    Mapped vulnerability asset: {ASSET_MAPPING[host]}")
        print(f"    CVE: {asset_risk['cve']}")
        print(f"    Vulnerability Severity: {asset_risk['severity']}")
        print(f"    Known Exploited (CISA KEV): {asset_risk['in_kev']}")

        new_severity = escalate_severity(original_severity, asset_risk)

        if new_severity != original_severity:
            print(f"\n[!] SEVERITY ESCALATED: {original_severity} -> {new_severity}")
            print(f"    Reason: Host has a KEV-listed Critical vulnerability ({asset_risk['cve']})")
        else:
            print(f"\n[=] Severity unchanged: already at {original_severity}")

        return new_severity
    else:
        print(f"\n[-] No known vulnerability context for {host}. Severity unchanged.")
        return original_severity


if __name__ == "__main__":
    # Example: the 5 identity-based alerts from Investigation #1
    alerts = [
        ("Kerberos User Enumeration", "WServer", "Medium"),
        ("Kerberos Password Brute Force", "WServer", "High"),
        ("New Domain Admin Shortly After Creation", "WServer", "Critical"),
        ("Remote Command Execution via Task Scheduler", "WServer", "High"),
        ("Potential DCSync Attack", "WServer", "Critical"),
    ]

    print("RISK-BASED ALERTING - Cross-referencing SOC alerts with vulnerability data")

    results = []
    for alert_name, host, severity in alerts:
        final_severity = process_alert(alert_name, host, severity)
        results.append((alert_name, host, severity, final_severity))

    print(f"\n\n{'='*65}")
    print("SUMMARY")
    print(f"{'='*65}")
    for alert_name, host, original, final in results:
        marker = " [ESCALATED]" if final != original else ""
        print(f"{alert_name}: {original} -> {final}{marker}")