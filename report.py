# report.py
# Writes two text files into the reports folder:
#   high_risk.txt   - only the HIGH and CRITICAL IPs
#   full_report.txt - everything

import os
from datetime import datetime

from detection import get_risk_level


def describe_ip(ip, events, alerts, scores, banned_ips):
    # collect everything we know about this IP
    ip_events = [e for e in events if e["ip"] == ip]
    users = sorted(set(e["user"] for e in ip_events))
    devices = sorted(set(e["device"] for e in ip_events))
    computers = sorted(set(e["computer"] for e in ip_events))
    fails = len([e for e in ip_events if not e["success"] and not e["blocked"]])
    blocked = len([e for e in ip_events if e["blocked"]])
    score = min(scores[ip], 100)

    lines = []
    lines.append(f"[{get_risk_level(score)}] {ip}  (risk score {score})")
    lines.append(f"   Location:  {ip_events[0]['location']}")
    lines.append(f"   Device:    {', '.join(devices)}")
    lines.append(f"   Computer:  {', '.join(computers)}")
    lines.append(f"   Accounts:  {', '.join(users)}")
    lines.append(f"   Failed: {fails}   Blocked: {blocked}")
    if ip in banned_ips:
        lines.append(f"   BANNED - {banned_ips[ip]}")
    for a in alerts:
        if a["ip"] == ip:
            lines.append(f"   - {a['rule']}: {a['message']}")
    lines.append("")
    return lines


def write_reports(events, alerts, scores, banned_ips, locked_accounts, tamper_problems):
    os.makedirs("reports", exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    ips_by_score = sorted(scores, key=scores.get, reverse=True)

    # ---- high risk report ----
    lines = ["HIGH RISK REPORT - " + now, "=" * 50, ""]
    if tamper_problems:
        lines.append("[CRITICAL] PROGRAM FILES WERE CHANGED:")
        for p in tamper_problems:
            lines.append("   " + p)
        lines.append("")
    for ip in ips_by_score:
        if get_risk_level(scores[ip]) in ("HIGH", "CRITICAL"):
            lines += describe_ip(ip, events, alerts, scores, banned_ips)
    with open("reports/high_risk.txt", "w") as f:
        f.write("\n".join(lines))

    # ---- full report ----
    lines = ["FULL THREAT REPORT - " + now, "=" * 50, ""]
    lines.append(f"Login attempts checked: {len(events)}")
    lines.append(f"Alerts: {len(alerts)}")
    lines.append(f"Banned IPs: {len(banned_ips)}")
    lines.append(f"Locked accounts: {', '.join(locked_accounts) or 'none'}")
    lines.append(f"Tamper check: {'PROBLEMS FOUND' if tamper_problems else 'OK'}")
    lines.append("")
    lines.append("--- Suspicious IPs ---")
    lines.append("")
    for ip in ips_by_score:
        lines += describe_ip(ip, events, alerts, scores, banned_ips)
    with open("reports/full_report.txt", "w") as f:
        f.write("\n".join(lines))
