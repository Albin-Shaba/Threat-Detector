# history.py
# Keeps one file with every alert, ban and tamper warning ever found: threat_history.csv
# It never gets erased, new things are added to the bottom.
# Open it in Excel or VS Code to search/sort everything.
#
# Each row has: when it was found, type (ALERT / BAN / TAMPER), threat level, score,
# IP, location, device, computer, what happened, which accounts the IP tried,
# first and last attempt times, and how many attempts failed / worked / were blocked.

import csv
import os
from datetime import datetime

from detection import get_risk_level

HISTORY_FILE = "threat_history.csv"
COLUMNS = ["found_at", "type", "threat_level", "score", "ip", "location", "device", "computer",
           "rule_or_reason", "details", "accounts_tried", "first_attempt", "last_attempt",
           "failed", "succeeded", "blocked"]

already_saved = None  # set of rows we've already written, so nothing gets saved twice


def load_already_saved():
    global already_saved
    already_saved = set()
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, newline="") as f:
            for row in csv.DictReader(f):
                already_saved.add((row["type"], row["ip"], row["rule_or_reason"]))


def ip_details(ip, events):
    # everything we know about one IP from the login attempts
    ip_events = [e for e in events if e["ip"] == ip]
    if not ip_events:
        return {}
    return {
        "location": ip_events[0]["location"],
        "device": ", ".join(sorted(set(e["device"] for e in ip_events))),
        "computer": ", ".join(sorted(set(e["computer"] for e in ip_events))),
        "accounts_tried": ", ".join(sorted(set(e["user"] for e in ip_events))),
        "first_attempt": min(e["time"] for e in ip_events).strftime("%Y-%m-%d %H:%M:%S"),
        "last_attempt": max(e["time"] for e in ip_events).strftime("%Y-%m-%d %H:%M:%S"),
        "failed": len([e for e in ip_events if not e["success"] and not e["blocked"]]),
        "succeeded": len([e for e in ip_events if e["success"] and not e["blocked"]]),
        "blocked": len([e for e in ip_events if e["blocked"]]),
    }


def save_history(events, alerts, scores, banned_ips, tamper_problems=None):
    if already_saved is None:
        load_already_saved()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_rows = []

    for a in alerts:
        key = ("ALERT", a["ip"], a["rule"])
        if key in already_saved:
            continue
        score = min(scores.get(a["ip"], 0), 100)
        row = {"found_at": now, "type": "ALERT", "threat_level": get_risk_level(score), "score": score,
               "ip": a["ip"], "rule_or_reason": a["rule"], "details": a["message"]}
        row.update(ip_details(a["ip"], events))
        new_rows.append(row)
        already_saved.add(key)

    for ip, reason in banned_ips.items():
        key = ("BAN", ip, reason)
        if key in already_saved:
            continue
        score = min(scores.get(ip, 0), 100)
        row = {"found_at": now, "type": "BAN", "threat_level": get_risk_level(score), "score": score,
               "ip": ip, "rule_or_reason": reason, "details": f"{ip} was banned"}
        row.update(ip_details(ip, events))
        new_rows.append(row)
        already_saved.add(key)

    for problem in tamper_problems or []:
        key = ("TAMPER", "", problem)
        if key in already_saved:
            continue
        new_rows.append({"found_at": now, "type": "TAMPER", "threat_level": "CRITICAL", "score": 100,
                         "rule_or_reason": problem, "details": "program file changed"})
        already_saved.add(key)

    if not new_rows:
        return 0

    new_file = not os.path.exists(HISTORY_FILE)
    with open(HISTORY_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file:
            writer.writeheader()
        writer.writerows(new_rows)
    return len(new_rows)
