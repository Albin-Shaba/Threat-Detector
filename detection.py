# detection.py
# The different checks for attacks. Each check returns a list of alerts.
# An alert is a dictionary with the IP, what happened, and how many risk points it's worth.

from datetime import timedelta

HONEYTOKENS_FILE = "honeytokens.txt"


def make_alert(ip, rule, message, points):
    return {"ip": ip, "rule": rule, "message": message, "points": points}


def get_risk_level(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def load_honeytokens():
    # fake accounts that no real person uses - anyone trying them is an attacker
    names = []
    with open(HONEYTOKENS_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line.lower())
    return names


# Check 1: brute force
# the same IP fails on the same account 5+ times within 10 minutes
def check_brute_force(events):
    alerts = []
    fail_times = {}  # (ip, user) -> list of times
    for e in events:
        if not e["success"]:
            key = (e["ip"], e["user"])
            if key not in fail_times:
                fail_times[key] = []
            fail_times[key].append(e["time"])

    for (ip, user), times in fail_times.items():
        # look at every group of 5 failures in a row
        for i in range(len(times) - 4):
            if times[i + 4] - times[i] <= timedelta(minutes=10):
                msg = f"{len(times)} failed logins on '{user}'"
                alerts.append(make_alert(ip, "Brute force", msg, 60))
                break
    return alerts


# Check 2: password spraying
# one IP tries a lot of DIFFERENT accounts (usually with one common password)
def check_password_spray(events):
    alerts = []
    users_tried = {}  # ip -> set of usernames
    for e in events:
        if not e["success"]:
            if e["ip"] not in users_tried:
                users_tried[e["ip"]] = set()
            users_tried[e["ip"]].add(e["user"])

    for ip, users in users_tried.items():
        if len(users) >= 4:
            msg = f"tried {len(users)} different accounts: {', '.join(sorted(users))}"
            alerts.append(make_alert(ip, "Password spray", msg, 60))
    return alerts


# Check 3: success after failures
# an IP fails a bunch then gets in - the attacker might have guessed the password
def check_success_after_failures(events):
    alerts = []
    fail_count = {}  # ip -> failures so far
    for e in events:
        ip = e["ip"]
        if not e["success"]:
            fail_count[ip] = fail_count.get(ip, 0) + 1
        else:
            if fail_count.get(ip, 0) >= 3:
                msg = f"logged in as '{e['user']}' after {fail_count[ip]} failures - account may be hacked!"
                alerts.append(make_alert(ip, "Success after failures", msg, 40))
            fail_count[ip] = 0
    return alerts


# Check 4: honeytokens
def check_honeytokens(events):
    alerts = []
    honeytokens = load_honeytokens()
    already_alerted = set()
    for e in events:
        if e["user"].lower() in honeytokens and e["ip"] not in already_alerted:
            msg = f"tried fake account '{e['user']}'"
            alerts.append(make_alert(e["ip"], "Honeytoken", msg, 100))
            already_alerted.add(e["ip"])
    return alerts


# Check 5: impossible travel
# a user logs in from two different countries less than an hour apart
def check_impossible_travel(events):
    alerts = []
    last_login = {}  # user -> last successful login event
    for e in events:
        if not e["success"]:
            continue
        user = e["user"]
        if user in last_login:
            prev = last_login[user]
            prev_country = prev["location"].split(", ")[-1]
            new_country = e["location"].split(", ")[-1]
            time_between = e["time"] - prev["time"]
            if prev_country != new_country and time_between < timedelta(hours=1):
                minutes = int(time_between.total_seconds() / 60)
                msg = f"'{user}' logged in from {prev['location']} then {e['location']} {minutes} min later"
                alerts.append(make_alert(e["ip"], "Impossible travel", msg, 70))
        last_login[user] = e
    # NOTE: this blames the second IP, but sometimes the first one is the attacker
    return alerts


def run_all_checks(events):
    alerts = []
    alerts += check_brute_force(events)
    alerts += check_password_spray(events)
    alerts += check_success_after_failures(events)
    alerts += check_honeytokens(events)
    alerts += check_impossible_travel(events)
    return alerts
