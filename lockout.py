# lockout.py
# Goes through the logins in order and decides who gets banned or locked.
#   - an IP that fails 5 times is banned
#   - an account that fails 5 times in a row is locked for 15 minutes
#   - an IP that tries a honeytoken account is banned right away
# Banned IPs are saved to banned_ips.json

import json
from datetime import timedelta

from detection import load_honeytokens

MAX_FAILS = 5
LOCK_TIME = timedelta(minutes=15)
BANNED_FILE = "banned_ips.json"


def apply_lockouts(events):
    honeytokens = load_honeytokens()
    banned_ips = {}        # ip -> reason
    locked_accounts = {}   # user -> time the lock ends
    ip_fails = {}
    user_fails = {}

    for e in events:
        ip = e["ip"]
        user = e["user"]

        # if already banned then this attempt gets blocked
        if ip in banned_ips:
            e["blocked"] = True
            continue

        if user.lower() in honeytokens:
            banned_ips[ip] = f"tried honeytoken account '{user}'"
            e["blocked"] = True
            continue

        # checks if account is locked right now
        if user in locked_accounts and e["time"] < locked_accounts[user]:
            e["blocked"] = True
            continue

        if e["success"]:
            user_fails[user] = 0
            continue

        # failed login - count it
        ip_fails[ip] = ip_fails.get(ip, 0) + 1
        user_fails[user] = user_fails.get(user, 0) + 1

        if ip_fails[ip] >= MAX_FAILS:
            banned_ips[ip] = f"{ip_fails[ip]} failed logins"
        if user_fails[user] >= MAX_FAILS:
            locked_accounts[user] = e["time"] + LOCK_TIME
            user_fails[user] = 0

    # TODO: ip_fails never resets, so a normal user who mistypes their
    # password 5 times over a whole month would get banned too

    with open(BANNED_FILE, "w") as f:
        json.dump(banned_ips, f, indent=2)

    return banned_ips, locked_accounts
