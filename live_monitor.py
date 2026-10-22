# live_monitor.py :)
# Runs forever and makes its own fake traffic in real time
#   every 5 seconds a new user logs in from a new IP
#   every 10-15 seconds a new attacker IP shows up and attacks
# The detector checks everything as it happens and prints alerts or bans
#   python live_monitor.py        press Ctrl+C to stop
# Everything is also saved to logs/live_logins.log and the reports folder
# gets updated after every attack.

import json
import os
import random
import time
from datetime import datetime, timedelta

from log_reader import get_location
from detection import run_all_checks, get_risk_level, load_honeytokens
from lockout import apply_lockouts
from tamper_check import check_for_tampering
from report import write_reports
from history import save_history, HISTORY_FILE

LOGIN_EVERY = 5               # seconds between normal logins
ATTACK_EVERY = (10, 15)       # random seconds between attacks
LIVE_LOG = "logs/live_logins.log"

NAMES = ["alex", "jordan", "taylor", "sam", "chris", "maria", "kevin", "lisa",
         "omar", "priya", "jake", "emma", "noah", "zoe", "liam", "ava"]
NORMAL_DEVICES = ["Chrome on Windows", "Safari on Mac", "Firefox on Linux",
                  "Safari on iPhone", "Chrome on Android", "Edge on Windows"]
ATTACK_DEVICES = ["Hydra", "python-requests", "curl", "Nmap", "Medusa", "Burp Suite"]
ATTACK_COMPUTERS = ["kali", "vps-server", "unknown", "DESKTOP-X7Q2", "scanner01", "parrot-os"]
USA = "198.51.100"
ATTACKER_RANGES = ["203.0.113", "198.18", "198.19", "192.0.2"]

# colors for the terminal
os.system("")  # turns on colors in the Windows terminal
GRAY, GREEN, YELLOW, ORANGE, RED, BOLD, RESET = (
    "\033[90m", "\033[92m", "\033[93m", "\033[38;5;208m", "\033[91m", "\033[1m", "\033[0m")
LEVEL_COLORS = {"LOW": GRAY, "MEDIUM": YELLOW, "HIGH": ORANGE, "CRITICAL": RED}

events = []
users = {}        # username -> (home ip, device, computer)
used_ips = set()


# ------------------------------------------------------------------ helpers
def random_ip(prefix):
    while True:
        if prefix.count(".") == 2:
            ip = f"{prefix}.{random.randint(1, 254)}"
        else:
            ip = f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip


def clock():
    return datetime.now().strftime("%H:%M:%S")


def add_event(when, user, ip, success, device, computer):
    event = {
        "time": when.replace(microsecond=0),
        "user": user,
        "ip": ip,
        "success": success,
        "device": device,
        "computer": computer,
        "location": get_location(ip),
        "blocked": False,
    }
    events.append(event)

    os.makedirs("logs", exist_ok=True)
    with open(LIVE_LOG, "a") as f:
        saved = dict(event)
        saved["time"] = event["time"].strftime("%Y-%m-%d %H:%M:%S")
        del saved["location"], saved["blocked"]
        f.write(json.dumps(saved) + "\n")


def new_attacker():
    return random_ip(random.choice(ATTACKER_RANGES)), random.choice(ATTACK_DEVICES), random.choice(ATTACK_COMPUTERS)


def times_ending_now(count, gap_seconds):
    # makes a list of times a few seconds apart that ends right now
    now = datetime.now()
    return [now - timedelta(seconds=gap_seconds * (count - 1 - i)) for i in range(count)]


# ------------------------------------------------------------ normal traffic
def normal_login():
    name = random.choice(NAMES) + str(random.randint(10, 99))
    while name in users:
        name = random.choice(NAMES) + str(random.randint(10, 99))
    ip = random_ip(USA)
    device = random.choice(NORMAL_DEVICES)
    users[name] = (ip, device, name.upper() + "-PC")
    add_event(datetime.now(), name, ip, True, device, users[name][2])
    print(f"{GRAY}[{clock()}]{RESET} {GREEN}LOGIN {RESET} {name:<10} from {ip:<16} ({get_location(ip)})")


# ------------------------------------------------------------------ attacks
# every attack is built to end up MEDIUM, HIGH or CRITICAL
def attack_brute_force():
    target = random.choice(list(users))
    ip, device, computer = new_attacker()
    tries = random.randint(5, 12)
    for t in times_ending_now(tries, 2):
        add_event(t, target, ip, False, device, computer)
    return ip, f"brute force on '{target}' ({tries} tries)"


def attack_guess_then_get_in():
    target = random.choice(list(users))
    ip, device, computer = new_attacker()
    fails = random.randint(3, 4)
    times = times_ending_now(fails + 1, 3)
    for t in times[:-1]:
        add_event(t, target, ip, False, device, computer)
    add_event(times[-1], target, ip, True, device, computer)
    return ip, f"failed {fails} times on '{target}' then GOT IN"


def attack_password_spray():
    targets = random.sample(list(users), min(random.randint(4, 6), len(users)))
    ip, device, computer = new_attacker()
    for name, t in zip(targets, times_ending_now(len(targets), 2)):
        add_event(t, name, ip, False, device, computer)
    return ip, f"password spray on {len(targets)} accounts"


def attack_honeytoken():
    ip, device, computer = new_attacker()
    fake = random.choice(load_honeytokens())
    add_event(datetime.now(), fake, ip, False, device, computer)
    return ip, f"tried honeytoken account '{fake}'"


def attack_stolen_password():
    # someone in another country logs in as a user who just logged in from the USA
    victim = random.choice(list(users))
    ip, device, computer = new_attacker()
    add_event(datetime.now(), victim, ip, True, device, computer)
    return ip, f"logged in as '{victim}' with a stolen password"


ATTACKS = [attack_brute_force, attack_guess_then_get_in, attack_password_spray,
           attack_honeytoken, attack_stolen_password]


# ------------------------------------------------------------------ detector
seen_alerts = set()
seen_bans = set()


def run_detector():
    events.sort(key=lambda e: e["time"])
    banned_ips, locked_accounts = apply_lockouts(events)
    alerts = run_all_checks(events)

    scores = {}
    for a in alerts:
        scores[a["ip"]] = scores.get(a["ip"], 0) + a["points"]

    for a in alerts:
        key = (a["ip"], a["rule"])
        if key not in seen_alerts:
            seen_alerts.add(key)
            score = min(scores[a["ip"]], 100)
            level = get_risk_level(score)
            color = LEVEL_COLORS[level]
            print(f"           {color}{BOLD}>>> {level} ({score}){RESET}{color} {a['ip']} - {a['rule']}: {a['message']}{RESET}")

    for ip, reason in banned_ips.items():
        if ip not in seen_bans:
            seen_bans.add(ip)
            print(f"           {RED}{BOLD}>>> BANNED {ip}{RESET}{RED} - {reason}{RESET}")

    # save anything new to the permanent history file right away
    save_history(events, alerts, scores, banned_ips)

    return alerts, scores, banned_ips, locked_accounts


def main():
    print(f"{BOLD}LIVE THREAT MONITOR{RESET} - press Ctrl+C to stop\n")
    tamper_problems = check_for_tampering()
    if tamper_problems:
        print(f"{RED}{BOLD}WARNING: program files were changed: {', '.join(tamper_problems)}{RESET}\n")
        save_history([], [], {}, {}, tamper_problems)

    # a few users are already logged in when we start, so attacks have targets
    for i in range(4):
        normal_login()

    next_login = time.time() + LOGIN_EVERY
    next_attack = time.time() + random.randint(*ATTACK_EVERY)
    results = run_detector()

    try:
        while True:
            now = time.time()
            if now >= next_login:
                normal_login()
                next_login += LOGIN_EVERY
                results = run_detector()

            if now >= next_attack:
                attack = random.choice(ATTACKS)
                ip, what = attack()
                print(f"{GRAY}[{clock()}]{RESET} {RED}ATTACK{RESET} {ip:<16} ({get_location(ip)}) {what}")
                results = run_detector()
                alerts, scores, banned_ips, locked_accounts = results
                write_reports(events, alerts, scores, banned_ips, locked_accounts, tamper_problems)
                next_attack = now + random.randint(*ATTACK_EVERY)

            time.sleep(0.2)

    except KeyboardInterrupt:
        alerts, scores, banned_ips, locked_accounts = results
        write_reports(events, alerts, scores, banned_ips, locked_accounts, tamper_problems)
        print(f"\n{BOLD}Stopped.{RESET} {len(events)} login attempts, {len(alerts)} alerts, "
              f"{len(banned_ips)} IPs banned, {len(locked_accounts)} accounts locked")
        for level in ["CRITICAL", "HIGH", "MEDIUM"]:
            count = len([ip for ip in scores if get_risk_level(scores[ip]) == level])
            print(f"  {LEVEL_COLORS[level]}{level}: {count}{RESET}")
        print("Reports saved in the reports folder. Full log in", LIVE_LOG)
        print("Every alert and ban is saved in", HISTORY_FILE)


if __name__ == "__main__":
    main()
