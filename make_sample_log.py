# make_sample_log.py
# Creates a fake login log with normal users AND random attacks mixed in.
# Every run is different: random IPs, random users, random attacks.
#
#   python make_sample_log.py        -> new random log every time
#   python make_sample_log.py 42     -> same log every time you use 42 (good for testing)
#
# It also writes logs/answer_key.txt listing every attack it made,
# so you can check if Threat_Detect.py caught them all.

import json
import os
import random
import sys
from datetime import datetime, timedelta

from detection import load_honeytokens

if len(sys.argv) > 1:
    random.seed(int(sys.argv[1]))

DAY = datetime(2026, 9, 30)
log = []
answer_key = []

NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "ivan", "judy", "mike", "nina", "oscar", "peggy", "sam", "trent"]
NORMAL_DEVICES = ["Chrome on Windows", "Safari on Mac", "Firefox on Linux",
                  "Safari on iPhone", "Chrome on Android", "Edge on Windows"]
ATTACK_DEVICES = ["Hydra", "python-requests", "curl", "Nmap", "Medusa", "Burp Suite"]
ATTACK_COMPUTERS = ["kali", "vps-server", "unknown", "DESKTOP-X7Q2", "scanner01", "parrot-os"]

# IP ranges for each country (must match LOCATIONS in log_reader.py)
USA = "198.51.100"
ATTACKER_RANGES = ["203.0.113", "198.18", "198.19", "192.0.2"]

used_ips = set()


def random_ip(prefix):
    # make a random IP inside a range, and never reuse one
    while True:
        if prefix.count(".") == 2:          # like 198.51.100
            ip = f"{prefix}.{random.randint(1, 254)}"
        else:                               # like 198.18
            ip = f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if ip not in used_ips:
            used_ips.add(ip)
            return ip


def random_time(start_hour=0, end_hour=23):
    return DAY + timedelta(hours=random.randint(start_hour, end_hour),
                           minutes=random.randint(0, 59), seconds=random.randint(0, 59))


def add(time, user, ip, success, device, computer):
    log.append({
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "ip": ip,
        "success": success,
        "device": device,
        "computer": computer,
    })


def new_attacker():
    return random_ip(random.choice(ATTACKER_RANGES)), random.choice(ATTACK_DEVICES), random.choice(ATTACK_COMPUTERS)


# ---------------------------------------------------------------- normal users
num_users = random.randint(6, 12)
user_names = random.sample(NAMES, num_users)
users = {}
for name in user_names:
    users[name] = (random_ip(USA), random.choice(NORMAL_DEVICES), name.upper() + "-PC")

for name, (ip, device, computer) in users.items():
    for i in range(random.randint(2, 5)):
        t = random_time(8, 17)
        typos = random.choice([0, 0, 0, 1, 1, 2])   # most people type it right
        for j in range(typos):
            add(t, name, ip, False, device, computer)
            t += timedelta(seconds=random.randint(5, 20))
        add(t, name, ip, True, device, computer)


# -------------------------------------------------------------------- attacks
def attack_guess_then_get_in():
    # attacker fails a few times, then guesses the password
    target = random.choice(user_names)
    ip, device, computer = new_attacker()
    fails = random.randint(2, 6)
    t = random_time()
    for i in range(fails):
        add(t, target, ip, False, device, computer)
        t += timedelta(seconds=random.randint(5, 40))
    add(t, target, ip, True, device, computer)
    answer_key.append(f"{ip}: failed {fails} times on '{target}' then GOT IN")


def attack_brute_force():
    target = random.choice(user_names)
    ip, device, computer = new_attacker()
    tries = random.randint(5, 20)
    t = random_time()
    for i in range(tries):
        add(t, target, ip, False, device, computer)
        t += timedelta(seconds=random.randint(2, 15))
    answer_key.append(f"{ip}: brute force, {tries} failed tries on '{target}'")


def attack_password_spray():
    ip, device, computer = new_attacker()
    targets = random.sample(user_names, random.randint(3, min(7, len(user_names))))
    t = random_time()
    for name in targets:
        add(t, name, ip, False, device, computer)
        t += timedelta(seconds=random.randint(20, 90))
    note = ""
    if random.random() < 0.5:   # sometimes the spray works on one person
        lucky = random.choice([n for n in user_names if n not in targets] or user_names)
        add(t, lucky, ip, True, device, computer)
        note = f", then GOT IN as '{lucky}'"
    answer_key.append(f"{ip}: password spray on {len(targets)} accounts{note}")


def attack_honeytoken():
    ip, device, computer = new_attacker()
    fake_account = random.choice(load_honeytokens())
    t = random_time()
    add(t, fake_account, ip, False, device, computer)
    for i in range(random.randint(0, 3)):   # sometimes it keeps going
        t += timedelta(seconds=random.randint(10, 60))
        add(t, random.choice(user_names), ip, False, device, computer)
    answer_key.append(f"{ip}: tried honeytoken account '{fake_account}'")


def attack_stolen_password():
    # a real user logs in, then someone in another country logs in as them soon after
    victim = random.choice(user_names)
    home_ip, device, computer = users[victim]
    t = random_time(8, 16)
    add(t, victim, home_ip, True, device, computer)
    ip, attack_device, attack_computer = new_attacker()
    minutes = random.randint(5, 50)
    add(t + timedelta(minutes=minutes), victim, ip, True, attack_device, attack_computer)
    answer_key.append(f"{ip}: used '{victim}'s stolen password {minutes} min after the real login")


def attack_slow_and_sneaky():
    # one try every 15-30 minutes so it never looks like brute force
    target = random.choice(user_names)
    ip, device, computer = new_attacker()
    tries = random.randint(4, 8)
    t = random_time(0, 12)
    for i in range(tries):
        add(t, target, ip, False, device, computer)
        t += timedelta(minutes=random.randint(15, 30))
    answer_key.append(f"{ip}: SLOW attack, {tries} tries on '{target}' spread over hours (hard to catch)")


ATTACKS = [attack_guess_then_get_in, attack_brute_force, attack_password_spray,
           attack_honeytoken, attack_stolen_password, attack_slow_and_sneaky]

num_attacks = random.randint(3, 7)
for i in range(num_attacks):
    attack = random.choice(ATTACKS)
    attack()


# ---------------------------------------------------------------- save files
log.sort(key=lambda e: e["time"])
os.makedirs("logs", exist_ok=True)
with open("logs/sample_logins.log", "w") as f:
    for entry in log:
        f.write(json.dumps(entry) + "\n")

with open("logs/answer_key.txt", "w") as f:
    f.write("ATTACKS IN THIS LOG (compare with reports/high_risk.txt)\n\n")
    for line in answer_key:
        f.write(line + "\n")

print(f"Made logs/sample_logins.log with {len(log)} login attempts")
print(f"{num_users} normal users and {num_attacks} attacks:")
for line in answer_key:
    print("  -", line)
