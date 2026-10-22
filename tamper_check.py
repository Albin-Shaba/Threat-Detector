# tamper_check.py
# Makes sure nobody edited the program files or the honeytoken list.
# The first time it runs it saves a hash (fingerprint) of each file.
# After that, if a file's hash changes, it gets reported as CRITICAL.
#
# If YOU changed the code on purpose, delete file_hashes.json and run again.

import hashlib
import json
import os

FILES_TO_CHECK = [
    "Threat_Detect.py",
    "log_reader.py",
    "detection.py",
    "lockout.py",
    "report.py",
    "history.py",
    "live_monitor.py",
    "honeytokens.txt",
]
HASH_FILE = "file_hashes.json"


def get_hash(filename):
    with open(filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_for_tampering():
    current = {}
    for name in FILES_TO_CHECK:
        if os.path.exists(name):
            current[name] = get_hash(name)

    # first run - nothing to compare to yet, so just save the hashes
    if not os.path.exists(HASH_FILE):
        with open(HASH_FILE, "w") as f:
            json.dump(current, f, indent=2)
        print("Saved file hashes for tamper checking")
        return []

    with open(HASH_FILE) as f:
        saved = json.load(f)

    problems = []
    for name in saved:
        if name not in current:
            problems.append(name + " was DELETED")
        elif current[name] != saved[name]:
            problems.append(name + " was CHANGED")
    return problems
