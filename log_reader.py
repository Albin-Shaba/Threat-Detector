# log_reader.py
# Reads the login log. Each line is one login attempt saved as JSON, like:
# {"time": "2026-09-30 02:14:00", "user": "alice", "ip": "203.0.113.10", "success": false, "device": "...", "computer": "..."}

import json
from datetime import datetime

# each IP is from this is fake data for the sample log.
# These IP ranges are just for testing and are never used on the real internet
# make_sample_log.py uses the same list to make random IPs.
# TODO: look up real IPs with a GeoIP database instead
LOCATIONS = {
    "198.51.100": "New York, USA",
    "203.0.113": "Moscow, Russia",
    "198.18": "Beijing, China",
    "198.19": "Sao Paulo, Brazil",
    "192.0.2": "Berlin, Germany",
}


def get_location(ip):
    for key in LOCATIONS:
        if ip == key or ip.startswith(key + "."):
            return LOCATIONS[key]
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local network"
    return "Unknown"


def read_log(filename):
    events = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue
            try:
                data = json.loads(line)
                event = {
                    "time": datetime.strptime(data["time"], "%Y-%m-%d %H:%M:%S"),
                    "user": data["user"],
                    "ip": data["ip"],
                    "success": data["success"],
                    "device": data.get("device", "Unknown"),
                    "computer": data.get("computer", "Unknown"),
                    "location": get_location(data["ip"]),
                    "blocked": False,
                }
                events.append(event)
            except (ValueError, KeyError):
                print("Skipping bad line:", line[:60])

    # make sure everything is in time order
    events.sort(key=lambda e: e["time"])
    return events
