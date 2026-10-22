# Login Threat Detector

A Python program that reads login logs and looks for attacks, it bans IPs that fail too many times, gives each suspicious IP a risk score, and writes the high-risk ones to a separate report

## How to run it

You need Python 3.8 or newer, nothing to install

```
python make_sample_log.py
python Threat_Detect.py
```

Then open `reports/high_risk.txt`

To analyze a different log: `python Threat_Detect.py path/to/log.log`

### Threat history

`threat_history.csv` is a permanent record. Each run adds new rows to the bottom and never erases old ones. Each row has:

- When it was found
- Type: ALERT, BAN or TAMPER
- Threat level and score
- IP, location, device and computer name
- What happened
- Which accounts the IP tried
- First and last attempt times
- How many attempts failed, succeeded or were blocked

Nothing gets saved twice, even if you analyze the same log again. Open the file in Excel to sort and filter it.

### Live mode (super happy about this)

```
python live_monitor.py
```

This runs until you press Ctrl+C. It makes its own traffic in real time:

- Every 5 seconds a new user logs in from a new IP.
- Every 10-15 seconds a new attacker shows up: brute force, password spray, a guessed password, a stolen password, or a honeytoken.

Alerts and bans print live in color. The reports folder updates after every attack. Every login attempt is saved to `logs/live_logins.log`, so you can run `python Threat_Detect.py logs/live_logins.log` on it afterwards.

## What it checks for

| Check | What it means | Points |
| Brute force | Same IP fails on one account 5+ times within 10 minutes | 60 |
| Password spray | One IP tries 4+ different accounts | 60 |
| Success after failures | IP fails 3+ times, then gets in (account may be hacked) | 40 |
| Honeytoken | Someone tries a fake account from `honeytokens.txt` | 100 |
| Impossible travel | User logs in from 2 countries less than an hour apart | 70 |

Risk levels: 0-29 LOW, 30-59 MEDIUM, 60-89 HIGH, 90+ CRITICAL

**Bans and lockouts**

- An IP is banned after 5 failed logins, and immediately if it tries a honeytoken account.
- An account is locked for 15 minutes after 5 failed logins in a row.
- Banned IPs are saved to `banned_ips.json`.

**Tamper check**

The first run saves a SHA-256 hash of every program file. If any file changes later, the report shows a CRITICAL warning. If you changed the code on purpose, delete `file_hashes.json` to reset it.

## Files

- `Threat_Detect.py` - main file, runs everything
- `log_reader.py` - reads the log file and looks up locations
- `detection.py` - the 5 attack checks
- `lockout.py` - banning and locking
- `tamper_check.py` - detects if program files were edited
- `report.py` - writes the reports
- `history.py` - saves every alert and ban ever found to `threat_history.csv`
- `live_monitor.py` - live mode, makes traffic and detects attacks in real time
- `make_sample_log.py` - makes a random fake log with attacks in it, plus an answer key
- `honeytokens.txt` - list of fake accounts

## Known issues

- **Impossible travel can blame the wrong IP.** It always flags the second login. In the sample log, the attacker logs into dave's account from China, and then dave's real New York IP gets flagged. Fix idea: flag whichever IP the user doesn't normally use.
- **IP fail counts never reset**, so a real user who mistypes their password 5 times over a long period gets banned.
- **Locations are fake.** They come from a small hardcoded list.

## Things I want to add

- Real IP locations using the free MaxMind GeoLite2 database
- Reading real Linux `/var/log/auth.log` files
- A login page that uses the ban list live
- Email alerts for CRITICAL findings
- Unit tests
