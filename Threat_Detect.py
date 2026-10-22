# Threat_Detect.py
# Main file - run this one.
#
#   python make_sample_log.py      (only needed once, creates logs/sample_logins.log)
#   python Threat_Detect.py        (analyzes the sample log)
#   python Threat_Detect.py logs/some_other_log.log

import sys

from log_reader import read_log
from detection import run_all_checks, get_risk_level
from lockout import apply_lockouts
from tamper_check import check_for_tampering
from report import write_reports
from history import save_history, HISTORY_FILE

DEFAULT_LOG = "logs/sample_logins.log"


def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = DEFAULT_LOG

    print("Reading", log_file, "...")
    try:
        events = read_log(log_file)
    except FileNotFoundError:
        print("Could not find", log_file)
        print("Run 'python make_sample_log.py' first to make a sample log.")
        return

    print("Found", len(events), "login attempts")

    # step 1 - replay the logins and ban/lock anyone who fails too much
    banned_ips, locked_accounts = apply_lockouts(events)

    # step 2 - look for attack patterns
    alerts = run_all_checks(events)

    # step 3 - add up points for each IP
    scores = {}
    for alert in alerts:
        ip = alert["ip"]
        scores[ip] = scores.get(ip, 0) + alert["points"]

    # step 4 - make sure nobody changed the code
    tamper_problems = check_for_tampering()

    write_reports(events, alerts, scores, banned_ips, locked_accounts, tamper_problems)

    # step 5 - add anything new to the permanent history file
    new_rows = save_history(events, alerts, scores, banned_ips, tamper_problems)

    # print a quick summary
    print()
    print("Alerts found:", len(alerts))
    print("IPs banned:", len(banned_ips))
    print("Accounts locked:", len(locked_accounts))
    for ip in sorted(scores, key=scores.get, reverse=True):
        print("  ", ip, "-", get_risk_level(scores[ip]), "(score", str(min(scores[ip], 100)) + ")")
    if tamper_problems:
        print("WARNING: program files were changed! Check reports/high_risk.txt")
    print()
    print("Reports saved in the reports folder. Start with reports/high_risk.txt")
    print(f"Added {new_rows} new rows to {HISTORY_FILE}")


if __name__ == "__main__":
    main()
