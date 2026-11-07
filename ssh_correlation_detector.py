import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
REPORT_FILE = "ssh_correlation_report.csv"

THRESHOLD = 5
BRUTE_WINDOW = timedelta(minutes=2)
CORRELATION_WINDOW = timedelta(minutes=5)

failed_events = defaultdict(list)
successful_events = []

pattern = re.compile(
    r'^(\S+)\s+\S+\s+sshd\[\d+\]:\s+(.*)$'
)

failed_pattern = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+)'
)

accepted_pattern = re.compile(
    r'Accepted password for (\S+) from (\S+)'
)

with open(LOG_FILE, "r") as log:
    for line in log:
        match = pattern.search(line)

        if not match:
            continue

        try:
            timestamp = datetime.fromisoformat(match.group(1))
        except ValueError:
            continue

        message = match.group(2)

        failed = failed_pattern.search(message)
        accepted = accepted_pattern.search(message)

        if failed:
            username, source_ip = failed.groups()
            failed_events[source_ip].append(
                (timestamp, username)
            )

        elif accepted:
            username, source_ip = accepted.groups()
            successful_events.append(
                (timestamp, username, source_ip)
            )

alerts = []

for source_ip, events in failed_events.items():
    events.sort()

    for i in range(len(events)):
        window = [
            event for event in events[:i + 1]
            if events[i][0] - event[0] <= BRUTE_WINDOW
        ]

        if len(window) < THRESHOLD:
            continue

        last_failure = events[i][0]

        matching_logins = [
            login for login in successful_events
            if login[2] == source_ip
            and login[0] > last_failure
            and login[0] <= last_failure + CORRELATION_WINDOW
        ]

        if matching_logins:
            for login in matching_logins:
                alerts.append({
                    "Source IP": source_ip,
                    "Failed Attempts": len(window),
                    "Last Failed Login": last_failure.isoformat(),
                    "Successful User": login[1],
                    "Successful Login": login[0].isoformat(),
                    "Severity": "CRITICAL",
                    "Status": "Brute Force Followed By Successful Login"
                })
        else:
            alerts.append({
                "Source IP": source_ip,
                "Failed Attempts": len(window),
                "Last Failed Login": last_failure.isoformat(),
                "Successful User": "None",
                "Successful Login": "None",
                "Severity": "HIGH",
                "Status": "Possible SSH Brute Force"
            })


print("\n===== SSH SOC CORRELATION DETECTOR =====")

if alerts:
    for alert in alerts:
        for key, value in alert.items():
            print(f"{key}: {value}")
        print("------------------------------")
else:
    print("No correlated brute-force activity detected.")

fields = [
    "Source IP",
    "Failed Attempts",
    "Last Failed Login",
    "Successful User",
    "Successful Login",
    "Severity",
    "Status"
]

with open(REPORT_FILE, "w", newline="") as report:
    writer = csv.DictWriter(report, fieldnames=fields)
    writer.writeheader()
    writer.writerows(alerts)

print(f"\nReport saved: {REPORT_FILE}")
print("===== ANALYSIS COMPLETED =====")
