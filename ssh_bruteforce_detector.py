import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
REPORT_FILE = "ssh_detection_report.csv"

THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=2)

failed_attempts = defaultdict(list)
successful_logins = defaultdict(list)

timestamp_pattern = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:\+\d{2}:\d{2}|Z))"
)

failed_pattern = re.compile(
    r"sshd.*?Failed password for "
    r"(?:invalid user )?(\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3})"
)

accepted_pattern = re.compile(
    r"sshd.*?Accepted password for "
    r"(\S+) from (\d{1,3}(?:\.\d{1,3}){3})"
)

# Read SSH authentication logs
with open(LOG_FILE, "r") as log:
    for line in log:

        if "sshd" not in line:
            continue

        time_match = timestamp_pattern.search(line)

        if not time_match:
            continue

        timestamp = datetime.fromisoformat(
            time_match.group(1).replace("Z", "+00:00")
        )

        failed_match = failed_pattern.search(line)
        accepted_match = accepted_pattern.search(line)

        if failed_match:
            username = failed_match.group(1)
            source_ip = failed_match.group(2)

            failed_attempts[source_ip].append(
                (timestamp, username)
            )

        elif accepted_match:
            username = accepted_match.group(1)
            source_ip = accepted_match.group(2)

            successful_logins[source_ip].append(
                (timestamp, username)
            )

alerts = []

# Phase 1: Time-based brute-force detection
for source_ip, events in failed_attempts.items():

    events.sort(key=lambda event: event[0])

    left = 0

    for right, event in enumerate(events):

        while (
            event[0] - events[left][0] > TIME_WINDOW
        ):
            left += 1

        window = events[left:right + 1]

        if len(window) >= THRESHOLD:

            alerts.append({
                "Event Type": "SSH Brute Force",
                "Timestamp": event[0].isoformat(),
                "Source IP": source_ip,
                "Failed Attempts": len(window),
                "Attempted Users": ", ".join(
                    sorted(set(user for _, user in window))
                ),
                "Successful User": "",
                "Severity": "HIGH",
                "Status": "Possible SSH Brute Force"
            })

            break

# Phase 2: Failed-to-successful login correlation
for source_ip, logins in successful_logins.items():

    failures = failed_attempts.get(source_ip, [])

    for success_time, success_user in logins:

        recent_failures = [
            (time, user)
            for time, user in failures
            if timedelta(0) <= success_time - time
            <= TIME_WINDOW
        ]

        if len(recent_failures) >= THRESHOLD:

            alerts.append({
                "Event Type": "Brute Force Followed by Success",
                "Timestamp": success_time.isoformat(),
                "Source IP": source_ip,
                "Failed Attempts": len(recent_failures),
                "Attempted Users": ", ".join(
                    sorted(set(user for _, user in recent_failures))
                ),
                "Successful User": success_user,
                "Severity": "CRITICAL",
                "Status": "Suspicious Successful SSH Login After Brute Force"
            })

# Display results
print("\n===== SSH SOC CORRELATION DETECTOR =====")

if alerts:

    for alert in alerts:

        print("\nEvent Type:", alert["Event Type"])
        print("Timestamp:", alert["Timestamp"])
        print("Source IP:", alert["Source IP"])
        print("Failed Attempts:", alert["Failed Attempts"])
        print("Attempted Users:", alert["Attempted Users"])
        print("Successful User:", alert["Successful User"])
        print("Severity:", alert["Severity"])
        print("Alert:", alert["Status"])

else:
    print("No brute-force or correlated login activity detected.")

# Export CSV report
fields = [
    "Event Type",
    "Timestamp",
    "Source IP",
    "Failed Attempts",
    "Attempted Users",
    "Successful User",
    "Severity",
    "Status"
]

with open(REPORT_FILE, "w", newline="") as csvfile:

    writer = csv.DictWriter(
        csvfile,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(alerts)

print("\nReport saved:", REPORT_FILE)
print("===== ANALYSIS COMPLETED =====")
