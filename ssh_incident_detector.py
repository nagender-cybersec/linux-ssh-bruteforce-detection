
import re
import csv
from datetime import datetime, timedelta

LOG_FILE = "/var/log/auth.log"
REPORT_FILE = "ssh_incident_report.csv"

THRESHOLD = 5
BRUTE_WINDOW = timedelta(minutes=2)
CORRELATION_WINDOW = timedelta(minutes=5)

failed_events = []
successful_events = []

log_pattern = re.compile(
    r'^(\S+)\s+\S+\s+sshd\[\d+\]:\s+(.*)$'
)

failed_pattern = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+)'
)

accepted_pattern = re.compile(
    r'Accepted password for (\S+) from (\S+)'
)

# STEP 1: Read SSH authentication logs

with open(LOG_FILE, "r") as log:
    for line in log:

        match = log_pattern.search(line)

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

            failed_events.append(
                (timestamp, username, source_ip)
            )

        elif accepted:
            username, source_ip = accepted.groups()

            successful_events.append(
                (timestamp, username, source_ip)
            )

# STEP 2: Group failed attempts into attack bursts

failed_by_ip = {}

for event in failed_events:
    timestamp, username, source_ip = event

    failed_by_ip.setdefault(source_ip, []).append(
        (timestamp, username)
    )

alerts = []

for source_ip, events in failed_by_ip.items():

    events.sort(key=lambda x: x[0])

    bursts = []
    current_burst = []

    for event in events:

        if not current_burst:
            current_burst.append(event)

        elif (
            event[0] - current_burst[-1][0]
            <= BRUTE_WINDOW
        ):
            current_burst.append(event)

        else:
            bursts.append(current_burst)
            current_burst = [event]

    if current_burst:
        bursts.append(current_burst)

    # STEP 3: Analyze each attack burst

    for burst in bursts:

        if len(burst) < THRESHOLD:
            continue

        last_failure = burst[-1][0]

        matching_logins = [
            login
            for login in successful_events
            if login[2] == source_ip
            and last_failure < login[0]
            and login[0] <= last_failure + CORRELATION_WINDOW
        ]

        matching_logins.sort(key=lambda x: x[0])

        attempted_users = sorted({
            username for timestamp, username in burst
        })

        incident_id = (
            f"SSH-{last_failure.strftime('%Y%m%d%H%M%S')}-"
            f"{source_ip.replace('.', '_').replace(':', '_')}"
        )

        if matching_logins:

            login = matching_logins[0]

            time_difference = (
                login[0] - last_failure
            ).total_seconds()

            severity = "CRITICAL"

            status = (
                "Brute Force Followed By Successful Login"
            )

            successful_user = login[1]
            successful_time = login[0].isoformat()

            recommendation = (
                "Investigate account, validate login, "
                "review source IP and consider containment."
            )

        else:

            time_difference = ""

            severity = "HIGH"

            status = "Possible SSH Brute Force"

            successful_user = "None"
            successful_time = "None"

            recommendation = (
                "Investigate source IP, review authentication "
                "logs and monitor further attempts."
            )

        alerts.append({
            "Incident ID": incident_id,
            "Source IP": source_ip,
            "Failed Attempts": len(burst),
            "Attempted Users": ", ".join(attempted_users),
            "Last Failed Login": last_failure.isoformat(),
            "Successful User": successful_user,
            "Successful Login": successful_time,
            "Time To Successful Login (Seconds)": time_difference,
            "Severity": severity,
            "Status": status,
            "Recommended Action": recommendation
        })

# STEP 4: Display SOC incident report

print("\n===== SSH SOC INCIDENT INVESTIGATION =====")

if alerts:

    for alert in alerts:

        print("\nIncident ID:", alert["Incident ID"])
        print("Source IP:", alert["Source IP"])
        print("Failed Attempts:", alert["Failed Attempts"])
        print("Successful User:", alert["Successful User"])
        print("Severity:", alert["Severity"])
        print("Status:", alert["Status"])
        print("Recommended Action:", alert["Recommended Action"])

        print("--------------------------------------")

else:
    print("No brute-force incidents detected.")

# STEP 5: Export consolidated incident report

fields = [
    "Incident ID",
    "Source IP",
    "Failed Attempts",
    "Attempted Users",
    "Last Failed Login",
    "Successful User",
    "Successful Login",
    "Time To Successful Login (Seconds)",
    "Severity",
    "Status",
    "Recommended Action"
]

with open(REPORT_FILE, "w", newline="") as report:

    writer = csv.DictWriter(
        report,
        fieldnames=fields
    )

    writer.writeheader()
    writer.writerows(alerts)

print("\nReport saved:", REPORT_FILE)
print("===== INVESTIGATION COMPLETED =====")

