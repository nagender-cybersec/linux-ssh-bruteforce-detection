
import subprocess
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5
BRUTE_WINDOW = timedelta(minutes=2)
CORRELATION_WINDOW = timedelta(minutes=5)

failed = defaultdict(deque)

failed_pattern = re.compile(
    r"sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(\S+) from (\S+)"
)

accepted_pattern = re.compile(
    r"sshd\[\d+\]: Accepted password for (\S+) from (\S+)"
)

print("===== SSH REAL-TIME SOC MONITOR =====")
print("Monitoring SSH authentication logs...")
print("Press CTRL+C to stop.")

process = subprocess.Popen(
    ["tail", "-n", "0", "-F", LOG_FILE],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

try:
    for line in process.stdout:
        timestamp_match = re.match(r"^(\S+)", line)

        if not timestamp_match:
            continue

        try:
            event_time = datetime.fromisoformat(
                timestamp_match.group(1).replace("Z", "+00:00")
            )
        except ValueError:
            continue

        failed_match = failed_pattern.search(line)
        accepted_match = accepted_pattern.search(line)

        if failed_match:
            username, source_ip = failed_match.groups()

            events = failed[source_ip]
            events.append((event_time, username))

            while events and event_time - events[0][0] > BRUTE_WINDOW:
                events.popleft()

            print(
                f"[FAILED] User={username} "
                f"Source={source_ip} "
                f"Attempts={len(events)}"
            )

            if len(events) == THRESHOLD:
                print("\n[HIGH] SSH BRUTE FORCE DETECTED")
                print("Source IP:", source_ip)
                print("Failed attempts:", len(events))
                print("==============================")

        elif accepted_match:
            username, source_ip = accepted_match.groups()

            recent_failures = [
                event for event in failed[source_ip]
                if timedelta(0) <= event_time - event[0]
                <= CORRELATION_WINDOW
            ]

            print(
                f"[SUCCESSFUL LOGIN] User={username} "
                f"Source={source_ip}"
            )

            if len(recent_failures) >= THRESHOLD:
                print("\n[CRITICAL] BRUTE FORCE FOLLOWED BY SUCCESSFUL LOGIN")
                print("Source IP:", source_ip)
                print("Failed attempts:", len(recent_failures))
                print("Successful user:", username)
                print("Severity: CRITICAL")
                print("Status: Investigate possible account compromise")
                print("==============================================")

except KeyboardInterrupt:
    print("\nMonitoring stopped.")

finally:
    process.terminate()

