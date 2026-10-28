
import csv
from collections import defaultdict
from datetime import datetime, timedelta

THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)

failed_attempts = defaultdict(list)
report_lines = []

with open("login_logs.csv", "r", newline="", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    for row in reader:
        ip = row["ip_address"].strip()
        status = row["status"].strip().upper()

        if status == "FAILED":
            event_time = datetime.strptime(
                row["timestamp"].strip(),
                "%Y-%m-%d %H:%M:%S"
            )
            failed_attempts[ip].append(event_time)

report_lines.append("=== BRUTE FORCE LOGIN DETECTOR REPORT ===")
report_lines.append("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
report_lines.append("")

found = False

for ip, times in failed_attempts.items():
    times.sort()

    for i, start_time in enumerate(times):
        recent = [
            t for t in times[i:]
            if t - start_time <= TIME_WINDOW
        ]

        if len(recent) >= THRESHOLD:
            report_lines.append("SECURITY ALERT!")
            report_lines.append("Suspicious IP: " + ip)
            report_lines.append(
                "Failed attempts within 5 minutes: " + str(len(recent))
            )
            report_lines.append("Possible brute-force activity detected.")
            report_lines.append("")
            found = True
            break

if not found:
    report_lines.append("No suspicious login activity detected.")

report_lines.append("")
report_lines.append("Detection completed.")

for line in report_lines:
    print(line)

with open("security_report.txt", "w", encoding="utf-8") as report:
    report.write("\n".join(report_lines) + "\n")

print("\nReport saved to security_report.txt")
