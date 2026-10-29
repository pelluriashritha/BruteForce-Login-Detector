import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta

import streamlit as st

st.set_page_config(
    page_title="Brute Force Login Detector",
    page_icon="🛡️"
)

st.title("🛡️ Brute Force Login Detector")
st.write(
    "Analyze login records to identify possible "
    "brute-force activity."
)

SAMPLE_LOGS = """ip_address,username,status,timestamp
192.168.1.10,admin,FAILED,2026-10-28 10:00:00
192.168.1.10,admin,FAILED,2026-10-28 10:01:00
192.168.1.10,admin,FAILED,2026-10-28 10:02:00
192.168.1.10,admin,FAILED,2026-10-28 10:03:00
192.168.1.20,user1,SUCCESS,2026-10-28 10:04:00
"""

st.info(
    "The app uses fictional sample records by default. "
    "You can upload another CSV file to test it."
)

uploaded_file = st.file_uploader(
    "Upload login_logs.csv (optional)",
    type=["csv"]
)

if uploaded_file:
    csv_text = uploaded_file.getvalue().decode("utf-8-sig")
else:
    csv_text = SAMPLE_LOGS

threshold = st.number_input(
    "Failed attempts needed for an alert",
    min_value=2,
    max_value=20,
    value=3
)

window_minutes = st.number_input(
    "Detection time window (minutes)",
    min_value=1,
    max_value=60,
    value=5
)

# Remove blank lines before the CSV header.
reader = csv.DictReader(io.StringIO(csv_text.lstrip()))

if not reader.fieldnames:
    st.error("The CSV file is empty or has no header.")
    st.stop()

reader.fieldnames = [
    name.strip() if name else ""
    for name in reader.fieldnames
]

required = {
    "ip_address", "username", "status", "timestamp"
}

if not required.issubset(set(reader.fieldnames)):
    st.error(
        "CSV must contain these columns: "
        "ip_address, username, status, timestamp"
    )
    st.stop()

failed_attempts = defaultdict(list)

try:
    for row in reader:
        ip = (row.get("ip_address") or "").strip()
        status = (row.get("status") or "").strip().upper()

        if not ip or status != "FAILED":
            continue

        timestamp = datetime.strptime(
            (row.get("timestamp") or "").strip(),
            "%Y-%m-%d %H:%M:%S"
        )

        failed_attempts[ip].append(timestamp)

except ValueError:
    st.error(
        "A timestamp is invalid. Use YYYY-MM-DD HH:MM:SS."
    )
    st.stop()

alerts = []
time_window = timedelta(minutes=int(window_minutes))

for ip, times in failed_attempts.items():
    times.sort()

    for i, start_time in enumerate(times):
        recent = [
            t for t in times[i:]
            if t - start_time <= time_window
        ]

        if len(recent) >= int(threshold):
            alerts.append((ip, len(recent)))
            break

report = [
    "BRUTE FORCE LOGIN DETECTOR REPORT",
    "Generated: " + datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    ),
    ""
]

st.subheader("Detection results")

if alerts:
    for ip, count in alerts:
        st.error("Possible suspicious login activity detected")
        st.write("Suspicious IP:", ip)
        st.write(
            f"Failed attempts within {window_minutes} minutes: "
            f"{count}"
        )

        report.extend([
            "SECURITY ALERT!",
            "Suspicious IP: " + ip,
            f"Failed attempts within {window_minutes} minutes: {count}",
            "Possible brute-force activity detected.",
            ""
        ])
else:
    st.success("No suspicious login activity detected.")
    report.append("No suspicious login activity detected.")

report.append("Detection completed.")

st.download_button(
    label="Download security report",
    data="\n".join(report) + "\n",
    file_name="security_report.txt",
    mime="text/plain"
)
