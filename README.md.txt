# BruteForce-Login-Detector

A Python mini project to detect suspicious login attempts using sample logs.

## Objective
To identify possible brute-force login activity by analyzing repeated failed login attempts from the same IP address within a five-minute window.

## Features
- Reads login records from a CSV file.
- Counts failed login attempts by IP address.
- Detects repeated failures within five minutes.
- Displays security alerts.
- Saves detection results in `security_report.txt`.

## Technologies Used
- Python
- CSV (Comma-Separated Values)
- Windows Command Prompt

## Project Files
- `detector.py` — analyzes login records and detects suspicious activity.
- `login_logs.csv` — contains fictional sample login records.
- `security_report.txt` — stores the detection report.
- `README.md` — describes the project.

## How to Run
1. Install Python.
2. Keep `detector.py` and `login_logs.csv` in the same folder.
3. Open Command Prompt in that folder.
4. Run:

   `python detector.py`

5. Open `security_report.txt` to view the saved report.

## Expected Result
The program displays a security alert when an IP address has three or more failed login attempts within five minutes.

## Disclaimer
This project is for educational and defensive cybersecurity purposes. It uses fictional sample login records and identifies possible suspicious activity; an alert does not prove an attack occurred.