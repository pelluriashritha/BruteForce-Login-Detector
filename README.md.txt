# Brute Force Login Detector

## Project Overview
This is a beginner-friendly cybersecurity mini project developed using Python. It analyzes sample login logs to identify possible brute-force login activity.

## Features
- Reads login records from a CSV file.
- Counts failed login attempts by IP address.
- Detects repeated failures within a five-minute window.
- Displays security alerts.
- Saves results in a text report.

## Technologies Used
- Python
- CSV files
- Windows Command Prompt

## How to Run
1. Install Python.
2. Place `detector.py` and `login_logs.csv` in the same folder.
3. Open Command Prompt in that folder.
4. Run:

   `python detector.py`

5. View the generated `security_report.txt` file.

## Disclaimer
This project uses fictional sample login records for educational and defensive cybersecurity purposes.
