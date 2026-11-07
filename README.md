# SSH Brute Force Detection and Incident Monitoring

## Project Overview
A Python-based SOC monitoring project that
detects SSH brute-force attacks by analyzing
Linux authentication logs.

## Features
- Real-time SSH authentication monitoring
- Failed login detection
- Brute-force attack identification
- Successful login detection
- Failed and successful login correlation
- Critical incident identification
- CSV incident report generation

## Technologies Used
- Ubuntu Linux (WSL)
- Python 3
- SSH / OpenSSH
- Linux Authentication Logs
- CSV Reporting

## Detection Scenarios
1. Multiple failed SSH login attempts
2. SSH brute-force detection
3. Brute-force followed by successful login

## Project Structure
- ssh_bruteforce_detector.py
- ssh_correlation_detector.py
- ssh_incident_detector.py
- ssh_realtime_monitor.py
- ssh_incident_report.csv
- ssh_correlation_report.csv

## Testing
Tested using simulated SSH authentication
failures and successful login events.

## Author
Nagender Thokala
