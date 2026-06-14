# Detection Engineering Toolkit

A Python platform that builds detection rules, simulates attacks, and automatically validates whether each detection actually works.

## Features

- JSON rule repository — every detection defined in `/rules`, add a new rule with zero code changes
- Attack simulation framework — five scenarios mapped to MITRE ATT&CK
- Events tagged with expected rule and expected outcome for automatic validation
- Detection validation engine — PASS, FAIL, and FALSE POSITIVE tracking
- Missed detection tracking — catches attacks that triggered nothing at all
- ATT&CK technique mapping across five attack lifecycle stages
- Detection rate and false positive rate, per rule and overall
- SQLite storage
- Flask dashboard with Chart.js visualizations

## Detection Rules

**SSH Brute Force**
Detects multiple failed logins from the same IP within a time window

**Web Scanning Activity**
Detects repeated HTTP 404 requests from the same IP

**Off Hours Login**
Detects successful logins between 00:00–05:00

**Suspicious PowerShell**
Detects PowerShell execution with encoded or bypass flags

**Suspicious Account Creation**
Detects creation of new user accounts

## Tech Stack

- Python
- Flask
- SQLite
- Chart.js

## Framework

- MITRE ATT&CK

## Project Workflow

```
Attack Simulator
↓
Detection Engine
↓
Rule Repository
↓
Validation Engine
↓
PASS / FAIL / FALSE POSITIVE
↓
SQLite Storage
↓
Flask Dashboard
```

## How To Run

**1. Install dependencies**
```
pip install flask
```

**2. Run the pipeline**
```
python main.py
```

**3. Run dashboard**
```
python dashboard/app.py
```

**4. Open**
```
http://127.0.0.1:5000
```

## Screenshots

### Platform Overview


![Overview](screenshots/overview.png)



### Detection Rules


![Rules](screenshots/rules.png)



### Validation Results


![Validation](screenshots/validation.png)



### ATT&CK Coverage


![Coverage](screenshots/coverage.png)



### Detection Metrics


![Metrics](screenshots/metrics.png)