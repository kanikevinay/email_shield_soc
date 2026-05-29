# 🛡️ Email Shield: Automated Real-Time SOC Dashboard

## Overview
Email Shield is an automated heuristics engine for live phishing and threat analysis of an intercepted Gmail stream. It combines a FastAPI backend, background mailbox polling, and a dynamic browser dashboard to surface suspicious mail events as they arrive.

## Architecture & Project Structure
```text
email_security_app/
├── app/
│   └── server.py
├── config/
│   ├── credentials.json
│   └── token.json
├── core/
│   └── scanner.py
├── start_watch.py
├── app_state.json
├── scan_history.json
├── .gitignore
└── README.md
```

## Core Features
- FastAPI lifespan-managed background daemon thread for continuous mailbox monitoring.
- 10-second mailbox polling cadence for near real-time Gmail history tracking.
- 5-second AJAX dashboard refreshes that update the live threat table without a full page reload.
- Heuristic risk scoring with row-level CRITICAL and WARNING status badges.
- Dedicated status and analysis panels for the selected email event.

## Setup & Installation
1. Clone the repository.
2. Create and activate the virtual environment from the project root.
3. Install the required Python dependencies.
4. Place Google Cloud authentication files in `config/` safely:
   - `config/credentials.json`
   - `config/token.json`

Example setup commands:
```powershell
git clone https://github.com/kanikevinay/email_shield_soc.git
cd email_security_app
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Execution
Run the application with:
```powershell
python -m uvicorn app.server:app --host 127.0.0.1 --port 8000
```

## Notes
- `app_state.json` and `scan_history.json` are runtime artifacts and should not be committed.
- Google token and credential files are intentionally excluded from version control.
