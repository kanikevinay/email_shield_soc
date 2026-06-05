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

**Configuration (.env)**

- Copy the provided `.env.template` to a local `.env` file and fill in values:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=service_role_key_here
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_OAUTH_REDIRECT_URI=https://your-domain.com/auth/callback
APP_TOKEN_ENCRYPTION_KEY=replace-with-long-random-string
APP_SESSION_SECRET=replace-with-long-random-string
COOKIE_SECURE=true
```

- Recommended: generate `APP_TOKEN_ENCRYPTION_KEY` and `APP_SESSION_SECRET` with a cryptographically-secure RNG (at least 32 bytes base64 or 64 hex characters).

**Supabase: Creating the required tables**

Use the SQL below in the Supabase SQL Editor (SQL -> New Query) to create the `users` and `scan_history` tables used by the app. The SQL is also included in `supabase_schema.sql` in the repository.

```sql
-- Users table
CREATE TABLE IF NOT EXISTS public.users (
   user_uuid uuid PRIMARY KEY,
   display_email text NOT NULL UNIQUE,
   encrypted_refresh_token text NOT NULL,
   active_monitoring boolean NOT NULL DEFAULT true,
   created_at timestamptz NOT NULL DEFAULT now(),
   updated_at timestamptz NOT NULL DEFAULT now()
);

-- Scan history table
CREATE TABLE IF NOT EXISTS public.scan_history (
   id bigserial PRIMARY KEY,
   user_uuid uuid NOT NULL REFERENCES public.users(user_uuid) ON DELETE CASCADE,
   message_id text NOT NULL,
   thread_id text,
   source text NOT NULL,
   sender text NOT NULL,
   subject text NOT NULL,
   risk_score integer NOT NULL DEFAULT 0,
   timestamp timestamptz NOT NULL DEFAULT now(),
   triggered_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
   status text NOT NULL DEFAULT 'clean',
   created_at timestamptz NOT NULL DEFAULT now(),
   UNIQUE (user_uuid, message_id)
);

-- Optional index for faster per-user queries
CREATE INDEX IF NOT EXISTS idx_scan_history_user_timestamp ON public.scan_history (user_uuid, timestamp DESC);
```

**Deploy / Run tips**

- Set environment variables before starting the app (example using PowerShell):

```powershell
setx SUPABASE_URL "https://your-project.supabase.co"
setx SUPABASE_SERVICE_ROLE_KEY "<your_service_role_key>"
setx GOOGLE_CLIENT_ID "<your_client_id>"
setx GOOGLE_CLIENT_SECRET "<your_client_secret>"
setx APP_TOKEN_ENCRYPTION_KEY "$(python -c "import secrets; print(secrets.token_urlsafe(48))")"
setx APP_SESSION_SECRET "$(python -c "import secrets; print(secrets.token_urlsafe(48))")"
```

- On Render, add the same env vars in the service's dashboard and ensure the app is served over HTTPS so cookies marked `Secure` work as intended.

