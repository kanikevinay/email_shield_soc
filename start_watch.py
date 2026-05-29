import json
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from core.scanner import update_runtime_state

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CONFIG_DIR = Path(__file__).resolve().parent / 'config'
TOKEN_FILE = CONFIG_DIR / 'token.json'
CREDENTIALS_FILE = CONFIG_DIR / 'credentials.json'


def _load_credentials():
    if not TOKEN_FILE.exists():
        print("[❌] Run auth_test.py first to generate config/token.json!")
        return None

    try:
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[❌] Failed to load config/token.json: {exc}")
        return None

    try:
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                creds.refresh(Request())
                with TOKEN_FILE.open('w', encoding='utf-8') as token_file:
                    token_file.write(creds.to_json())
            else:
                print("[❌] Auth token expired or missing. Run auth_test.py first!")
                return None
    except Exception as exc:
        print(f"[❌] Failed to refresh Gmail credentials: {exc}")
        return None

    return creds


def _load_project_id():
    if not CREDENTIALS_FILE.exists():
        print("[❌] Missing config/credentials.json. Download the OAuth client file again.")
        return None

    try:
        with CREDENTIALS_FILE.open('r', encoding='utf-8') as file_handle:
            config = json.load(file_handle)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[❌] Failed to load config/credentials.json: {exc}")
        return None

    installed_block = config.get('installed', {}) if isinstance(config, dict) else {}
    web_block = config.get('web', {}) if isinstance(config, dict) else {}
    project_id = installed_block.get('project_id') or web_block.get('project_id')

    if not project_id:
        print("[❌] config/credentials.json does not contain a project_id value.")
        return None

    return project_id


def start_inbox_watch():
    creds = _load_credentials()
    if not creds:
        return False

    project_id = _load_project_id()
    if not project_id:
        return False

    try:
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
    except Exception as exc:
        print(f"[❌] Failed to build Gmail service client: {exc}")
        return False

    topic_name = f"projects/{project_id}/topics/gmail-notifications"
    request_body = {
        'topicName': topic_name,
        'labelIds': ['INBOX'],
    }

    print(f"📡 Registering Gmail Watch API with topic: {topic_name}...")

    try:
        response = service.users().watch(userId='me', body=request_body).execute()
    except HttpError as exc:
        print(f"[❌] Gmail watch registration failed: {exc}")
        return False
    except Exception as exc:
        print(f"[❌] Unexpected error while registering Gmail watch: {exc}")
        return False

    print("\n" + "=" * 50)
    print("[✔] SUCCESS: GMAIL WATCH API IS ONLINE!")
    print(f"Start Time Token : {response.get('historyId')}")
    print(f"Expiration Epoch : {response.get('expiration')}")
    print("=" * 50 + "\n")
    print("Google is now tracking your incoming mail streams live.")

    update_runtime_state({
        'last_history_id': str(response.get('historyId')) if response.get('historyId') else None,
        'last_watch_expiration': response.get('expiration'),
        'watch_topic': topic_name,
    })
    return True


if __name__ == '__main__':
    start_inbox_watch()
