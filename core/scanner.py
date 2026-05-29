import base64
import binascii
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / 'config'
STATE_FILE = ROOT_DIR / 'app_state.json'
HISTORY_FILE = ROOT_DIR / 'scan_history.json'
TOKEN_FILE = CONFIG_DIR / 'token.json'
MAX_HISTORY_ENTRIES = 50


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _read_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default.copy() if isinstance(default, (dict, list)) else default

    try:
        with path.open('r', encoding='utf-8') as file_handle:
            data = json.load(file_handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return default.copy() if isinstance(default, (dict, list)) else default

    if isinstance(default, dict) and isinstance(data, dict):
        return data
    if isinstance(default, list) and isinstance(data, list):
        return data
    return default.copy() if isinstance(default, (dict, list)) else default


def _write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as file_handle:
        json.dump(data, file_handle, indent=2, ensure_ascii=True)


def load_runtime_state() -> Dict[str, Any]:
    state = {
        'last_history_id': None,
        'last_watch_expiration': None,
        'last_scan_at': None,
        'last_webhook_at': None,
        'last_scan_result': None,
        'last_notification': None,
        'watch_topic': None,
    }
    stored_state = _read_json_file(STATE_FILE, state)
    if not isinstance(stored_state, dict):
        return state
    state.update(stored_state)
    return state


def update_runtime_state(updates: Dict[str, Any]) -> Dict[str, Any]:
    state = load_runtime_state()
    state.update(updates)
    _write_json_file(STATE_FILE, state)
    return state


def _append_history_entry(entry: Dict[str, Any]) -> None:
    history = _read_json_file(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []
    history.append(entry)
    history = history[-MAX_HISTORY_ENTRIES:]
    _write_json_file(HISTORY_FILE, history)


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    history = _read_json_file(HISTORY_FILE, [])
    if not isinstance(history, list):
        return []
    return list(reversed(history[-limit:]))


def get_latest_successful_scan(limit: int = 25) -> Optional[Dict[str, Any]]:
    for entry in get_recent_scans(limit=limit):
        result = entry.get('result', {}) if isinstance(entry, dict) else {}
        if isinstance(result, dict) and result.get('status') in {'critical', 'warning', 'clean', 'no_changes', 'no_history', 'no_unread_messages'}:
            return entry
    return None


def record_scan_result(scan_result: Dict[str, Any], source: str = 'manual', notification: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    entry = {
        'timestamp': _utc_now(),
        'source': source,
        'notification': notification or {},
        'result': scan_result,
    }
    _append_history_entry(entry)
    update_runtime_state({
        'last_scan_at': entry['timestamp'],
        'last_scan_result': scan_result,
        'last_notification': notification or {},
    })
    return entry


def _unique_message_ids(message_ids: Iterable[str]) -> List[str]:
    ordered_ids: List[str] = []
    seen_ids = set()
    for message_id in message_ids:
        if message_id and message_id not in seen_ids:
            ordered_ids.append(message_id)
            seen_ids.add(message_id)
    return ordered_ids

def get_gmail_service():
    """Uses token.json to connect to your live Gmail channel securely."""
    if not TOKEN_FILE.exists():
        print("[❌] Auth token expired or missing. Run auth_test.py first!")
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

    try:
        return build('gmail', 'v1', credentials=creds, cache_discovery=False)
    except Exception as exc:
        print(f"[❌] Failed to build Gmail service client: {exc}")
        return None


def get_current_history_id():
    service = get_gmail_service()
    if not service:
        return None

    try:
        profile = service.users().getProfile(userId='me').execute()
    except HttpError as exc:
        print(f"[❌] Gmail API request failed while reading profile history id: {exc}")
        return None
    except Exception as exc:
        print(f"[❌] Unexpected error while reading profile history id: {exc}")
        return None

    history_id = profile.get('historyId')
    return str(history_id) if history_id else None


def _decode_gmail_base64url(data: str) -> str:
    padded_data = data + '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded_data.encode('utf-8')).decode('utf-8', errors='ignore')


def extract_email_body(payload):
    """Recursively decodes the body structure of the raw email data."""
    if not isinstance(payload, dict):
        return ""

    body = ""
    for part in payload.get('parts', []):
        body += extract_email_body(part)

    data = payload.get('body', {}).get('data')
    if isinstance(data, str) and data:
        try:
            body += _decode_gmail_base64url(data)
        except (binascii.Error, ValueError):
            pass

    return body


def _extract_headers(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    headers = payload.get('headers', [])
    return headers if isinstance(headers, list) else []


def _header_value(headers: List[Dict[str, Any]], header_name: str, default: str) -> str:
    return next(
        (
            header.get('value', '')
            for header in headers
            if header.get('name', '').lower() == header_name.lower()
        ),
        default,
    )


def _extract_message_timestamp(message: Dict[str, Any]) -> Optional[str]:
    internal_date = message.get('internalDate')
    try:
        timestamp_ms = int(internal_date)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _analyze_email_message(message: Dict[str, Any]) -> Dict[str, Any]:
    payload = message.get('payload', {})
    headers = _extract_headers(payload)

    subject = _header_value(headers, 'subject', 'No Subject')
    sender = _header_value(headers, 'from', 'Unknown Sender')
    email_body = extract_email_body(payload)
    subject_lower = subject.lower()
    email_body_lower = email_body.lower()

    print("\n" + "=" * 50)
    print("📥 LIVE EMAIL INTERCEPTED")
    print(f"FROM   : {sender}")
    print(f"SUBJECT: {subject}")
    print("=" * 50)

    risk_score = 0
    flags_triggered: List[str] = []

    danger_keywords = [
        r"verify your account", r"action required", r"suspend",
        r"bank account", r"crypto", r"login to your", r"urgent windows",
    ]
    for pattern in danger_keywords:
        if re.search(pattern, subject_lower) or re.search(pattern, email_body_lower):
            risk_score += 35
            flags_triggered.append(f"Suspicious terminology pattern matched: '{pattern}'")

    urgency_keywords = [r"immediately", r"within 24 hours", r"final warning", r"locked out"]
    for pattern in urgency_keywords:
        if re.search(pattern, subject_lower) or re.search(pattern, email_body_lower):
            risk_score += 20
            flags_triggered.append('High urgency tone detected (coercion tactic).')
            break

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_body)
    if urls:
        risk_score += 10
        for url in urls:
            if any(x in url for x in ['-login', 'verify-', 'update-', 'secure-']):
                risk_score += 25
                flags_triggered.append(f"Deceptive structural URL layout: {url}")
                break

    print("\n🛡️ THREAT MONITORING REPORT:")
    print(f"Overall Risk Score: {risk_score}/100")

    if risk_score >= 60:
        print("🚨 STATUS: CRITICAL - HIGHLY SUSPICIOUS / SPAM PHISHING THREAT")
        status = 'critical'
    elif risk_score >= 30:
        print("⚠️ STATUS: WARNING - SUSPICIOUS METADATA DETECTED")
        status = 'warning'
    else:
        print("✅ STATUS: CLEAN - SAFE GENUINE EMAIL")
        status = 'clean'

    if flags_triggered:
        print("\nRisk Indicators Identified:")
        for flag in flags_triggered:
            print(f"  • {flag}")
    print("=" * 50 + "\n")

    return {
        'status': status,
        'risk_score': risk_score,
        'flags': flags_triggered,
        'sender': sender,
        'subject': subject,
        'message_id': message.get('id'),
        'thread_id': message.get('threadId'),
        'received_at': _extract_message_timestamp(message),
        'snippet': message.get('snippet', ''),
    }


def scan_message_by_id(message_id: str):
    service = get_gmail_service()
    if not service:
        return {'status': 'error', 'message': 'Gmail service unavailable'}

    if not message_id:
        return {'status': 'error', 'message': 'Missing Gmail message id'}

    try:
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
    except HttpError as exc:
        message = f'Gmail API request failed while fetching message {message_id}: {exc}'
        print(f"[❌] {message}")
        return {'status': 'error', 'message': message}
    except Exception as exc:
        message = f'Unexpected error while fetching message {message_id}: {exc}'
        print(f"[❌] {message}")
        return {'status': 'error', 'message': message}

    return _analyze_email_message(message)

def scan_latest_email():
    service = get_gmail_service()
    if not service:
        return {"status": "error", "message": "Gmail service unavailable"}

    print("\n📡 Fetching your latest unread email metadata...")

    try:
        results = service.users().messages().list(
            userId='me',
            maxResults=1,
            q='is:unread in:inbox',
        ).execute()
    except HttpError as exc:
        message = f"Gmail API request failed while listing messages: {exc}"
        print(f"[❌] {message}")
        return {"status": "error", "message": message}
    except Exception as exc:
        message = f"Unexpected error while listing messages: {exc}"
        print(f"[❌] {message}")
        return {"status": "error", "message": message}

    messages = results.get('messages', [])

    if not messages:
        print("[ℹ] Your inbox is empty!")
        return {"status": "no_unread_messages", "message": "No unread inbox messages found"}

    msg_id = messages[0].get('id')
    if not msg_id:
        message = "Gmail API returned a message without an id"
        print(f"[❌] {message}")
        return {"status": "error", "message": message}
    return scan_message_by_id(msg_id)


def _collect_history_message_ids(service, start_history_id: str) -> List[str]:
    message_ids: List[str] = []
    page_token = None

    while True:
        response = service.users().history().list(
            userId='me',
            startHistoryId=str(start_history_id),
            historyTypes=['messageAdded'],
            pageToken=page_token,
        ).execute()

        for history_item in response.get('history', []):
            for added_message in history_item.get('messagesAdded', []):
                message = added_message.get('message', {})
                if isinstance(message, dict):
                    message_ids.append(message.get('id', ''))
            for message in history_item.get('messages', []):
                if isinstance(message, dict):
                    message_ids.append(message.get('id', ''))

        page_token = response.get('nextPageToken')
        if not page_token:
            break

    return _unique_message_ids(message_ids)


def scan_messages_since_history_id(start_history_id: Optional[str]):
    service = get_gmail_service()
    if not service:
        return {'status': 'error', 'message': 'Gmail service unavailable'}

    if not start_history_id:
        return {
            'status': 'no_history',
            'message': 'No watch history baseline is available yet',
            'scans': [],
            'processed_message_ids': [],
        }

    print(f"\n📡 Fetching Gmail history since {start_history_id}...")

    try:
        message_ids = _collect_history_message_ids(service, start_history_id)
    except HttpError as exc:
        message = f'Gmail API request failed while listing history from {start_history_id}: {exc}'
        print(f"[❌] {message}")
        return {'status': 'error', 'message': message}
    except Exception as exc:
        message = f'Unexpected error while listing history from {start_history_id}: {exc}'
        print(f"[❌] {message}")
        return {'status': 'error', 'message': message}

    if not message_ids:
        print('[ℹ] No new Gmail messages were returned by history tracking.')
        return {
            'status': 'no_changes',
            'message': 'No Gmail message changes were detected from history',
            'scans': [],
            'processed_message_ids': [],
        }

    scans: List[Dict[str, Any]] = []
    for message_id in message_ids:
        scan = scan_message_by_id(message_id)
        scans.append(scan)

    critical_count = sum(1 for item in scans if item.get('status') == 'critical')
    warning_count = sum(1 for item in scans if item.get('status') == 'warning')
    clean_count = sum(1 for item in scans if item.get('status') == 'clean')
    error_count = sum(1 for item in scans if item.get('status') == 'error')
    max_risk_score = max(
        (int(item.get('risk_score', 0)) for item in scans if isinstance(item.get('risk_score'), int)),
        default=0,
    )

    if critical_count:
        overall_status = 'critical'
    elif warning_count:
        overall_status = 'warning'
    elif clean_count:
        overall_status = 'clean'
    elif error_count:
        overall_status = 'error'
    else:
        overall_status = 'no_changes'

    return {
        'status': overall_status,
        'risk_score': max_risk_score,
        'scan_count': len(scans),
        'critical_count': critical_count,
        'warning_count': warning_count,
        'clean_count': clean_count,
        'error_count': error_count,
        'scans': scans,
        'processed_message_ids': message_ids,
    }


def is_newer_history_id(candidate_history_id: Optional[str], reference_history_id: Optional[str]) -> bool:
    if not candidate_history_id:
        return False
    if not reference_history_id:
        return True
    try:
        return int(candidate_history_id) > int(reference_history_id)
    except (TypeError, ValueError):
        return candidate_history_id != reference_history_id

if __name__ == '__main__':
    scan_latest_email()