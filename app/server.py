import base64
import binascii
import json
import logging
import socket
import threading
import sys
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
CONFIG_DIR = ROOT_DIR / 'config'

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from core.supabase_store import (
  SupabaseStore,
  build_google_authorization_url,
  build_scan_history_record,
  create_csrf_state,
  decrypt_refresh_token,
  encrypt_refresh_token,
  exchange_google_authorization_code,
  fetch_google_userinfo,
  get_google_client_config,
  resolve_google_redirect_uri,
  sign_payload,
  validate_csrf_state,
  verify_signed_payload,
)
from core.scanner import (
  scan_recent_unread_messages_for_user,
)


logger = logging.getLogger(__name__)
POLL_INTERVAL_SECONDS = 10
_poll_stop_event = threading.Event()
_poller_thread: Optional[threading.Thread] = None
_supabase_store: Optional[SupabaseStore] = None


def _get_supabase_store() -> Optional[SupabaseStore]:
  global _supabase_store
  if _supabase_store is not None:
    return _supabase_store
  try:
    _supabase_store = SupabaseStore.from_env()
  except Exception as exc:
    logger.error('Supabase store is unavailable: %s', exc)
    return None
  return _supabase_store


def _get_google_oauth_config(request_base_url: Optional[str] = None) -> Optional[Any]:
  try:
    config = get_google_client_config()
    config['redirect_uri'] = resolve_google_redirect_uri(request_base_url)
    return SimpleNamespace(**config)
  except Exception as exc:
    logger.error('Google OAuth configuration is unavailable: %s', exc)
    return None


def _request_base_url(request: Request) -> str:
  forwarded_proto = request.headers.get('x-forwarded-proto')
  forwarded_host = request.headers.get('x-forwarded-host')
  scheme = forwarded_proto or request.url.scheme or 'http'
  host = forwarded_host or request.headers.get('host') or request.url.netloc
  return f'{scheme}://{host}'


def _cookie_secure(request: Request) -> bool:
  env_flag = os.environ.get('COOKIE_SECURE', '').strip().lower()
  if env_flag in {'1', 'true', 'yes', 'on'}:
    return True
  if env_flag in {'0', 'false', 'no', 'off'}:
    return False
  return request.url.scheme == 'https' or request.headers.get('x-forwarded-proto', '').lower() == 'https'


def _set_session_cookie(response: RedirectResponse, session_payload: Dict[str, Any], request: Request) -> None:
  response.set_cookie(
    key='email_shield_session',
    value=sign_payload(session_payload, purpose='session'),
    httponly=True,
    secure=_cookie_secure(request),
    samesite='lax',
    max_age=60 * 60 * 24 * 7,
    path='/',
  )


def _get_session_payload(request: Request) -> Optional[Dict[str, Any]]:
  token = request.cookies.get('email_shield_session')
  if not token:
    return None
  try:
    payload = verify_signed_payload(token, purpose='session')
  except Exception:
    return None

  issued_at = int(payload.get('issued_at', 0) or 0)
  if issued_at and (datetime.now(timezone.utc).timestamp() - issued_at) > 60 * 60 * 24 * 7:
    return None
  return payload


def _user_from_request(request: Request) -> Optional[Dict[str, Any]]:
  session_payload = _get_session_payload(request)
  if not session_payload:
    return None
  user_uuid = session_payload.get('user_uuid')
  if not user_uuid:
    return None
  store = _get_supabase_store()
  if not store:
    return None
  user_row = store.get_user(str(user_uuid))
  if not isinstance(user_row, dict):
    return None
  return user_row


def _scan_row_to_entry(scan_row: Dict[str, Any]) -> Dict[str, Any]:
  if not isinstance(scan_row, dict):
    return {}
  result = {
    'status': scan_row.get('status', 'clean'),
    'risk_score': int(scan_row.get('risk_score') or 0),
    'flags': scan_row.get('triggered_flags', []) if isinstance(scan_row.get('triggered_flags', []), list) else [],
    'sender': scan_row.get('sender', 'Unknown Sender') or 'Unknown Sender',
    'subject': scan_row.get('subject', 'No Subject') or 'No Subject',
    'message_id': scan_row.get('message_id'),
    'thread_id': scan_row.get('thread_id'),
    'received_at': scan_row.get('timestamp'),
    'snippet': scan_row.get('snippet', ''),
  }
  return {
    'timestamp': scan_row.get('timestamp'),
    'source': scan_row.get('source', 'gmail'),
    'result': result,
  }


def _serialize_scan_rows(scan_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
  return [_scan_row_to_entry(row) for row in scan_rows if isinstance(row, dict)]


def _scan_result_to_history_rows(user_uuid: str, scan_result: Dict[str, Any]) -> List[Dict[str, Any]]:
  rows: List[Dict[str, Any]] = []
  if not isinstance(scan_result, dict):
    return rows
  scans = scan_result.get('scans', []) if isinstance(scan_result.get('scans', []), list) else []
  for child_scan in scans:
    if isinstance(child_scan, dict):
      rows.append(build_scan_history_record(user_uuid, child_scan, source='poller'))
  return rows


def _ingest_scan_result(store: SupabaseStore, user_row: Dict[str, Any], scan_result: Dict[str, Any], source: str) -> List[Dict[str, Any]]:
  inserted_rows: List[Dict[str, Any]] = []
  user_uuid = str(user_row.get('user_uuid', ''))
  if not user_uuid:
    return inserted_rows

  scans = scan_result.get('scans', []) if isinstance(scan_result.get('scans', []), list) else []
  for child_scan in scans:
    if not isinstance(child_scan, dict):
      continue
    record = build_scan_history_record(user_uuid, child_scan, source=source)
    inserted_rows.append(store.insert_scan_history(record))
  return inserted_rows


def _scan_active_users_once() -> None:
  store = _get_supabase_store()
  if not store:
    return

  try:
    active_users = store.list_active_users()
  except Exception as exc:
    logger.exception('Failed to load active users: %s', exc)
    return

  if not active_users:
    return

  oauth_config = _get_google_oauth_config()
  if not oauth_config:
    return

  for user_row in active_users:
    if not isinstance(user_row, dict):
      continue
    encrypted_refresh_token = user_row.get('encrypted_refresh_token', '')
    if not encrypted_refresh_token:
      continue

    try:
      refresh_token = decrypt_refresh_token(str(encrypted_refresh_token), secret=os.environ.get('APP_TOKEN_ENCRYPTION_KEY'))
    except Exception as exc:
      logger.warning('Skipping user %s because refresh token decryption failed: %s', user_row.get('display_email'), exc)
      continue

    try:
      scan_result = scan_recent_unread_messages_for_user(
        refresh_token=refresh_token,
        client_id=oauth_config.client_id,
        client_secret=oauth_config.client_secret,
        token_uri=oauth_config.token_uri,
      )
    except Exception as exc:
      logger.exception('User scan failed for %s: %s', user_row.get('display_email'), exc)
      continue

    try:
      _ingest_scan_result(store, user_row, scan_result, source='poller')
    except Exception as exc:
      logger.exception('Failed to persist scan history for %s: %s', user_row.get('display_email'), exc)


def _current_user_scans(request: Request, limit: int = 25) -> List[Dict[str, Any]]:
  user_row = _user_from_request(request)
  if not user_row:
    return []
  store = _get_supabase_store()
  if not store:
    return []
  try:
    scan_rows = store.list_user_scans(str(user_row['user_uuid']), limit=limit)
  except Exception as exc:
    logger.exception('Failed to load scans for %s: %s', user_row.get('display_email'), exc)
    return []
  return _serialize_scan_rows(scan_rows)


def _background_poller_files_ready() -> bool:
  store = _get_supabase_store()
  if not store:
    logger.error('Background Gmail poller cannot start until Supabase is configured.')
    return False

  oauth_config = _get_google_oauth_config()
  if not oauth_config:
    logger.error('Background Gmail poller cannot start until Google OAuth is configured.')
    return False

  logger.info('Background Gmail poller config ready for multi-user monitoring.')
  return True


def _background_poller_status() -> Dict[str, Any]:
  return {
    'running': bool(_poller_thread and _poller_thread.is_alive()),
    'interval_seconds': POLL_INTERVAL_SECONDS,
    'supabase_configured': bool(os.environ.get('SUPABASE_URL') and os.environ.get('SUPABASE_SERVICE_ROLE_KEY')),
    'google_oauth_configured': bool(os.environ.get('GOOGLE_CLIENT_ID') and os.environ.get('GOOGLE_CLIENT_SECRET')),
  }


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
  if _background_poller_files_ready():
    _start_background_poller()
  try:
    yield
  finally:
    _stop_background_poller()


app = FastAPI(title="Email Shield Dashboard", lifespan=lifespan)


STATUS_LABELS = {
    'critical': 'Critical',
    'warning': 'Warning',
    'clean': 'Clean',
    'error': 'Error',
    'no_changes': 'No Changes',
    'no_history': 'No History',
    'no_unread_messages': 'No Unread Mail',
}


def _is_port_available(host: str, port: int) -> bool:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_socket:
    probe_socket.settimeout(0.25)
    return probe_socket.connect_ex((host, port)) != 0


@app.get('/ping')
def ping():
  return {'status': 'awake'}


@app.get("/health")
def health(request: Request):
  user_row = _user_from_request(request)
  recent_scans = _current_user_scans(request, limit=12) if user_row else []
  latest_entry = recent_scans[0] if recent_scans else {}
  latest_result = latest_entry.get('result', {}) if isinstance(latest_entry, dict) else {}
  return {
    'status': 'online',
    'user': {
      'authenticated': bool(user_row),
      'display_email': user_row.get('display_email') if isinstance(user_row, dict) else None,
    },
    'latest_scan': latest_result,
    'recent_scan_count': len(recent_scans),
    'poller': _background_poller_status(),
  }


@app.get("/")
def home(request: Request):
  user_row = _user_from_request(request)
  recent_scans = _current_user_scans(request, limit=12) if user_row else []
  latest_successful_entry = recent_scans[0] if recent_scans else None
  return HTMLResponse(_render_dashboard({}, recent_scans, latest_successful_entry, user_row))


@app.get('/auth/login')
def auth_login(request: Request):
  oauth_config = _get_google_oauth_config(_request_base_url(request))
  if not oauth_config:
    return JSONResponse({'status': 'error', 'message': 'Google OAuth is not configured'}, status_code=500)

  state_token = create_csrf_state()
  authorization_url = build_google_authorization_url(oauth_config.redirect_uri, state_token)
  response = RedirectResponse(authorization_url, status_code=302)
  response.set_cookie(
    key='email_shield_oauth_state',
    value=state_token,
    httponly=True,
    secure=_cookie_secure(request),
    samesite='lax',
    max_age=600,
    path='/',
  )
  return response


@app.get('/auth/callback')
def auth_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
  if error:
    return JSONResponse({'status': 'error', 'message': error}, status_code=400)

  if not code or not state:
    return JSONResponse({'status': 'error', 'message': 'Missing OAuth code or state'}, status_code=400)

  cookie_state = request.cookies.get('email_shield_oauth_state')
  if not cookie_state or cookie_state != state:
    return JSONResponse({'status': 'error', 'message': 'OAuth state validation failed'}, status_code=400)

  try:
    validate_csrf_state(state)
  except Exception as exc:
    return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

  oauth_config = _get_google_oauth_config(_request_base_url(request))
  if not oauth_config:
    return JSONResponse({'status': 'error', 'message': 'Google OAuth is not configured'}, status_code=500)

  try:
    token_payload = exchange_google_authorization_code(code, oauth_config)
    access_token = str(token_payload.get('access_token', ''))
    refresh_token = str(token_payload.get('refresh_token', ''))
    if not refresh_token:
      return JSONResponse({'status': 'error', 'message': 'Google did not return a refresh token'}, status_code=400)
    userinfo = fetch_google_userinfo(access_token)
  except Exception as exc:
    logger.exception('OAuth callback failed: %s', exc)
    return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

  display_email = str(userinfo.get('email') or '').strip().lower()
  google_subject = str(userinfo.get('id') or userinfo.get('sub') or display_email)
  if not display_email:
    return JSONResponse({'status': 'error', 'message': 'Google user profile did not include an email address'}, status_code=400)

  user_uuid = google_user_uuid(google_subject, display_email)
  encrypted_refresh_token = encrypt_refresh_token(refresh_token, secret=os.environ.get('APP_TOKEN_ENCRYPTION_KEY'))
  store = _get_supabase_store()
  if not store:
    return JSONResponse({'status': 'error', 'message': 'Supabase is not configured'}, status_code=500)

  store.upsert_user(user_uuid, display_email, encrypted_refresh_token, active_monitoring=True)
  session_payload = {
    'session_id': str(uuid.uuid4()),
    'user_uuid': user_uuid,
    'email': display_email,
    'issued_at': int(datetime.now(timezone.utc).timestamp()),
  }
  response = RedirectResponse(url='/', status_code=302)
  _set_session_cookie(response, session_payload, request)
  response.delete_cookie('email_shield_oauth_state', path='/')
  return response


@app.get('/api/scans')
def api_scans(request: Request):
  user_row = _user_from_request(request)
  if not user_row:
    return JSONResponse({'items': [], 'status': 'unauthorized'}, status_code=401)
  return JSONResponse({'items': _current_user_scans(request, limit=25), 'status': 'success'})


@app.get("/api/status")
def api_status(request: Request):
  user_row = _user_from_request(request)
  recent_scans = _current_user_scans(request, limit=12) if user_row else []
  latest_successful_entry = recent_scans[0] if recent_scans else None
  return JSONResponse({
    'status': 'online',
    'user': {
      'authenticated': bool(user_row),
      'display_email': user_row.get('display_email') if isinstance(user_row, dict) else None,
    },
    'latest_scan': latest_successful_entry,
    'recent_scans': recent_scans,
    'poller': _background_poller_status(),
  })


@app.get("/api/recent-scans")
def api_recent_scans(request: Request):
    return api_scans(request)


def _poll_mailbox_once() -> None:
  _scan_active_users_once()


def _poll_mailbox_forever() -> None:
  while not _poll_stop_event.is_set():
    try:
      _poll_mailbox_once()
    except Exception as exc:
      logger.exception('Background Gmail poller failed: %s', exc)

    if _poll_stop_event.wait(POLL_INTERVAL_SECONDS):
      break


def _start_background_poller() -> None:
    global _poller_thread
    if _poller_thread and _poller_thread.is_alive():
        logger.info('Background Gmail poller is already running.')
        return

    _poll_stop_event.clear()
    _poller_thread = threading.Thread(target=_poll_mailbox_forever, name='gmail-poller', daemon=True)
    _poller_thread.start()
    logger.info('Started background Gmail poller thread with %s second interval.', POLL_INTERVAL_SECONDS)


def _stop_background_poller() -> None:
    global _poller_thread
    _poll_stop_event.set()
    if _poller_thread and _poller_thread.is_alive():
        _poller_thread.join(timeout=5)
    _poller_thread = None


@app.post("/scan-now")
async def scan_now(request: Request):
  user_row = _user_from_request(request)
  if not user_row:
    return JSONResponse({'status': 'error', 'message': 'Authentication required'}, status_code=401)

  store = _get_supabase_store()
  oauth_config = _get_google_oauth_config(_request_base_url(request))
  if not store or not oauth_config:
    return JSONResponse({'status': 'error', 'message': 'Backend configuration is incomplete'}, status_code=500)

  try:
    refresh_token = decrypt_refresh_token(str(user_row.get('encrypted_refresh_token', '')), secret=os.environ.get('APP_TOKEN_ENCRYPTION_KEY'))
  except Exception as exc:
    return JSONResponse({'status': 'error', 'message': f'Unable to decrypt refresh token: {exc}'}, status_code=500)

  scan_result = await run_in_threadpool(
    scan_recent_unread_messages_for_user,
    refresh_token,
    oauth_config.client_id,
    oauth_config.client_secret,
    oauth_config.token_uri,
  )
  await run_in_threadpool(_ingest_scan_result, store, user_row, scan_result, 'manual')
  status_code = 500 if scan_result.get('status') == 'error' else 200
  return JSONResponse(
    {
      'status': 'success' if status_code == 200 else 'error',
      'scan': _scan_result_to_history_rows(str(user_row.get('user_uuid', '')), scan_result),
    },
    status_code=status_code,
  )


@app.get("/test-scan")
async def test_scan(request: Request):
  return await scan_now(request)


def _decode_pubsub_message_data(encoded_data: Any) -> Dict[str, Any]:
    if not isinstance(encoded_data, str) or not encoded_data.strip():
        raise ValueError('Missing Pub/Sub message data')

    padded_data = encoded_data + '=' * (-len(encoded_data) % 4)

    try:
        decoded_bytes = base64.urlsafe_b64decode(padded_data.encode('utf-8'))
    except (binascii.Error, ValueError) as exc:
        raise ValueError('Invalid Pub/Sub base64 payload') from exc

    try:
        decoded_json = json.loads(decoded_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Decoded Pub/Sub payload is not valid JSON') from exc

    if not isinstance(decoded_json, dict):
        raise ValueError('Decoded Pub/Sub payload must be a JSON object')

    return decoded_json


@app.post("/webhook")
async def receive_gmail_notification(request: Request):
    """Listens for Google Pub/Sub real-time push messages."""
    try:
        body = await request.json()
    except ValueError as exc:
        logger.warning("Rejected webhook with invalid JSON body: %s", exc)
        return JSONResponse({'status': 'ignored', 'message': 'Invalid JSON body'}, status_code=200)

    message = body.get('message') if isinstance(body, dict) else None
    encoded_data = message.get('data') if isinstance(message, dict) else None

    if not encoded_data:
        logger.warning('Rejected webhook without Pub/Sub message.data field')
        return JSONResponse({'status': 'ignored', 'message': 'Missing Pub/Sub message.data field'}, status_code=200)

    try:
        decoded_json = _decode_pubsub_message_data(encoded_data)
    except ValueError as exc:
        logger.warning('Rejected webhook with undecodable Pub/Sub payload: %s', exc)
        return JSONResponse({'status': 'ignored', 'message': str(exc)}, status_code=200)

    email_address = decoded_json.get('emailAddress', 'unknown')
    history_id = decoded_json.get('historyId')
    notification = {
        'emailAddress': email_address,
        'historyId': history_id,
        'messageId': body.get('message', {}).get('messageId') if isinstance(body, dict) else None,
        'publishTime': body.get('message', {}).get('publishTime') if isinstance(body, dict) else None,
        'subscription': body.get('subscription') if isinstance(body, dict) else None,
    }
    logger.info('Live mail update intercepted for: %s', email_address)

    state = load_runtime_state()
    if history_id and not is_newer_history_id(str(history_id), state.get('last_history_id')):
        logger.info('Ignoring duplicate or stale Gmail history id: %s', history_id)
        return JSONResponse(
            {
                'status': 'ignored',
                'message': 'Duplicate or stale Gmail notification',
                'emailAddress': email_address,
                'historyId': history_id,
            },
            status_code=200,
        )

    start_history_id = state.get('last_history_id') or str(history_id or '')
    scan_result = await run_in_threadpool(scan_messages_since_history_id, start_history_id)

    if scan_result.get('status') in {'error', 'no_history'}:
        scan_result = await run_in_threadpool(scan_latest_email)

    if isinstance(scan_result, dict) and isinstance(scan_result.get('scans'), list) and scan_result.get('scans'):
        for child_scan in scan_result['scans']:
            if isinstance(child_scan, dict):
                record_scan_result(child_scan, source='webhook', notification=notification)
    else:
        record_scan_result(scan_result, source='webhook', notification=notification)

    update_runtime_state(
        {
            'last_history_id': str(history_id) if history_id else state.get('last_history_id'),
            'last_webhook_at': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
            'last_notification': notification,
        }
    )

    return JSONResponse(
        {
            'status': 'success',
            'emailAddress': email_address,
            'historyId': history_id,
            'scan': scan_result,
        },
        status_code=200,
    )


def _render_dashboard(state: Dict[str, Any], recent_scans: List[Dict[str, Any]], latest_entry: Optional[Dict[str, Any]] = None, current_user: Optional[Dict[str, Any]] = None) -> str:
    display_scans = _get_displayable_scans(recent_scans)
    latest_entry = latest_entry or (display_scans[0] if display_scans else None)
    latest_result = latest_entry.get('result', {}) if isinstance(latest_entry, dict) else {}

    selected_scan = latest_entry if isinstance(latest_entry, dict) else {}
    selected_result = selected_scan.get('result', {}) if isinstance(selected_scan, dict) else {}
    selected_status = _normalize_status(selected_result.get('status'))
    selected_sender = _safe_value(selected_result.get('sender'), 'Unknown Sender')
    selected_subject = _safe_value(selected_result.get('subject'), 'No Subject')
    selected_risk = int(selected_result.get('risk_score') or 0)
    selected_time = _format_scan_time(selected_scan.get('timestamp') if isinstance(selected_scan, dict) else None, 'No recent scans yet')
    selected_flags = selected_result.get('flags', []) if isinstance(selected_result.get('flags', []), list) else []
    selected_indicator_summary = _build_indicator_summary(selected_result)
    selected_links = _extract_links(selected_result)

    headline_status = _headline_status_text(state, latest_entry)
    headline_state_class = _headline_state_class(state, latest_entry)
    pipeline_copy = _pipeline_copy(state, latest_entry)
    auth_button_html = '<a class="button" href="/auth/login">Sign in with Google</a>' if not current_user else '<span class="status-chip live">Signed in as ' + escape(str(current_user.get('display_email', 'unknown'))) + '</span>'
    session_copy = 'Sign in with Google to unlock your personal scan stream.' if not current_user else 'Monitoring ' + escape(str(current_user.get('display_email', 'unknown'))) + ' in real time.'
    display_scans = _dedupe_display_scans(display_scans)
    stream_rows = '\n'.join(_render_stream_row(entry, index, index == 0) for index, entry in enumerate(display_scans))
    if not stream_rows:
      stream_rows = '<tr><td colspan="6" class="empty-row">No alert events yet. Click Trigger Manual Scan or wait for Gmail activity.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Email Shield SOC</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #08111d;
      --bg-2: #0b1727;
      --panel: rgba(8, 16, 28, 0.88);
      --panel-strong: rgba(10, 18, 32, 0.96);
      --border: rgba(148, 163, 184, 0.14);
      --text: #e7eef8;
      --muted: #97a7bd;
      --accent: #63dfc6;
      --accent-soft: rgba(99, 223, 198, 0.12);
      --warning: #f5c76a;
      --warning-soft: rgba(245, 199, 106, 0.14);
      --critical: #ff6f7d;
      --critical-soft: rgba(255, 111, 125, 0.15);
      --success: #5ce08a;
      --success-soft: rgba(92, 224, 138, 0.14);
      --shadow: 0 30px 80px rgba(1, 5, 14, 0.55);
    }}

    * {{ box-sizing: border-box; }}
    html, body {{ margin: 0; min-height: 100%; background: linear-gradient(180deg, #06101b 0%, #08111d 100%); color: var(--text); font-family: "Segoe UI Variable", "Segoe UI", system-ui, sans-serif; }}
    body {{
      background:
        radial-gradient(circle at top left, rgba(99, 223, 198, 0.16), transparent 26%),
        radial-gradient(circle at top right, rgba(88, 146, 255, 0.14), transparent 24%),
        linear-gradient(180deg, #06101b 0%, #08111d 100%);
    }}

    .shell {{ max-width: 1600px; width: min(100%, 1600px); margin: 0 auto; padding: 24px; }}
    .topbar {{
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      padding: 16px 18px; border: 1px solid var(--border); border-radius: 20px;
      background: rgba(8, 16, 28, 0.72); box-shadow: var(--shadow); backdrop-filter: blur(16px);
      margin-bottom: 18px;
    }}

    .brand {{ display: flex; flex-direction: column; gap: 4px; }}
    .brand .kicker {{ font-size: 12px; letter-spacing: 0.2em; text-transform: uppercase; color: var(--muted); }}
    .brand h1 {{ margin: 0; font-size: 22px; letter-spacing: -0.02em; }}
    .brand .sub {{ margin: 0; color: var(--muted); font-size: 13px; }}

    .status-chip {{
      display: inline-flex; align-items: center; gap: 10px; padding: 10px 14px; border-radius: 999px;
      font-size: 13px; font-weight: 700; letter-spacing: 0.01em; border: 1px solid transparent;
    }}
    .status-chip.standby {{ background: rgba(148, 163, 184, 0.12); border-color: rgba(148, 163, 184, 0.18); color: #d9e3ef; }}
    .status-chip.live {{ background: rgba(92, 224, 138, 0.12); border-color: rgba(92, 224, 138, 0.2); color: #c8f7d7; }}
    .status-chip.warning {{ background: var(--warning-soft); border-color: rgba(245, 199, 106, 0.24); color: #ffe5af; }}
    .status-chip.critical {{ background: var(--critical-soft); border-color: rgba(255, 111, 125, 0.24); color: #ffd8dd; }}

    .actions {{ display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }}
    .button {{
      appearance: none; border: 0; cursor: pointer; text-decoration: none;
      padding: 12px 16px; border-radius: 14px; font-weight: 800; font-size: 13px;
      background: linear-gradient(135deg, var(--accent), #a7f3df); color: #03141b;
      box-shadow: 0 12px 28px rgba(99, 223, 198, 0.22);
    }}
    .button.secondary {{ background: rgba(148, 163, 184, 0.12); color: var(--text); border: 1px solid var(--border); box-shadow: none; }}

    .layout {{ display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(340px, 0.72fr); gap: 18px; align-items: start; }}
    .panel {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 22px;
      box-shadow: var(--shadow); backdrop-filter: blur(16px); overflow: hidden; min-width: 0;
    }}
    .panel-header {{ padding: 18px 20px; border-bottom: 1px solid rgba(148, 163, 184, 0.1); display: flex; justify-content: space-between; gap: 16px; align-items: center; }}
    .panel-header h2 {{ margin: 0; font-size: 16px; letter-spacing: 0.03em; text-transform: uppercase; color: #dfe8f3; }}
    .panel-header p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}

    .stream {{ padding: 0; }}
    .table-wrap {{ overflow-x: auto; width: 100%; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; min-width: 0; }}
    thead th {{
      text-align: left; padding: 14px 18px; font-size: 12px; letter-spacing: 0.14em;
      text-transform: uppercase; color: var(--muted); background: rgba(8, 16, 28, 0.9);
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
    }}
    tbody tr {{ cursor: pointer; }}
    tbody tr:hover {{ background: rgba(99, 223, 198, 0.05); }}
    tbody tr.active {{ background: rgba(99, 223, 198, 0.09); }}
    tbody td {{ padding: 16px 18px; border-bottom: 1px solid rgba(148, 163, 184, 0.08); vertical-align: top; }}
    thead th:nth-child(1), tbody td:nth-child(1) {{ width: 86px; }}
    thead th:nth-child(2), tbody td:nth-child(2) {{ width: 102px; }}
    thead th:nth-child(5), tbody td:nth-child(5) {{ width: 112px; text-align: right; }}
    thead th:nth-child(6), tbody td:nth-child(6) {{ width: 140px; }}
    .time {{ color: var(--muted); white-space: nowrap; }}
    .sender {{ font-weight: 700; }}
    .subject {{ color: #edf3fb; line-height: 1.45; }}
    .badge {{
      display: inline-flex; align-items: center; justify-content: center; padding: 7px 11px; border-radius: 999px;
      font-size: 12px; font-weight: 800; letter-spacing: 0.02em; border: 1px solid transparent; white-space: nowrap;
    }}
    .badge.clean {{ background: var(--success-soft); color: #c9f5d8; border-color: rgba(92, 224, 138, 0.24); }}
    .badge.warning {{ background: var(--warning-soft); color: #ffe2a4; border-color: rgba(245, 199, 106, 0.24); }}
    .badge.critical {{ background: var(--critical-soft); color: #ffd7dc; border-color: rgba(255, 111, 125, 0.24); }}
    .badge.no_changes, .badge.error, .badge.no_history, .badge.no_unread_messages {{ background: rgba(148, 163, 184, 0.12); color: #d8e2ef; border-color: rgba(148, 163, 184, 0.18); }}
    .risk {{ font-weight: 800; }}
    .empty-row {{ text-align: center; color: var(--muted); padding: 24px 18px; }}

    .analysis {{ padding-bottom: 6px; }}
    .analysis-body {{ padding: 18px 20px 20px; display: grid; gap: 12px; }}
    .analysis-hero {{ padding: 16px; border-radius: 18px; background: rgba(8, 16, 28, 0.72); border: 1px solid rgba(148, 163, 184, 0.1); }}
    .analysis-hero .label {{ font-size: 11px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }}
    .analysis-hero .value {{ font-size: 15px; line-height: 1.6; word-break: break-word; }}
    .analysis-grid {{ display: grid; grid-template-columns: 1fr; gap: 10px; }}
    .analysis-item {{ padding: 14px 16px; border-radius: 16px; background: rgba(13, 22, 36, 0.8); border: 1px solid rgba(148, 163, 184, 0.1); }}
    .analysis-item .label {{ font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin-bottom: 7px; }}
    .analysis-item .value {{ font-size: 14px; line-height: 1.55; word-break: break-word; }}
    .analysis-list {{ margin: 0; padding-left: 18px; color: #dfe8f3; }}
    .analysis-list li {{ margin: 0 0 8px; }}
    .analysis-empty {{ color: var(--muted); font-size: 14px; }}
    .expand-wrap details {{ background: rgba(8, 16, 28, 0.65); border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 16px; overflow: hidden; }}
    .expand-wrap summary {{ cursor: pointer; list-style: none; padding: 14px 16px; font-weight: 800; }}
    .expand-wrap summary::-webkit-details-marker {{ display: none; }}
    .expand-wrap .inner {{ padding: 0 16px 16px; color: var(--muted); line-height: 1.6; }}

    .footer-note {{ padding: 16px 20px 20px; color: var(--muted); font-size: 13px; }}

    @media (max-width: 1180px) {{
      .layout {{ grid-template-columns: 1fr; }}
      table {{ min-width: 860px; }}
      .topbar {{ flex-direction: column; align-items: stretch; }}
      .actions {{ justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="kicker">Security Operations Center</div>
        <h1>Email Shield</h1>
        <p class="sub">{session_copy}</p>
      </div>
      <div class="actions">
        <div class="status-chip {headline_state_class}" id="pipeline-status">{escape(headline_status)}</div>
        {auth_button_html}
        <button class="button" type="button" onclick="runScanNow(this)">⚡ Trigger Manual Scan</button>
        <a class="button secondary" href="/api/status" target="_blank" rel="noreferrer">API Status</a>
      </div>
    </header>

    <main class="layout">
      <section class="panel stream">
        <div class="panel-header">
          <div>
            <h2>Live Threat Stream</h2>
            <p>SOURCE, SENDER, SUBJECT, RISK SCORE, STATUS.</p>
          </div>
          <div class="status-chip {headline_state_class}" id="stream-status">{escape(pipeline_copy)}</div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Time</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Risk Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="stream-body">
              {stream_rows}
            </tbody>
          </table>
        </div>
      </section>

      <aside class="panel analysis">
        <div class="panel-header">
          <div>
            <h2>Selected Email Analysis Breakdown</h2>
            <p>Threat indicators, keyword matches, and links extracted from the selected row.</p>
          </div>
        </div>
        <div class="analysis-body" id="analysis-body">
          <div class="analysis-hero">
            <div class="label">Selected message</div>
            <div class="value" id="selected-summary">{escape(selected_time)} · {escape(selected_sender)} · {escape(selected_subject)}</div>
          </div>

          <div class="analysis-grid">
            <div class="analysis-item">
              <div class="label">Threat indicators</div>
              <div class="value" id="indicator-summary">{escape(selected_indicator_summary)}</div>
            </div>
            <div class="analysis-item">
              <div class="label">Fraud keyword matches</div>
              <div class="value" id="keyword-summary">
                {_render_list_block(selected_flags, 'No keyword matches were identified for this message.')}
              </div>
            </div>
            <div class="analysis-item">
              <div class="label">Deceptive links</div>
              <div class="value" id="link-summary">
                {_render_list_block(selected_links, 'No deceptive links were extracted for this message.')}
              </div>
            </div>
          </div>

          <div class="expand-wrap">
            <details open>
              <summary>Raw message context</summary>
              <div class="inner">
                Sender: <span id="raw-sender">{escape(selected_sender)}</span><br />
                Subject: <span id="raw-subject">{escape(selected_subject)}</span><br />
                Risk Score: <span id="raw-risk">{selected_risk}</span><br />
                Status: <span id="raw-status">{escape(STATUS_LABELS.get(selected_status, selected_status.title()))}</span>
              </div>
            </details>
          </div>
        </div>
        <div class="footer-note">
          Missing Gmail fields default to <strong>No Subject</strong> and <strong>Unknown Sender</strong> so the UI cannot crash on partial payloads.
        </div>
      </aside>
    </main>
  </div>

  <script>
    let scans = {json.dumps([_serialize_scan(entry) for entry in display_scans], ensure_ascii=True)};
    let lastSnapshot = '';

    function runScanNow(button) {{
      if (button) {{
        button.disabled = true;
        button.textContent = 'Scanning...';
      }}
      fetch('/scan-now', {{ method: 'POST' }})
        .then(() => syncLiveStream(true))
        .catch((error) => {{
          console.error(error);
          alert('Manual scan failed. Check the backend logs.');
        }})
        .finally(() => {{
          if (button) {{
            button.disabled = false;
            button.textContent = '⚡ Trigger Manual Scan';
          }}
        }});
    }}

    function escapeHtml(text) {{
      return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
    }}

    function safeValue(value, fallback) {{
      if (value === null || value === undefined) {{
        return fallback;
      }}
      if (typeof value === 'string') {{
        const trimmed = value.trim();
        return trimmed || fallback;
      }}
      return String(value);
    }}

    function getResult(scan) {{
      if (scan && typeof scan.result === 'object' && scan.result !== null) {{
        return scan.result;
      }}
      return scan && typeof scan === 'object' ? scan : {{}};
    }}

    function normalizeStatus(status) {{
      const normalized = String(status || 'no_data').toLowerCase();
      return ['critical', 'warning', 'clean', 'error', 'no_changes', 'no_history', 'no_unread_messages'].includes(normalized) ? normalized : 'no_data';
    }}

    function statusLabel(status) {{
      const normalized = normalizeStatus(status);
      const labels = {{ clean: 'Clean', warning: 'Warning', critical: 'Critical', no_data: 'No Data', error: 'Error', no_changes: 'No Changes', no_history: 'No History', no_unread_messages: 'No Unread Mail' }};
      return labels[normalized] || normalized.replace(/_/g, ' ').replace(/\\b\\w/g, (match) => match.toUpperCase());
    }}

    function formatScanTime(value, fallback) {{
      if (!value || typeof value !== 'string') {{
        return fallback;
      }}
      const normalized = value.trim();
      if (!normalized) {{
        return fallback;
      }}
      const parsed = new Date(normalized);
      if (Number.isNaN(parsed.getTime())) {{
        return normalized.length >= 8 ? normalized.slice(0, 8) : normalized;
      }}
      return parsed.toLocaleTimeString([], {{ hour: '2-digit', minute: '2-digit', second: '2-digit' }});
    }}

    function scanSignature(scan) {{
      const result = getResult(scan);
      return [
        safeValue(scan.timestamp, ''),
        safeValue(scan.source, 'manual'),
        safeValue(result.message_id, ''),
        safeValue(result.thread_id, ''),
        safeValue(result.sender, ''),
        safeValue(result.subject, ''),
        safeValue(result.received_at, ''),
      ].join('|');
    }}

    function buildIndicatorSummary(result) {{
      const flags = Array.isArray(result.flags) ? result.flags : [];
      const riskScore = Number.parseInt(result.risk_score ?? 0, 10) || 0;
      if (!flags.length && riskScore === 0) {{
        return 'No significant threat indicators were detected.';
      }}
      const flagCount = flags.length;
      if (riskScore >= 60) {{
        return flagCount + ' indicator(s) triggered a critical score of ' + riskScore + '.';
      }}
      if (riskScore >= 30) {{
        return flagCount + ' indicator(s) triggered a warning score of ' + riskScore + '.';
      }}
      return flagCount + ' indicator(s) were recorded with a risk score of ' + riskScore + '.';
    }}

    function extractLinks(result) {{
      const flags = Array.isArray(result.flags) ? result.flags : [];
      const links = [];
      flags.forEach((flag) => {{
        if (typeof flag !== 'string') {{
          return;
        }}
        const candidate = flag.includes(':') ? flag.split(':', 2)[1].trim() : flag.trim();
        if (candidate && (candidate.includes('http://') || candidate.includes('https://') || candidate.includes('www.'))) {{
          links.push(candidate);
        }}
      }});
      return links;
    }}

    function listToHtml(items, emptyMessage) {{
      if (!items || !items.length) {{
        return '<span class="analysis-empty">' + escapeHtml(emptyMessage) + '</span>';
      }}
      return '<ul class="analysis-list">' + items.map((item) => '<li>' + escapeHtml(item) + '</li>').join('') + '</ul>';
    }}

    function normalizeScans(items) {{
      return (Array.isArray(items) ? items : []).filter((entry) => {{
        const status = normalizeStatus(getResult(entry).status);
        return status === 'critical' || status === 'warning' || status === 'clean';
      }}).map((entry) => {{
        const result = getResult(entry);
        return {{
          timestamp: safeValue(entry.timestamp, 'No recent scans yet'),
          source: safeValue(entry.source, 'manual'),
          status: normalizeStatus(result.status),
          risk_score: Number.parseInt(result.risk_score ?? 0, 10) || 0,
          sender: safeValue(result.sender, 'Unknown Sender'),
          subject: safeValue(result.subject, 'No Subject'),
          indicators: result.indicators || buildIndicatorSummary(result),
          flags: Array.isArray(result.flags) ? result.flags : [],
          links: extractLinks(result),
          signature: scanSignature(entry),
        }};
      }});
    }}

    function renderRow(scan, index, active) {{
      const rowClass = active ? 'active' : '';
      const badge = scan.status === 'critical' || scan.status === 'warning' || scan.status === 'clean' ? scan.status : 'no_changes';
      return '<tr data-index="' + index + '" data-signature="' + escapeHtml(scan.signature) + '" class="' + rowClass + '">' +
        '<td>' + escapeHtml(scan.source) + '</td>' +
        '<td class="time">' + escapeHtml(formatScanTime(scan.timestamp, 'No recent scans yet')) + '</td>' +
        '<td class="sender">' + escapeHtml(scan.sender) + '</td>' +
        '<td class="subject">' + escapeHtml(scan.subject) + '</td>' +
        '<td class="risk">' + scan.risk_score + '</td>' +
        '<td><span class="badge ' + badge + '">' + escapeHtml(statusLabel(scan.status)) + '</span></td>' +
      '</tr>';
    }}

    function bindRowHandlers() {{
      document.querySelectorAll('#stream-body tr[data-index]').forEach((row) => {{
        row.addEventListener('click', () => setSelectedScan(Number(row.dataset.index)));
      }});
    }}

    function renderStream(items) {{
      scans = normalizeScans(items);
      const streamBody = document.getElementById('stream-body');
      if (!streamBody) {{
        return;
      }}

      if (scans.length) {{
        streamBody.innerHTML = scans.map((scan, index) => renderRow(scan, index, index === 0)).join('');
      }} else {{
        streamBody.innerHTML = '<tr><td colspan="6" class="empty-row">No alert events yet. Click Trigger Manual Scan or wait for Gmail activity.</td></tr>';
      }}

      bindRowHandlers();
      if (scans.length) {{
        setSelectedScan(0);
      }}
    }}

    async function syncLiveStream(forceRender) {{
      try {{
        const response = await fetch('/api/scans', {{ cache: 'no-store' }});
        if (!response.ok) {{
          throw new Error('Scan endpoint returned ' + response.status);
        }}

        const payload = await response.json();
        const nextScans = Array.isArray(payload.items) ? payload.items : [];
        const nextSnapshot = nextScans.map((entry) => scanSignature(entry)).join('||');

        if (forceRender || nextSnapshot !== lastSnapshot) {{
          lastSnapshot = nextSnapshot;
          renderStream(nextScans);
        }}
      }} catch (error) {{
        console.error(error);
      }}
    }}

    scans = normalizeScans(scans);
    lastSnapshot = scans.map((scan) => scanSignature(scan)).join('||');

    function setSelectedScan(index) {{
      const scan = scans[index];
      if (!scan) {{
        return;
      }}

      const bodyRows = document.querySelectorAll('#stream-body tr[data-index]');
      bodyRows.forEach((row) => row.classList.remove('active'));
      const activeRow = document.querySelector(`#stream-body tr[data-index="${{index}}"]`);
      if (activeRow) {{
        activeRow.classList.add('active');
      }}

      document.getElementById('selected-summary').innerHTML = escapeHtml(scan.timestamp || 'No recent scans yet') + ' · ' + escapeHtml(scan.sender || 'Unknown Sender') + ' · ' + escapeHtml(scan.subject || 'No Subject');
      document.getElementById('indicator-summary').innerHTML = escapeHtml(scan.indicators || 'No significant indicators were recorded.');
      document.getElementById('keyword-summary').innerHTML = listToHtml(scan.flags || [], 'No keyword matches were identified for this message.');
      document.getElementById('link-summary').innerHTML = listToHtml(scan.links || [], 'No deceptive links were extracted for this message.');
      document.getElementById('raw-sender').textContent = scan.sender || 'Unknown Sender';
      document.getElementById('raw-subject').textContent = scan.subject || 'No Subject';
      document.getElementById('raw-risk').textContent = String(scan.risk_score ?? 0);
      document.getElementById('raw-status').textContent = statusLabel(scan.status);
    }}

    document.querySelectorAll('#stream-body tr[data-index]').forEach((row) => {{
      row.addEventListener('click', () => setSelectedScan(Number(row.dataset.index)));
    }});

    if (scans.length) {{
      setSelectedScan(0);
    }}

    syncLiveStream(true);
    setInterval(() => syncLiveStream(false), 5000);
  </script>
</body>
</html>"""


def _safe_value(value: Any, fallback: str) -> str:
  if value is None:
    return fallback
  if isinstance(value, str):
    return value.strip() or fallback
  return str(value)


def _format_scan_time(value: Any, fallback: str = 'No recent scans yet') -> str:
  if not isinstance(value, str) or not value.strip():
    return fallback

  normalized = value.strip()
  parsed = None

  try:
    parsed = datetime.fromisoformat(normalized.replace('Z', '+00:00'))
  except ValueError:
    parsed = None

  if parsed is None:
    return normalized[:8] if len(normalized) >= 8 else normalized

  if parsed.tzinfo is None:
    parsed = parsed.replace(tzinfo=timezone.utc)

  return parsed.astimezone(timezone.utc).strftime('%H:%M:%S')


def _normalize_status(status: Any) -> str:
  normalized = str(status or 'no_data').lower()
  return normalized if normalized in {'critical', 'warning', 'clean', 'error', 'no_changes', 'no_history', 'no_unread_messages'} else 'no_data'


def _get_displayable_scans(recent_scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
  displayable = []
  for entry in recent_scans:
    if not isinstance(entry, dict):
      continue
    result = entry.get('result', {}) if isinstance(entry.get('result', {}), dict) else {}
    status = _normalize_status(result.get('status'))
    if status in {'critical', 'warning', 'clean'}:
      displayable.append(entry)
  return displayable


def _dedupe_display_scans(display_scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
  deduped_scans: List[Dict[str, Any]] = []
  seen_keys = set()

  for entry in display_scans:
    if not isinstance(entry, dict):
      continue

    result = entry.get('result', {}) if isinstance(entry.get('result', {}), dict) else {}
    message_id = _safe_value(result.get('message_id'), '')
    thread_id = _safe_value(result.get('thread_id'), '')
    sender = _safe_value(result.get('sender'), '')
    subject = _safe_value(result.get('subject'), '')
    received_at = _safe_value(result.get('received_at'), '')
    source = _safe_value(entry.get('source'), 'manual')
    timestamp = _safe_value(entry.get('timestamp'), '')

    dedupe_key = message_id or thread_id or '|'.join([source, sender, subject, received_at, timestamp])
    if dedupe_key in seen_keys:
      continue

    seen_keys.add(dedupe_key)
    deduped_scans.append(entry)

  return deduped_scans


def _scan_signature(entry: Dict[str, Any]) -> str:
  result = entry.get('result', {}) if isinstance(entry, dict) and isinstance(entry.get('result', {}), dict) else {}
  source = _safe_value(entry.get('source'), 'manual')
  timestamp = _safe_value(entry.get('timestamp'), '')
  message_id = _safe_value(result.get('message_id'), '')
  thread_id = _safe_value(result.get('thread_id'), '')
  sender = _safe_value(result.get('sender'), '')
  subject = _safe_value(result.get('subject'), '')
  received_at = _safe_value(result.get('received_at'), '')
  return '|'.join([source, timestamp, message_id, thread_id, sender, subject, received_at])


def _headline_status_text(state: Dict[str, Any], latest_entry: Optional[Dict[str, Any]]) -> str:
  if isinstance(latest_entry, dict):
    status = _normalize_status((latest_entry.get('result', {}) or {}).get('status'))
    if status == 'critical':
      return '🔴 Pipeline Alert'
    if status == 'warning':
      return '🟠 Pipeline Warning'
    if status == 'clean':
      return '🟢 System Listening'
  if state.get('last_history_id'):
    return '🟡 Pipeline Standby'
  return '⚪ Pipeline Idle'


def _headline_state_class(state: Dict[str, Any], latest_entry: Optional[Dict[str, Any]]) -> str:
  if isinstance(latest_entry, dict):
    status = _normalize_status((latest_entry.get('result', {}) or {}).get('status'))
    if status in {'critical', 'warning', 'clean'}:
      return status
  return 'standby'


def _pipeline_copy(state: Dict[str, Any], latest_entry: Optional[Dict[str, Any]]) -> str:
  if isinstance(latest_entry, dict):
    status = _normalize_status((latest_entry.get('result', {}) or {}).get('status'))
    if status == 'critical':
      return 'Critical mail detected'
    if status == 'warning':
      return 'Suspicious mail detected'
    if status == 'clean':
      return 'Listening for new mail'
  return 'Monitoring live pipeline'


def _status_badge_class(status: str) -> str:
  return status if status in {'critical', 'warning', 'clean'} else 'no_changes'


def _render_stream_row(entry: Dict[str, Any], index: int, active: bool = False) -> str:
  result = entry.get('result', {}) if isinstance(entry, dict) and isinstance(entry.get('result', {}), dict) else {}
  status = _normalize_status(result.get('status'))
  status_label = STATUS_LABELS.get(status, 'No Data') if status != 'no_data' else 'No Data'
  sender = _safe_value(result.get('sender'), 'Unknown Sender')
  subject = _safe_value(result.get('subject'), 'No Subject')
  source = _safe_value(entry.get('source'), 'manual')
  timestamp = _safe_value(entry.get('timestamp'), '')
  display_time = _format_scan_time(timestamp, 'No recent scans yet')
  risk_score = int(result.get('risk_score') or 0)
  flags = result.get('flags', []) if isinstance(result.get('flags', []), list) else []
  indicators = _build_indicator_summary(result)
  links = _extract_links(result)
  row_class = 'active' if active else ''
  return (
    f'<tr data-index="{index}" class="{row_class}" '
    f'data-signature="{escape(_scan_signature(entry))}" '
    f'data-source="{escape(source)}" '
    f'data-time="{escape(display_time)}" '
    f'data-sender="{escape(sender)}" '
    f'data-subject="{escape(subject)}" '
    f'data-risk="{risk_score}" '
    f'data-status="{escape(status)}" '
    f'data-timestamp="{escape(timestamp)}" '
    f'data-indicators="{escape(indicators)}" '
    f'data-flags="{escape(json.dumps(flags, ensure_ascii=True))}" '
    f'data-links="{escape(json.dumps(links, ensure_ascii=True))}">'
    f'<td>{escape(source)}</td>'
    f'<td class="time">{escape(display_time)}</td>'
    f'<td class="sender">{escape(sender)}</td>'
    f'<td class="subject">{escape(subject)}</td>'
    f'<td class="risk">{risk_score}</td>'
    f'<td><span class="badge {_status_badge_class(status)}">{escape(status_label)}</span></td>'
    '</tr>'
  )


def _render_list_block(items: List[str], empty_message: str) -> str:
  if not items:
    return f'<span class="analysis-empty">{escape(empty_message)}</span>'
  return '<ul class="analysis-list">' + ''.join(f'<li>{escape(item)}</li>' for item in items) + '</ul>'


def _build_indicator_summary(result: Dict[str, Any]) -> str:
  flags = result.get('flags', []) if isinstance(result.get('flags', []), list) else []
  risk_score = int(result.get('risk_score') or 0)
  if not flags and risk_score == 0:
    return 'No significant threat indicators were detected.'
  flag_count = len(flags)
  if risk_score >= 60:
    return f'{flag_count} indicator(s) triggered a critical score of {risk_score}.'
  if risk_score >= 30:
    return f'{flag_count} indicator(s) triggered a warning score of {risk_score}.'
  return f'{flag_count} indicator(s) were recorded with a risk score of {risk_score}.'


def _extract_links(result: Dict[str, Any]) -> List[str]:
  flags = result.get('flags', []) if isinstance(result.get('flags', []), list) else []
  links = []
  for flag in flags:
    if not isinstance(flag, str):
      continue
    if ':' in flag:
      candidate = flag.split(':', 1)[1].strip()
    else:
      candidate = flag
    if candidate and ('http://' in candidate or 'https://' in candidate or 'www.' in candidate):
      links.append(candidate)
  return links


def _serialize_scan(entry: Dict[str, Any]) -> Dict[str, Any]:
  result = entry.get('result', {}) if isinstance(entry, dict) and isinstance(entry.get('result', {}), dict) else {}
  return {
    'timestamp': _safe_value(entry.get('timestamp'), 'No recent scans yet'),
    'source': _safe_value(entry.get('source'), 'manual'),
    'status': _normalize_status(result.get('status')),
    'risk_score': int(result.get('risk_score') or 0),
    'sender': _safe_value(result.get('sender'), 'Unknown Sender'),
    'subject': _safe_value(result.get('subject'), 'No Subject'),
    'indicators': _build_indicator_summary(result),
    'flags': result.get('flags', []) if isinstance(result.get('flags', []), list) else [],
    'links': _extract_links(result),
  }
if __name__ == "__main__":
    import uvicorn

    if not _is_port_available("127.0.0.1", 8000):
        print("[ℹ] Port 8000 is already in use. If Email Shield is still running, reuse that window or stop the existing process first.")
        raise SystemExit(0)

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
        lifespan="on",
        reload=False,
        timeout_keep_alive=2,
        timeout_graceful_shutdown=5,
        access_log=True,
    )
