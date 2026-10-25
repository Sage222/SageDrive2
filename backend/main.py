import os, json, time, math, secrets, bcrypt, mimetypes, io, re, shutil, struct, subprocess, threading, tempfile, zipfile, queue, requests
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import quote, urlparse, parse_qs, unquote
from flask import Flask, request, jsonify, send_file, send_from_directory, redirect
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import auth, smb_manager, gdrive_manager

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, supports_credentials=True, expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"])
auth.bootstrap_admin()

# ── Self-contained Auth 5-Strike / 15-Minute Anti-Hammering Lockout ───────────
_AUTH_MAX_ATTEMPTS = 5
_AUTH_LOCKOUT_SECONDS = 15 * 60  # 15 minutes
_AUTH_UNKNOWN_LOCKOUTS = {}
_auth_lock = threading.Lock()

def _auth_login_with_status(username, password):
    uname = (username or "").strip()
    now = time.time()
    with _auth_lock:
        users = auth._load_users()
        user = users.get(uname)
        record = user if user is not None else _AUTH_UNKNOWN_LOCKOUTS.setdefault(uname or "_anon_", {"failed_attempts": 0, "locked_until": 0})
        locked_until = float(record.get("locked_until", 0) or 0)

        if locked_until > now:
            rem = int(math.ceil(locked_until - now))
            mins = max(1, int(math.ceil(rem / 60)))
            msg = f"Account locked due to {_AUTH_MAX_ATTEMPTS} failed login attempts. Try again in {mins} minute{'s' if mins != 1 else ''} ({rem}s)."
            return None, msg, 429, {"locked": True, "retry_after": rem, "attempts_remaining": 0}

        if locked_until > 0 and locked_until <= now:
            record["locked_until"] = 0
            record["failed_attempts"] = 0
            if user is not None:
                auth._save_users(users)

        if user and bcrypt.checkpw((password or "").encode(), user["hash"].encode()):
            if user.get("failed_attempts") or user.get("locked_until"):
                user["failed_attempts"] = 0
                user["locked_until"] = 0
                auth._save_users(users)
            token = secrets.token_hex(32)
            auth.SESSIONS[token] = {"username": uname, "role": user["role"], "expires": now + auth.SESSION_TTL}
            return token, None, 200, {"locked": False, "attempts_remaining": _AUTH_MAX_ATTEMPTS}

        fails = int(record.get("failed_attempts", 0) or 0) + 1
        record["failed_attempts"] = fails

        if fails >= _AUTH_MAX_ATTEMPTS:
            record["locked_until"] = now + _AUTH_LOCKOUT_SECONDS
            if user is not None:
                auth._save_users(users)
            msg = f"Account locked for 15 minutes due to {_AUTH_MAX_ATTEMPTS} incorrect login attempts."
            return None, msg, 429, {"locked": True, "retry_after": _AUTH_LOCKOUT_SECONDS, "attempts_remaining": 0}

        if user is not None:
            auth._save_users(users)
        rem_tries = _AUTH_MAX_ATTEMPTS - fails
        msg = f"Invalid credentials ({rem_tries} attempt{'s' if rem_tries != 1 else ''} remaining before 15m lockout)"
        return None, msg, 401, {"locked": False, "attempts_remaining": rem_tries}

auth.login_with_status = _auth_login_with_status

# ── Self-contained Multi-SMB Share & Custom Name Support ──────────────────────
def _smb_add_share(name, host, share, username="", password="", port=445, custom_name=""):
    shares = smb_manager._load()
    base_sid = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_") or "smb_share"
    sid = base_sid
    conflict = next((s for s in shares if s["id"] == sid and (s.get("host") != host or s.get("share") != share)), None)
    if conflict:
        sid = f"{base_sid}_{secrets.token_hex(2)}"
    shares = [s for s in shares if s["id"] != sid]
    disp_name = (custom_name or name).strip()
    entry = {
        "id": sid,
        "name": disp_name,
        "custom_name": custom_name.strip() if custom_name else "",
        "original_name": name.strip(),
        "host": host,
        "share": share,
        "username": username,
        "password": password,
        "port": int(port or 445),
    }
    shares.append(entry)
    smb_manager._save(shares)
    return entry

def _smb_rename_share(share_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("Custom name cannot be empty")
    shares = smb_manager._load()
    target = None
    for s in shares:
        if s["id"] == share_id:
            if not s.get("original_name"):
                s["original_name"] = s.get("name", s["share"])
            s["name"] = new_name
            s["custom_name"] = new_name
            target = s
            break
    if not target:
        raise ValueError(f"Share {share_id!r} not found")
    smb_manager._save(shares)
    return target

smb_manager.add_share = _smb_add_share
smb_manager.rename_share = _smb_rename_share

# ── Multi-Account Google Drive Manager with Token Persistence & 401 Retry ─────
_gd_creds_lock = threading.Lock()
_gd_meta_cache = getattr(gdrive_manager, "_meta_cache", {})
_GD_META_TTL = 120.0
_GD_ACCOUNTS_FILE = gdrive_manager.DATA_DIR / "gdrive_accounts.json"
_GD_PENDING_OAUTH = {}
_SMB_SIZE_CACHE = {}
_SMB_SIZE_TTL = 60.0
_PROBE_CACHE = {}
_PROBE_TTL = 600.0

def _gd_parse_expiry(raw_expiry):
    if not raw_expiry:
        return None
    try:
        dt = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

def _gd_creds_to_dict(c):
    expiry_str = None
    if getattr(c, "expiry", None) is not None:
        expiry_str = c.expiry.isoformat()
    return {
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": list(c.scopes or gdrive_manager.SCOPES),
        "expiry": expiry_str,
    }

_RESERVED_SMB_NAMES = {"global", "homes", "printers", "print$", "ipc$"}

def _gd_sanitize_smb_share_name(raw_name, fallback="GoogleDrive"):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", (raw_name or "").strip()).strip("_-")
    if not cleaned or cleaned.lower() in _RESERVED_SMB_NAMES:
        cleaned = fallback
    return cleaned[:32]

def _gd_ensure_smb_fields(accounts):
    used = set()
    changed = False
    for idx, a in enumerate(accounts):
        if "smb_enabled" not in a:
            a["smb_enabled"] = True
            changed = True
        raw_share = (a.get("smb_share_name") or "").strip()
        if not raw_share:
            default_base = "GoogleDrive" if (idx == 0 or a.get("id") == "default") else (
                a.get("custom_name") or a.get("name") or f"GoogleDrive_{idx + 1}"
            )
            candidate = _gd_sanitize_smb_share_name(default_base, fallback=f"GoogleDrive_{idx + 1}")
            base_cand = candidate
            suffix = 2
            while candidate.lower() in used:
                candidate = f"{base_cand[:28]}_{suffix}"
                suffix += 1
            a["smb_share_name"] = candidate
            changed = True
        else:
            sanitized = _gd_sanitize_smb_share_name(raw_share, fallback=f"GoogleDrive_{idx + 1}")
            if sanitized.lower() in used:
                sanitized = f"{sanitized[:28]}_{idx + 1}"
            if sanitized != raw_share:
                a["smb_share_name"] = sanitized
                changed = True
        used.add(a["smb_share_name"].lower())
    return changed

def _gd_load_accounts_raw():
    if _GD_ACCOUNTS_FILE.exists():
        try:
            data = json.loads(_GD_ACCOUNTS_FILE.read_text())
            if isinstance(data, list):
                if _gd_ensure_smb_fields(data):
                    _GD_ACCOUNTS_FILE.write_text(json.dumps(data, indent=2))
                return data
        except Exception:
            pass
    if gdrive_manager.CREDS_FILE.exists():
        try:
            legacy = json.loads(gdrive_manager.CREDS_FILE.read_text())
            if legacy and (legacy.get("token") or legacy.get("refresh_token")):
                migrated = [{
                    "id": "default",
                    "name": "Google Drive",
                    "custom_name": "",
                    "original_name": "Google Drive",
                    "email": legacy.get("email", ""),
                    "smb_enabled": True,
                    "smb_share_name": "GoogleDrive",
                    "creds": legacy,
                }]
                _GD_ACCOUNTS_FILE.write_text(json.dumps(migrated, indent=2))
                return migrated
        except Exception:
            pass
    return []

def _gd_save_accounts_raw(accounts):
    _gd_ensure_smb_fields(accounts)
    _GD_ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2))
    if accounts and accounts[0].get("creds"):
        gdrive_manager.CREDS_FILE.write_text(json.dumps(accounts[0]["creds"], indent=2))
    elif not accounts and gdrive_manager.CREDS_FILE.exists():
        gdrive_manager.CREDS_FILE.unlink(missing_ok=True)

def _gd_list_accounts():
    accounts = _gd_load_accounts_raw()
    return [{
        "id": a["id"],
        "name": a.get("custom_name") or a.get("name") or "Google Drive",
        "custom_name": a.get("custom_name", ""),
        "original_name": a.get("original_name") or a.get("name") or "Google Drive",
        "email": a.get("email", ""),
        "smb_enabled": bool(a.get("smb_enabled", True)),
        "smb_share_name": a.get("smb_share_name") or "GoogleDrive",
    } for a in accounts]

def _gd_resolve_account_entry(account_id=None):
    accounts = _gd_load_accounts_raw()
    if not accounts:
        return None, accounts
    if not account_id or account_id in ("root", "default"):
        for a in accounts:
            if a["id"] == "default":
                return a, accounts
        return accounts[0], accounts
    for a in accounts:
        if a["id"] == account_id:
            return a, accounts
    return accounts[0], accounts

def _gd_save_creds(c, account_id=None, custom_name=None, email=None):
    with _gd_creds_lock:
        accounts = _gd_load_accounts_raw()
        c_dict = _gd_creds_to_dict(c)
        target = None
        if account_id:
            target = next((a for a in accounts if a["id"] == account_id), None)
        if not target and email:
            target = next((a for a in accounts if a.get("email") and a.get("email") == email), None)
        if target:
            target["creds"] = c_dict
            if email:
                target["email"] = email
            if custom_name:
                target["custom_name"] = custom_name.strip()
                target["name"] = custom_name.strip()
        else:
            new_id = "default" if not accounts else f"gdrive_{secrets.token_hex(3)}"
            default_label = "Google Drive" if not accounts else f"Google Drive {len(accounts) + 1}"
            if email and not custom_name:
                default_label = f"Google Drive ({email.split('@')[0]})"
            disp_name = (custom_name or "").strip() or default_label
            base_smb = "GoogleDrive" if not accounts else _gd_sanitize_smb_share_name(disp_name, fallback=f"GoogleDrive_{len(accounts) + 1}")
            accounts.append({
                "id": new_id,
                "name": disp_name,
                "custom_name": (custom_name or "").strip(),
                "original_name": default_label,
                "email": email or "",
                "smb_enabled": True,
                "smb_share_name": base_smb,
                "creds": c_dict,
            })
        _gd_save_accounts_raw(accounts)

def _gd_load_creds(force_refresh=False, account_id=None):
    with _gd_creds_lock:
        acc, accounts = _gd_resolve_account_entry(account_id)
        if not acc:
            return None
        d = acc.get("creds") or {}
        cfg = gdrive_manager.get_config()
        expiry_dt = _gd_parse_expiry(d.get("expiry"))
        c = Credentials(
            token=d.get("token"),
            refresh_token=d.get("refresh_token"),
            token_uri=d.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=d.get("client_id", cfg["client_id"]),
            client_secret=d.get("client_secret", cfg["client_secret"]),
            scopes=d.get("scopes", gdrive_manager.SCOPES),
            expiry=expiry_dt,
        )
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        needs_refresh = (
            force_refresh
            or not c.token
            or expiry_dt is None
            or not c.valid
            or (expiry_dt - now_utc).total_seconds() < 300
        )
        if needs_refresh and c.refresh_token:
            c.refresh(Request())
            acc["creds"] = _gd_creds_to_dict(c)
            _gd_save_accounts_raw(accounts)
        return c if (c.token or c.valid) else None

def _gd_is_authenticated(account_id=None):
    accounts = _gd_load_accounts_raw()
    if not accounts:
        return False
    try:
        c = _gd_load_creds(account_id=account_id)
        return c is not None and (c.valid or bool(c.refresh_token) or bool(c.token))
    except Exception:
        return False

def _gd_rename_account(account_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("Custom name cannot be empty")
    with _gd_creds_lock:
        accounts = _gd_load_accounts_raw()
        target = None
        for a in accounts:
            if a["id"] == account_id or (account_id in ("root", "default") and a == accounts[0]):
                if not a.get("original_name"):
                    a["original_name"] = a.get("name", "Google Drive")
                a["name"] = new_name
                a["custom_name"] = new_name
                target = a
                break
        if not target:
            raise ValueError(f"Google Drive account {account_id!r} not found")
        _gd_save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target["name"],
            "custom_name": target.get("custom_name", ""),
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "GoogleDrive",
        }

def _gd_update_account_smb_proxy(account_id, smb_enabled=None, smb_share_name=None):
    with _gd_creds_lock:
        accounts = _gd_load_accounts_raw()
        target = None
        for a in accounts:
            if a["id"] == account_id or (account_id in ("root", "default") and a == accounts[0]):
                target = a
                break
        if not target:
            raise ValueError(f"Google Drive account {account_id!r} not found")
        if smb_share_name is not None:
            raw = str(smb_share_name).strip()
            if not raw:
                raise ValueError("SMB share name cannot be empty")
            cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_-")[:32]
            if not cleaned or cleaned.lower() in _RESERVED_SMB_NAMES:
                raise ValueError(f"Invalid or reserved SMB share name: {raw!r}")
            for other in accounts:
                if other["id"] != target["id"] and (other.get("smb_share_name") or "").lower() == cleaned.lower():
                    raise ValueError(f"SMB share name '{cleaned}' is already used by another Google Drive")
            target["smb_share_name"] = cleaned
        if smb_enabled is not None:
            target["smb_enabled"] = bool(smb_enabled)
        _gd_save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target.get("custom_name") or target.get("name") or "Google Drive",
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "GoogleDrive",
        }

def _gd_remove_account(account_id=None):
    _gd_meta_cache.clear()
    with _gd_creds_lock:
        accounts = _gd_load_accounts_raw()
        if not account_id:
            _gd_save_accounts_raw([])
            return
        accounts = [a for a in accounts if a["id"] != account_id]
        _gd_save_accounts_raw(accounts)

def _gd_get_auth_url(custom_name=None, account_id=None):
    cfg = gdrive_manager.get_config()
    flow = Flow.from_client_config(gdrive_manager._client_config(), scopes=gdrive_manager.SCOPES, redirect_uri=cfg["redirect_uri"])
    url, state = flow.authorization_url(access_type="offline", prompt="select_account consent")
    if state:
        _GD_PENDING_OAUTH[state] = {
            "custom_name": (custom_name or "").strip(),
            "account_id": (account_id or "").strip(),
            "ts": time.time(),
        }
    return url

def _gd_handle_callback(code, state):
    cfg = gdrive_manager.get_config()
    flow = Flow.from_client_config(gdrive_manager._client_config(), scopes=gdrive_manager.SCOPES, redirect_uri=cfg["redirect_uri"])
    flow.fetch_token(code=code)
    c = flow.credentials
    pending = _GD_PENDING_OAUTH.pop(state, {}) if state else {}
    email = ""
    try:
        svc = build("drive", "v3", credentials=c, cache_discovery=False)
        about = svc.about().get(fields="user(displayName,emailAddress)").execute()
        email = (about.get("user") or {}).get("emailAddress", "")
    except Exception:
        pass
    _gd_save_creds(
        c,
        account_id=pending.get("account_id") or None,
        custom_name=pending.get("custom_name") or None,
        email=email,
    )

def _gd_svc(account_id=None):
    c = _gd_load_creds(account_id=account_id)
    if not c:
        raise RuntimeError("Not authenticated with Google Drive")
    return build("drive", "v3", credentials=c, cache_discovery=False)

def _gd_cache_key(account_id, file_id):
    return f"{account_id or 'default'}:{file_id}"

def _gd_list_files(folder_id="root", account_id=None):
    res = _gd_svc(account_id=account_id).files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(id,name,mimeType,size,modifiedTime,parents)",
        pageSize=200,
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    out = []
    now = time.time()
    for f in res.get("files", []):
        is_folder = f["mimeType"] == "application/vnd.google-apps.folder"
        size_val = int(f.get("size", 0) or 0)
        info = {
            "name": f["name"],
            "mimeType": f["mimeType"],
            "size": size_val,
        }
        _gd_meta_cache[_gd_cache_key(account_id, f["id"])] = (now, info)
        _gd_meta_cache[f["id"]] = (now, info)
        out.append({
            "id": f["id"],
            "name": f["name"],
            "type": "folder" if is_folder else "file",
            "size": size_val,
            "modified": f.get("modifiedTime", ""),
            "mimeType": f["mimeType"],
        })
    return out

def _gd_get_file_meta(file_id, account_id=None):
    now = time.time()
    ck = _gd_cache_key(account_id, file_id)
    cached = _gd_meta_cache.get(ck) or _gd_meta_cache.get(file_id)
    if cached and (now - cached[0]) < _GD_META_TTL:
        return cached[1]
    svc = _gd_svc(account_id=account_id)
    meta = svc.files().get(
        fileId=file_id,
        fields="name,mimeType,size",
        supportsAllDrives=True,
    ).execute()
    info = {
        "name": meta.get("name", "download"),
        "mimeType": meta.get("mimeType", "application/octet-stream"),
        "size": int(meta.get("size", 0) or 0),
    }
    _gd_meta_cache[ck] = (now, info)
    _gd_meta_cache[file_id] = (now, info)
    return info

def _gd_open_media_response(file_id, start=None, end=None, account_id=None):
    url = (
        f"https://www.googleapis.com/drive/v3/files/{file_id}"
        f"?alt=media&supportsAllDrives=true&acknowledgeAbuse=true"
    )
    for attempt in range(2):
        c = _gd_load_creds(force_refresh=(attempt > 0), account_id=account_id)
        if not c:
            raise RuntimeError("Not authenticated with Google Drive")
        headers = {"Authorization": f"Bearer {c.token}"}
        if start is not None and end is not None:
            headers["Range"] = f"bytes={start}-{end}"
        elif start:
            headers["Range"] = f"bytes={start}-"
        r = requests.get(url, headers=headers, stream=True, timeout=(15, 300))
        if r.status_code in (401, 403) and attempt == 0:
            r.close()
            continue
        if not r.ok:
            err_body = ""
            try:
                err_body = r.text[:300]
            except Exception:
                pass
            r.close()
            raise RuntimeError(f"Google Drive stream failed ({r.status_code}): {err_body}")
        return r
    raise RuntimeError("Google Drive authentication failed after token refresh")

def _gd_stream_file_range(file_id, start=0, end=None, chunk_size=262144, account_id=None):
    def _gen():
        curr_start = int(start or 0)
        retries = 0
        while True:
            if end is not None and curr_start > end:
                break
            r = None
            prev_start = curr_start
            try:
                r = _gd_open_media_response(file_id, start=curr_start, end=end, account_id=account_id)
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        curr_start += len(chunk)
                        yield chunk
                        if end is not None and curr_start > end:
                            break
                break
            except GeneratorExit:
                break
            except Exception:
                if end is not None and curr_start > end:
                    break
                if curr_start > prev_start:
                    retries = 0
                else:
                    retries += 1
                if retries > 4:
                    raise
            finally:
                if r is not None:
                    try:
                        r.close()
                    except Exception:
                        pass
    return _gen()

def _gd_download_file(file_id, account_id=None):
    svc = _gd_svc(account_id=account_id)
    meta = svc.files().get(
        fileId=file_id,
        fields="name,mimeType",
        supportsAllDrives=True,
    ).execute()
    name, mime = meta["name"], meta["mimeType"]
    export_map = {
        "application/vnd.google-apps.document":
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.google-apps.spreadsheet":
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.google-apps.presentation":
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    }
    buf = io.BytesIO()
    req = svc.files().export_media(fileId=file_id, mimeType=export_map[mime]) \
        if mime in export_map else svc.files().get_media(fileId=file_id, supportsAllDrives=True)
    dl = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = dl.next_chunk()
    return buf.getvalue(), name, mime

def _gd_ensure_folder_path(base_folder_id, parts, account_id=None):
    svc = _gd_svc(account_id=account_id)
    curr_id = base_folder_id or "root"
    for part in parts:
        if not part:
            continue
        safe_part = part.replace("'", "\\'")
        q = (
            f"'{curr_id}' in parents and name = '{safe_part}' "
            f"and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        )
        res = svc.files().list(
            q=q,
            fields="files(id)",
            pageSize=1,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        ).execute()
        files = res.get("files", [])
        if files:
            curr_id = files[0]["id"]
        else:
            created = svc.files().create(
                body={
                    "name": part,
                    "parents": [curr_id],
                    "mimeType": "application/vnd.google-apps.folder",
                },
                fields="id",
                supportsAllDrives=True,
            ).execute()
            curr_id = created["id"]
    return curr_id

def _gd_upload_file(parent_id, filename, data_or_stream, mime_type="application/octet-stream", relative_path=None, account_id=None):
    svc = _gd_svc(account_id=account_id)
    target_parent = parent_id or "root"
    actual_name = filename
    if relative_path:
        norm_rel = relative_path.replace("\x00", "").replace("\\", "/").lstrip("/")
        segments = [s for s in norm_rel.split("/") if s and s != "."]
        if any(s == ".." for s in segments):
            raise ValueError("Invalid relative_path: path traversal ('..') is not allowed")
        if len(segments) > 1:
            target_parent = _gd_ensure_folder_path(target_parent, segments[:-1], account_id=account_id)
            actual_name = segments[-1]
        elif segments:
            actual_name = segments[0]
    stream_obj = data_or_stream if hasattr(data_or_stream, "read") else io.BytesIO(
        data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
    )
    media = MediaIoBaseUpload(stream_obj, mimetype=mime_type, chunksize=8 * 1024 * 1024, resumable=True)
    svc.files().create(
        body={"name": actual_name, "parents": [target_parent]},
        media_body=media,
        fields="id",
        supportsAllDrives=True,
    ).execute()

def _gd_update_file_content(file_id, data_or_stream, mime_type="text/plain; charset=utf-8", account_id=None):
    _gd_meta_cache.pop(_gd_cache_key(account_id, file_id), None)
    _gd_meta_cache.pop(file_id, None)
    svc = _gd_svc(account_id=account_id)
    stream_obj = data_or_stream if hasattr(data_or_stream, "read") else io.BytesIO(
        data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
    )
    media = MediaIoBaseUpload(stream_obj, mimetype=mime_type, chunksize=8 * 1024 * 1024, resumable=True)
    return svc.files().update(
        fileId=file_id,
        media_body=media,
        fields="id,name,size,modifiedTime",
        supportsAllDrives=True,
    ).execute()

def _gd_move_file(file_id, dest_folder_id, account_id=None):
    dest_id = dest_folder_id or "root"
    if file_id == dest_id:
        raise ValueError("Cannot move a folder into itself")
    _gd_meta_cache.pop(_gd_cache_key(account_id, file_id), None)
    _gd_meta_cache.pop(file_id, None)
    svc = _gd_svc(account_id=account_id)
    meta = svc.files().get(
        fileId=file_id,
        fields="id,name,parents",
        supportsAllDrives=True,
    ).execute()
    prev_parents = ",".join(meta.get("parents") or [])
    return svc.files().update(
        fileId=file_id,
        addParents=dest_id,
        removeParents=prev_parents,
        fields="id,name,parents",
        supportsAllDrives=True,
    ).execute()

def _gd_rename_file(file_id, new_name, account_id=None):
    _gd_meta_cache.pop(_gd_cache_key(account_id, file_id), None)
    _gd_meta_cache.pop(file_id, None)
    return _gd_svc(account_id=account_id).files().update(
        fileId=file_id,
        body={"name": new_name},
        fields="id,name",
        supportsAllDrives=True,
    ).execute()

def _gd_delete_file(file_id, account_id=None):
    _gd_meta_cache.pop(_gd_cache_key(account_id, file_id), None)
    _gd_meta_cache.pop(file_id, None)
    _gd_svc(account_id=account_id).files().delete(fileId=file_id, supportsAllDrives=True).execute()

def _gd_create_folder(parent_id, name, account_id=None):
    f = _gd_svc(account_id=account_id).files().create(
        body={
            "name": name,
            "parents": [parent_id],
            "mimeType": "application/vnd.google-apps.folder",
        },
        fields="id",
        supportsAllDrives=True,
    ).execute()
    return f["id"]

def _gd_create_zip_tmpfile(file_ids, account_id=None):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    def _add_item(zf, fid, arc_prefix):
        meta = _gd_get_file_meta(fid, account_id=account_id)
        name = meta["name"]
        mime = meta["mimeType"]
        arc_path = f"{arc_prefix}/{name}" if arc_prefix else name
        if mime == "application/vnd.google-apps.folder":
            children = _gd_list_files(fid, account_id=account_id)
            if not children:
                zf.writestr(arc_path.rstrip("/") + "/", b"")
            for ch in children:
                _add_item(zf, ch["id"], arc_path)
        else:
            data, _, _ = _gd_download_file(fid, account_id=account_id)
            zf.writestr(arc_path, data)

    try:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for fid in file_ids:
                _add_item(zf, fid, "")
        size = os.path.getsize(tmp.name)
        return tmp.name, size
    except Exception:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        raise

gdrive_manager._save_creds = _gd_save_creds
gdrive_manager._load_creds = _gd_load_creds
gdrive_manager.is_authenticated = _gd_is_authenticated
gdrive_manager.list_accounts = _gd_list_accounts
gdrive_manager.rename_account = _gd_rename_account
gdrive_manager.update_account_smb_proxy = _gd_update_account_smb_proxy
gdrive_manager.sanitize_smb_share_name = _gd_sanitize_smb_share_name
gdrive_manager.remove_account = _gd_remove_account
gdrive_manager.get_auth_url = _gd_get_auth_url
gdrive_manager.handle_callback = _gd_handle_callback
gdrive_manager.revoke = _gd_remove_account
gdrive_manager._svc = _gd_svc
gdrive_manager.list_files = _gd_list_files
gdrive_manager.get_file_meta = _gd_get_file_meta
gdrive_manager.stream_file_range = _gd_stream_file_range
gdrive_manager.download_file = _gd_download_file
gdrive_manager.ensure_folder_path = _gd_ensure_folder_path
gdrive_manager.upload_file = _gd_upload_file
gdrive_manager.update_file_content = _gd_update_file_content
gdrive_manager.move_file = _gd_move_file
gdrive_manager.rename_file = _gd_rename_file
gdrive_manager.delete_file = _gd_delete_file
gdrive_manager.create_folder = _gd_create_folder
gdrive_manager.create_zip_tmpfile = _gd_create_zip_tmpfile

# ── Ensure smb_manager has path sanitization, streaming upload, move, & size cache ─
def _sanitize_smb_path(path, allow_root=True):
    raw = str(path or "").replace("\x00", "").replace("\\", "/").strip()
    parts = []
    for seg in raw.split("/"):
        seg = seg.strip()
        if not seg or seg == ".":
            continue
        if seg == "..":
            raise ValueError("Invalid SMB path: path traversal ('..') is not allowed")
        parts.append(seg)
    if not parts:
        if allow_root:
            return "/"
        raise ValueError("SMB path cannot be empty")
    return "/" + "/".join(parts)

def _smb_upload_file(share_id, dest_path, data_or_stream):
    norm_path = _sanitize_smb_path(dest_path, allow_root=False)
    cfg = smb_manager._cfg(share_id)
    c = smb_manager._conn(cfg)
    try:
        parent = "/".join(norm_path.split("/")[:-1])
        if parent and parent != "/":
            smb_manager._ensure_dirs_on_conn(c, cfg["share"], parent)
        file_obj = data_or_stream if hasattr(data_or_stream, "read") else io.BytesIO(
            data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
        )
        c.storeFile(cfg["share"], norm_path, file_obj)
    finally:
        c.close()

def _smb_move_path(share_id, old_path, dest_dir):
    norm_old = _sanitize_smb_path(old_path, allow_root=False)
    norm_dest_dir = _sanitize_smb_path(dest_dir, allow_root=True)
    base_name = norm_old.rstrip("/").split("/")[-1]
    new_path = (norm_dest_dir.rstrip("/") + "/" + base_name) if norm_dest_dir != "/" else ("/" + base_name)
    if new_path == norm_old:
        return new_path
    if new_path.startswith(norm_old.rstrip("/") + "/"):
        raise ValueError("Cannot move a folder into itself")
    cfg = smb_manager._cfg(share_id)
    c = smb_manager._conn(cfg)
    try:
        if norm_dest_dir != "/":
            smb_manager._ensure_dirs_on_conn(c, cfg["share"], norm_dest_dir)
        c.rename(cfg["share"], norm_old, new_path)
        return new_path
    finally:
        c.close()

smb_manager.sanitize_smb_path = _sanitize_smb_path
smb_manager.upload_file = _smb_upload_file
smb_manager.move_path = _smb_move_path

def _get_smb_file_size(share_id, path):
    norm_path = _sanitize_smb_path(path, allow_root=False)
    key = f"{share_id}:{norm_path}"
    now = time.time()
    cached = _SMB_SIZE_CACHE.get(key)
    if cached and (now - cached[0]) < _SMB_SIZE_TTL:
        return cached[1]
    sz = smb_manager.get_file_size(share_id, norm_path)
    _SMB_SIZE_CACHE[key] = (now, sz)
    return sz

def _smb_stream_file_range(share_id, path, start=0, length=None, chunk_size=262144):
    path = _sanitize_smb_path(path, allow_root=False)
    q = queue.Queue(maxsize=32)
    sentinel = object()
    aborted = threading.Event()
    smb_op_timeout = 14400

    class _AbortStream(Exception):
        pass

    class _QueueWriter:
        def __init__(self, max_bytes):
            self.remaining = max_bytes
            self.written = 0
            self.buf = bytearray()

        def write(self, data):
            if aborted.is_set():
                raise _AbortStream()
            if not data:
                return 0
            if self.remaining is not None:
                if self.remaining <= 0:
                    raise _AbortStream()
                if len(data) > self.remaining:
                    data = data[:self.remaining]
                self.remaining -= len(data)
            self.written += len(data)
            self.buf.extend(data)
            while len(self.buf) >= chunk_size:
                if aborted.is_set():
                    raise _AbortStream()
                try:
                    q.put(bytes(self.buf[:chunk_size]), timeout=0.5)
                    del self.buf[:chunk_size]
                except queue.Full:
                    if aborted.is_set():
                        raise _AbortStream()
            return len(data)

        def flush(self):
            while self.buf and not aborted.is_set():
                try:
                    q.put(bytes(self.buf), timeout=0.5)
                    self.buf.clear()
                except queue.Full:
                    if aborted.is_set():
                        break

    def _producer():
        cfg = None
        writer = _QueueWriter(length)
        retries = 0
        try:
            cfg = smb_manager._cfg(share_id)
            while not aborted.is_set():
                if writer.remaining is not None and writer.remaining <= 0:
                    break
                c = None
                prev_written = writer.written
                try:
                    c = smb_manager._conn(cfg)
                    curr_offset = start + writer.written
                    if curr_offset == 0 and writer.remaining is None:
                        c.retrieveFile(cfg["share"], path, writer, timeout=smb_op_timeout)
                    else:
                        max_len = writer.remaining if (writer.remaining is not None and writer.remaining > 0) else -1
                        c.retrieveFileFromOffset(
                            cfg["share"],
                            path,
                            writer,
                            offset=curr_offset,
                            max_length=max_len,
                            timeout=smb_op_timeout,
                        )
                    writer.flush()
                    break
                except _AbortStream:
                    break
                except Exception as e:
                    if aborted.is_set():
                        break
                    if writer.remaining is not None and writer.remaining <= 0:
                        writer.flush()
                        break
                    if writer.written > prev_written:
                        retries = 0
                    else:
                        retries += 1
                    if retries > 4:
                        try:
                            writer.flush()
                        except Exception:
                            pass
                        try:
                            q.put(e, timeout=1.0)
                        except Exception:
                            pass
                        break
                finally:
                    if c is not None:
                        try:
                            c.close()
                        except Exception:
                            pass
        except Exception as outer_e:
            if not aborted.is_set():
                try:
                    q.put(outer_e, timeout=1.0)
                except Exception:
                    pass
        finally:
            try:
                q.put(sentinel, timeout=1.0)
            except Exception:
                pass

    threading.Thread(target=_producer, daemon=True).start()

    try:
        sent = 0
        while True:
            item = q.get()
            if item is sentinel:
                break
            if isinstance(item, Exception):
                raise item
            sent += len(item)
            yield item
            if length is not None and sent >= length:
                break
    finally:
        aborted.set()

smb_manager.stream_file_range = _smb_stream_file_range

# ── Internal Loopback HTTP Range Server for FFmpeg & FFprobe ──────────────────
class _InternalMediaRangeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _handle_request(self, send_body=True):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        try:
            if parsed.path.startswith("/smb/"):
                share_id = unquote(parsed.path[len("/smb/"):])
                smb_path = qs.get("path", [""])[0]
                file_size = _get_smb_file_size(share_id, smb_path)
                kind = "smb"
            elif parsed.path.startswith("/gdrive/"):
                file_id = unquote(parsed.path[len("/gdrive/"):])
                account_id = qs.get("account_id", [None])[0]
                meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
                file_size = meta["size"]
                kind = "gdrive"
            else:
                self.send_response(404)
                self.end_headers()
                return

            rng = self.headers.get("Range")
            if rng and file_size > 0 and rng.startswith("bytes="):
                m = re.search(r"bytes=(\d*)-(\d*)", rng)
                if not m:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                if not m.group(1) and m.group(2):
                    suffix = int(m.group(2))
                    start = max(0, file_size - suffix)
                    end = file_size - 1
                else:
                    start = int(m.group(1)) if m.group(1) else 0
                    end = int(m.group(2)) if m.group(2) else file_size - 1
                if start >= file_size or start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                end = min(end, file_size - 1)
                length = end - start + 1
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(length))
                self.end_headers()
            else:
                start = 0
                end = max(0, file_size - 1)
                length = file_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                if file_size > 0:
                    self.send_header("Content-Length", str(file_size))
                self.end_headers()

            if not send_body:
                return

            fetch_len = length
            if kind == "smb":
                gen = smb_manager.stream_file_range(share_id, smb_path, start=start, length=fetch_len)
            else:
                end_byte = (start + fetch_len - 1) if fetch_len > 0 else None
                gen = gdrive_manager.stream_file_range(file_id, start=start, end=end_byte, account_id=account_id)

            try:
                for chunk in gen:
                    if not chunk:
                        continue
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                try:
                    gen.close()
                except Exception:
                    pass
        except Exception:
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def do_GET(self):
        self._handle_request(send_body=True)

_internal_media_server = ThreadingHTTPServer(("127.0.0.1", 0), _InternalMediaRangeHandler)
_INTERNAL_MEDIA_PORT = _internal_media_server.server_port
threading.Thread(target=_internal_media_server.serve_forever, daemon=True).start()

def _internal_smb_url(share_id, path):
    return f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/smb/{quote(str(share_id))}?path={quote(str(path))}"

def _internal_gdrive_url(file_id, account_id=None):
    base = f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/gdrive/{quote(str(file_id))}"
    if account_id:
        return f"{base}?account_id={quote(str(account_id))}"
    return base

MEDIA_MIMES = {
    "mp4": "video/mp4",
    "m4v": "video/mp4",
    "mov": "video/mp4",
    "webm": "video/webm",
    "mkv": "video/mp4",
    "ogv": "video/ogg",
    "avi": "video/x-msvideo",
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "ogg": "audio/ogg",
    "oga": "audio/ogg",
    "opus": "audio/ogg",
    "m4a": "audio/mp4",
    "aac": "audio/aac",
    "flac": "audio/flac",
    "weba": "audio/webm",
    "wma": "audio/x-ms-wma",
    "aiff": "audio/aiff",
    "aif": "audio/aiff",
    "eac3": "audio/eac3",
    "ec3": "audio/eac3",
    "ac3": "audio/ac3",
    "dts": "audio/vnd.dts",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "jfif": "image/jpeg",
    "png": "image/png",
    "apng": "image/apng",
    "gif": "image/gif",
    "webp": "image/webp",
    "svg": "image/svg+xml",
    "bmp": "image/bmp",
    "ico": "image/x-icon",
    "avif": "image/avif",
    "pdf": "application/pdf",
    "txt": "text/plain; charset=utf-8",
    "md": "text/plain; charset=utf-8",
    "log": "text/plain; charset=utf-8",
    "csv": "text/plain; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "xml": "text/xml; charset=utf-8",
    "yaml": "text/plain; charset=utf-8",
    "yml": "text/plain; charset=utf-8",
    "ini": "text/plain; charset=utf-8",
    "conf": "text/plain; charset=utf-8",
    "toml": "text/plain; charset=utf-8",
    "py": "text/plain; charset=utf-8",
    "sh": "text/plain; charset=utf-8",
    "js": "text/plain; charset=utf-8",
    "ts": "text/plain; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "html": "text/html; charset=utf-8",
}

def guess_media_mime(filename, fallback=None):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in MEDIA_MIMES:
        return MEDIA_MIMES[ext]
    if fallback == "video/quicktime":
        return "video/mp4"
    if fallback in ("audio/mp3", "audio/mpeg3", "audio/x-mp3"):
        return "audio/mpeg"
    if fallback in ("audio/x-wav", "audio/wave"):
        return "audio/wav"
    if fallback in ("audio/x-m4a", "audio/m4a"):
        return "audio/mp4"
    if fallback in ("audio/x-flac",):
        return "audio/flac"
    guessed = mimetypes.guess_type(filename)[0]
    if guessed and guessed not in ("application/octet-stream", "video/quicktime"):
        return guessed
    if fallback and fallback not in ("application/octet-stream", "video/quicktime"):
        return fallback
    return "application/octet-stream"

def make_content_disposition(filename, is_download=False):
    disp_type = "attachment" if is_download else "inline"
    safe_ascii = "".join(c if 32 <= ord(c) < 127 and c not in ('"', "\\") else "_" for c in filename)
    encoded = quote(filename)
    return f"{disp_type}; filename=\"{safe_ascii}\"; filename*=UTF-8''{encoded}"

def _stream_and_unlink_tmpfile(tmp_path, chunk_size=262144):
    try:
        with open(tmp_path, "rb") as fp:
            while True:
                data = fp.read(chunk_size)
                if not data:
                    break
                yield data
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

# ── Media Codec Probe & Smart Remux / Transcode ───────────────────────────────
def _parse_duration_val(val):
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val) if val > 0 else 0.0
    s = str(val).strip()
    if not s or s.upper() == "N/A":
        return 0.0
    try:
        v = float(s)
        if v > 0 and math.isfinite(v):
            return v
    except Exception:
        pass
    m = re.match(r"^(\d+):(\d{1,2}):(\d{1,2}(?:\.\d+)?)", s)
    if m:
        try:
            hrs = int(m.group(1))
            mins = int(m.group(2))
            secs = float(m.group(3))
            return hrs * 3600.0 + mins * 60.0 + secs
        except Exception:
            pass
    return 0.0

def _extract_probe_duration(fmt, streams):
    candidates = [
        _parse_duration_val((fmt or {}).get("duration")),
    ]
    fmt_tags = (fmt or {}).get("tags") or {}
    for k, v in fmt_tags.items():
        if str(k).lower().startswith("duration"):
            candidates.append(_parse_duration_val(v))
    for st in (streams or []):
        candidates.append(_parse_duration_val(st.get("duration")))
        st_tags = st.get("tags") or {}
        for k, v in st_tags.items():
            if str(k).lower().startswith("duration"):
                candidates.append(_parse_duration_val(v))
    valid = [c for c in candidates if c and c > 0 and math.isfinite(c)]
    return max(valid) if valid else 0.0

def _analyze_probe_data(data, filename=""):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    streams = data.get("streams") or []
    fmt = data.get("format") or {}

    non_cover_videos = [
        s for s in streams
        if s.get("codec_type") == "video"
        and (s.get("codec_name") or "").lower() not in ("mjpeg", "png", "bmp", "gif", "webp")
    ]
    video_streams = non_cover_videos or [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]

    v0 = video_streams[0] if video_streams else None
    a0 = audio_streams[0] if audio_streams else None

    video_codec = (v0.get("codec_name") or "").lower() if v0 else ""
    video_pix_fmt = (v0.get("pix_fmt") or "").lower() if v0 else ""
    audio_codec = (a0.get("codec_name") or "").lower() if a0 else ""
    audio_channels = int(a0.get("channels") or 0) if a0 else 0

    has_video = bool(v0)
    has_audio = bool(a0)

    # Audio codecs natively decoded by all browsers in <video>/<audio>
    safe_audio_codecs = {"aac", "mp3", "opus"}
    if ext in ("webm", "ogg", "ogv", "oga"):
        safe_audio_codecs.add("vorbis")
    if not has_video and ext in ("wav", "flac"):
        safe_audio_codecs.update({"pcm_s16le", "pcm_s24le", "pcm_f32le", "pcm_u8", "flac"})

    # EAC3, AC3, DTS, TrueHD, MLP, PCM in video, FLAC/ALAC in video, WMA, MP2, Vorbis in MP4/MKV, or >2ch non-AAC need transcoding
    needs_audio_transcode = False
    if has_audio:
        if audio_codec not in safe_audio_codecs:
            needs_audio_transcode = True
        elif audio_channels > 2 and audio_codec != "aac":
            needs_audio_transcode = True

    is_10bit_h264 = video_codec == "h264" and video_pix_fmt.endswith(("10le", "10be", "12le", "12be"))
    needs_video_transcode = False
    if has_video:
        if video_codec not in ("h264", "hevc", "vp8", "vp9", "av1") or is_10bit_h264:
            needs_video_transcode = True

    non_native_container = ext in ("avi", "wmv", "flv", "ts", "m2ts", "mpg", "mpeg", "vob", "divx")
    can_remux_video = has_video and video_codec in ("h264", "hevc") and not is_10bit_h264

    if has_video:
        if needs_video_transcode:
            recommended_mode = "full"
        elif needs_audio_transcode or non_native_container:
            recommended_mode = "remux" if can_remux_video else "full"
        else:
            recommended_mode = "direct"
    else:
        recommended_mode = "audio" if (needs_audio_transcode or ext in ("eac3", "ec3", "ac3", "dts", "wma", "aiff", "aif", "alac", "mka", "mp2")) else "direct"

    audio_tracks_out = []
    for idx, s in enumerate(audio_streams):
        tags = s.get("tags") or {}
        audio_tracks_out.append({
            "index": idx,
            "codec": (s.get("codec_name") or "unknown").lower(),
            "channels": int(s.get("channels") or 0),
            "language": tags.get("language") or tags.get("LANGUAGE") or "",
            "title": tags.get("title") or tags.get("TITLE") or "",
        })

    duration = _extract_probe_duration(fmt, streams)

    return {
        "has_video": has_video,
        "video_codec": video_codec,
        "video_pix_fmt": video_pix_fmt,
        "has_audio": has_audio,
        "audio_codec": audio_codec,
        "audio_channels": audio_channels,
        "audio_streams": audio_tracks_out,
        "duration": duration,
        "needs_audio_transcode": needs_audio_transcode,
        "needs_video_transcode": needs_video_transcode,
        "can_remux_video": can_remux_video,
        "recommended_mode": recommended_mode,
    }

def probe_media_info(cache_key, internal_url, filename="", fallback_gen_fn=None):
    now = time.time()
    cached = _PROBE_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _PROBE_TTL:
        return cached[1]

    show_entries = "stream=index,codec_type,codec_name,profile,pix_fmt,channels,sample_rate,duration:stream_tags:format=format_name,duration:format_tags"
    cmd = [
        "ffprobe",
        "-v", "error",
        "-probesize", "10000000",
        "-analyzeduration", "10000000",
        "-show_entries", show_entries,
        "-of", "json",
        internal_url,
    ]
    data = None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if res.returncode == 0 and res.stdout.strip():
            parsed = json.loads(res.stdout)
            if parsed.get("streams"):
                data = parsed
    except Exception:
        pass

    if not data and fallback_gen_fn is not None:
        try:
            proc = subprocess.Popen(
                [
                    "ffprobe",
                    "-v", "error",
                    "-probesize", "8000000",
                    "-analyzeduration", "8000000",
                    "-show_entries", show_entries,
                    "-of", "json",
                    "pipe:0",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            gen = fallback_gen_fn()
            sent = 0
            try:
                for chunk in gen:
                    if proc.poll() is not None or sent >= 8 * 1024 * 1024:
                        break
                    proc.stdin.write(chunk)
                    sent += len(chunk)
            except Exception:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                try:
                    gen.close()
                except Exception:
                    pass
            out, _ = proc.communicate(timeout=8)
            if out:
                parsed = json.loads(out.decode("utf-8", errors="ignore"))
                if parsed.get("streams"):
                    data = parsed
        except Exception:
            pass

    info = _analyze_probe_data(data or {}, filename)
    if data and data.get("streams"):
        _PROBE_CACHE[cache_key] = (now, info)
    return info

def _patch_mp4_moov_duration(chunk, duration_sec):
    """
    Patches the ISO BMFF moov header (mvhd, tkhd, mdhd, and mvex/mehd) emitted
    by FFmpeg's -movflags empty_moov so browsers and players know the full
    duration of a live-remuxed or transcoded video immediately from the first chunk.
    """
    if not chunk or not duration_sec or duration_sec <= 0 or not math.isfinite(duration_sec):
        return chunk
    try:
        buf = bytearray(chunk)
        mvhd_ts = [1000]

        def _walk(b, start, end):
            pos = start
            while pos + 8 <= end:
                sz, btype = struct.unpack(">I4s", b[pos:pos+8])
                if sz < 8 or pos + sz > end:
                    break
                if btype == b"mvhd":
                    ver = b[pos+8]
                    if ver == 0 and sz >= 28:
                        ts = struct.unpack(">I", b[pos+20:pos+24])[0] or 1000
                        mvhd_ts[0] = ts
                        struct.pack_into(">I", b, pos+24, min(0xFFFFFFFF, int(round(duration_sec * ts))))
                    elif ver == 1 and sz >= 40:
                        ts = struct.unpack(">I", b[pos+28:pos+32])[0] or 1000
                        mvhd_ts[0] = ts
                        struct.pack_into(">Q", b, pos+32, int(round(duration_sec * ts)))
                elif btype == b"tkhd":
                    ver = b[pos+8]
                    ts = mvhd_ts[0]
                    if ver == 0 and sz >= 32:
                        struct.pack_into(">I", b, pos+28, min(0xFFFFFFFF, int(round(duration_sec * ts))))
                    elif ver == 1 and sz >= 44:
                        struct.pack_into(">Q", b, pos+36, int(round(duration_sec * ts)))
                elif btype == b"mdhd":
                    ver = b[pos+8]
                    if ver == 0 and sz >= 28:
                        ts = struct.unpack(">I", b[pos+20:pos+24])[0] or 1000
                        struct.pack_into(">I", b, pos+24, min(0xFFFFFFFF, int(round(duration_sec * ts))))
                    elif ver == 1 and sz >= 40:
                        ts = struct.unpack(">I", b[pos+28:pos+32])[0] or 1000
                        struct.pack_into(">Q", b, pos+32, int(round(duration_sec * ts)))
                elif btype in (b"moov", b"trak", b"mdia"):
                    _walk(b, pos+8, pos+sz)
                elif btype == b"moof":
                    break
                pos += sz

        _walk(buf, 0, len(buf))
        pos = 0
        while pos + 8 <= len(buf):
            sz, btype = struct.unpack(">I4s", buf[pos:pos+8])
            if sz < 8 or pos + sz > len(buf):
                break
            if btype == b"moov":
                cpos = pos + 8
                cend = pos + sz
                while cpos + 8 <= cend:
                    csz, ctype = struct.unpack(">I4s", buf[cpos:cpos+8])
                    if csz < 8 or cpos + csz > cend:
                        break
                    if ctype == b"mvex":
                        has_mehd = b"mehd" in buf[cpos+8:cpos+csz]
                        if not has_mehd:
                            mehd_dur = min(0xFFFFFFFF, int(round(duration_sec * mvhd_ts[0])))
                            mehd_box = struct.pack(">I4sB3sI", 16, b"mehd", 0, b"\x00\x00\x00", mehd_dur)
                            struct.pack_into(">I", buf, cpos, csz + 16)
                            struct.pack_into(">I", buf, pos, sz + 16)
                            buf[cpos+8:cpos+8] = mehd_box
                        break
                    cpos += csz
                break
            pos += sz
        return bytes(buf)
    except Exception:
        return chunk

def _build_ffmpeg_video_cmd(input_spec, mode="full", video_codec="h264", audio_track=0, start_time=0.0):
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
    if start_time and start_time > 0:
        cmd += ["-ss", f"{start_time:.3f}"]
    cmd += ["-i", input_spec]
    cmd += ["-map", "0:V:0", "-map", f"0:a:{max(0, int(audio_track))}?", "-sn", "-dn"]
    if mode == "remux":
        vtag = "hvc1" if video_codec == "hevc" else "avc1"
        cmd += ["-c:v", "copy", "-tag:v", vtag]
    else:
        cmd += [
            "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p",
            "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
        ]
    cmd += [
        "-af", "aresample=async=1:first_pts=0",
        "-c:a", "aac", "-ac", "2", "-ar", "48000", "-b:a", "192k",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "frag_keyframe+empty_moov+default_base_moof",
        "-f", "mp4",
        "pipe:1",
    ]
    return cmd

def transcode_media_stream(internal_url=None, chunk_iterable_fn=None, filename="", mode="auto", audio_track=0, start_time=0.0, probe_info=None, duration_hint=0.0):
    """
    Streams fragmented MP4 with universal 2-channel stereo AAC audio and patches
    the initial moov header with the true full media duration.
    """
    vcodec = (probe_info or {}).get("video_codec") or "h264"
    can_remux = (probe_info or {}).get("can_remux_video", False)
    total_dur = float((probe_info or {}).get("duration") or duration_hint or 0.0)
    effective_dur = max(0.0, total_dur - float(start_time or 0.0)) if total_dur > 0 else 0.0

    if mode == "auto":
        effective_mode = "remux" if can_remux else "full"
    elif mode in ("remux", "full"):
        effective_mode = mode
    else:
        effective_mode = "full"

    attempts = []
    if internal_url:
        if effective_mode == "remux":
            attempts.append(("url", "remux"))
        attempts.append(("url", "full"))
    if chunk_iterable_fn is not None:
        attempts.append(("pipe", "full"))

    for src_kind, attempt_mode in attempts:
        proc = None
        gen = None
        try:
            if src_kind == "url":
                cmd = _build_ffmpeg_video_cmd(
                    internal_url,
                    mode=attempt_mode,
                    video_codec=vcodec,
                    audio_track=audio_track,
                    start_time=start_time,
                )
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=65536)
            else:
                cmd = _build_ffmpeg_video_cmd(
                    "pipe:0",
                    mode="full",
                    video_codec=vcodec,
                    audio_track=audio_track,
                    start_time=0.0,
                )
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=65536)
                gen = chunk_iterable_fn()

                def _feed_stdin(p=proc, g=gen):
                    try:
                        for chunk in g:
                            if p.poll() is not None:
                                break
                            p.stdin.write(chunk)
                    except Exception:
                        pass
                    finally:
                        try:
                            p.stdin.close()
                        except Exception:
                            pass
                        try:
                            g.close()
                        except Exception:
                            pass

                threading.Thread(target=_feed_stdin, daemon=True).start()

            init_buf = bytearray()
            while len(init_buf) < 16384:
                piece = proc.stdout.read(65536 - len(init_buf))
                if not piece:
                    break
                init_buf.extend(piece)
                if b"moof" in init_buf:
                    break

            if not init_buf:
                try:
                    proc.kill()
                except Exception:
                    pass
                continue

            first_chunk = _patch_mp4_moov_duration(bytes(init_buf), effective_dur)
            yield first_chunk
            while True:
                out = proc.stdout.read(65536)
                if not out:
                    break
                yield out
            return
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            if gen is not None:
                try:
                    gen.close()
                except Exception:
                    pass

def transcode_stream(chunk_iterable):
    return transcode_media_stream(
        internal_url=None,
        chunk_iterable_fn=lambda: chunk_iterable,
        mode="full",
    )

def transcode_audio_stream(chunk_iterable, internal_url=None, start_time=0.0):
    """
    Transcodes any audio stream (including 5.1/7.1 EAC3, AC3, DTS, FLAC, WMA, ALAC)
    into universal 2-channel stereo MP3.
    """
    proc = None
    gen = None
    try:
        if internal_url:
            cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
            if start_time and start_time > 0:
                cmd += ["-ss", f"{start_time:.3f}"]
            cmd += [
                "-i", internal_url,
                "-vn",
                "-af", "aresample=async=1:first_pts=0",
                "-c:a", "libmp3lame", "-ac", "2", "-ar", "48000", "-b:a", "192k",
                "-f", "mp3",
                "pipe:1",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                bufsize=65536,
            )
            first = proc.stdout.read(65536)
            if first:
                yield first
                while True:
                    out = proc.stdout.read(65536)
                    if not out:
                        break
                    yield out
                return
            try:
                proc.kill()
            except Exception:
                pass

        gen = chunk_iterable() if callable(chunk_iterable) else chunk_iterable
        proc = subprocess.Popen(
            [
                "ffmpeg",
                "-hide_banner", "-loglevel", "error",
                "-i", "pipe:0",
                "-vn",
                "-af", "aresample=async=1:first_pts=0",
                "-c:a", "libmp3lame", "-ac", "2", "-ar", "48000", "-b:a", "192k",
                "-f", "mp3",
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=65536,
        )

        def feed_stdin(p=proc, g=gen):
            try:
                for chunk in g:
                    if p.poll() is not None:
                        break
                    p.stdin.write(chunk)
            except Exception:
                pass
            finally:
                try:
                    p.stdin.close()
                except Exception:
                    pass
                try:
                    g.close()
                except Exception:
                    pass

        threading.Thread(target=feed_stdin, daemon=True).start()
        while True:
            out = proc.stdout.read(65536)
            if not out:
                break
            yield out
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        if gen is not None:
            try:
                gen.close()
            except Exception:
                pass

# ── SPA catch-all ─────────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def spa(path):
    static = Path(app.static_folder)
    target = static / path
    if path and target.exists():
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def api_login():
    body = request.get_json(force=True) or {}
    u = body.get("username","")
    pw = body.get("password","")
    token, err_msg, status_code, meta = auth.login_with_status(u, pw)
    if token:
        resp = jsonify({"token": token})
        resp.set_cookie("sd_token", token, max_age=auth.SESSION_TTL, path="/", httponly=True, samesite="Lax")
        return resp
    return jsonify({
        "error": err_msg or "Invalid credentials",
        "locked": meta.get("locked", False),
        "retry_after": meta.get("retry_after", 0),
        "attempts_remaining": meta.get("attempts_remaining", 0),
    }), status_code

@app.post("/api/auth/logout")
@auth.require_auth
def api_logout():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    auth.logout(t)
    resp = jsonify({"ok": True})
    resp.delete_cookie("sd_token", path="/")
    return resp

@app.get("/api/auth/me")
@auth.require_auth
def api_me():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    s = auth.get_session(t)
    return jsonify({"username": s["username"], "role": s["role"]})

# ── SMB ───────────────────────────────────────────────────────────────────────
@app.get("/api/smb/shares")
@auth.require_auth
def smb_list_shares():
    return jsonify([{k:v for k,v in s.items() if k != "password"}
                    for s in smb_manager.list_shares()])

@app.post("/api/smb/shares")
@auth.require_auth
def smb_add_share():
    b = request.get_json(force=True) or {}
    try:
        entry = smb_manager.add_share(
            name=b["name"], host=b["host"], share=b["share"],
            username=b.get("username",""), password=b.get("password",""),
            port=int(b.get("port", 445)),
            custom_name=b.get("custom_name", ""))
        return jsonify({k:v for k,v in entry.items() if k != "password"}), 201
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/smb/shares/<share_id>/rename")
@auth.require_auth
def smb_rename_share(share_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    try:
        updated = smb_manager.rename_share(share_id, new_name)
        return jsonify({k:v for k,v in updated.items() if k != "password"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/smb/shares/<share_id>")
@auth.require_auth
def smb_delete_share(share_id):
    smb_manager.remove_share(share_id)
    return jsonify({"ok": True})

@app.get("/api/smb/browse/<share_id>")
@auth.require_auth
def smb_browse(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", "/"), allow_root=True)
        return jsonify(smb_manager.browse(share_id, path))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/probe/<share_id>")
@auth.require_auth
def smb_probe(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", ""), allow_root=False)
        filename = path.split("/")[-1] or "media"
        internal_url = _internal_smb_url(share_id, path)
        info = probe_media_info(
            cache_key=f"smb:{share_id}:{path}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=4 * 1024 * 1024),
        )
        return jsonify(info)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/download/<share_id>")
@auth.require_auth
def smb_download(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", ""), allow_root=False)
        filename = path.split("/")[-1] or "download"
        file_size = _get_smb_file_size(share_id, path)
        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_smb_url(share_id, path)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            probe_info = probe_media_info(
                cache_key=f"smb:{share_id}:{path}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=min(file_size, 8 * 1024 * 1024)),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename)
        range_header = request.headers.get("Range")
        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                smb_manager.stream_file_range(share_id, path, start=start, length=length),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/upload/<share_id>")
@auth.require_auth
def smb_upload(share_id):
    dest = request.args.get("path", "/")
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        norm_dest = _sanitize_smb_path(dest, allow_root=True)
        sub_path = (rel_path or f.filename or "").lstrip("/")
        target_path = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + sub_path, allow_root=False)
        smb_manager.upload_file(share_id, target_path, f.stream)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{target_path}", None)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/smb/content/<share_id>")
@auth.require_auth
def smb_save_content(share_id):
    b = request.get_json(force=True) or {}
    raw_path = (b.get("path") or request.args.get("path") or "").strip()
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        target_path = _sanitize_smb_path(raw_path, allow_root=False)
        encoded = str(content).encode("utf-8")
        smb_manager.upload_file(share_id, target_path, io.BytesIO(encoded))
        _SMB_SIZE_CACHE[f"{share_id}:{target_path}"] = (time.time(), len(encoded))
        return jsonify({"ok": True, "path": target_path, "size": len(encoded)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/rename/<share_id>")
@auth.require_auth
def smb_rename(share_id):
    b = request.get_json(force=True) or {}
    old_path = (b.get("path") or "").strip()
    new_name = (b.get("new_name") or "").strip()
    if not old_path or not new_name:
        return jsonify({"error": "path and new_name are required"}), 400
    try:
        norm_old = _sanitize_smb_path(old_path, allow_root=False)
        new_path = smb_manager.rename_path(share_id, norm_old, new_name)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{norm_old}", None)
        return jsonify({"ok": True, "path": new_path})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/zip/<share_id>")
@auth.require_auth
def smb_zip(share_id):
    b = request.get_json(force=True) or {}
    paths = b.get("paths") or []
    if not paths:
        return jsonify({"error": "No paths provided"}), 400
    try:
        clean_paths = [_sanitize_smb_path(p, allow_root=False) for p in paths]
        tmp_path, zip_size = smb_manager.create_zip_tmpfile(share_id, clean_paths)
        archive_name = b.get("name") or "SageDrive_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/smb/delete/<share_id>")
@auth.require_auth
def smb_delete_file(share_id):
    b = request.get_json(force=True) or {}
    try:
        p = _sanitize_smb_path(b.get("path",""), allow_root=False)
        smb_manager.delete_path(share_id, p, b.get("is_dir", False))
        _SMB_SIZE_CACHE.pop(f"{share_id}:{p}", None)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/mkdir/<share_id>")
@auth.require_auth
def smb_mkdir(share_id):
    b = request.get_json(force=True) or {}
    try:
        p = _sanitize_smb_path(b.get("path",""), allow_root=False)
        smb_manager.create_directory(share_id, p)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Google Drive ──────────────────────────────────────────────────────────────
@app.get("/api/gdrive/status")
@auth.require_auth
def gdrive_status():
    accounts = gdrive_manager.list_accounts()
    return jsonify({
        "configured": gdrive_manager.is_configured(),
        "authenticated": gdrive_manager.is_authenticated(),
        "accounts": accounts,
    })

@app.get("/api/gdrive/accounts")
@auth.require_auth
def gdrive_list_accounts():
    return jsonify(gdrive_manager.list_accounts())

@app.post("/api/gdrive/accounts/<account_id>/rename")
@auth.require_auth
def gdrive_rename_account(account_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    try:
        acc = gdrive_manager.rename_account(account_id, new_name)
        return jsonify(acc)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/gdrive/accounts/<account_id>")
@auth.require_auth
def gdrive_delete_account(account_id):
    gdrive_manager.remove_account(account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/gdrive/config")
@auth.require_auth
def gdrive_get_config():
    return jsonify(gdrive_manager.get_config())

@app.post("/api/gdrive/config")
@auth.require_auth
def gdrive_save_config():
    b = request.get_json(force=True) or {}
    cfg = gdrive_manager.save_config(
        b.get("client_id", ""),
        b.get("client_secret", ""),
        b.get("redirect_uri", "")
    )
    return jsonify({"ok": True, "configured": gdrive_manager.is_configured()})

@app.get("/api/gdrive/auth")
@auth.require_auth
def gdrive_auth():
    if not gdrive_manager.is_configured():
        return jsonify({"error": "Google OAuth not configured"}), 400
    custom_name = request.args.get("name", "").strip()
    account_id = request.args.get("account_id", "").strip()
    return jsonify({"url": gdrive_manager.get_auth_url(custom_name=custom_name, account_id=account_id)})

@app.get("/api/gdrive/callback")
def gdrive_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing code", 400
    try:
        gdrive_manager.handle_callback(code, state)
        try:
            _reconcile_smb_proxy()
        except Exception:
            pass
        return redirect("/#gdrive-connected")
    except Exception as e:
        return f"OAuth error: {e}", 500

@app.delete("/api/gdrive/revoke")
@auth.require_auth
def gdrive_revoke():
    account_id = request.args.get("account_id", "").strip() or None
    gdrive_manager.revoke(account_id=account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/gdrive/files")
@auth.require_auth
def gdrive_files():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    try:
        return jsonify(gdrive_manager.list_files(folder_id, account_id=account_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/probe/<file_id>")
@auth.require_auth
def gdrive_probe(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        file_size = meta["size"]
        internal_url = _internal_gdrive_url(file_id, account_id=account_id)
        end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
        info = probe_media_info(
            cache_key=f"gdrive:{account_id or 'default'}:{file_id}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/download/<file_id>")
@auth.require_auth
def gdrive_download(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        raw_mime = meta["mimeType"]
        file_size = meta["size"]

        # Google Workspace native docs must be exported
        if raw_mime.startswith("application/vnd.google-apps."):
            data, filename, mime = gdrive_manager.download_file(file_id, account_id=account_id)
            return send_file(
                io.BytesIO(data),
                download_name=filename,
                as_attachment=bool(request.args.get("dl")),
                mimetype=mime or "application/octet-stream",
            )

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_gdrive_url(file_id, account_id=account_id)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            end_byte = min(file_size - 1, 8 * 1024 * 1024 - 1) if file_size > 0 else 8 * 1024 * 1024 - 1
            probe_info = probe_media_info(
                cache_key=f"gdrive:{account_id or 'default'}:{file_id}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename, raw_mime)
        range_header = request.headers.get("Range")

        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                gdrive_manager.stream_file_range(file_id, start=start, end=end, account_id=account_id),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            if file_size > 0:
                resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except Exception as e:
        print(f"GDRIVE DOWNLOAD ERROR file_id={file_id}: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/upload")
@auth.require_auth
def gdrive_upload():
    folder_id = request.args.get("folder","root")
    account_id = request.args.get("account_id", "").strip() or None
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        gdrive_manager.upload_file(
            folder_id,
            f.filename,
            f.stream,
            f.content_type or "application/octet-stream",
            relative_path=rel_path or None,
            account_id=account_id,
        )
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/gdrive/content/<file_id>")
@auth.require_auth
def gdrive_save_content(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        mime = guess_media_mime(meta.get("name", "file.txt"), meta.get("mimeType"))
        if mime == "application/octet-stream":
            mime = "text/plain; charset=utf-8"
        encoded = str(content).encode("utf-8")
        updated = gdrive_manager.update_file_content(
            file_id,
            io.BytesIO(encoded),
            mime_type=mime,
            account_id=account_id,
        )
        return jsonify({"ok": True, "size": len(encoded), "file": updated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/rename/<file_id>")
@auth.require_auth
def gdrive_rename(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    new_name = (b.get("name") or b.get("new_name") or "").strip()
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    try:
        gdrive_manager.rename_file(file_id, new_name, account_id=account_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/zip")
@auth.require_auth
def gdrive_zip():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    ids = b.get("ids") or []
    if not ids:
        return jsonify({"error": "No file IDs provided"}), 400
    try:
        tmp_path, zip_size = gdrive_manager.create_zip_tmpfile(ids, account_id=account_id)
        archive_name = b.get("name") or "GoogleDrive_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/gdrive/delete/<file_id>")
@auth.require_auth
def gdrive_delete(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        gdrive_manager.delete_file(file_id, account_id=account_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/mkdir")
@auth.require_auth
def gdrive_mkdir():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    try:
        fid = gdrive_manager.create_folder(b.get("parent","root"), b.get("name","New Folder"), account_id=account_id)
        return jsonify({"id": fid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Cross-Drive Transfer & Move (SMB <-> Google Drive & SMB <-> SMB & GDrive <-> GDrive) ──
def _copy_smb_item_to_gdrive(src_share, smb_path, is_folder, dest_folder_id, dest_account_id=None):
    norm_smb = _sanitize_smb_path(smb_path, allow_root=False)
    name = norm_smb.rstrip("/").split("/")[-1]
    if is_folder:
        new_folder_id = gdrive_manager.ensure_folder_path(dest_folder_id, [name], account_id=dest_account_id)
        for child in smb_manager.browse(src_share, norm_smb):
            _copy_smb_item_to_gdrive(
                src_share,
                child["path"],
                child["type"] == "folder",
                new_folder_id,
                dest_account_id=dest_account_id,
            )
    else:
        data = smb_manager.read_file_bytes(src_share, norm_smb)
        mime = guess_media_mime(name)
        gdrive_manager.upload_file(dest_folder_id, name, data, mime, account_id=dest_account_id)

def _copy_gdrive_item_to_smb(file_id, is_folder, dest_share, dest_smb_dir, src_account_id=None):
    meta = gdrive_manager.get_file_meta(file_id, account_id=src_account_id)
    name = meta["name"]
    norm_dest = _sanitize_smb_path(dest_smb_dir, allow_root=True)
    target_path = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + name, allow_root=False)
    if is_folder or meta["mimeType"] == "application/vnd.google-apps.folder":
        smb_manager.create_directory(dest_share, target_path)
        for child in gdrive_manager.list_files(file_id, account_id=src_account_id):
            _copy_gdrive_item_to_smb(
                child["id"],
                child["type"] == "folder",
                dest_share,
                target_path,
                src_account_id=src_account_id,
            )
    else:
        data, _, _ = gdrive_manager.download_file(file_id, account_id=src_account_id)
        smb_manager.upload_file(dest_share, target_path, data)

def _copy_smb_item_to_smb(src_share, smb_path, is_folder, dest_share, dest_smb_dir):
    norm_smb = _sanitize_smb_path(smb_path, allow_root=False)
    name = norm_smb.rstrip("/").split("/")[-1]
    norm_dest = _sanitize_smb_path(dest_smb_dir, allow_root=True)
    target_path = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + name, allow_root=False)
    if is_folder:
        smb_manager.create_directory(dest_share, target_path)
        for child in smb_manager.browse(src_share, norm_smb):
            _copy_smb_item_to_smb(
                src_share,
                child["path"],
                child["type"] == "folder",
                dest_share,
                target_path,
            )
    else:
        data = smb_manager.read_file_bytes(src_share, norm_smb)
        smb_manager.upload_file(dest_share, target_path, data)

def _copy_gdrive_item_to_gdrive(file_id, is_folder, dest_folder_id, src_account_id=None, dest_account_id=None):
    meta = gdrive_manager.get_file_meta(file_id, account_id=src_account_id)
    name = meta["name"]
    if is_folder or meta["mimeType"] == "application/vnd.google-apps.folder":
        new_folder_id = gdrive_manager.ensure_folder_path(dest_folder_id, [name], account_id=dest_account_id)
        for child in gdrive_manager.list_files(file_id, account_id=src_account_id):
            _copy_gdrive_item_to_gdrive(
                child["id"],
                child["type"] == "folder",
                new_folder_id,
                src_account_id=src_account_id,
                dest_account_id=dest_account_id,
            )
    else:
        data, _, mime = gdrive_manager.download_file(file_id, account_id=src_account_id)
        gdrive_manager.upload_file(dest_folder_id, name, data, mime, account_id=dest_account_id)

@app.post("/api/transfer")
@auth.require_auth
def transfer_items():
    b = request.get_json(force=True) or {}
    operation = (b.get("operation") or "copy").strip().lower()
    is_move = (operation == "move")
    src_type = b.get("src_type")
    src_drive = b.get("src_drive")
    dest_type = b.get("dest_type")
    dest_drive = b.get("dest_drive")
    dest_folder = b.get("dest_folder") or ("/" if dest_type == "smb" else "root")
    items = b.get("items") or []

    if not items:
        return jsonify({"error": "No items selected for transfer"}), 400

    try:
        if dest_type == "smb":
            dest_folder = _sanitize_smb_path(dest_folder, allow_root=True)
        count = 0
        for item in items:
            is_folder = item.get("type") == "folder"
            if is_move and src_type == "smb" and dest_type == "smb" and src_drive == dest_drive:
                src_path = _sanitize_smb_path(item["path"], allow_root=False)
                smb_manager.move_path(src_drive, src_path, dest_folder)
                _SMB_SIZE_CACHE.pop(f"{src_drive}:{src_path}", None)
            elif is_move and src_type == "gdrive" and dest_type == "gdrive" and src_drive == dest_drive:
                gdrive_manager.move_file(item["id"], dest_folder, account_id=src_drive)
            elif src_type == "smb" and dest_type == "gdrive":
                src_path = _sanitize_smb_path(item["path"], allow_root=False)
                _copy_smb_item_to_gdrive(src_drive, src_path, is_folder, dest_folder, dest_account_id=dest_drive)
                if is_move:
                    smb_manager.delete_path(src_drive, src_path, is_folder)
                    _SMB_SIZE_CACHE.pop(f"{src_drive}:{src_path}", None)
            elif src_type == "gdrive" and dest_type == "smb":
                _copy_gdrive_item_to_smb(item["id"], is_folder, dest_drive, dest_folder, src_account_id=src_drive)
                if is_move:
                    gdrive_manager.delete_file(item["id"], account_id=src_drive)
            elif src_type == "smb" and dest_type == "smb":
                src_path = _sanitize_smb_path(item["path"], allow_root=False)
                _copy_smb_item_to_smb(src_drive, src_path, is_folder, dest_drive, dest_folder)
                if is_move:
                    smb_manager.delete_path(src_drive, src_path, is_folder)
                    _SMB_SIZE_CACHE.pop(f"{src_drive}:{src_path}", None)
            elif src_type == "gdrive" and dest_type == "gdrive":
                _copy_gdrive_item_to_gdrive(item["id"], is_folder, dest_folder, src_account_id=src_drive, dest_account_id=dest_drive)
                if is_move:
                    gdrive_manager.delete_file(item["id"], account_id=src_drive)
            else:
                return jsonify({"error": "Invalid source or destination type"}), 400
            count += 1
        return jsonify({"ok": True, "copied": count, "moved": count if is_move else 0, "operation": "move" if is_move else "copy"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Multi-Drive SMB Proxy Manager & Credentials ───────────────────────────────
_smb_proxy_lock = threading.Lock()
_SMB_MOUNTS_BASE = Path("/mnt/gdrive_mounts")

def _safe_rclone_id(account_id):
    return re.sub(r"[^A-Za-z0-9_]", "_", str(account_id or "default"))

def _get_active_mount_points():
    mounted = set()
    try:
        if Path("/proc/mounts").exists():
            for line in Path("/proc/mounts").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    mounted.add(parts[1])
    except Exception:
        pass
    return mounted

def _unmount_path(mount_path):
    mp = str(mount_path)
    for cmd in (["fusermount", "-uz", mp], ["fusermount3", "-uz", mp], ["umount", "-l", mp]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, check=False, capture_output=True, timeout=5)
            except Exception:
                pass
    if mp not in _get_active_mount_points():
        return True
    return False

def _reconcile_smb_proxy():
    with _smb_proxy_lock:
        accounts = _gd_load_accounts_raw()
        cfg = gdrive_manager.get_config()

        # 1. Write multi-account rclone.conf
        rclone_blocks = []
        for idx, acc in enumerate(accounts):
            d = acc.get("creds") or {}
            if not (d.get("token") or d.get("refresh_token")):
                continue
            rc_id = _safe_rclone_id(acc["id"])
            rclone_token = json.dumps({
                "access_token": d.get("token", ""),
                "token_type": "Bearer",
                "refresh_token": d.get("refresh_token", ""),
                "expiry": "2020-01-01T00:00:00Z",
            })
            client_id = d.get("client_id") or cfg.get("client_id", "")
            client_secret = d.get("client_secret") or cfg.get("client_secret", "")
            block = (
                f"[gdrive_{rc_id}]\n"
                f"type = drive\n"
                f"client_id = {client_id}\n"
                f"client_secret = {client_secret}\n"
                f"scope = drive\n"
                f"token = {rclone_token}\n"
            )
            rclone_blocks.append(block)
            if idx == 0:
                rclone_blocks.append(
                    f"[gdrive]\n"
                    f"type = drive\n"
                    f"client_id = {client_id}\n"
                    f"client_secret = {client_secret}\n"
                    f"scope = drive\n"
                    f"token = {rclone_token}\n"
                )

        try:
            os.makedirs("/root/.config/rclone", exist_ok=True)
            Path("/root/.config/rclone/rclone.conf").write_text("\n".join(rclone_blocks))
        except Exception as e:
            print(f"SMB Proxy rclone.conf write warning: {e}", flush=True)

        # 2. Reconcile FUSE mounts under /mnt/gdrive_mounts/<id>
        has_rclone = bool(shutil.which("rclone"))
        try:
            _SMB_MOUNTS_BASE.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        mounted_paths = _get_active_mount_points()
        # Unmount legacy single-drive /mnt/gdrive if mounted so per-drive shares take over cleanly
        if "/mnt/gdrive" in mounted_paths:
            _unmount_path("/mnt/gdrive")
            mounted_paths = _get_active_mount_points()

        desired_mounts = {}
        for acc in accounts:
            d = acc.get("creds") or {}
            if bool(acc.get("smb_enabled", True)) and (d.get("token") or d.get("refresh_token")):
                rc_id = _safe_rclone_id(acc["id"])
                mpath = str(_SMB_MOUNTS_BASE / rc_id)
                desired_mounts[mpath] = f"gdrive_{rc_id}:"

        # Unmount any stale or disabled mounts under /mnt/gdrive_mounts/
        for mp in list(mounted_paths):
            if mp.startswith(str(_SMB_MOUNTS_BASE) + "/") and mp not in desired_mounts:
                _unmount_path(mp)

        mounted_paths = _get_active_mount_points()
        if has_rclone:
            newly_started = False
            for mpath, remote_name in desired_mounts.items():
                if mpath not in mounted_paths:
                    try:
                        os.makedirs(mpath, exist_ok=True)
                        subprocess.run(
                            [
                                "rclone", "mount", remote_name, mpath,
                                "--config", "/root/.config/rclone/rclone.conf",
                                "--allow-other",
                                "--buffer-size", "16M",
                                "--vfs-read-chunk-size", "32M",
                                "--vfs-cache-mode", "writes",
                                "--vfs-cache-max-size", "512M",
                                "--dir-cache-time", "5m",
                                "--daemon",
                            ],
                            check=False,
                            capture_output=True,
                            timeout=10,
                        )
                        newly_started = True
                    except Exception as e:
                        print(f"SMB Proxy rclone mount warning for {remote_name}: {e}", flush=True)
            if newly_started:
                for _ in range(6):
                    time.sleep(0.25)
                    mounted_paths = _get_active_mount_points()
                    if all(mp in mounted_paths for mp in desired_mounts):
                        break

        # 3. Generate /etc/samba/smb.conf with a separate share stanza per enabled Google Drive
        smb_conf_lines = [
            "[global]",
            "   workgroup = WORKGROUP",
            "   server string = SageDrive SMB Proxy",
            "   security = user",
            "   map to guest = Never",
            "   log file = /var/log/samba/%m.log",
            "   max log size = 50",
            "   oplocks = no",
            "   kernel oplocks = no",
            "   strict allocate = yes",
            "   ntlm auth = yes",
            "   server min protocol = NT1",
            "",
        ]
        for acc in accounts:
            if not bool(acc.get("smb_enabled", True)):
                continue
            share_name = _gd_sanitize_smb_share_name(acc.get("smb_share_name") or "GoogleDrive")
            rc_id = _safe_rclone_id(acc["id"])
            mpath = str(_SMB_MOUNTS_BASE / rc_id)
            try:
                os.makedirs(mpath, exist_ok=True)
            except Exception:
                pass
            smb_conf_lines.extend([
                f"[{share_name}]",
                f"   path = {mpath}",
                f"   comment = SageDrive - {acc.get('custom_name') or acc.get('name') or share_name}",
                "   valid users = @sambausers",
                "   writable = yes",
                "   browseable = yes",
                "   create mask = 0775",
                "   directory mask = 0775",
                "",
            ])

        smb_conf_text = "\n".join(smb_conf_lines)
        for conf_target in (Path("/etc/samba/smb.conf"), Path("/app/smb.conf")):
            try:
                if conf_target.parent.exists():
                    conf_target.write_text(smb_conf_text)
            except Exception:
                pass

        # 4. Reload or start smbd
        if shutil.which("smbcontrol"):
            try:
                subprocess.run(["smbcontrol", "all", "reload-config"], check=False, capture_output=True, timeout=4)
            except Exception:
                pass
        if shutil.which("pkill"):
            try:
                subprocess.run(["pkill", "-HUP", "smbd"], check=False, capture_output=True, timeout=4)
            except Exception:
                pass

        return _get_smb_proxy_status_unlocked()

def _get_smb_proxy_status_unlocked():
    creds_file = Path(os.environ.get("DATA_DIR", "/app/data")) / "smb_proxy_credentials.json"
    username = "sagedrive"
    configured = False
    if creds_file.exists():
        try:
            d = json.loads(creds_file.read_text())
            username = d.get("username", "sagedrive")
            configured = True
        except Exception:
            pass
    accounts = _gd_load_accounts_raw()
    mounted_paths = _get_active_mount_points()
    has_rclone = bool(shutil.which("rclone"))
    shares = []
    for acc in accounts:
        rc_id = _safe_rclone_id(acc["id"])
        mpath = str(_SMB_MOUNTS_BASE / rc_id)
        enabled = bool(acc.get("smb_enabled", True))
        is_mounted = (mpath in mounted_paths) if has_rclone else enabled
        shares.append({
            "account_id": acc["id"],
            "account_name": acc.get("custom_name") or acc.get("name") or "Google Drive",
            "email": acc.get("email", ""),
            "smb_enabled": enabled,
            "smb_share_name": acc.get("smb_share_name") or "GoogleDrive",
            "mount_path": mpath,
            "mounted": is_mounted,
        })
    return {
        "username": username,
        "configured": configured,
        "shares": shares,
    }

@app.get("/api/smb/proxy-credentials")
@auth.require_auth
def get_smb_proxy_creds():
    with _smb_proxy_lock:
        return jsonify(_get_smb_proxy_status_unlocked())

@app.get("/api/smb/proxy-shares")
@auth.require_auth
def get_smb_proxy_shares():
    with _smb_proxy_lock:
        return jsonify(_get_smb_proxy_status_unlocked())

@app.post("/api/smb/proxy-shares/<account_id>")
@auth.require_auth
def update_smb_proxy_share(account_id):
    b = request.get_json(force=True) or {}
    smb_enabled = b.get("smb_enabled") if "smb_enabled" in b else None
    smb_share_name = b.get("smb_share_name") if "smb_share_name" in b else None
    try:
        updated = gdrive_manager.update_account_smb_proxy(
            account_id,
            smb_enabled=smb_enabled,
            smb_share_name=smb_share_name,
        )
        status = _reconcile_smb_proxy()
        return jsonify({
            "ok": True,
            "share": updated,
            "shares": status.get("shares", []),
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/proxy-reconcile")
@auth.require_auth
def reconcile_smb_proxy_route():
    try:
        status = _reconcile_smb_proxy()
        return jsonify({"ok": True, **status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/proxy-credentials")
@auth.require_auth
def set_smb_proxy_creds():
    body = request.get_json(force=True) or {}
    username = (body.get("username") or "sagedrive").strip()
    password = (body.get("password") or "").strip()

    if not password:
        return jsonify({"error": "Password is required"}), 400

    creds_file = Path(os.environ.get("DATA_DIR", "/app/data")) / "smb_proxy_credentials.json"
    creds_file.write_text(json.dumps({"username": username, "password": password}, indent=2))

    try:
        subprocess.run(["groupadd", "-f", "sambausers"], check=False)
        subprocess.run(["useradd", "-M", "-s", "/sbin/nologin", "-G", "sambausers", username],
                       check=False, capture_output=True)
        subprocess.run(["usermod", "-aG", "sambausers", username], check=False, capture_output=True)
        proc = subprocess.run(
            ["smbpasswd", "-s", "-a", username],
            input=f"{password}\n{password}\n",
            text=True, capture_output=True
        )
        _reconcile_smb_proxy()
        return jsonify({"ok": True, "message": f"Credentials saved. Reconnect as '{username}'."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Trigger initial multi-drive SMB proxy reconciliation in background on startup
threading.Thread(target=lambda: _reconcile_smb_proxy(), daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
