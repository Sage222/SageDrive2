import json, os, io, time, threading, tempfile, zipfile, secrets, re, requests
from datetime import datetime, timezone
from pathlib import Path
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
CREDS_FILE = DATA_DIR / "gdrive_token.json"
ACCOUNTS_FILE = DATA_DIR / "gdrive_accounts.json"
CONFIG_FILE = DATA_DIR / "gdrive_client.json"
SCOPES = ["https://www.googleapis.com/auth/drive"]

_creds_lock = threading.Lock()
_meta_cache = {}
_META_TTL = 120.0
_META_MAX_ENTRIES = 4000
_PENDING_OAUTH = {}
_OAUTH_TTL = 1800.0

_RESERVED_SMB_NAMES = {"global", "homes", "printers", "print$", "ipc$"}


def _prune_caches(now=None):
    now = now or time.time()
    expired_meta = [k for k, v in list(_meta_cache.items()) if (now - v[0]) >= _META_TTL]
    for k in expired_meta:
        _meta_cache.pop(k, None)
    if len(_meta_cache) > _META_MAX_ENTRIES:
        sorted_keys = sorted(_meta_cache.keys(), key=lambda k: _meta_cache[k][0])
        for k in sorted_keys[: len(_meta_cache) - _META_MAX_ENTRIES]:
            _meta_cache.pop(k, None)
    expired_oauth = [k for k, v in list(_PENDING_OAUTH.items()) if (now - v.get("ts", 0)) >= _OAUTH_TTL]
    for k in expired_oauth:
        _PENDING_OAUTH.pop(k, None)


def generate_unique_name(desired_name, existing_names):
    lower_set = {str(n).lower() for n in existing_names if n}
    if desired_name.lower() not in lower_set:
        return desired_name
    if "." in desired_name and not desired_name.startswith("."):
        base, ext = desired_name.rsplit(".", 1)
        ext = "." + ext
    else:
        base, ext = desired_name, ""
    idx = 1
    while True:
        cand = f"{base} ({idx}){ext}"
        if cand.lower() not in lower_set:
            return cand
        idx += 1


def _env_defaults():
    return {
        "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        "redirect_uri": os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8080/api/gdrive/callback"),
    }


def get_config():
    cfg = _env_defaults()
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text())
            cfg["client_id"] = stored.get("client_id", cfg["client_id"])
            cfg["client_secret"] = stored.get("client_secret", cfg["client_secret"])
            cfg["redirect_uri"] = stored.get("redirect_uri", cfg["redirect_uri"])
        except Exception:
            pass
    return cfg


def save_config(client_id, client_secret, redirect_uri):
    cfg = {
        "client_id": (client_id or "").strip(),
        "client_secret": (client_secret or "").strip(),
        "redirect_uri": (redirect_uri or "").strip() or "http://localhost:8080/api/gdrive/callback",
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg


def is_configured():
    cfg = get_config()
    return bool(cfg["client_id"] and cfg["client_secret"] and cfg["redirect_uri"])


def _parse_expiry(raw_expiry):
    if not raw_expiry:
        return None
    try:
        dt = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None


def _creds_to_dict(c):
    expiry_str = None
    if getattr(c, "expiry", None) is not None:
        expiry_str = c.expiry.isoformat()
    return {
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": list(c.scopes or SCOPES),
        "expiry": expiry_str,
    }


def sanitize_smb_share_name(raw_name, fallback="GoogleDrive"):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", (raw_name or "").strip()).strip("_-")
    if not cleaned or cleaned.lower() in _RESERVED_SMB_NAMES:
        cleaned = fallback
    return cleaned[:32]


def _ensure_smb_fields(accounts):
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
            candidate = sanitize_smb_share_name(default_base, fallback=f"GoogleDrive_{idx + 1}")
            base_cand = candidate
            suffix = 2
            while candidate.lower() in used:
                candidate = f"{base_cand[:28]}_{suffix}"
                suffix += 1
            a["smb_share_name"] = candidate
            changed = True
        else:
            sanitized = sanitize_smb_share_name(raw_share, fallback=f"GoogleDrive_{idx + 1}")
            if sanitized.lower() in used:
                sanitized = f"{sanitized[:28]}_{idx + 1}"
            if sanitized != raw_share:
                a["smb_share_name"] = sanitized
                changed = True
        used.add(a["smb_share_name"].lower())
    return changed


def _load_accounts_raw():
    if ACCOUNTS_FILE.exists():
        try:
            data = json.loads(ACCOUNTS_FILE.read_text())
            if isinstance(data, list):
                if _ensure_smb_fields(data):
                    ACCOUNTS_FILE.write_text(json.dumps(data, indent=2))
                return data
        except Exception:
            pass
    if CREDS_FILE.exists():
        try:
            legacy = json.loads(CREDS_FILE.read_text())
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
                DATA_DIR.mkdir(parents=True, exist_ok=True)
                ACCOUNTS_FILE.write_text(json.dumps(migrated, indent=2))
                return migrated
        except Exception:
            pass
    return []


def _save_accounts_raw(accounts):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_smb_fields(accounts)
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2))
    if accounts and accounts[0].get("creds"):
        CREDS_FILE.write_text(json.dumps(accounts[0]["creds"], indent=2))
    elif not accounts and CREDS_FILE.exists():
        CREDS_FILE.unlink(missing_ok=True)


def list_accounts():
    accounts = _load_accounts_raw()
    return [{
        "id": a["id"],
        "name": a.get("custom_name") or a.get("name") or "Google Drive",
        "custom_name": a.get("custom_name", ""),
        "original_name": a.get("original_name") or a.get("name") or "Google Drive",
        "email": a.get("email", ""),
        "smb_enabled": bool(a.get("smb_enabled", True)),
        "smb_share_name": a.get("smb_share_name") or "GoogleDrive",
    } for a in accounts]


def _resolve_account_entry(account_id=None):
    accounts = _load_accounts_raw()
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


def is_authenticated(account_id=None):
    accounts = _load_accounts_raw()
    if not accounts:
        return False
    try:
        c = _load_creds(account_id=account_id)
        return c is not None and (c.valid or bool(c.refresh_token) or bool(c.token))
    except Exception:
        return False


def _client_config():
    cfg = get_config()
    return {"web": {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uris": [cfg["redirect_uri"]],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }}


def _load_creds(force_refresh=False, account_id=None):
    with _creds_lock:
        acc, accounts = _resolve_account_entry(account_id)
        if not acc:
            return None
        d = acc.get("creds") or {}
        cfg = get_config()
        expiry_dt = _parse_expiry(d.get("expiry"))
        c = Credentials(
            token=d.get("token"),
            refresh_token=d.get("refresh_token"),
            token_uri=d.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=d.get("client_id", cfg["client_id"]),
            client_secret=d.get("client_secret", cfg["client_secret"]),
            scopes=d.get("scopes", SCOPES),
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
            acc["creds"] = _creds_to_dict(c)
            _save_accounts_raw(accounts)
        return c if (c.token or c.valid) else None


def _save_creds(c, account_id=None, custom_name=None, email=None):
    with _creds_lock:
        accounts = _load_accounts_raw()
        c_dict = _creds_to_dict(c)
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
            base_smb = "GoogleDrive" if not accounts else sanitize_smb_share_name(disp_name, fallback=f"GoogleDrive_{len(accounts) + 1}")
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
        _save_accounts_raw(accounts)


def rename_account(account_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("Custom name cannot be empty")
    with _creds_lock:
        accounts = _load_accounts_raw()
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
        _save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target["name"],
            "custom_name": target.get("custom_name", ""),
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "GoogleDrive",
        }


def update_account_smb_proxy(account_id, smb_enabled=None, smb_share_name=None):
    with _creds_lock:
        accounts = _load_accounts_raw()
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
        _save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target.get("custom_name") or target.get("name") or "Google Drive",
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "GoogleDrive",
        }


def remove_account(account_id=None):
    _meta_cache.clear()
    with _creds_lock:
        accounts = _load_accounts_raw()
        if not account_id:
            _save_accounts_raw([])
            return
        accounts = [a for a in accounts if a["id"] != account_id]
        _save_accounts_raw(accounts)


def _svc(account_id=None):
    c = _load_creds(account_id=account_id)
    if not c:
        raise RuntimeError("Not authenticated with Google Drive")
    return build("drive", "v3", credentials=c, cache_discovery=False)


def get_auth_url(custom_name=None, account_id=None):
    _prune_caches()
    cfg = get_config()
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=cfg["redirect_uri"])
    url, state = flow.authorization_url(access_type="offline", prompt="select_account consent")
    if state:
        _PENDING_OAUTH[state] = {
            "custom_name": (custom_name or "").strip(),
            "account_id": (account_id or "").strip(),
            "ts": time.time(),
        }
    return url


def handle_callback(code, state):
    _prune_caches()
    cfg = get_config()
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=cfg["redirect_uri"])
    flow.fetch_token(code=code)
    c = flow.credentials
    pending = _PENDING_OAUTH.pop(state, {}) if state else {}
    email = ""
    try:
        svc = build("drive", "v3", credentials=c, cache_discovery=False)
        about = svc.about().get(fields="user(displayName,emailAddress)").execute()
        email = (about.get("user") or {}).get("emailAddress", "")
    except Exception:
        pass
    _save_creds(
        c,
        account_id=pending.get("account_id") or None,
        custom_name=pending.get("custom_name") or None,
        email=email,
    )


def revoke(account_id=None):
    remove_account(account_id=account_id)


def _cache_key(account_id, file_id):
    return f"{account_id or 'default'}:{file_id}"


def list_files(folder_id="root", account_id=None):
    _prune_caches()
    svc = _svc(account_id=account_id)
    out = []
    now = time.time()
    page_token = None
    pages = 0
    while pages < 50:
        pages += 1
        res = svc.files().list(
            q=f"'{folder_id}' in parents and trashed=false",
            fields="nextPageToken,files(id,name,mimeType,size,modifiedTime,parents)",
            pageSize=500,
            pageToken=page_token,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
        ).execute()
        for f in res.get("files", []):
            is_folder = f["mimeType"] == "application/vnd.google-apps.folder"
            size_val = int(f.get("size", 0) or 0)
            info = {
                "name": f["name"],
                "mimeType": f["mimeType"],
                "size": size_val,
            }
            _meta_cache[_cache_key(account_id, f["id"])] = (now, info)
            _meta_cache[f["id"]] = (now, info)
            out.append({
                "id": f["id"],
                "name": f["name"],
                "type": "folder" if is_folder else "file",
                "size": size_val,
                "modified": f.get("modifiedTime", ""),
                "mimeType": f["mimeType"],
            })
        page_token = res.get("nextPageToken")
        if not page_token:
            break
    return out


def get_file_meta(file_id, account_id=None):
    now = time.time()
    _prune_caches(now)
    ck = _cache_key(account_id, file_id)
    cached = _meta_cache.get(ck) or _meta_cache.get(file_id)
    if cached and (now - cached[0]) < _META_TTL:
        return cached[1]
    svc = _svc(account_id=account_id)
    meta = svc.files().get(
        fileId=file_id,
        fields="name,mimeType,size,parents",
        supportsAllDrives=True,
    ).execute()
    info = {
        "name": meta.get("name", "download"),
        "mimeType": meta.get("mimeType", "application/octet-stream"),
        "size": int(meta.get("size", 0) or 0),
        "parents": meta.get("parents") or [],
    }
    _meta_cache[ck] = (now, info)
    _meta_cache[file_id] = (now, info)
    return info


def _open_media_response(file_id, start=None, end=None, account_id=None):
    url = (
        f"https://www.googleapis.com/drive/v3/files/{file_id}"
        f"?alt=media&supportsAllDrives=true&acknowledgeAbuse=true"
    )
    for attempt in range(2):
        c = _load_creds(force_refresh=(attempt > 0), account_id=account_id)
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


def stream_file_range(file_id, start=0, end=None, chunk_size=262144, account_id=None):
    def _gen():
        curr_start = int(start or 0)
        retries = 0
        while True:
            if end is not None and curr_start > end:
                break
            r = None
            prev_start = curr_start
            try:
                r = _open_media_response(file_id, start=curr_start, end=end, account_id=account_id)
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


def download_file(file_id, account_id=None):
    svc = _svc(account_id=account_id)
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


def ensure_folder_path(base_folder_id, parts, account_id=None):
    """
    Ensures nested folder segments exist under base_folder_id on Google Drive,
    returning the leaf folder ID.
    """
    svc = _svc(account_id=account_id)
    curr_id = base_folder_id or "root"
    for part in parts:
        if not part:
            continue
        safe_part = part.replace("\\", "\\\\").replace("'", "\\'")
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


def find_existing_folder_path(base_folder_id, parts, account_id=None):
    """
    Walks existing folder segments under base_folder_id without creating new folders.
    Returns the folder ID if all segments exist, or None if any segment is missing.
    """
    svc = _svc(account_id=account_id)
    curr_id = base_folder_id or "root"
    for part in parts:
        if not part:
            continue
        safe_part = part.replace("\\", "\\\\").replace("'", "\\'")
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
        if not files:
            return None
        curr_id = files[0]["id"]
    return curr_id


def find_items_by_name(parent_id, name, account_id=None):
    svc = _svc(account_id=account_id)
    target_parent = parent_id or "root"
    safe_name = name.replace("\\", "\\\\").replace("'", "\\'")
    q = f"'{target_parent}' in parents and name = '{safe_name}' and trashed = false"
    res = svc.files().list(
        q=q,
        fields="files(id,name,mimeType,size)",
        pageSize=50,
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
    ).execute()
    return res.get("files", [])


def resolve_upload_target(parent_id, filename, relative_path=None, account_id=None):
    target_parent = parent_id or "root"
    actual_name = filename
    if relative_path:
        norm_rel = relative_path.replace("\x00", "").replace("\\", "/").lstrip("/")
        segments = [s for s in norm_rel.split("/") if s and s != "."]
        if any(s == ".." for s in segments):
            raise ValueError("Invalid relative_path: path traversal ('..') is not allowed")
        if len(segments) > 1:
            target_parent = ensure_folder_path(target_parent, segments[:-1], account_id=account_id)
            actual_name = segments[-1]
        elif segments:
            actual_name = segments[0]
    return target_parent, actual_name


def _prepare_conflict_target(target_parent, actual_name, conflict_action="replace", account_id=None):
    action = (conflict_action or "replace").strip().lower()
    if action == "keep_both":
        existing = list_files(target_parent, account_id=account_id)
        actual_name = generate_unique_name(actual_name, [e["name"] for e in existing])
        return actual_name, []
    if action == "replace":
        matches = find_items_by_name(target_parent, actual_name, account_id=account_id)
        file_matches = [m["id"] for m in matches if m.get("mimeType") != "application/vnd.google-apps.folder"]
        return actual_name, file_matches
    return actual_name, []


def start_resumable_upload(
    parent_id,
    filename,
    mime_type="application/octet-stream",
    total_size=None,
    relative_path=None,
    account_id=None,
    conflict_action="replace",
):
    target_parent, actual_name = resolve_upload_target(
        parent_id, filename, relative_path=relative_path, account_id=account_id
    )
    actual_name, existing_ids = _prepare_conflict_target(
        target_parent, actual_name, conflict_action=conflict_action, account_id=account_id
    )
    # If replacing an existing file on Google Drive, use PATCH on the first existing file ID
    # and clean up any extra duplicate IDs so file replacement is atomic.
    primary_update_id = existing_ids[0] if existing_ids else None
    for extra_id in existing_ids[1:]:
        try:
            delete_file(extra_id, account_id=account_id)
        except Exception:
            pass

    if primary_update_id:
        _meta_cache.pop(_cache_key(account_id, primary_update_id), None)
        _meta_cache.pop(primary_update_id, None)
        url = f"https://www.googleapis.com/upload/drive/v3/files/{primary_update_id}?uploadType=resumable&supportsAllDrives=true"
        method = "PATCH"
        body = {"name": actual_name}
    else:
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true"
        method = "POST"
        body = {"name": actual_name, "parents": [target_parent]}

    for attempt in range(2):
        c = _load_creds(force_refresh=(attempt > 0), account_id=account_id)
        if not c:
            raise RuntimeError("Not authenticated with Google Drive")
        headers = {
            "Authorization": f"Bearer {c.token}",
            "Content-Type": "application/json; charset=UTF-8",
            "X-Upload-Content-Type": mime_type or "application/octet-stream",
        }
        if total_size is not None and int(total_size) >= 0:
            headers["X-Upload-Content-Length"] = str(int(total_size))
        r = requests.request(
            method,
            url,
            headers=headers,
            json=body,
            timeout=30,
        )
        if r.status_code in (401, 403) and attempt == 0:
            continue
        if not r.ok:
            raise RuntimeError(f"Google Drive resumable init failed ({r.status_code}): {r.text[:300]}")
        loc = r.headers.get("Location")
        if not loc:
            raise RuntimeError("Google Drive did not return a resumable upload Location header")
        return loc
    raise RuntimeError("Google Drive authentication failed after token refresh")


def push_resumable_chunk(resumable_uri, chunk_bytes, offset, total_size=None):
    chunk_len = len(chunk_bytes)
    if chunk_len == 0:
        return int(offset or 0)
    end_byte = int(offset) + chunk_len - 1
    total_str = str(int(total_size)) if (total_size is not None and int(total_size) > 0) else "*"
    headers = {
        "Content-Length": str(chunk_len),
        "Content-Range": f"bytes {int(offset)}-{end_byte}/{total_str}",
    }
    r = requests.put(resumable_uri, data=chunk_bytes, headers=headers, timeout=300)
    if r.status_code not in (200, 201, 308):
        raise RuntimeError(f"Google Drive chunk upload failed ({r.status_code}): {r.text[:300]}")
    return int(offset) + chunk_len


def query_resumable_offset(resumable_uri, total_size=None):
    total_str = str(int(total_size)) if (total_size is not None and int(total_size) > 0) else "*"
    headers = {
        "Content-Length": "0",
        "Content-Range": f"bytes */{total_str}",
    }
    r = requests.put(resumable_uri, headers=headers, timeout=20)
    if r.status_code in (200, 201):
        return int(total_size or 0)
    if r.status_code == 308:
        rng = r.headers.get("Range") or ""
        if "-" in rng:
            try:
                return int(rng.split("-")[-1].strip()) + 1
            except Exception:
                pass
        return 0
    raise RuntimeError(f"Google Drive session check failed ({r.status_code})")


def cancel_resumable_upload(resumable_uri):
    if not resumable_uri:
        return
    try:
        requests.delete(resumable_uri, timeout=15)
    except Exception:
        pass


def upload_file(
    parent_id,
    filename,
    data_or_stream,
    mime_type="application/octet-stream",
    relative_path=None,
    account_id=None,
    total_size=None,
    conflict_action="replace",
):
    if (conflict_action or "").strip().lower() == "skip":
        target_parent, actual_name = resolve_upload_target(
            parent_id, filename, relative_path=relative_path, account_id=account_id
        )
        if find_items_by_name(target_parent, actual_name, account_id=account_id):
            return

    if isinstance(data_or_stream, (bytes, bytearray)):
        raw_bytes = bytes(data_or_stream)
        total_size = len(raw_bytes)
        stream_obj = io.BytesIO(raw_bytes)
    elif hasattr(data_or_stream, "read"):
        stream_obj = data_or_stream
    else:
        raw_bytes = str(data_or_stream).encode("utf-8")
        total_size = len(raw_bytes)
        stream_obj = io.BytesIO(raw_bytes)

    resumable_uri = start_resumable_upload(
        parent_id,
        filename,
        mime_type=mime_type,
        total_size=total_size,
        relative_path=relative_path,
        account_id=account_id,
        conflict_action=conflict_action,
    )
    if total_size is not None and int(total_size) == 0:
        r = requests.put(
            resumable_uri,
            data=b"",
            headers={"Content-Length": "0", "Content-Range": "bytes */0"},
            timeout=60,
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"Google Drive empty file upload failed ({r.status_code}): {r.text[:300]}")
        return

    chunk_unit = 5 * 1024 * 1024  # 5 MiB (multiple of 256 KiB required by Google Drive)
    offset = 0
    while True:
        buf = bytearray()
        while len(buf) < chunk_unit:
            part = stream_obj.read(chunk_unit - len(buf))
            if not part:
                break
            buf.extend(part)
        if not buf:
            if offset == 0:
                requests.put(
                    resumable_uri,
                    data=b"",
                    headers={"Content-Length": "0", "Content-Range": "bytes */0"},
                    timeout=60,
                )
            break
        is_last = len(buf) < chunk_unit
        final_total = (offset + len(buf)) if (is_last and total_size is None) else total_size
        offset = push_resumable_chunk(resumable_uri, bytes(buf), offset, total_size=final_total)
        if is_last:
            break


def update_file_content(file_id, data_or_stream, mime_type="text/plain; charset=utf-8", account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    svc = _svc(account_id=account_id)
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


def move_file(file_id, dest_folder_id, account_id=None, conflict_action="replace"):
    dest_id = dest_folder_id or "root"
    if file_id == dest_id:
        raise ValueError("Cannot move a folder into itself")
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    svc = _svc(account_id=account_id)
    meta = svc.files().get(
        fileId=file_id,
        fields="id,name,parents",
        supportsAllDrives=True,
    ).execute()
    item_name = meta.get("name") or "item"
    action = (conflict_action or "replace").strip().lower()
    existing = [m for m in find_items_by_name(dest_id, item_name, account_id=account_id) if m["id"] != file_id]
    body_patch = {}
    if existing:
        if action == "skip":
            return {"id": file_id, "name": item_name, "skipped": True}
        elif action == "keep_both":
            all_dest = list_files(dest_id, account_id=account_id)
            body_patch["name"] = generate_unique_name(item_name, [e["name"] for e in all_dest if e["id"] != file_id])
        elif action == "replace":
            for m in existing:
                try:
                    delete_file(m["id"], account_id=account_id)
                except Exception:
                    pass
    prev_parents = ",".join(meta.get("parents") or [])
    return svc.files().update(
        fileId=file_id,
        addParents=dest_id,
        removeParents=prev_parents,
        body=body_patch if body_patch else None,
        fields="id,name,parents",
        supportsAllDrives=True,
    ).execute()


def rename_file(file_id, new_name, account_id=None, conflict_action="replace"):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("New name is required")
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    svc = _svc(account_id=account_id)
    action = (conflict_action or "replace").strip().lower()
    meta = svc.files().get(fileId=file_id, fields="id,name,parents", supportsAllDrives=True).execute()
    parents = meta.get("parents") or ["root"]
    parent_id = parents[0] if parents else "root"
    existing = [m for m in find_items_by_name(parent_id, new_name, account_id=account_id) if m["id"] != file_id]
    if existing:
        if action == "skip":
            return {"id": file_id, "name": meta.get("name"), "skipped": True}
        elif action == "keep_both":
            all_siblings = list_files(parent_id, account_id=account_id)
            new_name = generate_unique_name(new_name, [e["name"] for e in all_siblings if e["id"] != file_id])
        elif action == "replace":
            for m in existing:
                try:
                    delete_file(m["id"], account_id=account_id)
                except Exception:
                    pass
    return svc.files().update(
        fileId=file_id,
        body={"name": new_name},
        fields="id,name",
        supportsAllDrives=True,
    ).execute()


def delete_file(file_id, account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    _svc(account_id=account_id).files().delete(fileId=file_id, supportsAllDrives=True).execute()


def create_folder(parent_id, name, account_id=None):
    f = _svc(account_id=account_id).files().create(
        body={
            "name": name,
            "parents": [parent_id],
            "mimeType": "application/vnd.google-apps.folder",
        },
        fields="id",
        supportsAllDrives=True,
    ).execute()
    return f["id"]


def create_zip_tmpfile(file_ids, account_id=None):
    """
    Creates a temporary .zip archive containing the specified Google Drive
    files and folders (recursively) by streaming 256 KiB chunks directly into
    the ZIP compressor without loading whole files into RAM.
    Returns (tmp_path, zip_size).
    """
    tmp = tempfile.NamedTemporaryFile(prefix="sagedrive_gd_zip_", delete=False, suffix=".zip")
    tmp.close()

    def _add_item(zf, fid, arc_prefix):
        meta = get_file_meta(fid, account_id=account_id)
        name = meta["name"]
        mime = meta["mimeType"]
        arc_path = f"{arc_prefix}/{name}".lstrip("/") if arc_prefix else name
        if mime == "application/vnd.google-apps.folder":
            children = list_files(fid, account_id=account_id)
            if not children:
                zinfo = zipfile.ZipInfo(arc_path.rstrip("/") + "/")
                zf.writestr(zinfo, b"")
            for ch in children:
                _add_item(zf, ch["id"], arc_path)
        elif mime.startswith("application/vnd.google-apps."):
            data, _, _ = download_file(fid, account_id=account_id)
            zinfo = zipfile.ZipInfo(arc_path)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            with zf.open(zinfo, mode="w", force_zip64=True) as dest:
                dest.write(data)
        else:
            zinfo = zipfile.ZipInfo(arc_path)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            with zf.open(zinfo, mode="w", force_zip64=True) as dest:
                for chunk in stream_file_range(fid, start=0, end=None, account_id=account_id):
                    if chunk:
                        dest.write(chunk)

    try:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for fid in file_ids:
                if fid:
                    _add_item(zf, fid, "")
        size = os.path.getsize(tmp.name)
        return tmp.name, size
    except Exception:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        raise
