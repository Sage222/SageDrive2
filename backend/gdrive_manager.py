import json, os, io, time, threading, tempfile, zipfile, secrets, requests
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
_PENDING_OAUTH = {}

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

def _load_accounts_raw():
    if ACCOUNTS_FILE.exists():
        try:
            data = json.loads(ACCOUNTS_FILE.read_text())
            if isinstance(data, list):
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
                    "email": legacy.get("email", ""),
                    "creds": legacy,
                }]
                ACCOUNTS_FILE.write_text(json.dumps(migrated, indent=2))
                return migrated
        except Exception:
            pass
    return []

def _save_accounts_raw(accounts):
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
            accounts.append({
                "id": new_id,
                "name": disp_name,
                "custom_name": (custom_name or "").strip(),
                "original_name": default_label,
                "email": email or "",
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
    res = _svc(account_id=account_id).files().list(
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
    return out

def get_file_meta(file_id, account_id=None):
    now = time.time()
    ck = _cache_key(account_id, file_id)
    cached = _meta_cache.get(ck) or _meta_cache.get(file_id)
    if cached and (now - cached[0]) < _META_TTL:
        return cached[1]
    svc = _svc(account_id=account_id)
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
    r = _open_media_response(file_id, start=start, end=end, account_id=account_id)
    def _gen():
        try:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
        finally:
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

def upload_file(parent_id, filename, data, mime_type="application/octet-stream", relative_path=None, account_id=None):
    svc = _svc(account_id=account_id)
    target_parent = parent_id or "root"
    actual_name = filename
    if relative_path:
        norm_rel = relative_path.replace("\\", "/").lstrip("/")
        segments = [s for s in norm_rel.split("/") if s]
        if len(segments) > 1:
            target_parent = ensure_folder_path(target_parent, segments[:-1], account_id=account_id)
            actual_name = segments[-1]
        elif segments:
            actual_name = segments[0]
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype=mime_type, resumable=True)
    svc.files().create(
        body={"name": actual_name, "parents": [target_parent]},
        media_body=media,
        fields="id",
        supportsAllDrives=True,
    ).execute()

def rename_file(file_id, new_name, account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    return _svc(account_id=account_id).files().update(
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
    files and folders (recursively). Returns (tmp_path, zip_size).
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    def _add_item(zf, fid, arc_prefix):
        meta = get_file_meta(fid, account_id=account_id)
        name = meta["name"]
        mime = meta["mimeType"]
        arc_path = f"{arc_prefix}/{name}" if arc_prefix else name
        if mime == "application/vnd.google-apps.folder":
            children = list_files(fid, account_id=account_id)
            if not children:
                zf.writestr(arc_path.rstrip("/") + "/", b"")
            for ch in children:
                _add_item(zf, ch["id"], arc_path)
        else:
            data, _, _ = download_file(fid, account_id=account_id)
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

