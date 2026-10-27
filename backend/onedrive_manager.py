import json, os, io, time, threading, tempfile, zipfile, secrets, re, requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlencode

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
ACCOUNTS_FILE = DATA_DIR / "onedrive_accounts.json"
CONFIG_FILE = DATA_DIR / "onedrive_client.json"
SCOPES = ["Files.ReadWrite.All", "offline_access", "User.Read"]

_creds_lock = threading.Lock()
_meta_cache = {}
_META_TTL = 120.0
_PENDING_OAUTH = {}

_RESERVED_SMB_NAMES = {"global", "homes", "printers", "print$", "ipc$"}


def _env_defaults():
    return {
        "client_id": os.environ.get("ONEDRIVE_CLIENT_ID", ""),
        "client_secret": os.environ.get("ONEDRIVE_CLIENT_SECRET", ""),
        "redirect_uri": os.environ.get("ONEDRIVE_REDIRECT_URI", "http://localhost:8080/api/onedrive/callback"),
        "tenant_id": os.environ.get("ONEDRIVE_TENANT_ID", "common") or "common",
    }


def get_config():
    cfg = _env_defaults()
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text())
            cfg["client_id"] = stored.get("client_id", cfg["client_id"])
            cfg["client_secret"] = stored.get("client_secret", cfg["client_secret"])
            cfg["redirect_uri"] = stored.get("redirect_uri", cfg["redirect_uri"])
            cfg["tenant_id"] = (stored.get("tenant_id") or cfg["tenant_id"] or "common").strip()
        except Exception:
            pass
    return cfg


def save_config(client_id, client_secret, redirect_uri, tenant_id="common"):
    cfg = {
        "client_id": (client_id or "").strip(),
        "client_secret": (client_secret or "").strip(),
        "redirect_uri": (redirect_uri or "").strip() or "http://localhost:8080/api/onedrive/callback",
        "tenant_id": (tenant_id or "common").strip() or "common",
    }
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    return cfg


def is_configured():
    cfg = get_config()
    return bool(cfg["client_id"] and cfg["redirect_uri"])


def sanitize_smb_share_name(raw_name, fallback="OneDrive"):
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
            default_base = "OneDrive" if idx == 0 else (
                a.get("custom_name") or a.get("name") or f"OneDrive_{idx + 1}"
            )
            candidate = sanitize_smb_share_name(default_base, fallback=f"OneDrive_{idx + 1}")
            base_cand = candidate
            suffix = 2
            while candidate.lower() in used:
                candidate = f"{base_cand[:28]}_{suffix}"
                suffix += 1
            a["smb_share_name"] = candidate
            changed = True
        else:
            sanitized = sanitize_smb_share_name(raw_share, fallback=f"OneDrive_{idx + 1}")
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
    return []


def _save_accounts_raw(accounts):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_smb_fields(accounts)
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2))


def list_accounts():
    accounts = _load_accounts_raw()
    return [{
        "id": a["id"],
        "name": a.get("custom_name") or a.get("name") or "OneDrive",
        "custom_name": a.get("custom_name", ""),
        "original_name": a.get("original_name") or a.get("name") or "OneDrive",
        "email": a.get("email", ""),
        "drive_id": a.get("drive_id", ""),
        "drive_type": a.get("drive_type", "personal"),
        "smb_enabled": bool(a.get("smb_enabled", True)),
        "smb_share_name": a.get("smb_share_name") or "OneDrive",
    } for a in accounts]


def _resolve_account_entry(account_id=None):
    accounts = _load_accounts_raw()
    if not accounts:
        return None, accounts
    if not account_id or account_id in ("root", "default"):
        return accounts[0], accounts
    for a in accounts:
        if a["id"] == account_id:
            return a, accounts
    return accounts[0], accounts


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


def _refresh_token_request(refresh_token, cfg, creds_dict):
    tenant = (creds_dict.get("tenant_id") or cfg.get("tenant_id") or "common").strip()
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    payload = {
        "client_id": creds_dict.get("client_id") or cfg["client_id"],
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": " ".join(SCOPES),
    }
    secret = creds_dict.get("client_secret") or cfg.get("client_secret") or ""
    if secret:
        payload["client_secret"] = secret
    r = requests.post(token_url, data=payload, timeout=20)
    if not r.ok:
        raise RuntimeError(f"OneDrive token refresh failed ({r.status_code}): {r.text[:300]}")
    tok = r.json()
    expires_in = int(tok.get("expires_in", 3600) or 3600)
    expiry_dt = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=expires_in)
    return {
        "token": tok["access_token"],
        "refresh_token": tok.get("refresh_token") or refresh_token,
        "client_id": payload["client_id"],
        "client_secret": secret,
        "tenant_id": tenant,
        "expiry": expiry_dt.isoformat() + "Z",
    }


def _load_creds(force_refresh=False, account_id=None):
    with _creds_lock:
        acc, accounts = _resolve_account_entry(account_id)
        if not acc:
            return None
        d = acc.get("creds") or {}
        cfg = get_config()
        expiry_dt = _parse_expiry(d.get("expiry"))
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        needs_refresh = (
            force_refresh
            or not d.get("token")
            or expiry_dt is None
            or (expiry_dt - now_utc).total_seconds() < 300
        )
        if needs_refresh and d.get("refresh_token"):
            new_d = _refresh_token_request(d["refresh_token"], cfg, d)
            acc["creds"] = new_d
            _save_accounts_raw(accounts)
            d = new_d
        return d if d.get("token") else None


def is_authenticated(account_id=None):
    accounts = _load_accounts_raw()
    if not accounts:
        return False
    try:
        d = _load_creds(account_id=account_id)
        return bool(d and (d.get("token") or d.get("refresh_token")))
    except Exception:
        return False


def get_auth_url(custom_name=None, account_id=None):
    cfg = get_config()
    tenant = (cfg.get("tenant_id") or "common").strip()
    state = secrets.token_urlsafe(24)
    _PENDING_OAUTH[state] = {
        "custom_name": (custom_name or "").strip(),
        "account_id": (account_id or "").strip(),
        "ts": time.time(),
    }
    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "redirect_uri": cfg["redirect_uri"],
        "response_mode": "query",
        "scope": " ".join(SCOPES),
        "state": state,
        "prompt": "select_account",
    }
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"


def handle_callback(code, state):
    cfg = get_config()
    tenant = (cfg.get("tenant_id") or "common").strip()
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    payload = {
        "client_id": cfg["client_id"],
        "code": code,
        "redirect_uri": cfg["redirect_uri"],
        "grant_type": "authorization_code",
        "scope": " ".join(SCOPES),
    }
    if cfg.get("client_secret"):
        payload["client_secret"] = cfg["client_secret"]
    r = requests.post(token_url, data=payload, timeout=20)
    if not r.ok:
        raise RuntimeError(f"OneDrive token exchange failed ({r.status_code}): {r.text[:300]}")
    tok = r.json()
    access_token = tok["access_token"]
    refresh_token = tok.get("refresh_token", "")
    expires_in = int(tok.get("expires_in", 3600) or 3600)
    expiry_dt = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=expires_in)

    email = ""
    drive_id = ""
    drive_type = "personal"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        me_resp = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=15)
        if me_resp.ok:
            me_data = me_resp.json()
            email = me_data.get("mail") or me_data.get("userPrincipalName") or ""
    except Exception:
        pass
    try:
        drv_resp = requests.get("https://graph.microsoft.com/v1.0/me/drive", headers=headers, timeout=15)
        if drv_resp.ok:
            drv_data = drv_resp.json()
            drive_id = drv_data.get("id") or ""
            drive_type = (drv_data.get("driveType") or "personal").lower()
            if not email:
                owner_user = ((drv_data.get("owner") or {}).get("user") or {})
                email = owner_user.get("email") or owner_user.get("displayName") or ""
    except Exception:
        pass

    creds_dict = {
        "token": access_token,
        "refresh_token": refresh_token,
        "client_id": cfg["client_id"],
        "client_secret": cfg.get("client_secret", ""),
        "tenant_id": tenant,
        "expiry": expiry_dt.isoformat() + "Z",
    }
    pending = _PENDING_OAUTH.pop(state, {}) if state else {}
    _save_creds(
        creds_dict,
        account_id=pending.get("account_id") or None,
        custom_name=pending.get("custom_name") or None,
        email=email,
        drive_id=drive_id,
        drive_type=drive_type,
    )


def _save_creds(c_dict, account_id=None, custom_name=None, email=None, drive_id=None, drive_type=None):
    with _creds_lock:
        accounts = _load_accounts_raw()
        target = None
        if account_id:
            target = next((a for a in accounts if a["id"] == account_id), None)
        if not target and email:
            target = next((a for a in accounts if a.get("email") and a.get("email").lower() == email.lower()), None)
        if target:
            target["creds"] = c_dict
            if email:
                target["email"] = email
            if drive_id:
                target["drive_id"] = drive_id
            if drive_type:
                target["drive_type"] = drive_type
            if custom_name:
                target["custom_name"] = custom_name.strip()
                target["name"] = custom_name.strip()
        else:
            new_id = "onedrive_default" if not accounts else f"onedrive_{secrets.token_hex(3)}"
            default_label = "OneDrive" if not accounts else f"OneDrive {len(accounts) + 1}"
            if email and not custom_name:
                default_label = f"OneDrive ({email.split('@')[0]})"
            disp_name = (custom_name or "").strip() or default_label
            base_smb = "OneDrive" if not accounts else sanitize_smb_share_name(disp_name, fallback=f"OneDrive_{len(accounts) + 1}")
            accounts.append({
                "id": new_id,
                "name": disp_name,
                "custom_name": (custom_name or "").strip(),
                "original_name": default_label,
                "email": email or "",
                "drive_id": drive_id or "",
                "drive_type": drive_type or "personal",
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
                    a["original_name"] = a.get("name", "OneDrive")
                a["name"] = new_name
                a["custom_name"] = new_name
                target = a
                break
        if not target:
            raise ValueError(f"OneDrive account {account_id!r} not found")
        _save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target["name"],
            "custom_name": target.get("custom_name", ""),
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "OneDrive",
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
            raise ValueError(f"OneDrive account {account_id!r} not found")
        if smb_share_name is not None:
            raw = str(smb_share_name).strip()
            if not raw:
                raise ValueError("SMB share name cannot be empty")
            cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_-")[:32]
            if not cleaned or cleaned.lower() in _RESERVED_SMB_NAMES:
                raise ValueError(f"Invalid or reserved SMB share name: {raw!r}")
            for other in accounts:
                if other["id"] != target["id"] and (other.get("smb_share_name") or "").lower() == cleaned.lower():
                    raise ValueError(f"SMB share name '{cleaned}' is already used by another OneDrive")
            target["smb_share_name"] = cleaned
        if smb_enabled is not None:
            target["smb_enabled"] = bool(smb_enabled)
        _save_accounts_raw(accounts)
        return {
            "id": target["id"],
            "name": target.get("custom_name") or target.get("name") or "OneDrive",
            "email": target.get("email", ""),
            "smb_enabled": bool(target.get("smb_enabled", True)),
            "smb_share_name": target.get("smb_share_name") or "OneDrive",
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


def revoke(account_id=None):
    remove_account(account_id=account_id)


def _graph_request(method, path_or_url, account_id=None, **kwargs):
    url = path_or_url if path_or_url.startswith("http") else f"https://graph.microsoft.com/v1.0{path_or_url}"
    for attempt in range(2):
        c = _load_creds(force_refresh=(attempt > 0), account_id=account_id)
        if not c:
            raise RuntimeError("Not authenticated with OneDrive")
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {c['token']}"
        r = requests.request(method, url, headers=headers, timeout=kwargs.pop("timeout", 30), **kwargs)
        if r.status_code in (401, 403) and attempt == 0:
            r.close()
            continue
        if not r.ok:
            err_msg = ""
            try:
                err_msg = r.text[:300]
            except Exception:
                pass
            r.close()
            raise RuntimeError(f"OneDrive API error ({r.status_code}): {err_msg}")
        return r
    raise RuntimeError("OneDrive authentication failed after token refresh")


def _cache_key(account_id, file_id):
    return f"{account_id or 'default'}:{file_id}"


def list_files(folder_id="root", account_id=None):
    if not folder_id or folder_id == "root":
        ep = "/me/drive/root/children?$top=200"
    else:
        ep = f"/me/drive/items/{folder_id}/children?$top=200"
    r = _graph_request("GET", ep, account_id=account_id)
    data = r.json()
    out = []
    now = time.time()
    for item in data.get("value", []):
        is_folder = "folder" in item
        size_val = int(item.get("size", 0) or 0)
        file_obj = item.get("file") or {}
        mime = "application/vnd.ms-folder" if is_folder else (file_obj.get("mimeType") or "application/octet-stream")
        dl_url = item.get("@microsoft.graph.downloadUrl") or ""
        info = {
            "name": item.get("name", "item"),
            "mimeType": mime,
            "size": size_val,
            "downloadUrl": dl_url,
            "isFolder": is_folder,
        }
        _meta_cache[_cache_key(account_id, item["id"])] = (now, info)
        _meta_cache[item["id"]] = (now, info)
        out.append({
            "id": item["id"],
            "name": item.get("name", "item"),
            "type": "folder" if is_folder else "file",
            "size": size_val,
            "modified": item.get("lastModifiedDateTime", ""),
            "mimeType": mime,
        })
    return out


def get_file_meta(file_id, account_id=None, require_download_url=False):
    now = time.time()
    ck = _cache_key(account_id, file_id)
    cached = _meta_cache.get(ck) or _meta_cache.get(file_id)
    if cached and (now - cached[0]) < _META_TTL:
        if not require_download_url or cached[1].get("downloadUrl"):
            return cached[1]
    r = _graph_request("GET", f"/me/drive/items/{file_id}", account_id=account_id)
    meta = r.json()
    is_folder = "folder" in meta
    file_obj = meta.get("file") or {}
    mime = "application/vnd.ms-folder" if is_folder else (file_obj.get("mimeType") or "application/octet-stream")
    info = {
        "name": meta.get("name", "download"),
        "mimeType": mime,
        "size": int(meta.get("size", 0) or 0),
        "downloadUrl": meta.get("@microsoft.graph.downloadUrl") or "",
        "isFolder": is_folder,
    }
    _meta_cache[ck] = (now, info)
    _meta_cache[file_id] = (now, info)
    return info


def _open_media_response(file_id, start=None, end=None, account_id=None):
    for attempt in range(2):
        meta = get_file_meta(file_id, account_id=account_id, require_download_url=(attempt == 0))
        dl_url = meta.get("downloadUrl") if attempt == 0 else ""
        headers = {}
        if start is not None and end is not None:
            headers["Range"] = f"bytes={start}-{end}"
        elif start:
            headers["Range"] = f"bytes={start}-"

        if dl_url:
            r = requests.get(dl_url, headers=headers, stream=True, timeout=(15, 300))
            if r.status_code in (401, 403, 404) and attempt == 0:
                r.close()
                _meta_cache.pop(_cache_key(account_id, file_id), None)
                _meta_cache.pop(file_id, None)
                continue
            if r.ok:
                return r
            r.close()

        c = _load_creds(force_refresh=(attempt > 0), account_id=account_id)
        if not c:
            raise RuntimeError("Not authenticated with OneDrive")
        headers["Authorization"] = f"Bearer {c['token']}"
        content_url = f"https://graph.microsoft.com/v1.0/me/drive/items/{file_id}/content"
        r = requests.get(content_url, headers=headers, stream=True, timeout=(15, 300), allow_redirects=True)
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
            raise RuntimeError(f"OneDrive stream failed ({r.status_code}): {err_body}")
        return r
    raise RuntimeError("OneDrive authentication failed after token refresh")


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
    meta = get_file_meta(file_id, account_id=account_id, require_download_url=True)
    name = meta["name"]
    mime = meta["mimeType"]
    buf = io.BytesIO()
    for chunk in stream_file_range(file_id, start=0, end=None, account_id=account_id):
        buf.write(chunk)
    return buf.getvalue(), name, mime


def create_folder(parent_id, name, account_id=None):
    if not parent_id or parent_id == "root":
        ep = "/me/drive/root/children"
    else:
        ep = f"/me/drive/items/{parent_id}/children"
    r = _graph_request(
        "POST",
        ep,
        account_id=account_id,
        json={
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename",
        },
    )
    return r.json()["id"]


def ensure_folder_path(base_folder_id, parts, account_id=None):
    curr_id = base_folder_id or "root"
    for part in parts:
        if not part:
            continue
        children = list_files(curr_id, account_id=account_id)
        existing = next((c for c in children if c["type"] == "folder" and c["name"].lower() == part.lower()), None)
        if existing:
            curr_id = existing["id"]
        else:
            curr_id = create_folder(curr_id, part, account_id=account_id)
    return curr_id


def upload_file(parent_id, filename, data_or_stream, mime_type="application/octet-stream", relative_path=None, account_id=None):
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

    stream_obj = data_or_stream if hasattr(data_or_stream, "read") else io.BytesIO(
        data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
    )

    # Read first 4MB chunk; if the entire file fits in <=4MB, use simple PUT; otherwise use UploadSession
    chunk_unit = 327680 * 10  # 3.2 MiB (exact multiple of 320 KiB as required by Microsoft Graph)
    first_chunk = stream_obj.read(chunk_unit)
    second_chunk = stream_obj.read(chunk_unit)

    safe_name = requests.utils.quote(actual_name)
    if not second_chunk:
        if target_parent == "root":
            put_ep = f"/me/drive/root:/{safe_name}:/content"
        else:
            put_ep = f"/me/drive/items/{target_parent}:/{safe_name}:/content"
        _graph_request(
            "PUT",
            put_ep,
            account_id=account_id,
            data=first_chunk or b"",
            headers={"Content-Type": mime_type or "application/octet-stream"},
            timeout=120,
        )
        return

    # Large file upload via UploadSession
    if target_parent == "root":
        sess_ep = f"/me/drive/root:/{safe_name}:/createUploadSession"
    else:
        sess_ep = f"/me/drive/items/{target_parent}:/{safe_name}:/createUploadSession"

    # SpooledTemporaryFile keeps up to 16MB in memory and spills larger streams to disk so we know total file size for Content-Range
    with tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024) as tmp:
        tmp.write(first_chunk)
        tmp.write(second_chunk)
        while True:
            buf = stream_obj.read(chunk_unit)
            if not buf:
                break
            tmp.write(buf)
        total_size = tmp.tell()
        tmp.seek(0)

        sess_resp = _graph_request(
            "POST",
            sess_ep,
            account_id=account_id,
            json={"item": {"@microsoft.graph.conflictBehavior": "replace", "name": actual_name}},
        )
        upload_url = sess_resp.json()["uploadUrl"]

        offset = 0
        while offset < total_size:
            piece = tmp.read(chunk_unit)
            if not piece:
                break
            end_byte = offset + len(piece) - 1
            headers = {
                "Content-Length": str(len(piece)),
                "Content-Range": f"bytes {offset}-{end_byte}/{total_size}",
            }
            up_r = requests.put(upload_url, data=piece, headers=headers, timeout=300)
            if not up_r.ok and up_r.status_code not in (200, 201, 202):
                raise RuntimeError(f"OneDrive chunk upload failed ({up_r.status_code}): {up_r.text[:300]}")
            offset += len(piece)


def update_file_content(file_id, data_or_stream, mime_type="text/plain; charset=utf-8", account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    raw_bytes = data_or_stream.read() if hasattr(data_or_stream, "read") else (
        data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
    )
    r = _graph_request(
        "PUT",
        f"/me/drive/items/{file_id}/content",
        account_id=account_id,
        data=raw_bytes,
        headers={"Content-Type": mime_type or "text/plain; charset=utf-8"},
        timeout=120,
    )
    return r.json()


def move_file(file_id, dest_folder_id, account_id=None):
    dest_id = dest_folder_id or "root"
    if file_id == dest_id:
        raise ValueError("Cannot move a folder into itself")
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    if dest_id == "root":
        root_r = _graph_request("GET", "/me/drive/root", account_id=account_id)
        dest_id = root_r.json()["id"]
    r = _graph_request(
        "PATCH",
        f"/me/drive/items/{file_id}",
        account_id=account_id,
        json={"parentReference": {"id": dest_id}},
    )
    return r.json()


def rename_file(file_id, new_name, account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    r = _graph_request(
        "PATCH",
        f"/me/drive/items/{file_id}",
        account_id=account_id,
        json={"name": new_name},
    )
    return r.json()


def delete_file(file_id, account_id=None):
    _meta_cache.pop(_cache_key(account_id, file_id), None)
    _meta_cache.pop(file_id, None)
    _graph_request("DELETE", f"/me/drive/items/{file_id}", account_id=account_id)


def create_zip_tmpfile(file_ids, account_id=None):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    def _add_item(zf, fid, arc_prefix):
        meta = get_file_meta(fid, account_id=account_id)
        name = meta["name"]
        is_folder = meta.get("isFolder") or meta.get("mimeType") == "application/vnd.ms-folder"
        arc_path = f"{arc_prefix}/{name}" if arc_prefix else name
        if is_folder:
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
