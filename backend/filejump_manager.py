import io
import json
import mimetypes
import os
import posixpath
import re
import secrets
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import requests

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
ACCOUNTS_FILE = DATA_DIR / "filejump_accounts.json"

DEFAULT_REST_BASE = os.getenv("FILEJUMP_API_URL", "https://filejump.com/api").rstrip("/")
DEFAULT_UPLOAD_URL = os.getenv("FILEJUMP_UPLOAD_URL", "https://uploads.filejump.com/api/upload").rstrip("/")
DEFAULT_WEBDAV_BASE = os.getenv("FILEJUMP_WEBDAV_URL", "https://uploads.filejump.com/dav").rstrip("/")

LEGACY_FILEJUMP_HOSTS = {
    "https://drive.filejump.com",
    "http://drive.filejump.com",
    "https://app.filejump.com",
    "http://app.filejump.com",
    "https://filejump.com",
    "http://filejump.com",
}

RESERVED_SMB_NAMES = {"global", "homes", "printers", "print$", "ipc$"}


def sanitize_smb_share_name(raw_name, fallback="FileJump"):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(raw_name or "").strip()).strip("_-")
    if not cleaned or cleaned.lower() in RESERVED_SMB_NAMES:
        cleaned = fallback
    return cleaned[:32]


def _normalize_rest_api_url(url_str):
    """
    Normalizes any FileJump REST URL to the canonical API root (https://filejump.com/api).
    """
    raw = str(url_str or DEFAULT_REST_BASE).strip().rstrip("/")
    if not raw:
        raw = DEFAULT_REST_BASE
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    for suffix in ("/api/v1", "/api"):
        if raw.endswith(suffix):
            raw = raw[:-len(suffix)]
    raw = raw.rstrip("/")
    if raw.lower() in LEGACY_FILEJUMP_HOSTS:
        return "https://filejump.com/api"
    return f"{raw}/api"


def _normalize_rest_base(url_str):
    """
    Returns the host origin without trailing /api (e.g. https://filejump.com)
    so callers that append /api/... always target https://filejump.com/api/...
    """
    api_url = _normalize_rest_api_url(url_str)
    if api_url.endswith("/api"):
        return api_url[:-4]
    return api_url


def _normalize_webdav_base(url_str):
    raw = str(url_str or DEFAULT_WEBDAV_BASE).strip().rstrip("/")
    if not raw:
        raw = DEFAULT_WEBDAV_BASE
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    return raw.rstrip("/")


def _ensure_smb_proxy_fields(accounts):
    used = set()
    changed = False
    for idx, acc in enumerate(accounts):
        if acc.get("auth_type", "token") != "webdav":
            cur_url = str(acc.get("api_url") or "").strip().rstrip("/")
            norm_url = _normalize_rest_api_url(cur_url)
            if cur_url != norm_url:
                acc["api_url"] = norm_url
                changed = True
            if acc.get("upload_url") != DEFAULT_UPLOAD_URL:
                acc["upload_url"] = DEFAULT_UPLOAD_URL
                changed = True
        if "smb_enabled" not in acc:
            acc["smb_enabled"] = True
            changed = True
        raw_share = str(acc.get("smb_share_name") or "").strip()
        if not raw_share:
            default_base = (
                "FileJump"
                if (idx == 0 or acc.get("id") == "default")
                else (acc.get("custom_name") or acc.get("name") or f"FileJump_{idx + 1}")
            )
            candidate = sanitize_smb_share_name(default_base, fallback=f"FileJump_{idx + 1}")
            base_cand = candidate
            suffix = 2
            while candidate.lower() in used:
                candidate = f"{base_cand[:28]}_{suffix}"
                suffix += 1
            acc["smb_share_name"] = candidate
            changed = True
        else:
            sanitized = sanitize_smb_share_name(raw_share, fallback=f"FileJump_{idx + 1}")
            if sanitized.lower() in used:
                sanitized = f"{sanitized[:28]}_{idx + 1}"
            if sanitized != raw_share:
                acc["smb_share_name"] = sanitized
                changed = True
        used.add(acc["smb_share_name"].lower())
    return changed


def _load_accounts_raw():
    if ACCOUNTS_FILE.exists():
        try:
            data = json.loads(ACCOUNTS_FILE.read_text())
            if isinstance(data, list):
                if _ensure_smb_proxy_fields(data):
                    _save_accounts_raw(data)
                return data
        except Exception:
            pass
    return []


def _save_accounts_raw(accounts):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_smb_proxy_fields(accounts)
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2))


def list_accounts():
    accounts = _load_accounts_raw()
    out = []
    for a in accounts:
        auth_t = a.get("auth_type", "token")
        out.append({
            "id": a.get("id", "default"),
            "name": a.get("custom_name") or a.get("name") or "FileJump",
            "custom_name": a.get("custom_name", ""),
            "original_name": a.get("original_name") or a.get("name") or "FileJump",
            "email": a.get("email", ""),
            "auth_type": auth_t,
            "api_url": (
                _normalize_webdav_base(a.get("api_url"))
                if auth_t == "webdav"
                else _normalize_rest_api_url(a.get("api_url"))
            ),
            "upload_url": DEFAULT_UPLOAD_URL if auth_t != "webdav" else "",
            "smb_enabled": bool(a.get("smb_enabled", True)),
            "smb_share_name": a.get("smb_share_name") or "FileJump",
        })
    return out


def update_account_smb_proxy(account_id, smb_enabled=None, smb_share_name=None):
    accounts = _load_accounts_raw()
    target = None
    for a in accounts:
        if a.get("id") == account_id or (account_id in ("root", "default") and a is accounts[0]):
            target = a
            break
    if not target:
        raise ValueError(f"FileJump account '{account_id}' not found")

    if smb_share_name is not None:
        raw = str(smb_share_name).strip()
        if not raw:
            raise ValueError("SMB share name cannot be empty")
        cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", raw).strip("_-")[:32]
        if not cleaned or cleaned.lower() in RESERVED_SMB_NAMES:
            raise ValueError(f"Invalid or reserved SMB share name: '{raw}'")
        for other in accounts:
            if other is not target and str(other.get("smb_share_name") or "").lower() == cleaned.lower():
                raise ValueError(f"SMB share name '{cleaned}' is already in use by another FileJump account")
        target["smb_share_name"] = cleaned

    if smb_enabled is not None:
        target["smb_enabled"] = bool(smb_enabled)

    _save_accounts_raw(accounts)
    return {
        "id": target.get("id", "default"),
        "name": target.get("custom_name") or target.get("name") or "FileJump",
        "email": target.get("email", ""),
        "auth_type": target.get("auth_type", "token"),
        "smb_enabled": bool(target.get("smb_enabled", True)),
        "smb_share_name": target.get("smb_share_name") or "FileJump",
    }


def _find_account(account_id=None):
    accounts = _load_accounts_raw()
    if not accounts:
        return None
    if not account_id or account_id in ("root", "default"):
        for a in accounts:
            if a.get("id") == "default":
                return a
        return accounts[0]
    for a in accounts:
        if a.get("id") == account_id:
            return a
    return None


def rename_account(account_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("Custom name cannot be empty")
    accounts = _load_accounts_raw()
    target = None
    for a in accounts:
        if a.get("id") == account_id or (account_id in ("root", "default") and a is accounts[0]):
            target = a
            break
    if not target:
        raise ValueError(f"FileJump account '{account_id}' not found")
    if not target.get("original_name"):
        target["original_name"] = target.get("name") or "FileJump"
    target["name"] = new_name
    target["custom_name"] = new_name
    _save_accounts_raw(accounts)
    return {
        "id": target.get("id"),
        "name": target.get("name"),
        "custom_name": target.get("custom_name", ""),
        "email": target.get("email", ""),
    }


def remove_account(account_id=None):
    if not account_id:
        _save_accounts_raw([])
        return
    accounts = _load_accounts_raw()
    accounts = [a for a in accounts if a.get("id") != account_id]
    _save_accounts_raw(accounts)


def revoke(account_id=None):
    remove_account(account_id)


def is_configured():
    return True


def is_authenticated(account_id=None):
    return _find_account(account_id) is not None


def _probe_rest_account(api_token, base_url=None, email_hint=""):
    api_base = _normalize_rest_api_url(base_url or DEFAULT_REST_BASE)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }

    last_err = None
    for probe_ep in ("/auth/user", "/files?per_page=1", "/folders"):
        try:
            r = requests.get(f"{api_base}{probe_ep}", headers=headers, timeout=12)
            if r.status_code in (401, 403):
                last_err = f"FileJump API rejected token ({r.status_code})"
                continue
            if r.status_code < 400:
                data = {}
                try:
                    data = r.json()
                except Exception:
                    pass
                user_obj = None
                if isinstance(data, dict):
                    if isinstance(data.get("user"), dict):
                        user_obj = data["user"]
                    elif isinstance(data.get("data"), dict) and ("email" in data["data"] or "name" in data["data"]):
                        user_obj = data["data"]
                    elif "email" in data:
                        user_obj = data
                detected_email = email_hint
                detected_name = ""
                if isinstance(user_obj, dict):
                    detected_email = user_obj.get("email") or detected_email
                    detected_name = (
                        user_obj.get("name")
                        or user_obj.get("display_name")
                        or user_obj.get("first_name")
                        or ""
                    )
                return {
                    "api_url": api_base,
                    "email": detected_email or "",
                    "display_name": detected_name,
                }
        except Exception as e:
            last_err = str(e)
            continue

    if last_err and "rejected token" in last_err:
        raise ValueError(last_err)
    return {
        "api_url": api_base,
        "email": email_hint or "",
        "display_name": "",
    }


def _probe_webdav_account(email, password_or_token, webdav_url=None):
    base = _normalize_webdav_base(webdav_url)
    try:
        r = requests.request(
            "PROPFIND",
            f"{base}/",
            auth=(email, password_or_token),
            headers={"Depth": "0"},
            timeout=15,
        )
        if r.status_code in (401, 403):
            raise ValueError(f"FileJump WebDAV authentication failed (HTTP {r.status_code})")
    except ValueError:
        raise
    except Exception:
        pass
    return {
        "api_url": base,
        "email": email,
    }


def add_account(auth_type="token", api_token="", email="", api_url="", custom_name="", account_id=None):
    auth_type = str(auth_type or "token").strip().lower()
    if auth_type not in ("token", "webdav"):
        auth_type = "token"

    api_token = str(api_token or "").strip()
    email = str(email or "").strip()
    custom_name = str(custom_name or "").strip()

    if not api_token:
        raise ValueError("FileJump API Access Token or WebDAV password/token is required")
    if auth_type == "webdav" and not email:
        raise ValueError("Account email is required for FileJump WebDAV authentication")

    if auth_type == "webdav":
        info = _probe_webdav_account(email, api_token, api_url or DEFAULT_WEBDAV_BASE)
        resolved_url = info["api_url"]
        resolved_email = info["email"] or email
        detected_title = ""
    else:
        info = _probe_rest_account(api_token, api_url or DEFAULT_REST_BASE, email_hint=email)
        resolved_url = info["api_url"]
        resolved_email = info["email"] or email
        detected_title = info.get("display_name") or ""

    accounts = _load_accounts_raw()
    target = None
    if account_id:
        for a in accounts:
            if a.get("id") == account_id:
                target = a
                break

    if target:
        target["auth_type"] = auth_type
        target["api_token"] = api_token
        target["api_url"] = resolved_url
        if auth_type != "webdav":
            target["upload_url"] = DEFAULT_UPLOAD_URL
        if resolved_email:
            target["email"] = resolved_email
        if custom_name:
            target["custom_name"] = custom_name
            target["name"] = custom_name
    else:
        new_id = "default" if len(accounts) == 0 else f"filejump_{secrets.token_hex(3)}"
        idx = len(accounts) + 1
        default_label = (
            f"FileJump ({detected_title})"
            if detected_title
            else (f"FileJump ({resolved_email})" if resolved_email else ("FileJump" if idx == 1 else f"FileJump {idx}"))
        )
        disp_name = custom_name if custom_name else default_label
        target = {
            "id": new_id,
            "name": disp_name,
            "custom_name": custom_name,
            "original_name": default_label,
            "email": resolved_email,
            "auth_type": auth_type,
            "api_token": api_token,
            "api_url": resolved_url,
            "upload_url": DEFAULT_UPLOAD_URL if auth_type != "webdav" else "",
            "smb_enabled": True,
        }
        accounts.append(target)

    _save_accounts_raw(accounts)
    return {
        "id": target.get("id"),
        "name": target.get("custom_name") or target.get("name") or "FileJump",
        "custom_name": target.get("custom_name", ""),
        "original_name": target.get("original_name") or target.get("name") or "FileJump",
        "email": target.get("email", ""),
        "auth_type": target.get("auth_type", "token"),
        "api_url": target.get("api_url", resolved_url),
        "upload_url": target.get("upload_url", DEFAULT_UPLOAD_URL if auth_type != "webdav" else ""),
        "smb_enabled": bool(target.get("smb_enabled", True)),
        "smb_share_name": target.get("smb_share_name") or "FileJump",
    }


def _require_account(account_id=None):
    acc = _find_account(account_id)
    if not acc:
        raise RuntimeError("FileJump account is not connected")
    return acc


# ── WebDAV Implementation Helpers ─────────────────────────────────────────────
def _webdav_norm_path(file_id_or_path):
    if not file_id_or_path or file_id_or_path == "root" or file_id_or_path == "/":
        return "/"
    raw = str(file_id_or_path).strip().replace("\\", "/")
    parts = [p for p in raw.split("/") if p and p not in (".", "..")]
    return "/" + "/".join(parts) if parts else "/"


def _webdav_build_url(acc, rel_path):
    base = _normalize_webdav_base(acc.get("api_url") or DEFAULT_WEBDAV_BASE)
    norm = _webdav_norm_path(rel_path)
    if norm == "/":
        return f"{base}/"
    encoded_parts = [quote(seg, safe="") for seg in norm.strip("/").split("/")]
    return f"{base}/" + "/".join(encoded_parts)


def _webdav_auth(acc):
    return (acc.get("email") or "", acc.get("api_token") or "")


def _parse_webdav_multistatus(xml_bytes, base_url, requested_norm_path):
    root = ET.fromstring(xml_bytes)
    parsed_base_path = unquote(urlparse(base_url).path).rstrip("/")
    req_norm = _webdav_norm_path(requested_norm_path).rstrip("/")
    items = []

    for resp in root.findall(".//{DAV:}response"):
        href_el = resp.find("{DAV:}href")
        if href_el is None or not href_el.text:
            continue
        raw_href = unquote(urlparse(href_el.text.strip()).path)
        rel = raw_href
        if parsed_base_path and rel.startswith(parsed_base_path):
            rel = rel[len(parsed_base_path):]
        rel_clean = _webdav_norm_path(rel)

        if rel_clean.rstrip("/") == req_norm:
            continue

        prop = resp.find(".//{DAV:}prop")
        if prop is None:
            continue
        res_type = prop.find("{DAV:}resourcetype")
        is_dir = (res_type is not None and res_type.find("{DAV:}collection") is not None) or raw_href.endswith("/")

        disp_el = prop.find("{DAV:}displayname")
        name = (disp_el.text.strip() if (disp_el is not None and disp_el.text) else "") or posixpath.basename(rel_clean.rstrip("/"))
        if not name:
            continue

        len_el = prop.find("{DAV:}getcontentlength")
        try:
            size = int(len_el.text.strip()) if (len_el is not None and len_el.text) else 0
        except Exception:
            size = 0

        mod_el = prop.find("{DAV:}getlastmodified")
        modified = mod_el.text.strip() if (mod_el is not None and mod_el.text) else datetime.now(timezone.utc).isoformat()

        mime_el = prop.find("{DAV:}getcontenttype")
        mime_type = (
            "application/vnd.filejump.folder"
            if is_dir
            else (
                (mime_el.text.strip() if (mime_el is not None and mime_el.text) else "")
                or mimetypes.guess_type(name)[0]
                or "application/octet-stream"
            )
        )

        items.append({
            "id": rel_clean,
            "name": name,
            "type": "folder" if is_dir else "file",
            "size": 0 if is_dir else size,
            "modified": modified,
            "mimeType": mime_type,
        })

    items.sort(key=lambda x: (0 if x["type"] == "folder" else 1, x["name"].lower()))
    return items


# ── REST API Implementation Helpers (https://filejump.com/kb/api-guide) ───────
def _rest_headers(acc, content_type=None, accept="application/json"):
    h = {
        "Authorization": f"Bearer {acc.get('api_token') or ''}",
    }
    if accept:
        h["Accept"] = accept
    if content_type:
        h["Content-Type"] = content_type
    return h


def _rest_base(acc):
    return _normalize_rest_base(acc.get("api_url") or DEFAULT_REST_BASE)


def _rest_upload_url(acc):
    return str(acc.get("upload_url") or DEFAULT_UPLOAD_URL).strip().rstrip("/") or DEFAULT_UPLOAD_URL


def _parse_rest_id(raw_id):
    """
    Returns (is_explicit_folder: bool, clean_id: str | None).
    Folder IDs returned to the UI are prefixed with 'folder:' so that numeric
    folder IDs and numeric file IDs from /api/folders and /api/files never collide.
    """
    if raw_id is None:
        return True, None
    s = str(raw_id).strip()
    if s in ("", "root", "/", "0", "folder:root", "folder:0", "folder:/"):
        return True, None
    if s.startswith("folder:"):
        return True, s[len("folder:"):].strip()
    if s.startswith("file:"):
        return False, s[len("file:"):].strip()
    return False, s


def _extract_list_from_payload(payload, *keys):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    data_val = payload.get("data")
    if isinstance(data_val, list):
        return data_val
    if isinstance(data_val, dict):
        if isinstance(data_val.get("data"), list):
            return data_val["data"]
        for k in keys:
            if isinstance(data_val.get(k), list):
                return data_val[k]
    for k in keys:
        if isinstance(payload.get(k), list):
            return payload[k]
    return []


def _normalize_rest_entry(item, force_type=None):
    if not isinstance(item, dict):
        return None
    raw_type = str(force_type or item.get("type") or "").lower()
    is_folder = (
        raw_type == "folder"
        or bool(item.get("is_folder"))
        or ("parent_id" in item and "mime_type" not in item and "file_size" not in item and "size" not in item)
    )
    raw_id = item.get("id") if item.get("id") is not None else item.get("hash")
    if raw_id is None or str(raw_id) == "":
        return None
    clean_id = str(raw_id).strip()
    if clean_id.startswith("folder:"):
        clean_id = clean_id[len("folder:"):]
    entry_id = f"folder:{clean_id}" if is_folder else clean_id
    name = item.get("name") or item.get("file_name") or clean_id
    size = 0 if is_folder else int(item.get("size") or item.get("file_size") or 0)
    modified = item.get("updated_at") or item.get("created_at") or datetime.now(timezone.utc).isoformat()
    mime = (
        "application/vnd.filejump.folder"
        if is_folder
        else (
            item.get("mime_type")
            or item.get("mime")
            or mimetypes.guess_type(name)[0]
            or "application/octet-stream"
        )
    )
    return {
        "id": entry_id,
        "raw_id": clean_id,
        "hash": item.get("hash") or clean_id,
        "name": name,
        "type": "folder" if is_folder else "file",
        "size": size,
        "modified": modified,
        "mimeType": mime,
        "url": item.get("download_url") or item.get("url") or "",
        "parent_id": item.get("folder_id") if not is_folder else item.get("parent_id"),
    }


def _rest_get_entry_raw(acc, file_id):
    base = _rest_base(acc)
    headers = _rest_headers(acc)
    is_folder_hint, clean_id = _parse_rest_id(file_id)
    if not clean_id:
        return {"id": "root", "name": "root", "type": "folder", "size": 0}

    q_id = quote(str(clean_id))
    if is_folder_hint:
        endpoints = [
            (f"/api/folders/{q_id}", "folder"),
        ]
    else:
        endpoints = [
            (f"/api/files/{q_id}", "file"),
            (f"/api/folders/{q_id}", "folder"),
        ]

    for ep, ftype in endpoints:
        r = requests.get(f"{base}{ep}", headers=headers, timeout=20)
        if r.status_code == 404:
            continue
        if r.status_code < 400:
            data = r.json()
            if isinstance(data, dict):
                entry = (
                    data.get("data")
                    or data.get("file")
                    or data.get("folder")
                    or data.get("fileEntry")
                    or data.get("entry")
                    or data
                )
                if isinstance(entry, dict) and (entry.get("id") is not None or entry.get("name")):
                    if ftype and "type" not in entry:
                        entry = dict(entry)
                        entry["type"] = ftype
                    return entry
    raise FileNotFoundError(f"FileJump entry '{file_id}' not found")


def _rest_open_download_response(acc, file_id, range_header=None):
    base = _rest_base(acc)
    _, clean_id = _parse_rest_id(file_id)
    if not clean_id:
        raise ValueError("Cannot download root folder directly")

    # Note: Do NOT send Accept: application/json when requesting the binary stream,
    # because /api/files/{id}/download returns JSON instead of redirecting if Accept: application/json is set.
    stream_headers = _rest_headers(acc, accept="*/*")
    if range_header:
        stream_headers["Range"] = range_header

    q_id = quote(str(clean_id))
    candidate_urls = [
        f"{base}/api/files/{q_id}/download",
        f"{base}/api/files/download/{q_id}",
    ]

    last_resp = None
    for url in candidate_urls:
        r = requests.get(url, headers=stream_headers, stream=True, timeout=(15, 300), allow_redirects=True)
        if r.status_code == 404:
            r.close()
            continue
        if r.status_code < 400:
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                try:
                    j = r.json()
                    data_obj = j.get("data") if isinstance(j.get("data"), dict) else j
                    dl_url = (
                        (data_obj.get("download_url") if isinstance(data_obj, dict) else None)
                        or j.get("download_url")
                        or j.get("url")
                    )
                    if dl_url:
                        r.close()
                        dl_headers = {"Accept": "*/*"}
                        if range_header:
                            dl_headers["Range"] = range_header
                        if urlparse(dl_url).netloc == urlparse(base).netloc:
                            dl_headers["Authorization"] = f"Bearer {acc.get('api_token') or ''}"
                        r2 = requests.get(dl_url, headers=dl_headers, stream=True, timeout=(15, 300), allow_redirects=True)
                        if r2.status_code < 400:
                            return r2
                except Exception:
                    pass
            return r
        last_resp = r
        try:
            r.close()
        except Exception:
            pass

    if last_resp is not None:
        last_resp.raise_for_status()
    raise RuntimeError(f"Unable to stream FileJump file '{file_id}'")


# ── Unified Public Operations ─────────────────────────────────────────────────
def list_files(folder_id="root", account_id=None):
    acc = _require_account(account_id)
    if acc.get("auth_type") == "webdav":
        url = _webdav_build_url(acc, folder_id)
        if not url.endswith("/"):
            url += "/"
        r = requests.request(
            "PROPFIND",
            url,
            auth=_webdav_auth(acc),
            headers={"Depth": "1"},
            timeout=30,
        )
        r.raise_for_status()
        return _parse_webdav_multistatus(r.content, _webdav_build_url(acc, "/"), folder_id)

    base = _rest_base(acc)
    headers = _rest_headers(acc)
    _, clean_parent_id = _parse_rest_id(folder_id)

    # Official FileJump REST API (https://filejump.com/api/folders + https://filejump.com/api/files)
    folder_params = {}
    if clean_parent_id:
        folder_params["parent_id"] = clean_parent_id

    r_folders = requests.get(f"{base}/api/folders", headers=headers, params=folder_params, timeout=30)
    r_folders.raise_for_status()
    raw_folders = _extract_list_from_payload(r_folders.json(), "folders", "entries")

    # If inside a subfolder and /api/folders?parent_id=... returned empty, also check /api/folders/all
    if clean_parent_id and not raw_folders:
        try:
            r_all_f = requests.get(f"{base}/api/folders/all", headers=headers, timeout=20)
            if r_all_f.status_code < 400:
                raw_folders = _extract_list_from_payload(r_all_f.json(), "folders", "entries")
        except Exception:
            pass

    out = []
    seen_ids = set()
    for raw_f in raw_folders:
        if not isinstance(raw_f, dict):
            continue
        if "parent_id" in raw_f or "parentId" in raw_f:
            f_parent = raw_f.get("parent_id") if "parent_id" in raw_f else raw_f.get("parentId")
            if clean_parent_id is None:
                if f_parent not in (None, "", 0, "0", "root"):
                    continue
            else:
                if str(f_parent) != str(clean_parent_id):
                    continue
        norm = _normalize_rest_entry(raw_f, force_type="folder")
        if norm and norm["id"] not in seen_ids:
            seen_ids.add(norm["id"])
            out.append({
                "id": norm["id"],
                "name": norm["name"],
                "type": "folder",
                "size": 0,
                "modified": norm["modified"],
                "mimeType": norm["mimeType"],
            })

    file_params = {"per_page": 500}
    if clean_parent_id:
        file_params["folder_id"] = clean_parent_id
    r_files = requests.get(f"{base}/api/files", headers=headers, params=file_params, timeout=30)
    r_files.raise_for_status()
    raw_files = _extract_list_from_payload(r_files.json(), "files", "fileEntries", "entries")

    for raw_item in raw_files:
        if not isinstance(raw_item, dict):
            continue
        if "folder_id" in raw_item or "folderId" in raw_item:
            item_folder = raw_item.get("folder_id") if "folder_id" in raw_item else raw_item.get("folderId")
            if clean_parent_id is None:
                if item_folder not in (None, "", 0, "0", "root"):
                    continue
            else:
                if str(item_folder) != str(clean_parent_id):
                    continue
        norm = _normalize_rest_entry(raw_item, force_type="file")
        if norm and norm["id"] not in seen_ids:
            seen_ids.add(norm["id"])
            out.append({
                "id": norm["id"],
                "name": norm["name"],
                "type": norm["type"],
                "size": norm["size"],
                "modified": norm["modified"],
                "mimeType": norm["mimeType"],
            })

    out.sort(key=lambda x: (0 if x["type"] == "folder" else 1, x["name"].lower()))
    return out


def get_file_meta(file_id, account_id=None):
    acc = _require_account(account_id)
    if acc.get("auth_type") == "webdav":
        url = _webdav_build_url(acc, file_id)
        r = requests.request(
            "PROPFIND",
            url,
            auth=_webdav_auth(acc),
            headers={"Depth": "0"},
            timeout=20,
        )
        r.raise_for_status()
        root = ET.fromstring(r.content)
        prop = root.find(".//{DAV:}prop")
        res_type = prop.find("{DAV:}resourcetype") if prop is not None else None
        is_dir = res_type is not None and res_type.find("{DAV:}collection") is not None
        disp_el = prop.find("{DAV:}displayname") if prop is not None else None
        name = (
            disp_el.text.strip()
            if (disp_el is not None and disp_el.text)
            else posixpath.basename(_webdav_norm_path(file_id).rstrip("/")) or "root"
        )
        len_el = prop.find("{DAV:}getcontentlength") if prop is not None else None
        size = int(len_el.text.strip()) if (len_el is not None and len_el.text) else 0
        mime_el = prop.find("{DAV:}getcontenttype") if prop is not None else None
        mime_type = (
            "application/vnd.filejump.folder"
            if is_dir
            else (
                (mime_el.text.strip() if (mime_el is not None and mime_el.text) else "")
                or mimetypes.guess_type(name)[0]
                or "application/octet-stream"
            )
        )
        return {
            "id": _webdav_norm_path(file_id),
            "name": name,
            "size": 0 if is_dir else size,
            "mimeType": mime_type,
            "isFolder": is_dir,
        }

    is_folder_hint, _ = _parse_rest_id(file_id)
    raw = _rest_get_entry_raw(acc, file_id)
    norm = _normalize_rest_entry(raw, force_type="folder" if is_folder_hint else None)
    return {
        "id": norm["id"],
        "name": norm["name"],
        "size": norm["size"],
        "mimeType": norm["mimeType"],
        "isFolder": norm["type"] == "folder",
    }


def stream_file_range(file_id, start=0, end=None, chunk_size=262144, account_id=None):
    acc = _require_account(account_id)
    range_header = None
    if start > 0 or end is not None:
        range_header = f"bytes={start}-{end}" if end is not None else f"bytes={start}-"

    if acc.get("auth_type") == "webdav":
        url = _webdav_build_url(acc, file_id)
        headers = {"Range": range_header} if range_header else {}
        r = requests.get(url, auth=_webdav_auth(acc), headers=headers, stream=True, timeout=(15, 300))
        r.raise_for_status()
    else:
        r = _rest_open_download_response(acc, file_id, range_header=range_header)

    def _gen():
        try:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
        finally:
            r.close()

    return _gen()


def download_file(file_id, account_id=None):
    meta = get_file_meta(file_id, account_id=account_id)
    buf = io.BytesIO()
    for chunk in stream_file_range(file_id, start=0, end=None, account_id=account_id):
        buf.write(chunk)
    return buf.getvalue(), meta["name"], meta["mimeType"]


def create_folder(parent_id, name, account_id=None):
    acc = _require_account(account_id)
    name = (name or "New Folder").strip()
    if acc.get("auth_type") == "webdav":
        base_norm = _webdav_norm_path(parent_id)
        new_norm = f"/{name}" if base_norm == "/" else f"{base_norm.rstrip('/')}/{name}"
        url = _webdav_build_url(acc, new_norm)
        r = requests.request("MKCOL", url, auth=_webdav_auth(acc), timeout=20)
        if r.status_code not in (200, 201, 204, 405):
            r.raise_for_status()
        return new_norm

    base = _rest_base(acc)
    headers = _rest_headers(acc, "application/json")
    _, clean_parent = _parse_rest_id(parent_id)
    parent_val = None
    if clean_parent:
        parent_val = int(clean_parent) if str(clean_parent).isdigit() else clean_parent

    body = {"name": name, "parent_id": parent_val}
    r = requests.post(f"{base}/api/folders", headers=headers, json=body, timeout=20)
    r.raise_for_status()
    data = r.json()
    folder = data.get("data") or data.get("folder") or data.get("fileEntry") or data
    raw_fid = folder.get("id") if isinstance(folder, dict) else None
    if raw_fid is not None:
        return f"folder:{raw_fid}"
    return f"folder:{name}"


def ensure_folder_path(base_folder_id, parts, account_id=None):
    curr_id = base_folder_id or "root"
    for part in parts:
        part = part.strip()
        if not part or part in (".", ".."):
            continue
        existing = list_files(curr_id, account_id=account_id)
        found_id = None
        for item in existing:
            if item.get("type") == "folder" and item.get("name") == part:
                found_id = item.get("id")
                break
        if found_id:
            curr_id = found_id
        else:
            curr_id = create_folder(curr_id, part, account_id=account_id)
    return curr_id


class _MultipartStreamReader:
    """
    Streams a multipart/form-data body (preamble + file stream + epilogue)
    in small chunks without buffering the file in memory or on disk.
    """
    def __init__(self, preamble: bytes, stream_obj, file_size: int, epilogue: bytes):
        self._preamble = memoryview(preamble)
        self._preamble_pos = 0
        self._stream = stream_obj
        self._file_remaining = max(0, int(file_size))
        self._epilogue = memoryview(epilogue)
        self._epilogue_pos = 0
        self.total_length = len(preamble) + max(0, int(file_size)) + len(epilogue)

    def __len__(self):
        return self.total_length

    def read(self, size=65536):
        if size is None or size < 0:
            size = 65536
        if self._preamble_pos < len(self._preamble):
            take = min(size, len(self._preamble) - self._preamble_pos)
            chunk = bytes(self._preamble[self._preamble_pos:self._preamble_pos + take])
            self._preamble_pos += take
            return chunk
        if self._file_remaining > 0:
            to_read = min(size, self._file_remaining)
            chunk = self._stream.read(to_read)
            if chunk:
                self._file_remaining -= len(chunk)
                return chunk
            self._file_remaining = 0
        if self._epilogue_pos < len(self._epilogue):
            take = min(size, len(self._epilogue) - self._epilogue_pos)
            chunk = bytes(self._epilogue[self._epilogue_pos:self._epilogue_pos + take])
            self._epilogue_pos += take
            return chunk
        return b""


def resolve_upload_target(parent_id, filename, relative_path=None, account_id=None):
    target_parent = parent_id or "root"
    actual_name = filename
    if relative_path:
        norm = relative_path.replace("\\", "/").strip("/")
        parts = [p for p in norm.split("/") if p and p not in (".", "..")]
        if len(parts) > 1:
            target_parent = ensure_folder_path(target_parent, parts[:-1], account_id=account_id)
            actual_name = parts[-1]
        elif len(parts) == 1:
            actual_name = parts[0]
    return target_parent, actual_name


def upload_file(
    parent_id,
    filename,
    data_or_stream,
    mime_type="application/octet-stream",
    relative_path=None,
    account_id=None,
    total_size=None,
):
    acc = _require_account(account_id)
    target_parent, actual_name = resolve_upload_target(
        parent_id, filename, relative_path=relative_path, account_id=account_id
    )

    if acc.get("auth_type") == "webdav":
        base_norm = _webdav_norm_path(target_parent)
        dest_norm = f"/{actual_name}" if base_norm == "/" else f"{base_norm.rstrip('/')}/{actual_name}"
        url = _webdav_build_url(acc, dest_norm)
        headers = {"Content-Type": mime_type or "application/octet-stream"}
        if isinstance(data_or_stream, (bytes, bytearray)):
            body = bytes(data_or_stream)
            headers["Content-Length"] = str(len(body))
        else:
            if total_size is not None and int(total_size) >= 0:
                headers["Content-Length"] = str(int(total_size))
                if int(total_size) == 0:
                    body = b""
                else:
                    body = data_or_stream
            else:
                if hasattr(data_or_stream, "seek"):
                    try:
                        data_or_stream.seek(0)
                    except Exception:
                        pass
                body = data_or_stream
        r = requests.put(
            url,
            auth=_webdav_auth(acc),
            headers=headers,
            data=body,
            timeout=(20, 14400),
        )
        r.raise_for_status()
        return dest_norm

    upload_url = _rest_upload_url(acc)
    headers = {"Authorization": f"Bearer {acc.get('api_token') or ''}", "Accept": "application/json"}
    _, clean_parent = _parse_rest_id(target_parent)
    form_data = {}
    if clean_parent:
        form_data["folder_id"] = str(clean_parent)

    if isinstance(data_or_stream, (bytes, bytearray)):
        stream_obj = io.BytesIO(data_or_stream)
        if total_size is None:
            total_size = len(data_or_stream)
    else:
        stream_obj = data_or_stream

    # When total_size is known, stream multipart/form-data directly to https://uploads.filejump.com/api/upload
    if total_size is not None and int(total_size) >= 0 and not hasattr(stream_obj, "seek"):
        boundary = f"----SageDriveBoundary{secrets.token_hex(12)}"
        parts_buf = []
        for k, v in form_data.items():
            parts_buf.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
                f"{v}\r\n"
            )
        safe_fn = actual_name.replace('"', "%22")
        parts_buf.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{safe_fn}"\r\n'
            f"Content-Type: {mime_type or 'application/octet-stream'}\r\n\r\n"
        )
        preamble = "".join(parts_buf).encode("utf-8")
        epilogue = f"\r\n--{boundary}--\r\n".encode("utf-8")
        mp_reader = _MultipartStreamReader(preamble, stream_obj, int(total_size), epilogue)
        req_headers = dict(headers)
        req_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        req_headers["Content-Length"] = str(mp_reader.total_length)
        r = requests.post(
            upload_url,
            headers=req_headers,
            data=mp_reader,
            timeout=(20, 14400),
        )
        r.raise_for_status()
        resp = r.json()
        entry = resp.get("data") or resp.get("file") or resp.get("fileEntry") or resp
        return str((entry.get("id") if isinstance(entry, dict) else None) or actual_name)

    if hasattr(stream_obj, "seek"):
        try:
            stream_obj.seek(0)
        except Exception:
            pass
    files = {"file": (actual_name, stream_obj, mime_type or "application/octet-stream")}
    r = requests.post(upload_url, headers=headers, data=form_data, files=files, timeout=(20, 14400))
    r.raise_for_status()
    resp = r.json()
    entry = resp.get("data") or resp.get("file") or resp.get("fileEntry") or resp
    return str((entry.get("id") if isinstance(entry, dict) else None) or actual_name)


def update_file_content(file_id, data_or_stream, mime_type="text/plain; charset=utf-8", account_id=None):
    acc = _require_account(account_id)
    if isinstance(data_or_stream, str):
        raw_bytes = data_or_stream.encode("utf-8")
    elif isinstance(data_or_stream, (bytes, bytearray)):
        raw_bytes = bytes(data_or_stream)
    else:
        raw_bytes = data_or_stream.read()

    if acc.get("auth_type") == "webdav":
        url = _webdav_build_url(acc, file_id)
        r = requests.put(
            url,
            auth=_webdav_auth(acc),
            headers={"Content-Type": mime_type or "text/plain; charset=utf-8"},
            data=raw_bytes,
            timeout=60,
        )
        r.raise_for_status()
        return {"id": _webdav_norm_path(file_id), "size": len(raw_bytes)}

    raw_entry = _rest_get_entry_raw(acc, file_id)
    parent_id = raw_entry.get("folder_id") or raw_entry.get("parent_id") or "root"
    name = raw_entry.get("name") or raw_entry.get("file_name") or "file.txt"
    new_id = upload_file(parent_id, name, raw_bytes, mime_type=mime_type, account_id=account_id)
    if str(new_id) != str(file_id):
        try:
            delete_file(file_id, account_id=account_id)
        except Exception:
            pass
    return {"id": new_id, "size": len(raw_bytes)}


def move_file(file_id, dest_folder_id, account_id=None):
    acc = _require_account(account_id)
    if acc.get("auth_type") == "webdav":
        src_norm = _webdav_norm_path(file_id)
        base_name = posixpath.basename(src_norm.rstrip("/"))
        dest_dir = _webdav_norm_path(dest_folder_id)
        new_norm = f"/{base_name}" if dest_dir == "/" else f"{dest_dir.rstrip('/')}/{base_name}"
        if new_norm == src_norm:
            return {"id": src_norm}
        src_url = _webdav_build_url(acc, src_norm)
        dest_url = _webdav_build_url(acc, new_norm)
        r = requests.request(
            "MOVE",
            src_url,
            auth=_webdav_auth(acc),
            headers={"Destination": dest_url, "Overwrite": "T"},
            timeout=30,
        )
        r.raise_for_status()
        return {"id": new_norm}

    base = _rest_base(acc)
    headers = _rest_headers(acc, "application/json")
    is_folder_hint, clean_id = _parse_rest_id(file_id)
    _, clean_dest = _parse_rest_id(dest_folder_id)
    dest_val = None
    if clean_dest:
        dest_val = int(clean_dest) if str(clean_dest).isdigit() else clean_dest

    q_id = quote(str(clean_id))
    if is_folder_hint:
        endpoints = [
            (f"/api/folders/{q_id}/move", {"parent_id": dest_val}),
        ]
    else:
        endpoints = [
            (f"/api/files/{q_id}/move", {"folder_id": dest_val, "workspace_id": None}),
            (f"/api/folders/{q_id}/move", {"parent_id": dest_val}),
        ]

    last_resp = None
    for ep, payload in endpoints:
        r = requests.post(f"{base}{ep}", headers=headers, json=payload, timeout=30)
        if r.status_code == 404:
            last_resp = r
            continue
        r.raise_for_status()
        return r.json()

    if last_resp is not None:
        last_resp.raise_for_status()
    raise RuntimeError(f"Failed to move FileJump item '{file_id}'")


def rename_file(file_id, new_name, account_id=None):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("New name cannot be empty")
    acc = _require_account(account_id)
    if acc.get("auth_type") == "webdav":
        src_norm = _webdav_norm_path(file_id)
        parent_dir = posixpath.dirname(src_norm.rstrip("/")) or "/"
        new_norm = f"/{new_name}" if parent_dir == "/" else f"{parent_dir.rstrip('/')}/{new_name}"
        src_url = _webdav_build_url(acc, src_norm)
        dest_url = _webdav_build_url(acc, new_norm)
        r = requests.request(
            "MOVE",
            src_url,
            auth=_webdav_auth(acc),
            headers={"Destination": dest_url, "Overwrite": "T"},
            timeout=30,
        )
        r.raise_for_status()
        return {"id": new_norm, "name": new_name}

    base = _rest_base(acc)
    headers = _rest_headers(acc, "application/json")
    is_folder_hint, clean_id = _parse_rest_id(file_id)
    q_id = quote(str(clean_id))
    if is_folder_hint:
        endpoints = [f"/api/folders/{q_id}"]
    else:
        endpoints = [f"/api/files/{q_id}", f"/api/folders/{q_id}"]

    last_resp = None
    for ep in endpoints:
        r = requests.put(f"{base}{ep}", headers=headers, json={"name": new_name}, timeout=20)
        if r.status_code == 404:
            last_resp = r
            continue
        if r.status_code < 400:
            return r.json()
        last_resp = r
    if last_resp is not None:
        last_resp.raise_for_status()
    raise RuntimeError(f"Failed to rename FileJump item '{file_id}'")


def delete_file(file_id, account_id=None):
    acc = _require_account(account_id)
    if acc.get("auth_type") == "webdav":
        url = _webdav_build_url(acc, file_id)
        r = requests.delete(url, auth=_webdav_auth(acc), timeout=30)
        if r.status_code not in (200, 204, 404):
            r.raise_for_status()
        return

    base = _rest_base(acc)
    headers = _rest_headers(acc, "application/json")
    is_folder_hint, clean_id = _parse_rest_id(file_id)
    q_id = quote(str(clean_id))
    if is_folder_hint:
        candidates = [
            (f"/api/folders/{q_id}", "delete", None),
        ]
    else:
        candidates = [
            (f"/api/files/{q_id}", "delete", None),
            (f"/api/folders/{q_id}", "delete", None),
        ]

    last_resp = None
    for ep, method, payload in candidates:
        r = getattr(requests, method)(f"{base}{ep}", headers=headers, json=payload, timeout=30)
        if r.status_code < 400:
            return
        last_resp = r
    if last_resp is not None and last_resp.status_code != 404:
        last_resp.raise_for_status()


def _add_filejump_item_to_zip(zf, file_id, arc_prefix="", account_id=None):
    meta = get_file_meta(file_id, account_id=account_id)
    name = meta["name"]
    arc_path = f"{arc_prefix}/{name}".lstrip("/") if arc_prefix else name
    if meta["isFolder"]:
        children = list_files(file_id, account_id=account_id)
        if not children:
            zinfo = zipfile.ZipInfo(arc_path.rstrip("/") + "/")
            zf.writestr(zinfo, b"")
        else:
            for ch in children:
                _add_filejump_item_to_zip(zf, ch["id"], arc_path, account_id=account_id)
    else:
        zinfo = zipfile.ZipInfo(arc_path)
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        with zf.open(zinfo, mode="w", force_zip64=True) as dest:
            for chunk in stream_file_range(file_id, start=0, end=None, account_id=account_id):
                dest.write(chunk)


def create_zip_tmpfile(file_ids, account_id=None):
    tmp = tempfile.NamedTemporaryFile(prefix="sagedrive_fj_zip_", suffix=".zip", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        with zipfile.ZipFile(tmp_path, mode="w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for fid in file_ids:
                if not fid:
                    continue
                _add_filejump_item_to_zip(zf, str(fid), "", account_id=account_id)
        size = os.path.getsize(tmp_path)
        return tmp_path, size
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise
