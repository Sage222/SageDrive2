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

DEFAULT_REST_BASE = os.getenv("FILEJUMP_API_URL", "https://drive.filejump.com").rstrip("/")
DEFAULT_WEBDAV_BASE = os.getenv("FILEJUMP_WEBDAV_URL", "https://uploads.filejump.com/dav").rstrip("/")

RESERVED_SMB_NAMES = {"global", "homes", "printers", "print$", "ipc$"}


def sanitize_smb_share_name(raw_name, fallback="FileJump"):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(raw_name or "").strip()).strip("_-")
    if not cleaned or cleaned.lower() in RESERVED_SMB_NAMES:
        cleaned = fallback
    return cleaned[:32]


def _normalize_rest_base(url_str):
    raw = str(url_str or DEFAULT_REST_BASE).strip().rstrip("/")
    if not raw:
        raw = DEFAULT_REST_BASE
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    for suffix in ("/api/v1", "/api"):
        if raw.endswith(suffix):
            raw = raw[:-len(suffix)]
    return raw.rstrip("/")


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
        out.append({
            "id": a.get("id", "default"),
            "name": a.get("custom_name") or a.get("name") or "FileJump",
            "custom_name": a.get("custom_name", ""),
            "original_name": a.get("original_name") or a.get("name") or "FileJump",
            "email": a.get("email", ""),
            "auth_type": a.get("auth_type", "token"),
            "api_url": a.get("api_url") or (DEFAULT_WEBDAV_BASE if a.get("auth_type") == "webdav" else DEFAULT_REST_BASE),
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
    candidates = []
    if base_url:
        candidates.append(_normalize_rest_base(base_url))
    for default_host in ("https://drive.filejump.com", "https://app.filejump.com", "https://filejump.com"):
        if default_host not in candidates:
            candidates.append(default_host)

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Accept": "application/json",
    }

    last_err = None
    for host in candidates:
        for probe_ep in ("/api/v1/drive/file-entries?perPage=1", "/api/v1/file-entries?perPage=1", "/api/v1/users/me"):
            try:
                r = requests.get(f"{host}{probe_ep}", headers=headers, timeout=12)
                if r.status_code in (401, 403):
                    last_err = f"FileJump API rejected token ({r.status_code})"
                    continue
                if r.status_code < 400:
                    data = {}
                    try:
                        data = r.json()
                    except Exception:
                        pass
                    user_obj = data.get("user") if isinstance(data, dict) else None
                    detected_email = email_hint
                    detected_name = ""
                    if isinstance(user_obj, dict):
                        detected_email = user_obj.get("email") or detected_email
                        detected_name = user_obj.get("display_name") or user_obj.get("first_name") or ""
                    return {
                        "api_url": host,
                        "email": detected_email or "",
                        "display_name": detected_name,
                    }
            except Exception as e:
                last_err = str(e)
                continue

    if last_err and "rejected token" in last_err:
        raise ValueError(last_err)
    return {
        "api_url": candidates[0] if candidates else DEFAULT_REST_BASE,
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


# ── REST API Implementation Helpers ───────────────────────────────────────────
def _rest_headers(acc, content_type=None):
    h = {
        "Authorization": f"Bearer {acc.get('api_token') or ''}",
        "Accept": "application/json",
    }
    if content_type:
        h["Content-Type"] = content_type
    return h


def _rest_base(acc):
    return _normalize_rest_base(acc.get("api_url") or DEFAULT_REST_BASE)


def _normalize_rest_entry(item):
    if not isinstance(item, dict):
        return None
    raw_type = str(item.get("type") or "").lower()
    is_folder = raw_type == "folder" or bool(item.get("is_folder"))
    entry_id = str(item.get("id") if item.get("id") is not None else item.get("hash") or "")
    if not entry_id:
        return None
    name = item.get("name") or item.get("file_name") or entry_id
    size = 0 if is_folder else int(item.get("file_size") or item.get("size") or 0)
    modified = item.get("updated_at") or item.get("created_at") or datetime.now(timezone.utc).isoformat()
    mime = (
        "application/vnd.filejump.folder"
        if is_folder
        else (item.get("mime") or mimetypes.guess_type(name)[0] or "application/octet-stream")
    )
    return {
        "id": entry_id,
        "hash": item.get("hash") or entry_id,
        "name": name,
        "type": "folder" if is_folder else "file",
        "size": size,
        "modified": modified,
        "mimeType": mime,
        "url": item.get("url") or "",
    }


def _rest_get_entry_raw(acc, file_id):
    base = _rest_base(acc)
    headers = _rest_headers(acc)
    for ep in (
        f"/api/v1/file-entries/{quote(str(file_id))}",
        f"/api/v1/drive/file-entries/{quote(str(file_id))}",
        f"/api/v1/entries/{quote(str(file_id))}",
    ):
        r = requests.get(f"{base}{ep}", headers=headers, timeout=20)
        if r.status_code == 404:
            continue
        if r.status_code < 400:
            data = r.json()
            if isinstance(data, dict):
                entry = data.get("fileEntry") or data.get("entry") or data.get("data") or data
                if isinstance(entry, dict) and (entry.get("id") is not None or entry.get("name")):
                    return entry
    raise FileNotFoundError(f"FileJump entry '{file_id}' not found")


def _rest_open_download_response(acc, file_id, range_header=None):
    base = _rest_base(acc)
    headers = _rest_headers(acc)
    if range_header:
        headers["Range"] = range_header

    entry_hash = None
    entry_url = None
    try:
        raw = _rest_get_entry_raw(acc, file_id)
        entry_hash = raw.get("hash")
        entry_url = raw.get("url")
    except Exception:
        pass

    candidate_urls = []
    if entry_url:
        if entry_url.startswith(("http://", "https://")):
            candidate_urls.append(entry_url)
        else:
            candidate_urls.append(f"{base}/{entry_url.lstrip('/')}")
    if entry_hash:
        candidate_urls.append(f"{base}/api/v1/file-entries/download/{quote(str(entry_hash))}")
    candidate_urls.extend([
        f"{base}/api/v1/file-entries/download/{quote(str(file_id))}",
        f"{base}/api/v1/file-entries/{quote(str(file_id))}?alt=media",
        f"{base}/api/v1/uploads/{quote(str(file_id))}",
    ])

    last_resp = None
    for url in candidate_urls:
        r = requests.get(url, headers=headers, stream=True, timeout=(15, 300), allow_redirects=True)
        if r.status_code < 400:
            ctype = (r.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype and not url.endswith("alt=media"):
                try:
                    j = r.json()
                    dl_url = j.get("url") or j.get("download_url")
                    if dl_url:
                        r.close()
                        dl_headers = {"Range": range_header} if range_header else {}
                        r2 = requests.get(dl_url, headers=dl_headers, stream=True, timeout=(15, 300))
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
    params = {"perPage": 500}
    if folder_id and folder_id not in ("root", "/", "0"):
        params["folderId"] = folder_id
        params["parentIds"] = folder_id

    for ep in ("/api/v1/drive/file-entries", "/api/v1/file-entries"):
        r = requests.get(f"{base}{ep}", headers=headers, params=params, timeout=30)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        payload = r.json()
        raw_list = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(raw_list, list) and isinstance(payload, dict):
            raw_list = payload.get("fileEntries") or payload.get("entries") or []
        out = []
        for raw_item in raw_list or []:
            norm = _normalize_rest_entry(raw_item)
            if norm:
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

    return []


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

    raw = _rest_get_entry_raw(acc, file_id)
    norm = _normalize_rest_entry(raw)
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
    body = {"name": name}
    if parent_id and parent_id not in ("root", "/", "0"):
        body["parentId"] = parent_id
    r = requests.post(f"{base}/api/v1/folders", headers=headers, json=body, timeout=20)
    r.raise_for_status()
    data = r.json()
    folder = data.get("folder") or data.get("fileEntry") or data.get("data") or data
    return str(folder.get("id") or folder.get("hash") or name)


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


def upload_file(parent_id, filename, data_or_stream, mime_type="application/octet-stream", relative_path=None, account_id=None):
    acc = _require_account(account_id)
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

    if acc.get("auth_type") == "webdav":
        base_norm = _webdav_norm_path(target_parent)
        dest_norm = f"/{actual_name}" if base_norm == "/" else f"{base_norm.rstrip('/')}/{actual_name}"
        url = _webdav_build_url(acc, dest_norm)
        if isinstance(data_or_stream, (bytes, bytearray)):
            body = bytes(data_or_stream)
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
            headers={"Content-Type": mime_type or "application/octet-stream"},
            data=body,
            timeout=(20, 1800),
        )
        r.raise_for_status()
        return dest_norm

    base = _rest_base(acc)
    headers = {"Authorization": f"Bearer {acc.get('api_token') or ''}", "Accept": "application/json"}
    form_data = {}
    if target_parent and target_parent not in ("root", "/", "0"):
        form_data["parentId"] = str(target_parent)

    if isinstance(data_or_stream, (bytes, bytearray)):
        stream_obj = io.BytesIO(data_or_stream)
    else:
        if hasattr(data_or_stream, "seek"):
            try:
                data_or_stream.seek(0)
            except Exception:
                pass
        stream_obj = data_or_stream

    last_err = None
    for ep in ("/api/v1/uploads", "/api/v1/file-entries", "/api/v1/files"):
        try:
            if hasattr(stream_obj, "seek"):
                stream_obj.seek(0)
            files = {"file": (actual_name, stream_obj, mime_type or "application/octet-stream")}
            r = requests.post(f"{base}{ep}", headers=headers, data=form_data, files=files, timeout=(20, 1800))
            if r.status_code == 404:
                continue
            r.raise_for_status()
            resp = r.json()
            entry = resp.get("fileEntry") or resp.get("data") or resp
            return str(entry.get("id") or entry.get("hash") or actual_name)
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("FileJump upload failed")


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
    parent_id = raw_entry.get("parent_id") or "root"
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
    dest_val = None if (not dest_folder_id or dest_folder_id in ("root", "/", "0")) else dest_folder_id
    r = requests.post(
        f"{base}/api/v1/file-entries/move",
        headers=headers,
        json={"entryIds": [file_id], "destinationId": dest_val},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


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
    for method in ("put", "patch", "post"):
        r = getattr(requests, method)(
            f"{base}/api/v1/file-entries/{quote(str(file_id))}",
            headers=headers,
            json={"name": new_name},
            timeout=20,
        )
        if r.status_code < 400:
            return r.json()
    r.raise_for_status()


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
    for ep, method, payload in (
        ("/api/v1/file-entries/delete", "post", {"entryIds": [file_id], "deleteForever": False}),
        ("/api/v1/file-entries", "delete", {"entryIds": [file_id]}),
        (f"/api/v1/file-entries/{quote(str(file_id))}", "delete", None),
    ):
        r = getattr(requests, method)(f"{base}{ep}", headers=headers, json=payload, timeout=30)
        if r.status_code < 400 or r.status_code == 404:
            return
    r.raise_for_status()


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
