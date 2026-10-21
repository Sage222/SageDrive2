import json, os, io, tempfile, zipfile, requests
from pathlib import Path
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
CREDS_FILE = DATA_DIR / "gdrive_token.json"
CONFIG_FILE = DATA_DIR / "gdrive_client.json"
SCOPES = ["https://www.googleapis.com/auth/drive"]

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

def is_authenticated():
    if not CREDS_FILE.exists():
        return False
    c = _load_creds()
    return c is not None and (c.valid or bool(c.refresh_token))

def _client_config():
    cfg = get_config()
    return {"web": {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "redirect_uris": [cfg["redirect_uri"]],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }}

def _load_creds():
    if not CREDS_FILE.exists():
        return None
    d = json.loads(CREDS_FILE.read_text())
    cfg = get_config()
    c = Credentials(
        token=d.get("token"),
        refresh_token=d.get("refresh_token"),
        token_uri=d.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=d.get("client_id", cfg["client_id"]),
        client_secret=d.get("client_secret", cfg["client_secret"]),
        scopes=d.get("scopes", SCOPES),
    )
    if not c.valid and c.refresh_token:
        c.refresh(Request())
        _save_creds(c)
    return c if c.valid else None

def _save_creds(c):
    CREDS_FILE.write_text(json.dumps({
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": list(c.scopes or SCOPES),
    }, indent=2))

def _svc():
    c = _load_creds()
    if not c:
        raise RuntimeError("Not authenticated with Google Drive")
    return build("drive", "v3", credentials=c)

def get_auth_url():
    cfg = get_config()
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=cfg["redirect_uri"])
    url, _ = flow.authorization_url(access_type="offline", prompt="consent")
    return url

def handle_callback(code, state):
    cfg = get_config()
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=cfg["redirect_uri"])
    flow.fetch_token(code=code)
    _save_creds(flow.credentials)

def revoke():
    CREDS_FILE.unlink(missing_ok=True)

def list_files(folder_id="root"):
    res = _svc().files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(id,name,mimeType,size,modifiedTime,parents)",
        pageSize=200
    ).execute()
    out = []
    for f in res.get("files", []):
        is_folder = f["mimeType"] == "application/vnd.google-apps.folder"
        out.append({
            "id": f["id"],
            "name": f["name"],
            "type": "folder" if is_folder else "file",
            "size": int(f.get("size", 0)),
            "modified": f.get("modifiedTime", ""),
            "mimeType": f["mimeType"],
        })
    return out

def get_file_meta(file_id):
    svc = _svc()
    meta = svc.files().get(fileId=file_id, fields="name,mimeType,size").execute()
    return {
        "name": meta.get("name", "download"),
        "mimeType": meta.get("mimeType", "application/octet-stream"),
        "size": int(meta.get("size", 0) or 0),
    }

def stream_file_range(file_id, start=0, end=None, chunk_size=262144):
    c = _load_creds()
    if not c:
        raise RuntimeError("Not authenticated with Google Drive")
    headers = {"Authorization": f"Bearer {c.token}"}
    if start is not None and end is not None:
        headers["Range"] = f"bytes={start}-{end}"
    elif start:
        headers["Range"] = f"bytes={start}-"
    url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
    with requests.get(url, headers=headers, stream=True, timeout=60) as r:
        r.raise_for_status()
        for chunk in r.iter_content(chunk_size=chunk_size):
            if chunk:
                yield chunk

def download_file(file_id):
    svc = _svc()
    meta = svc.files().get(fileId=file_id, fields="name,mimeType").execute()
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
        if mime in export_map else svc.files().get_media(fileId=file_id)
    dl = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = dl.next_chunk()
    return buf.getvalue(), name, mime

def ensure_folder_path(base_folder_id, parts):
    """
    Ensures nested folder segments exist under base_folder_id on Google Drive,
    returning the leaf folder ID.
    """
    svc = _svc()
    curr_id = base_folder_id or "root"
    for part in parts:
        if not part:
            continue
        safe_part = part.replace("'", "\\'")
        q = (
            f"'{curr_id}' in parents and name = '{safe_part}' "
            f"and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        )
        res = svc.files().list(q=q, fields="files(id)", pageSize=1).execute()
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
            ).execute()
            curr_id = created["id"]
    return curr_id

def upload_file(parent_id, filename, data, mime_type="application/octet-stream", relative_path=None):
    svc = _svc()
    target_parent = parent_id or "root"
    actual_name = filename
    if relative_path:
        norm_rel = relative_path.replace("\\", "/").lstrip("/")
        segments = [s for s in norm_rel.split("/") if s]
        if len(segments) > 1:
            target_parent = ensure_folder_path(target_parent, segments[:-1])
            actual_name = segments[-1]
        elif segments:
            actual_name = segments[0]
    media = MediaIoBaseUpload(io.BytesIO(data), mimetype=mime_type, resumable=True)
    svc.files().create(
        body={"name": actual_name, "parents": [target_parent]},
        media_body=media,
        fields="id"
    ).execute()

def rename_file(file_id, new_name):
    return _svc().files().update(
        fileId=file_id,
        body={"name": new_name},
        fields="id,name"
    ).execute()

def delete_file(file_id):
    _svc().files().delete(fileId=file_id).execute()

def create_folder(parent_id, name):
    f = _svc().files().create(
        body={
            "name": name,
            "parents": [parent_id],
            "mimeType": "application/vnd.google-apps.folder",
        },
        fields="id"
    ).execute()
    return f["id"]

def create_zip_tmpfile(file_ids):
    """
    Creates a temporary .zip archive containing the specified Google Drive
    files and folders (recursively). Returns (tmp_path, zip_size).
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    def _add_item(zf, fid, arc_prefix):
        meta = get_file_meta(fid)
        name = meta["name"]
        mime = meta["mimeType"]
        arc_path = f"{arc_prefix}/{name}" if arc_prefix else name
        if mime == "application/vnd.google-apps.folder":
            children = list_files(fid)
            if not children:
                zf.writestr(arc_path.rstrip("/") + "/", b"")
            for ch in children:
                _add_item(zf, ch["id"], arc_path)
        else:
            data, _, _ = download_file(fid)
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
