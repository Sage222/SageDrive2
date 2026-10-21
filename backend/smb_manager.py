import json, os, io, socket, tempfile
from pathlib import Path
from smb.SMBConnection import SMBConnection

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
SHARES_FILE = DATA_DIR / "smb_shares.json"

def _load(): return json.loads(SHARES_FILE.read_text()) if SHARES_FILE.exists() else []
def _save(s): SHARES_FILE.write_text(json.dumps(s, indent=2))
def list_shares(): return _load()

def add_share(name, host, share, username, password, port=445):
    sid = name.lower().replace(" ", "_")
    shares = [s for s in _load() if s["id"] != sid]
    entry = {"id": sid, "name": name, "host": host, "share": share,
             "username": username, "password": password, "port": port}
    shares.append(entry)
    _save(shares)
    return entry

def remove_share(share_id):
    _save([s for s in _load() if s["id"] != share_id])

def _resolve(host):
    try: return socket.gethostbyaddr(host)[0].split(".")[0].upper()
    except Exception: return host.split(".")[0].upper()

def _conn(cfg):
    host = cfg["host"]
    port = int(cfg.get("port", 445))
    c = SMBConnection(
        cfg["username"], cfg["password"],
        "SAGEDRIVE", _resolve(host),
        use_ntlm_v2=True,
        is_direct_tcp=(port == 445),
    )
    if not c.connect(host, port):
        raise ConnectionError(f"SMB connect failed for {host}:{port}")
    return c

def _cfg(share_id):
    s = {s["id"]: s for s in _load()}.get(share_id)
    if not s: raise ValueError(f"Share {share_id!r} not found")
    return s

def browse(share_id, path="/"):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        return [{"name": e.filename, "type": "folder" if e.isDirectory else "file",
                 "size": e.file_size, "modified": e.last_write_time,
                 "path": path.rstrip("/") + "/" + e.filename}
                for e in c.listPath(cfg["share"], path) if e.filename not in (".", "..")]
    finally: c.close()

def get_file_size(share_id, path):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        attrs = c.getAttributes(cfg["share"], path)
        return attrs.file_size
    finally:
        c.close()

def stream_file_range(share_id, path, start=0, length=None, chunk_size=262144):
    """
    Generator that streams a byte range [start, start + length) directly from SMB
    using retrieveFileFromOffset without downloading the whole file to /tmp first.
    """
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        offset = start
        remaining = length
        while remaining is None or remaining > 0:
            to_read = chunk_size if remaining is None else min(chunk_size, remaining)
            buf = io.BytesIO()
            c.retrieveFileFromOffset(cfg["share"], path, buf, offset=offset, max_length=to_read)
            data = buf.getvalue()
            if not data:
                break
            offset += len(data)
            if remaining is not None:
                remaining -= len(data)
            yield data
    finally:
        c.close()

def retrieve_to_tmpfile(share_id, path):
    """
    Download the full file from SMB into a temp file on disk.
    Returns (tmp_path, filename, file_size). Caller must delete tmp_path.
    """
    cfg = _cfg(share_id)
    c = _conn(cfg)
    filename = path.split("/")[-1]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + filename)
    try:
        c.retrieveFile(cfg["share"], path, tmp)
        tmp.flush()
        size = tmp.tell()
        tmp.close()
        return tmp.name, filename, size
    except Exception:
        tmp.close()
        os.unlink(tmp.name)
        raise
    finally:
        c.close()

def upload_file(share_id, dest_path, data):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try: c.storeFile(cfg["share"], dest_path, io.BytesIO(data))
    finally: c.close()

def delete_path(share_id, path, is_dir=False):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        if is_dir: c.deleteDirectory(cfg["share"], path)
        else: c.deleteFiles(cfg["share"], path)
    finally: c.close()

def create_directory(share_id, path):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try: c.createDirectory(cfg["share"], path)
    finally: c.close()
