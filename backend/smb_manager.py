import json, os, io, socket, tempfile, queue, threading, zipfile
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
    Streams a byte range [start, start + length) from SMB using a single
    retrieveFileFromOffset (or retrieveFile) call in a background thread.
    Flushes the final chunk and signals completion before closing the SMB socket
    so HTTP downloads never hang at 100%.
    """
    q = queue.Queue(maxsize=32)
    sentinel = object()

    class _QueueWriter:
        def __init__(self, max_bytes):
            self.remaining = max_bytes
            self.buf = bytearray()

        def write(self, data):
            if not data:
                return 0
            if self.remaining is not None:
                if self.remaining <= 0:
                    return 0
                if len(data) > self.remaining:
                    data = data[:self.remaining]
                self.remaining -= len(data)
            self.buf.extend(data)
            while len(self.buf) >= chunk_size:
                q.put(bytes(self.buf[:chunk_size]))
                del self.buf[:chunk_size]
            return len(data)

        def flush(self):
            if self.buf:
                q.put(bytes(self.buf))
                self.buf.clear()

    def _producer():
        c = None
        try:
            cfg = _cfg(share_id)
            c = _conn(cfg)
            writer = _QueueWriter(length)
            if start == 0 and length is None:
                c.retrieveFile(cfg["share"], path, writer)
            else:
                max_len = length if (length is not None and length > 0) else -1
                c.retrieveFileFromOffset(cfg["share"], path, writer, offset=start, max_length=max_len)
            writer.flush()
        except Exception as e:
            try:
                writer.flush()
            except Exception:
                pass
            q.put(e)
        finally:
            q.put(sentinel)
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass

    threading.Thread(target=_producer, daemon=True).start()

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

def read_file_bytes(share_id, path):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    buf = io.BytesIO()
    try:
        c.retrieveFile(cfg["share"], path, buf)
        return buf.getvalue()
    finally:
        c.close()

def _ensure_dirs_on_conn(c, share_name, dir_path):
    parts = [p for p in dir_path.replace("\\", "/").split("/") if p]
    built = ""
    for part in parts:
        built += "/" + part
        try:
            c.getAttributes(share_name, built)
        except Exception:
            try:
                c.createDirectory(share_name, built)
            except Exception:
                pass

def upload_file(share_id, dest_path, data):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        norm_path = "/" + dest_path.replace("\\", "/").lstrip("/")
        parent = "/".join(norm_path.split("/")[:-1])
        if parent and parent != "/":
            _ensure_dirs_on_conn(c, cfg["share"], parent)
        c.storeFile(cfg["share"], norm_path, io.BytesIO(data))
    finally:
        c.close()

def rename_path(share_id, old_path, new_name):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        norm_old = "/" + old_path.replace("\\", "/").lstrip("/")
        parent = "/".join(norm_old.rstrip("/").split("/")[:-1])
        new_path = (parent + "/" + new_name) if parent else ("/" + new_name)
        c.rename(cfg["share"], norm_old, new_path)
        return new_path
    finally:
        c.close()

def _delete_recursive_on_conn(c, share_name, path, is_dir=False):
    if not is_dir:
        c.deleteFiles(share_name, path)
        return
    for e in c.listPath(share_name, path):
        if e.filename in (".", ".."):
            continue
        child_path = path.rstrip("/") + "/" + e.filename
        if e.isDirectory:
            _delete_recursive_on_conn(c, share_name, child_path, True)
        else:
            c.deleteFiles(share_name, child_path)
    c.deleteDirectory(share_name, path)

def delete_path(share_id, path, is_dir=False):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        _delete_recursive_on_conn(c, cfg["share"], path, is_dir)
    finally:
        c.close()

def create_directory(share_id, path):
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        _ensure_dirs_on_conn(c, cfg["share"], path)
    finally:
        c.close()

def create_zip_tmpfile(share_id, paths):
    """
    Creates a temporary .zip archive containing all specified file/folder paths
    from the SMB share. Returns (tmp_path, zip_size). Caller must unlink tmp_path.
    """
    cfg = _cfg(share_id)
    c = _conn(cfg)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    def _add_to_zip(zf, smb_path, arc_prefix):
        try:
            attrs = c.getAttributes(cfg["share"], smb_path)
        except Exception:
            return
        if attrs.isDirectory:
            entries = [e for e in c.listPath(cfg["share"], smb_path) if e.filename not in (".", "..")]
            if not entries:
                zf.writestr(arc_prefix.rstrip("/") + "/", b"")
            for e in entries:
                child_smb = smb_path.rstrip("/") + "/" + e.filename
                child_arc = (arc_prefix.rstrip("/") + "/" + e.filename) if arc_prefix else e.filename
                _add_to_zip(zf, child_smb, child_arc)
        else:
            file_tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                c.retrieveFile(cfg["share"], smb_path, file_tmp)
                file_tmp.flush()
                file_tmp.close()
                zf.write(file_tmp.name, arcname=arc_prefix)
            finally:
                try:
                    os.unlink(file_tmp.name)
                except Exception:
                    pass

    try:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in paths:
                norm_p = "/" + p.replace("\\", "/").lstrip("/")
                base_name = norm_p.rstrip("/").split("/")[-1] or "root"
                _add_to_zip(zf, norm_p, base_name)
        size = os.path.getsize(tmp.name)
        return tmp.name, size
    except Exception:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
        raise
    finally:
        c.close()
