import json, os, io, re, socket, tempfile, queue, threading, zipfile, secrets
from pathlib import Path
from smb.SMBConnection import SMBConnection

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
SHARES_FILE = DATA_DIR / "smb_shares.json"


def _load():
    return json.loads(SHARES_FILE.read_text()) if SHARES_FILE.exists() else []


def _save(s):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SHARES_FILE.write_text(json.dumps(s, indent=2))


def list_shares():
    return _load()


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


def add_share(name, host, share, username="", password="", port=445, custom_name=""):
    shares = _load()
    base_sid = re.sub(r"[^a-z0-9_]+", "_", name.strip().lower()).strip("_") or "smb_share"
    sid = base_sid
    conflict = next(
        (s for s in shares if s["id"] == sid and (s.get("host") != host or s.get("share") != share)),
        None,
    )
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
    _save(shares)
    return entry


def rename_share(share_id, new_name):
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("Custom name cannot be empty")
    shares = _load()
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
    _save(shares)
    return target


def remove_share(share_id):
    _save([s for s in _load() if s["id"] != share_id])


def _resolve(host):
    try:
        return socket.gethostbyaddr(host)[0].split(".")[0].upper()
    except Exception:
        return host.split(".")[0].upper()


def _conn(cfg):
    host = cfg["host"]
    port = int(cfg.get("port", 445))
    c = SMBConnection(
        cfg["username"],
        cfg["password"],
        "SAGEDRIVE",
        _resolve(host),
        use_ntlm_v2=True,
        is_direct_tcp=(port == 445),
    )
    if not c.connect(host, port):
        raise ConnectionError(f"SMB connect failed for {host}:{port}")
    return c


def sanitize_smb_path(path, allow_root=True):
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


def _cfg(share_id):
    s = {s["id"]: s for s in _load()}.get(share_id)
    if not s:
        raise ValueError(f"Share {share_id!r} not found")
    return s


def browse(share_id, path="/"):
    norm_path = sanitize_smb_path(path, allow_root=True)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        return [
            {
                "name": e.filename,
                "type": "folder" if e.isDirectory else "file",
                "size": e.file_size,
                "modified": e.last_write_time,
                "path": norm_path.rstrip("/") + "/" + e.filename,
            }
            for e in c.listPath(cfg["share"], norm_path)
            if e.filename not in (".", "..")
        ]
    finally:
        c.close()


def path_exists(share_id, path):
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        attrs = c.getAttributes(cfg["share"], norm_path)
        return {
            "exists": True,
            "type": "folder" if attrs.isDirectory else "file",
            "size": int(attrs.file_size or 0),
        }
    except Exception:
        return {"exists": False}
    finally:
        c.close()


def get_file_size(share_id, path):
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        attrs = c.getAttributes(cfg["share"], norm_path)
        return attrs.file_size
    finally:
        c.close()


def stream_file_range(share_id, path, start=0, length=None, chunk_size=262144):
    """
    Streams a byte range [start, start + length) from SMB using
    retrieveFileFromOffset (or retrieveFile) in a background thread with a 4-hour
    transfer timeout and automatic byte-accurate reconnect/resume if the SMB
    connection drops mid-stream. Aborts immediately if the caller closes the
    generator early (e.g. during Range seeking or ffprobe).
    """
    norm_path = sanitize_smb_path(path, allow_root=False)
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
            cfg = _cfg(share_id)
            while not aborted.is_set():
                if writer.remaining is not None and writer.remaining <= 0:
                    break
                c = None
                prev_written = writer.written
                try:
                    c = _conn(cfg)
                    curr_offset = start + writer.written
                    if curr_offset == 0 and writer.remaining is None:
                        c.retrieveFile(cfg["share"], norm_path, writer, timeout=smb_op_timeout)
                    else:
                        max_len = writer.remaining if (writer.remaining is not None and writer.remaining > 0) else -1
                        c.retrieveFileFromOffset(
                            cfg["share"],
                            norm_path,
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


def retrieve_to_tmpfile(share_id, path):
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    filename = norm_path.split("/")[-1]
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix="_" + filename)
    try:
        c.retrieveFile(cfg["share"], norm_path, tmp)
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
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    buf = io.BytesIO()
    try:
        c.retrieveFile(cfg["share"], norm_path, buf)
        return buf.getvalue()
    finally:
        c.close()


def _ensure_dirs_on_conn(c, share_name, dir_path):
    norm_dir = sanitize_smb_path(dir_path, allow_root=True)
    parts = [p for p in norm_dir.split("/") if p]
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


def _resolve_conflict_path_on_conn(c, share_name, target_path, conflict_action="replace"):
    action = (conflict_action or "replace").strip().lower()
    if action not in ("skip", "keep_both", "replace"):
        action = "replace"
    try:
        attrs = c.getAttributes(share_name, target_path)
        exists = True
        is_dir = attrs.isDirectory
    except Exception:
        exists = False
        is_dir = False

    if not exists:
        return target_path, False

    if action == "skip":
        return target_path, True

    if action == "keep_both":
        parent = "/".join(target_path.rstrip("/").split("/")[:-1]) or "/"
        base_name = target_path.rstrip("/").split("/")[-1]
        try:
            siblings = [e.filename for e in c.listPath(share_name, parent) if e.filename not in (".", "..")]
        except Exception:
            siblings = [base_name]
        unique_name = generate_unique_name(base_name, siblings)
        new_target = (parent.rstrip("/") + "/" + unique_name) if parent != "/" else ("/" + unique_name)
        return new_target, False

    # action == "replace": if target exists and we will be renaming/moving onto it, caller can delete it
    return target_path, False


def upload_file(share_id, dest_path, data_or_stream, conflict_action="replace"):
    norm_path = sanitize_smb_path(dest_path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        parent = "/".join(norm_path.split("/")[:-1])
        if parent and parent != "/":
            _ensure_dirs_on_conn(c, cfg["share"], parent)
        resolved_path, should_skip = _resolve_conflict_path_on_conn(
            c, cfg["share"], norm_path, conflict_action=conflict_action
        )
        if should_skip:
            return resolved_path
        file_obj = data_or_stream if hasattr(data_or_stream, "read") else io.BytesIO(
            data_or_stream if isinstance(data_or_stream, (bytes, bytearray)) else str(data_or_stream).encode("utf-8")
        )
        c.storeFile(cfg["share"], resolved_path, file_obj)
        return resolved_path
    finally:
        c.close()


def upload_chunk(share_id, dest_path, chunk_bytes, offset=0, truncate=False):
    norm_path = sanitize_smb_path(dest_path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        if offset == 0:
            parent = "/".join(norm_path.split("/")[:-1])
            if parent and parent != "/":
                _ensure_dirs_on_conn(c, cfg["share"], parent)
        bio = io.BytesIO(chunk_bytes if isinstance(chunk_bytes, (bytes, bytearray)) else bytes(chunk_bytes))
        c.storeFileFromOffset(
            cfg["share"],
            norm_path,
            bio,
            offset=int(offset or 0),
            truncate=bool(truncate),
            timeout=300,
        )
    finally:
        c.close()


def prepare_upload_target(share_id, dest_path, conflict_action="keep_both"):
    """Ensure parent directories exist on SMB share and resolve filename conflicts. Returns (resolved_path, should_skip)."""
    norm_path = sanitize_smb_path(dest_path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        parent = "/".join(norm_path.split("/")[:-1])
        if parent and parent != "/":
            _ensure_dirs_on_conn(c, cfg["share"], parent)
        return _resolve_conflict_path_on_conn(
            c, cfg["share"], norm_path, conflict_action=conflict_action
        )
    finally:
        c.close()


class PersistentSMBWriter:
    """
    Maintains a single persistent SMBConnection across an entire file stream
    to eliminate per-chunk TCP + SMB authentication handshake overhead.
    Automatically reconnects and retries if the connection drops mid-transfer.
    """

    def __init__(self, share_id: str, resolved_path: str):
        self.share_id = share_id
        self.norm_path = sanitize_smb_path(resolved_path, allow_root=False)
        self.cfg = _cfg(share_id)
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None:
            self.conn = _conn(self.cfg)
        return self.conn

    def _reset_conn(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def write_chunk(self, chunk_bytes: bytes, offset: int = 0, truncate: bool = False):
        payload = chunk_bytes if isinstance(chunk_bytes, (bytes, bytearray)) else bytes(chunk_bytes)
        last_err = None
        for attempt in range(3):
            try:
                c = self._ensure_conn()
                if offset == 0 and attempt == 0:
                    parent = "/".join(self.norm_path.split("/")[:-1])
                    if parent and parent != "/":
                        _ensure_dirs_on_conn(c, self.cfg["share"], parent)
                bio = io.BytesIO(payload)
                c.storeFileFromOffset(
                    self.cfg["share"],
                    self.norm_path,
                    bio,
                    offset=int(offset or 0),
                    truncate=bool(truncate),
                    timeout=300,
                )
                return
            except Exception as exc:
                last_err = exc
                self._reset_conn()
        if last_err is not None:
            raise last_err

    def close(self):
        self._reset_conn()


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


def rename_path(share_id, old_path, new_name, conflict_action="replace"):
    norm_old = sanitize_smb_path(old_path, allow_root=False)
    clean_name = (new_name or "").replace("\x00", "").replace("/", "").replace("\\", "").strip()
    if not clean_name or clean_name in (".", ".."):
        raise ValueError("Invalid new name")
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        parent = "/".join(norm_old.rstrip("/").split("/")[:-1])
        new_path = (parent + "/" + clean_name) if parent else ("/" + clean_name)
        if new_path == norm_old:
            return new_path
        action = (conflict_action or "replace").strip().lower()
        try:
            existing_attrs = c.getAttributes(cfg["share"], new_path)
        except Exception:
            existing_attrs = None
        if existing_attrs is not None and new_path.lower() != norm_old.lower():
            if action == "skip":
                return norm_old
            elif action == "keep_both":
                resolved_path, _ = _resolve_conflict_path_on_conn(c, cfg["share"], new_path, conflict_action="keep_both")
                new_path = resolved_path
            elif action == "replace":
                _delete_recursive_on_conn(c, cfg["share"], new_path, existing_attrs.isDirectory)
        c.rename(cfg["share"], norm_old, new_path)
        return new_path
    finally:
        c.close()


def move_path(share_id, old_path, dest_dir, conflict_action="replace"):
    norm_old = sanitize_smb_path(old_path, allow_root=False)
    norm_dest_dir = sanitize_smb_path(dest_dir, allow_root=True)
    base_name = norm_old.rstrip("/").split("/")[-1]
    new_path = (norm_dest_dir.rstrip("/") + "/" + base_name) if norm_dest_dir != "/" else ("/" + base_name)
    if new_path == norm_old:
        return new_path
    if new_path.startswith(norm_old.rstrip("/") + "/"):
        raise ValueError("Cannot move a folder into itself")
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        if norm_dest_dir != "/":
            _ensure_dirs_on_conn(c, cfg["share"], norm_dest_dir)
        action = (conflict_action or "replace").strip().lower()
        try:
            existing_attrs = c.getAttributes(cfg["share"], new_path)
        except Exception:
            existing_attrs = None
        if existing_attrs is not None:
            if action == "skip":
                return norm_old
            elif action == "keep_both":
                resolved_path, _ = _resolve_conflict_path_on_conn(c, cfg["share"], new_path, conflict_action="keep_both")
                new_path = resolved_path
            elif action == "replace":
                _delete_recursive_on_conn(c, cfg["share"], new_path, existing_attrs.isDirectory)
        c.rename(cfg["share"], norm_old, new_path)
        return new_path
    finally:
        c.close()


def delete_path(share_id, path, is_dir=False):
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        _delete_recursive_on_conn(c, cfg["share"], norm_path, is_dir)
    finally:
        c.close()


def create_directory(share_id, path):
    norm_path = sanitize_smb_path(path, allow_root=False)
    cfg = _cfg(share_id)
    c = _conn(cfg)
    try:
        _ensure_dirs_on_conn(c, cfg["share"], norm_path)
    finally:
        c.close()


def create_zip_tmpfile(share_id, paths):
    """
    Creates a temporary .zip archive containing all specified file/folder paths
    from the SMB share by streaming SMB file contents directly into the ZIP
    deflate stream without creating intermediate per-file temp files on disk.
    Returns (tmp_path, zip_size). Caller must unlink tmp_path.
    """
    cfg = _cfg(share_id)
    c = _conn(cfg)
    tmp = tempfile.NamedTemporaryFile(prefix="sagedrive_smb_zip_", delete=False, suffix=".zip")
    tmp.close()

    def _add_to_zip(zf, smb_path, arc_prefix):
        try:
            attrs = c.getAttributes(cfg["share"], smb_path)
        except Exception:
            return
        if attrs.isDirectory:
            entries = [e for e in c.listPath(cfg["share"], smb_path) if e.filename not in (".", "..")]
            if not entries:
                zinfo = zipfile.ZipInfo(arc_prefix.rstrip("/") + "/")
                zf.writestr(zinfo, b"")
            for e in entries:
                child_smb = smb_path.rstrip("/") + "/" + e.filename
                child_arc = (arc_prefix.rstrip("/") + "/" + e.filename) if arc_prefix else e.filename
                _add_to_zip(zf, child_smb, child_arc)
        else:
            zinfo = zipfile.ZipInfo(arc_prefix.lstrip("/"))
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            with zf.open(zinfo, mode="w", force_zip64=True) as dest:
                c.retrieveFile(cfg["share"], smb_path, dest, timeout=14400)

    try:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for p in paths:
                norm_p = sanitize_smb_path(p, allow_root=False)
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
