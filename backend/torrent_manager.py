import base64
import ctypes
import hashlib
import json
import mimetypes
import os
import posixpath
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import filejump_manager
import gdrive_manager

try:
    import libtorrent as lt
    LIBTORRENT_AVAILABLE = True
    LIBTORRENT_VERSION = getattr(lt, "__version__", getattr(lt, "version", "available"))
except Exception:
    lt = None
    LIBTORRENT_AVAILABLE = False
    LIBTORRENT_VERSION = None

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
TORRENTS_STATE_FILE = DATA_DIR / "torrents_state.json"
TORRENT_SETTINGS_FILE = DATA_DIR / "torrent_settings.json"
TORRENT_META_DIR = DATA_DIR / "torrent_meta"
SCRATCH_ROOT = Path(os.environ.get("TORRENT_SCRATCH_DIR", "/tmp/sagedrive_torrents"))

MAX_TORRENT_FILE_BYTES = 15 * 1024 * 1024  # 15 MiB cap for .torrent metadata uploads
DEFAULT_SETTINGS = {
    "listen_port": 6881,
    "window_mb": 24,
    "max_connections": 60,
    "download_rate_limit_kbps": 0,  # 0 = unlimited
    "default_conflict_action": "keep_both",
}

# Linux fallocate flags for releasing already-streamed blocks back to the OS
_FALLOC_FL_KEEP_SIZE = 0x01
_FALLOC_FL_PUNCH_HOLE = 0x02
_libc = None
try:
    _libc = ctypes.CDLL("libc.so.6", use_errno=True)
    _libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong]
    _libc.fallocate.restype = ctypes.c_int
except Exception:
    _libc = None


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _punch_hole_fd(fd: int, offset: int, length: int):
    """Immediately release already-uploaded byte blocks back to the OS kernel."""
    if _libc is None or fd is None or length <= 0 or offset < 0:
        return False
    try:
        res = _libc.fallocate(fd, _FALLOC_FL_PUNCH_HOLE | _FALLOC_FL_KEEP_SIZE, int(offset), int(length))
        return res == 0
    except Exception:
        return False


def _sanitize_rel_path(raw_path: str) -> str:
    cleaned = str(raw_path or "").replace("\x00", "").replace("\\", "/").strip("/")
    parts = [p.strip() for p in cleaned.split("/") if p.strip() and p.strip() not in (".", "..")]
    if not parts:
        return "file"
    safe_parts = [re.sub(r'[<>:"|?*\x00-\x1f]+', "_", p) for p in parts]
    return "/".join(safe_parts)


# ── Pure-Python Bencode Parser (for instant, dependency-free .torrent inspection) ──
def _bdecode_next(data: bytes, idx: int, depth: int = 0):
    if depth > 64:
        raise ValueError("Torrent metadata nesting too deep")
    if idx >= len(data):
        raise ValueError("Unexpected end of bencoded data")
    ch = data[idx:idx + 1]
    if ch == b"i":
        end = data.index(b"e", idx + 1)
        val = int(data[idx + 1:end])
        return val, end + 1
    if ch == b"l":
        idx += 1
        out = []
        while idx < len(data) and data[idx:idx + 1] != b"e":
            item, idx = _bdecode_next(data, idx, depth + 1)
            out.append(item)
        if idx >= len(data):
            raise ValueError("Unterminated bencode list")
        return out, idx + 1
    if ch == b"d":
        idx += 1
        out = {}
        while idx < len(data) and data[idx:idx + 1] != b"e":
            key, idx = _bdecode_next(data, idx, depth + 1)
            if not isinstance(key, bytes):
                raise ValueError("Bencode dictionary keys must be bytes")
            val_start = idx
            val, idx = _bdecode_next(data, idx, depth + 1)
            out[key] = val
            if depth == 0 and key == b"info":
                out[b"__raw_info__"] = data[val_start:idx]
        if idx >= len(data):
            raise ValueError("Unterminated bencode dict")
        return out, idx + 1
    if b"0" <= ch <= b"9":
        colon = data.index(b":", idx)
        length = int(data[idx:colon])
        if length < 0:
            raise ValueError("Invalid bencode byte string length")
        start = colon + 1
        end = start + length
        if end > len(data):
            raise ValueError("Truncated bencode byte string")
        return data[start:end], end
    raise ValueError(f"Invalid bencode token at offset {idx}")


def parse_torrent_bytes(raw_bytes: bytes):
    if not raw_bytes or len(raw_bytes) > MAX_TORRENT_FILE_BYTES:
        raise ValueError("Invalid or oversized .torrent file (max 15 MiB)")
    decoded, _ = _bdecode_next(raw_bytes, 0, 0)
    if not isinstance(decoded, dict) or not isinstance(decoded.get(b"info"), dict):
        raise ValueError("Missing torrent info dictionary")
    info = decoded[b"info"]
    raw_info = decoded.get(b"__raw_info__")
    info_hash = hashlib.sha1(raw_info).hexdigest().lower() if raw_info else secrets.token_hex(20)
    raw_name = info.get(b"name.utf-8") or info.get(b"name") or b"Torrent"
    name = raw_name.decode("utf-8", errors="replace").strip() or "Torrent"
    piece_length = int(info.get(b"piece length") or 0)

    files = []
    if b"files" in info and isinstance(info[b"files"], list):
        offset = 0
        root_dir = _sanitize_rel_path(name)
        for idx, entry in enumerate(info[b"files"]):
            if not isinstance(entry, dict):
                continue
            path_parts = entry.get(b"path.utf-8") or entry.get(b"path") or []
            decoded_parts = [
                (p.decode("utf-8", errors="replace") if isinstance(p, bytes) else str(p))
                for p in path_parts
            ]
            # Skip BitTorrent padding files
            if any(p.startswith("_____padding_file_") for p in decoded_parts):
                offset += int(entry.get(b"length") or 0)
                continue
            rel_sub = _sanitize_rel_path("/".join(decoded_parts))
            rel_path = _sanitize_rel_path(f"{root_dir}/{rel_sub}")
            size = max(0, int(entry.get(b"length") or 0))
            files.append({
                "index": idx,
                "name": posixpath.basename(rel_path),
                "relative_path": rel_path,
                "size": size,
                "offset": offset,
                "selected": True,
                "uploaded_bytes": 0,
                "status": "queued",
                "error": "",
                "cloud_file_id": "",
            })
            offset += size
    else:
        size = max(0, int(info.get(b"length") or 0))
        rel_path = _sanitize_rel_path(name)
        files.append({
            "index": 0,
            "name": posixpath.basename(rel_path),
            "relative_path": rel_path,
            "size": size,
            "offset": 0,
            "selected": True,
            "uploaded_bytes": 0,
            "status": "queued",
            "error": "",
            "cloud_file_id": "",
        })

    trackers = []
    if isinstance(decoded.get(b"announce"), bytes):
        trackers.append(decoded[b"announce"].decode("utf-8", errors="replace"))
    if isinstance(decoded.get(b"announce-list"), list):
        for tier in decoded[b"announce-list"]:
            if isinstance(tier, list):
                for tr in tier:
                    if isinstance(tr, bytes):
                        u = tr.decode("utf-8", errors="replace")
                        if u not in trackers:
                            trackers.append(u)

    total_bytes = sum(f["size"] for f in files)
    return {
        "source_type": "torrent_file",
        "info_hash": info_hash,
        "name": name,
        "piece_length": piece_length,
        "total_bytes": total_bytes,
        "files": files,
        "trackers": trackers[:25],
        "metadata_ready": True,
    }


def parse_magnet_uri(magnet_uri: str):
    uri = str(magnet_uri or "").strip()
    if not uri.lower().startswith("magnet:?"):
        raise ValueError("Magnet URI must start with 'magnet:?'")
    parsed = urlparse(uri)
    qs = parse_qs(parsed.query)
    xts = qs.get("xt") or []
    info_hash = ""
    for xt in xts:
        low = xt.strip().lower()
        if low.startswith("urn:btih:"):
            h = low[len("urn:btih:"):].strip()
            if len(h) == 40 and re.fullmatch(r"[0-9a-f]{40}", h):
                info_hash = h
                break
            if len(h) == 32:
                try:
                    info_hash = base64.b32decode(h.upper()).hex().lower()
                    break
                except Exception:
                    pass
        elif low.startswith("urn:btmh:"):
            h = low[len("urn:btmh:"):].strip()
            if len(h) >= 40:
                info_hash = h
                break
    if not info_hash:
        raise ValueError("Invalid magnet link: missing valid BitTorrent info-hash (xt=urn:btih:...)")
    dn_list = qs.get("dn") or []
    name = unquote(dn_list[0]).strip() if dn_list else f"Torrent {info_hash[:10]}"
    trackers = [unquote(t).strip() for t in (qs.get("tr") or []) if t.strip()]
    return {
        "source_type": "magnet",
        "magnet_uri": uri,
        "info_hash": info_hash,
        "name": name or f"Torrent {info_hash[:10]}",
        "piece_length": 0,
        "total_bytes": 0,
        "files": [],
        "trackers": trackers[:25],
        "metadata_ready": False,
    }


class _TorrentSequentialReader:
    """
    Non-seekable streaming reader for FileJump (_MultipartStreamReader / WebDAV PUT)
    that pulls verified sequential bytes directly from libtorrent's bounded sliding
    window and immediately punches holes on already-read blocks so disk usage stays near zero.
    """

    def __init__(self, streamer, file_idx: int, file_size: int, file_offset: int, backing_path: Path):
        self._streamer = streamer
        self._file_idx = file_idx
        self._file_size = int(file_size)
        self._file_offset = int(file_offset)
        self._backing_path = backing_path
        self._pos = 0
        self._punched_up_to = 0
        self._fd = None
        self._closed = False

    def _ensure_fd(self):
        if self._fd is None:
            self._fd = os.open(str(self._backing_path), os.O_RDWR)
        return self._fd

    def read(self, size: int = 262144) -> bytes:
        if self._closed or self._pos >= self._file_size:
            return b""
        if size is None or size <= 0:
            size = 262144
        want = min(int(size), self._file_size - self._pos)
        if want <= 0:
            return b""

        # Ensure the piece(s) covering [pos, pos + want) are verified in the sliding window
        abs_start = self._file_offset + self._pos
        ready_len = self._streamer.wait_for_range(abs_start, want, self._file_idx, self._pos)
        if ready_len <= 0:
            return b""

        fd = self._ensure_fd()
        chunk = os.pread(fd, ready_len, self._pos)
        if not chunk:
            raise RuntimeError("Unexpected EOF reading sparse torrent piece")
        self._pos += len(chunk)

        # Punch hole in aligned 4 KiB blocks as soon as bytes are handed off
        punch_end = (self._pos // 4096) * 4096
        if punch_end > self._punched_up_to:
            _punch_hole_fd(fd, self._punched_up_to, punch_end - self._punched_up_to)
            self._punched_up_to = punch_end

        self._streamer.on_bytes_streamed(self._file_idx, self._pos, len(chunk))
        return chunk

    def close(self):
        self._closed = True
        if self._fd is not None:
            try:
                if self._file_size > self._punched_up_to:
                    _punch_hole_fd(self._fd, self._punched_up_to, self._file_size - self._punched_up_to)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None


class _ActiveJobStreamer:
    """Manages the bounded sliding piece window for a single active libtorrent handle."""

    def __init__(self, manager, job_id: str, handle, tinfo, save_dir: Path, window_bytes: int):
        self.manager = manager
        self.job_id = job_id
        self.handle = handle
        self.tinfo = tinfo
        self.save_dir = save_dir
        self.piece_length = max(16384, int(tinfo.piece_length()))
        self.num_pieces = int(tinfo.num_pieces())
        self.window_bytes = max(8 * 1024 * 1024, int(window_bytes))
        self.window_pieces = max(2, min(64, int(self.window_bytes // self.piece_length) + 1))
        self._active_window_start = -1
        self._active_window_end = -1
        self._last_stat_ts = 0.0
        self._up_bytes_window = 0
        self._up_rate_ts = time.time()
        self._up_rate = 0
        self._stop_event = threading.Event()

    def request_stop(self):
        self._stop_event.set()

    def _check_abort(self):
        if self._stop_event.is_set():
            raise InterruptedError("Torrent transfer paused or cancelled")
        job = self.manager._get_job_ref(self.job_id)
        if not job or job.get("status") in ("paused", "cancelled"):
            raise InterruptedError("Torrent transfer paused or cancelled")

    def set_window(self, start_piece: int, file_last_piece: int):
        start_piece = max(0, min(start_piece, self.num_pieces - 1))
        end_piece = min(file_last_piece, self.num_pieces - 1, start_piece + self.window_pieces - 1)
        if start_piece == self._active_window_start and end_piece == self._active_window_end:
            return
        priorities = [0] * self.num_pieces
        for p in range(start_piece, end_piece + 1):
            if not self.handle.have_piece(p):
                dist = p - start_piece
                priorities[p] = 7 if dist == 0 else (6 if dist <= 2 else 4)
        self.handle.prioritize_pieces(priorities)
        for p in range(start_piece, end_piece + 1):
            if not self.handle.have_piece(p):
                self.handle.set_piece_deadline(p, (p - start_piece) * 250)
        self._active_window_start = start_piece
        self._active_window_end = end_piece

    def _estimate_window_usage(self, cursor_piece: int, file_last_piece: int) -> int:
        end_p = min(file_last_piece, self.num_pieces - 1, cursor_piece + self.window_pieces - 1)
        buffered = 0
        for p in range(cursor_piece, end_p + 1):
            if self.handle.have_piece(p):
                buffered += self.piece_length
        return min(buffered, self.window_bytes)

    def refresh_stats(self, cursor_piece: int = 0, file_last_piece: int = 0, force: bool = False):
        now = time.time()
        if not force and (now - self._last_stat_ts) < 0.75:
            return
        self._last_stat_ts = now
        try:
            st = self.handle.status()
            dl_rate = int(getattr(st, "download_rate", 0) or 0)
            peers = int(getattr(st, "num_peers", 0) or 0)
            seeds = int(getattr(st, "num_seeds", 0) or 0)
        except Exception:
            dl_rate, peers, seeds = 0, 0, 0

        dt = max(0.25, now - self._up_rate_ts)
        if dt >= 1.0:
            self._up_rate = int(self._up_bytes_window / dt)
            self._up_bytes_window = 0
            self._up_rate_ts = now

        win_used = self._estimate_window_usage(cursor_piece, file_last_piece)
        self.manager._update_live_stats(
            self.job_id,
            download_rate=dl_rate,
            upload_rate=self._up_rate,
            peers=peers,
            seeds=seeds,
            window_bytes=win_used,
            window_cap_bytes=self.window_bytes,
        )

    def wait_for_range(self, abs_start: int, want: int, file_idx: int, file_pos: int) -> int:
        piece_idx = abs_start // self.piece_length
        offset_in_piece = abs_start % self.piece_length
        readable_in_piece = min(want, self.piece_length - offset_in_piece)

        finfo = self.tinfo.files()
        file_end_abs = finfo.file_offset(file_idx) + finfo.file_size(file_idx)
        file_last_piece = max(piece_idx, (max(0, file_end_abs - 1)) // self.piece_length)

        self.set_window(piece_idx, file_last_piece)
        while not self.handle.have_piece(piece_idx):
            self._check_abort()
            self.refresh_stats(piece_idx, file_last_piece)
            time.sleep(0.15)
        self.refresh_stats(piece_idx, file_last_piece)
        return readable_in_piece

    def wait_initial_buffer(self, file_idx: int, target_bytes: int = 2 * 1024 * 1024):
        """Wait until the first piece(s) of a file are ready before opening a FileJump HTTP upload."""
        finfo = self.tinfo.files()
        f_off = finfo.file_offset(file_idx)
        f_sz = finfo.file_size(file_idx)
        if f_sz <= 0:
            return
        first_p = f_off // self.piece_length
        last_p = (f_off + f_sz - 1) // self.piece_length
        need_end_p = min(last_p, (f_off + min(f_sz, target_bytes) - 1) // self.piece_length)
        self.set_window(first_p, last_p)
        for p in range(first_p, need_end_p + 1):
            while not self.handle.have_piece(p):
                self._check_abort()
                self.refresh_stats(first_p, last_p)
                time.sleep(0.15)

    def on_bytes_streamed(self, file_idx: int, uploaded_bytes: int, delta: int):
        self._up_bytes_window += max(0, int(delta))
        self.manager._update_file_progress(self.job_id, file_idx, uploaded_bytes)


class TorrentManager:
    def __init__(self, activity_logger=None):
        self._lock = threading.RLock()
        self._activity_logger = activity_logger
        self._jobs = []
        self._settings = dict(DEFAULT_SETTINGS)
        self._session = None
        self._active_streamer = None
        self._active_job_id = None
        self._wake_event = threading.Event()
        self._worker_started = False

        # Clean up any leftover ephemeral scratch files on startup (zero persistent disk leak)
        shutil.rmtree(SCRATCH_ROOT, ignore_errors=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        TORRENT_META_DIR.mkdir(parents=True, exist_ok=True)

        self._load_settings()
        self._load_jobs()
        self._start_worker()

    def set_activity_logger(self, logger_fn):
        self._activity_logger = logger_fn

    def _log(self, action, category, details, drive="Torrents", target="", user="admin"):
        if callable(self._activity_logger):
            try:
                self._activity_logger(action, category, details, drive=drive, target=target, user=user)
            except Exception:
                pass

    def _load_settings(self):
        if TORRENT_SETTINGS_FILE.exists():
            try:
                raw = json.loads(TORRENT_SETTINGS_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    merged = dict(DEFAULT_SETTINGS)
                    merged.update(raw)
                    self._settings = self._validate_settings(merged)
                    return
            except Exception:
                pass
        self._settings = dict(DEFAULT_SETTINGS)

    def _validate_settings(self, raw: dict):
        listen_port = int(raw.get("listen_port", DEFAULT_SETTINGS["listen_port"]) or 6881)
        listen_port = max(1024, min(65535, listen_port))
        window_mb = int(raw.get("window_mb", DEFAULT_SETTINGS["window_mb"]) or 24)
        window_mb = max(8, min(64, window_mb))
        max_conn = int(raw.get("max_connections", DEFAULT_SETTINGS["max_connections"]) or 60)
        max_conn = max(10, min(300, max_conn))
        dl_limit = int(raw.get("download_rate_limit_kbps", 0) or 0)
        dl_limit = max(0, min(1_000_000, dl_limit))
        conflict = str(raw.get("default_conflict_action") or "keep_both").strip().lower()
        if conflict not in ("keep_both", "skip", "replace"):
            conflict = "keep_both"
        return {
            "listen_port": listen_port,
            "window_mb": window_mb,
            "max_connections": max_conn,
            "download_rate_limit_kbps": dl_limit,
            "default_conflict_action": conflict,
        }

    def _save_settings(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = TORRENT_SETTINGS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._settings, indent=2), encoding="utf-8")
        os.replace(tmp, TORRENT_SETTINGS_FILE)

    def get_settings(self):
        with self._lock:
            out = dict(self._settings)
            out["engine_available"] = LIBTORRENT_AVAILABLE
            out["engine_version"] = str(LIBTORRENT_VERSION or "")
            return out

    def update_settings(self, updates: dict, user="admin"):
        with self._lock:
            merged = dict(self._settings)
            merged.update(updates or {})
            self._settings = self._validate_settings(merged)
            self._save_settings()
            if self._session is not None:
                self._apply_session_settings(self._session)
            self._log(
                "Torrent Settings Updated",
                "change",
                f"Port {self._settings['listen_port']}, window {self._settings['window_mb']} MiB, max peers {self._settings['max_connections']}",
                drive="Torrents",
                target="Engine Settings",
                user=user,
            )
            return self.get_settings()

    def _load_jobs(self):
        if TORRENTS_STATE_FILE.exists():
            try:
                raw = json.loads(TORRENTS_STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    changed = False
                    for job in raw:
                        if job.get("status") in ("streaming", "fetching_metadata"):
                            job["status"] = "paused"
                            job["stats"]["download_rate"] = 0
                            job["stats"]["upload_rate"] = 0
                            job["stats"]["peers"] = 0
                            job["stats"]["seeds"] = 0
                            job["stats"]["window_bytes"] = 0
                            changed = True
                    self._jobs = raw
                    if changed:
                        self._save_jobs_unlocked()
                    return
            except Exception:
                pass
        self._jobs = []

    def _save_jobs_unlocked(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = TORRENTS_STATE_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._jobs, indent=2), encoding="utf-8")
        os.replace(tmp, TORRENTS_STATE_FILE)

    def _get_job_ref(self, job_id: str):
        with self._lock:
            for j in self._jobs:
                if j["id"] == job_id:
                    return j
            return None

    def _ensure_session(self):
        if not LIBTORRENT_AVAILABLE:
            raise RuntimeError(
                "libtorrent is not installed in this runtime. Rebuild the Docker container to enable live BitTorrent streaming."
            )
        if self._session is None:
            settings = {
                "listen_interfaces": f"0.0.0.0:{self._settings['listen_port']}",
                "enable_dht": True,
                "enable_lsd": False,
                "enable_upnp": True,
                "enable_natpmp": True,
                "connections_limit": self._settings["max_connections"],
                "download_rate_limit": self._settings["download_rate_limit_kbps"] * 1024,
                "upload_rate_limit": 256 * 1024,  # modest upload cap so cloud uplink isn't starved
                "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.status_notification,
            }
            self._session = lt.session(settings)
            try:
                self._session.add_dht_router("router.bittorrent.com", 6881)
                self._session.add_dht_router("router.utorrent.com", 6881)
                self._session.add_dht_router("dht.transmissionbt.com", 6881)
            except Exception:
                pass
        return self._session

    def _apply_session_settings(self, ses):
        try:
            ses.apply_settings({
                "listen_interfaces": f"0.0.0.0:{self._settings['listen_port']}",
                "connections_limit": self._settings["max_connections"],
                "download_rate_limit": self._settings["download_rate_limit_kbps"] * 1024,
            })
        except Exception:
            pass

    def _start_worker(self):
        if self._worker_started:
            return
        self._worker_started = True
        t = threading.Thread(target=self._worker_loop, name="sagedrive-torrent-worker", daemon=True)
        t.start()

    def _recompute_job_totals(self, job: dict):
        selected_files = [f for f in job.get("files", []) if f.get("selected", True)]
        total_sel = sum(int(f.get("size") or 0) for f in selected_files)
        uploaded_sel = sum(min(int(f.get("size") or 0), int(f.get("uploaded_bytes") or 0)) for f in selected_files)
        job["stats"]["total_bytes"] = total_sel
        job["stats"]["uploaded_bytes"] = uploaded_sel
        rate = int(job["stats"].get("upload_rate") or job["stats"].get("download_rate") or 0)
        rem = max(0, total_sel - uploaded_sel)
        job["stats"]["eta_seconds"] = int(rem / rate) if (rate > 0 and rem > 0) else 0

    def _update_live_stats(self, job_id: str, **kwargs):
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                return
            for k, v in kwargs.items():
                job["stats"][k] = v
            self._recompute_job_totals(job)
            job["updated_at"] = _now_iso()

    def _update_file_progress(self, job_id: str, file_idx: int, uploaded_bytes: int):
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                return
            for f in job.get("files", []):
                if f["index"] == file_idx:
                    f["uploaded_bytes"] = min(int(f["size"]), int(uploaded_bytes))
                    break
            self._recompute_job_totals(job)
            job["updated_at"] = _now_iso()

    def inspect_source(self, magnet_uri: str = None, torrent_bytes: bytes = None):
        if torrent_bytes:
            return parse_torrent_bytes(torrent_bytes)
        if magnet_uri:
            return parse_magnet_uri(magnet_uri)
        raise ValueError("Provide either a magnet link or a .torrent file")

    def list_jobs(self):
        with self._lock:
            return [json.loads(json.dumps(j)) for j in self._jobs]

    def get_job(self, job_id: str):
        with self._lock:
            j = self._get_job_ref(job_id)
            return json.loads(json.dumps(j)) if j else None

    def create_job(
        self,
        destination: dict,
        magnet_uri: str = None,
        torrent_bytes: bytes = None,
        selected_indices=None,
        created_by: str = "admin",
    ):
        provider = str((destination or {}).get("provider") or "").strip().lower()
        if provider not in ("gdrive", "filejump"):
            raise ValueError("Destination provider must be 'gdrive' or 'filejump'")
        account_id = str((destination or {}).get("account_id") or "default").strip() or "default"
        folder_id = str((destination or {}).get("folder_id") or "root").strip() or "root"
        folder_path = str((destination or {}).get("folder_path") or "/").strip() or "/"
        account_name = str((destination or {}).get("account_name") or ("Google Drive" if provider == "gdrive" else "FileJump")).strip()
        conflict_action = str((destination or {}).get("conflict_action") or self._settings["default_conflict_action"]).strip().lower()
        if conflict_action not in ("keep_both", "skip", "replace"):
            conflict_action = "keep_both"

        if provider == "gdrive" and not gdrive_manager.is_authenticated(account_id=account_id):
            raise ValueError("Selected Google Drive account is not connected")
        if provider == "filejump" and not filejump_manager.is_authenticated(account_id=account_id):
            raise ValueError("Selected FileJump account is not connected")

        parsed = self.inspect_source(magnet_uri=magnet_uri, torrent_bytes=torrent_bytes)
        job_id = f"tor_{int(time.time())}_{secrets.token_hex(4)}"

        meta_file_path = ""
        if torrent_bytes:
            TORRENT_META_DIR.mkdir(parents=True, exist_ok=True)
            mf = TORRENT_META_DIR / f"{job_id}.torrent"
            mf.write_bytes(torrent_bytes)
            meta_file_path = str(mf)

        files = parsed.get("files", [])
        if selected_indices is not None and files:
            sel_set = {int(i) for i in selected_indices}
            for f in files:
                f["selected"] = f["index"] in sel_set
                f["status"] = "queued" if f["selected"] else "skipped"

        now = _now_iso()
        win_cap = int(self._settings["window_mb"]) * 1024 * 1024
        job = {
            "id": job_id,
            "info_hash": parsed["info_hash"],
            "name": parsed["name"],
            "source_type": parsed["source_type"],
            "magnet_uri": parsed.get("magnet_uri", ""),
            "meta_file": meta_file_path,
            "destination": {
                "provider": provider,
                "account_id": account_id,
                "account_name": account_name,
                "folder_id": folder_id,
                "folder_path": folder_path,
                "conflict_action": conflict_action,
            },
            "status": "queued",
            "metadata_ready": bool(parsed.get("metadata_ready")),
            "error_message": "",
            "stats": {
                "total_bytes": sum(f["size"] for f in files if f.get("selected", True)),
                "uploaded_bytes": 0,
                "download_rate": 0,
                "upload_rate": 0,
                "peers": 0,
                "seeds": 0,
                "window_bytes": 0,
                "window_cap_bytes": win_cap,
                "eta_seconds": 0,
            },
            "files": files,
            "created_at": now,
            "updated_at": now,
            "completed_at": "",
            "created_by": created_by,
        }

        with self._lock:
            self._jobs.insert(0, job)
            self._save_jobs_unlocked()

        self._log(
            "Torrent Added",
            "add",
            f"Queued '{job['name']}' → {account_name} ({folder_path}) [zero-disk stream]",
            drive=account_name,
            target=job["name"],
            user=created_by,
        )
        self._wake_event.set()
        return self.get_job(job_id)

    def pause_job(self, job_id: str, user="admin"):
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                raise KeyError("Torrent job not found")
            if job["status"] in ("completed",):
                return self.get_job(job_id)
            job["status"] = "paused"
            job["stats"]["download_rate"] = 0
            job["stats"]["upload_rate"] = 0
            job["stats"]["window_bytes"] = 0
            job["updated_at"] = _now_iso()
            if self._active_job_id == job_id and self._active_streamer:
                self._active_streamer.request_stop()
            self._save_jobs_unlocked()
        self._log("Torrent Paused", "change", f"Paused torrent '{job['name']}'", drive="Torrents", target=job["name"], user=user)
        return self.get_job(job_id)

    def resume_job(self, job_id: str, user="admin"):
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                raise KeyError("Torrent job not found")
            if job["status"] == "completed":
                return self.get_job(job_id)
            job["status"] = "queued"
            job["error_message"] = ""
            for f in job.get("files", []):
                if f.get("selected", True) and f.get("status") in ("error", "paused"):
                    f["status"] = "queued"
                    f["error"] = ""
            job["updated_at"] = _now_iso()
            self._save_jobs_unlocked()
        self._log("Torrent Resumed", "change", f"Resumed torrent '{job['name']}'", drive="Torrents", target=job["name"], user=user)
        self._wake_event.set()
        return self.get_job(job_id)

    def retry_job(self, job_id: str, file_index=None, user="admin"):
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                raise KeyError("Torrent job not found")
            job["status"] = "queued"
            job["error_message"] = ""
            for f in job.get("files", []):
                if file_index is not None and f["index"] != int(file_index):
                    continue
                if f.get("selected", True) and f.get("status") != "completed":
                    f["status"] = "queued"
                    f["error"] = ""
                    if job["destination"]["provider"] == "filejump":
                        f["uploaded_bytes"] = 0
            self._recompute_job_totals(job)
            job["updated_at"] = _now_iso()
            self._save_jobs_unlocked()
        self._log("Torrent Retried", "change", f"Retrying torrent '{job['name']}'", drive="Torrents", target=job["name"], user=user)
        self._wake_event.set()
        return self.get_job(job_id)

    def delete_job(self, job_id: str, user="admin"):
        removed_name = job_id
        meta_file = ""
        with self._lock:
            job = self._get_job_ref(job_id)
            if not job:
                raise KeyError("Torrent job not found")
            removed_name = job.get("name") or job_id
            meta_file = job.get("meta_file") or ""
            job["status"] = "cancelled"
            if self._active_job_id == job_id and self._active_streamer:
                self._active_streamer.request_stop()
            # Cancel any open Google Drive resumable upload sessions cleanly
            for f in job.get("files", []):
                uri = f.get("gdrive_resumable_uri")
                if uri:
                    gdrive_manager.cancel_resumable_upload(uri)
            self._jobs = [j for j in self._jobs if j["id"] != job_id]
            self._save_jobs_unlocked()

        if meta_file:
            try:
                Path(meta_file).unlink(missing_ok=True)
            except Exception:
                pass
        shutil.rmtree(SCRATCH_ROOT / job_id, ignore_errors=True)
        self._log("Torrent Removed", "delete", f"Removed torrent '{removed_name}' and cleared transient buffer", drive="Torrents", target=removed_name, user=user)
        return True

    def _worker_loop(self):
        while True:
            self._wake_event.wait(timeout=2.0)
            self._wake_event.clear()
            while True:
                next_job_id = None
                with self._lock:
                    # FIFO among queued jobs (oldest queued first)
                    queued = [j for j in reversed(self._jobs) if j.get("status") == "queued"]
                    if queued:
                        next_job_id = queued[0]["id"]
                if not next_job_id:
                    break
                self._run_job(next_job_id)

    def _run_job(self, job_id: str):
        job_snap = self.get_job(job_id)
        if not job_snap or job_snap["status"] != "queued":
            return

        save_dir = SCRATCH_ROOT / job_id
        handle = None
        ses = None
        try:
            ses = self._ensure_session()
            save_dir.mkdir(parents=True, exist_ok=True)

            with self._lock:
                job = self._get_job_ref(job_id)
                if not job or job["status"] != "queued":
                    return
                job["status"] = "fetching_metadata" if not job["metadata_ready"] else "streaming"
                job["error_message"] = ""
                job["updated_at"] = _now_iso()
                self._save_jobs_unlocked()

            if job_snap["source_type"] == "torrent_file" and job_snap.get("meta_file") and Path(job_snap["meta_file"]).exists():
                tinfo = lt.torrent_info(job_snap["meta_file"])
                atp = lt.add_torrent_params()
                atp.ti = tinfo
                atp.save_path = str(save_dir)
                atp.storage_mode = lt.storage_mode_t.storage_mode_sparse
                handle = ses.add_torrent(atp)
            else:
                atp = lt.parse_magnet_uri(job_snap["magnet_uri"])
                atp.save_path = str(save_dir)
                atp.storage_mode = lt.storage_mode_t.storage_mode_sparse
                handle = ses.add_torrent(atp)

            # Wait for magnet metadata if needed
            meta_deadline = time.time() + 180.0
            while not handle.status().has_metadata:
                cur = self._get_job_ref(job_id)
                if not cur or cur["status"] in ("paused", "cancelled"):
                    raise InterruptedError("Paused while fetching metadata")
                st = handle.status()
                self._update_live_stats(
                    job_id,
                    peers=int(getattr(st, "num_peers", 0) or 0),
                    seeds=int(getattr(st, "num_seeds", 0) or 0),
                )
                if time.time() > meta_deadline:
                    raise TimeoutError("Timed out waiting for magnet metadata (no peers responded within 3 minutes)")
                time.sleep(0.4)

            tinfo = handle.torrent_file()
            num_pieces = int(tinfo.num_pieces())
            # Zero-disk discipline: disable ALL pieces immediately, only enable sliding window per active file!
            handle.prioritize_pieces([0] * num_pieces)

            # Populate files list from resolved magnet metadata if not yet populated
            fstorage = tinfo.files()
            with self._lock:
                job = self._get_job_ref(job_id)
                if not job:
                    raise InterruptedError("Job deleted")
                if not job["files"]:
                    resolved_files = []
                    for i in range(fstorage.num_files()):
                        fp = fstorage.file_path(i)
                        if "_____padding_file_" in fp:
                            continue
                        rel_path = _sanitize_rel_path(fp)
                        resolved_files.append({
                            "index": i,
                            "name": posixpath.basename(rel_path),
                            "relative_path": rel_path,
                            "size": int(fstorage.file_size(i)),
                            "offset": int(fstorage.file_offset(i)),
                            "selected": True,
                            "uploaded_bytes": 0,
                            "status": "queued",
                            "error": "",
                            "cloud_file_id": "",
                        })
                    job["files"] = resolved_files
                    job["name"] = tinfo.name() or job["name"]
                    job["metadata_ready"] = True
                job["status"] = "streaming"
                self._recompute_job_totals(job)
                self._save_jobs_unlocked()

            win_bytes = int(self._settings["window_mb"]) * 1024 * 1024
            streamer = _ActiveJobStreamer(self, job_id, handle, tinfo, save_dir, win_bytes)
            with self._lock:
                self._active_job_id = job_id
                self._active_streamer = streamer

            # Stream selected files strictly 1 file at a time
            while True:
                next_file = None
                with self._lock:
                    job = self._get_job_ref(job_id)
                    if not job or job["status"] in ("paused", "cancelled"):
                        raise InterruptedError("Paused or cancelled")
                    for f in job["files"]:
                        if f.get("selected", True) and f.get("status") not in ("completed", "skipped"):
                            next_file = dict(f)
                            f["status"] = "streaming"
                            f["error"] = ""
                            break
                    self._save_jobs_unlocked()
                if not next_file:
                    break

                self._stream_single_file(job_id, streamer, handle, tinfo, save_dir, next_file)

            # All selected files finished!
            with self._lock:
                job = self._get_job_ref(job_id)
                if job and job["status"] not in ("paused", "cancelled"):
                    job["status"] = "completed"
                    job["completed_at"] = _now_iso()
                    job["updated_at"] = job["completed_at"]
                    job["stats"]["download_rate"] = 0
                    job["stats"]["upload_rate"] = 0
                    job["stats"]["window_bytes"] = 0
                    job["stats"]["eta_seconds"] = 0
                    self._recompute_job_totals(job)
                    self._save_jobs_unlocked()
                    dest = job["destination"]
                    self._log(
                        "Torrent Completed",
                        "add",
                        f"Streamed '{job['name']}' straight to {dest['account_name']} ({dest['folder_path']})",
                        drive=dest["account_name"],
                        target=job["name"],
                        user=job.get("created_by", "admin"),
                    )

        except InterruptedError:
            with self._lock:
                job = self._get_job_ref(job_id)
                if job and job["status"] != "cancelled":
                    job["status"] = "paused"
                    for f in job.get("files", []):
                        if f.get("status") == "streaming":
                            f["status"] = "paused"
                    job["stats"]["download_rate"] = 0
                    job["stats"]["upload_rate"] = 0
                    job["stats"]["window_bytes"] = 0
                    job["updated_at"] = _now_iso()
                    self._save_jobs_unlocked()
        except Exception as exc:
            err_msg = str(exc)
            with self._lock:
                job = self._get_job_ref(job_id)
                if job and job["status"] != "cancelled":
                    job["status"] = "error"
                    job["error_message"] = err_msg
                    for f in job.get("files", []):
                        if f.get("status") == "streaming":
                            f["status"] = "error"
                            f["error"] = err_msg
                    job["stats"]["download_rate"] = 0
                    job["stats"]["upload_rate"] = 0
                    job["stats"]["window_bytes"] = 0
                    job["updated_at"] = _now_iso()
                    self._save_jobs_unlocked()
                    self._log(
                        "Torrent Error",
                        "change",
                        f"Torrent '{job['name']}' failed: {err_msg}",
                        drive=job["destination"]["account_name"],
                        target=job["name"],
                        user=job.get("created_by", "admin"),
                    )
        finally:
            with self._lock:
                if self._active_job_id == job_id:
                    self._active_job_id = None
                    self._active_streamer = None
            if ses is not None and handle is not None:
                try:
                    ses.remove_torrent(handle, lt.session.delete_files)
                except Exception:
                    try:
                        ses.remove_torrent(handle)
                    except Exception:
                        pass
            shutil.rmtree(save_dir, ignore_errors=True)

    def _stream_single_file(self, job_id: str, streamer: _ActiveJobStreamer, handle, tinfo, save_dir: Path, file_rec: dict):
        job = self.get_job(job_id)
        dest = job["destination"]
        provider = dest["provider"]
        account_id = dest["account_id"]
        folder_id = dest["folder_id"]
        conflict_action = dest["conflict_action"]

        fidx = int(file_rec["index"])
        fstorage = tinfo.files()
        file_size = int(fstorage.file_size(fidx))
        file_offset = int(fstorage.file_offset(fidx))
        rel_path = file_rec["relative_path"]
        filename = file_rec["name"]
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        backing_path = save_dir / fstorage.file_path(fidx)

        cloud_file_id = ""
        if provider == "gdrive":
            cloud_file_id = self._stream_file_to_gdrive(
                job_id, streamer, fidx, file_size, file_offset, backing_path,
                folder_id, filename, rel_path, mime_type, account_id, conflict_action, file_rec,
            )
        elif provider == "filejump":
            cloud_file_id = self._stream_file_to_filejump(
                job_id, streamer, fidx, file_size, file_offset, backing_path,
                folder_id, filename, rel_path, mime_type, account_id, conflict_action,
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        # Immediately release all pieces for this completed file and unlink sparse backing file
        try:
            backing_path.unlink(missing_ok=True)
        except Exception:
            pass

        with self._lock:
            j = self._get_job_ref(job_id)
            if j:
                for f in j["files"]:
                    if f["index"] == fidx:
                        f["status"] = "completed"
                        f["uploaded_bytes"] = file_size
                        f["cloud_file_id"] = str(cloud_file_id or "")
                        f["error"] = ""
                        f.pop("gdrive_resumable_uri", None)
                        break
                self._recompute_job_totals(j)
                self._save_jobs_unlocked()

    def _stream_file_to_gdrive(
        self, job_id, streamer, fidx, file_size, file_offset, backing_path,
        folder_id, filename, rel_path, mime_type, account_id, conflict_action, file_rec,
    ):
        # Honor skip conflict policy before starting any download pieces
        if conflict_action == "skip":
            target_parent, actual_name = gdrive_manager.resolve_upload_target(
                folder_id, filename, relative_path=rel_path, account_id=account_id
            )
            existing = gdrive_manager.find_items_by_name(target_parent, actual_name, account_id=account_id)
            if existing:
                return existing[0].get("id", "")

        resumable_uri = file_rec.get("gdrive_resumable_uri") or ""
        offset = 0
        if resumable_uri:
            try:
                offset = int(gdrive_manager.query_resumable_offset(resumable_uri, total_size=file_size))
            except Exception:
                resumable_uri = ""
                offset = 0

        if not resumable_uri:
            resumable_uri = gdrive_manager.start_resumable_upload(
                folder_id,
                filename,
                mime_type=mime_type,
                total_size=file_size,
                relative_path=rel_path,
                account_id=account_id,
                conflict_action=conflict_action,
            )
            with self._lock:
                j = self._get_job_ref(job_id)
                if j:
                    for f in j["files"]:
                        if f["index"] == fidx:
                            f["gdrive_resumable_uri"] = resumable_uri
                            break
                    self._save_jobs_unlocked()

        if file_size == 0:
            gdrive_manager.upload_file(
                folder_id, filename, b"", mime_type=mime_type,
                relative_path=rel_path, account_id=account_id,
                total_size=0, conflict_action=conflict_action,
            )
            return ""

        chunk_unit = 5 * 1024 * 1024  # 5 MiB (multiple of 256 KiB required by Google Drive)
        fd = None
        punched_up_to = offset
        try:
            while offset < file_size:
                streamer._check_abort()
                buf = bytearray()
                target_chunk = min(chunk_unit, file_size - offset)
                cur_read_pos = offset
                while len(buf) < target_chunk:
                    want = target_chunk - len(buf)
                    ready_len = streamer.wait_for_range(file_offset + cur_read_pos, want, fidx, cur_read_pos)
                    if fd is None:
                        fd = os.open(str(backing_path), os.O_RDWR)
                    data = os.pread(fd, ready_len, cur_read_pos)
                    if not data:
                        raise RuntimeError("Unexpected EOF reading sparse torrent piece")
                    buf.extend(data)
                    cur_read_pos += len(data)

                offset = gdrive_manager.push_resumable_chunk(
                    resumable_uri, bytes(buf), offset, total_size=file_size
                )
                streamer.on_bytes_streamed(fidx, offset, len(buf))

                # Immediately punch hole on confirmed uploaded range to free physical blocks!
                if fd is not None:
                    punch_end = (offset // 4096) * 4096
                    if punch_end > punched_up_to:
                        _punch_hole_fd(fd, punched_up_to, punch_end - punched_up_to)
                        punched_up_to = punch_end
        finally:
            if fd is not None:
                try:
                    if file_size > punched_up_to:
                        _punch_hole_fd(fd, punched_up_to, file_size - punched_up_to)
                    os.close(fd)
                except Exception:
                    pass
        return ""

    def _stream_file_to_filejump(
        self, job_id, streamer, fidx, file_size, file_offset, backing_path,
        folder_id, filename, rel_path, mime_type, account_id, conflict_action,
    ):
        if file_size == 0:
            return filejump_manager.upload_file(
                folder_id, filename, b"", mime_type=mime_type,
                relative_path=rel_path, account_id=account_id,
                total_size=0, conflict_action=conflict_action,
            )

        # Pre-buffer first 2 MiB of verified pieces before opening the FileJump HTTP upload stream
        streamer.wait_initial_buffer(fidx, target_bytes=min(file_size, 2 * 1024 * 1024))
        reader = _TorrentSequentialReader(streamer, fidx, file_size, file_offset, backing_path)
        try:
            return filejump_manager.upload_file(
                folder_id,
                filename,
                reader,
                mime_type=mime_type,
                relative_path=rel_path,
                account_id=account_id,
                total_size=file_size,
                conflict_action=conflict_action,
            )
        finally:
            reader.close()


_manager_instance = None
_manager_lock = threading.Lock()


def get_manager(activity_logger=None) -> TorrentManager:
    global _manager_instance
    with _manager_lock:
        if _manager_instance is None:
            _manager_instance = TorrentManager(activity_logger=activity_logger)
        elif activity_logger is not None:
            _manager_instance.set_activity_logger(activity_logger)
        return _manager_instance
