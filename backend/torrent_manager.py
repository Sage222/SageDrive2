import base64
import ctypes
import hashlib
import importlib
import json
import mimetypes
import os
import posixpath
import re
import secrets
import shutil
import site
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import filejump_manager
import gdrive_manager
import smb_manager

lt = None
LIBTORRENT_AVAILABLE = False
LIBTORRENT_VERSION = None
LIBTORRENT_SOURCE = ""


def _ensure_dist_packages_on_path():
    """
    Ensure pip site-packages come BEFORE Debian/Ubuntu /usr/lib/python3/dist-packages
    so PyPI binary wheel upgrades always take precedence over older apt packages.
    """
    try:
        for sp in reversed(site.getsitepackages()):
            if os.path.isdir(sp):
                if sp in sys.path:
                    sys.path.remove(sp)
                sys.path.insert(0, sp)
    except Exception:
        pass
    for candidate in ("/usr/local/lib/python3/dist-packages", "/usr/lib/python3/dist-packages"):
        if os.path.isdir(candidate) and candidate not in sys.path:
            sys.path.append(candidate)


def _try_import_libtorrent(force_reload: bool = False):
    global lt, LIBTORRENT_AVAILABLE, LIBTORRENT_VERSION, LIBTORRENT_SOURCE
    _ensure_dist_packages_on_path()
    try:
        importlib.invalidate_caches()
        if force_reload and "libtorrent" in sys.modules:
            del sys.modules["libtorrent"]
        mod = importlib.import_module("libtorrent")
        lt = mod
        LIBTORRENT_AVAILABLE = True
        LIBTORRENT_VERSION = str(getattr(mod, "__version__", getattr(mod, "version", "available")) or "available")
        mod_file = str(getattr(mod, "__file__", "") or "")
        if "/site-packages/" in mod_file or "/usr/local/" in mod_file:
            LIBTORRENT_SOURCE = "PyPI wheel"
        elif "/dist-packages/" in mod_file:
            LIBTORRENT_SOURCE = "Debian apt"
        else:
            LIBTORRENT_SOURCE = "system"
        return True
    except Exception:
        lt = None
        LIBTORRENT_AVAILABLE = False
        LIBTORRENT_VERSION = None
        LIBTORRENT_SOURCE = ""
        return False


_try_import_libtorrent()

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
TORRENTS_STATE_FILE = DATA_DIR / "torrents_state.json"
TORRENT_SETTINGS_FILE = DATA_DIR / "torrent_settings.json"
TORRENT_META_DIR = DATA_DIR / "torrent_meta"
SCRATCH_ROOT = Path(os.environ.get("TORRENT_SCRATCH_DIR", "/tmp/sagedrive_torrents"))

MAX_TORRENT_FILE_BYTES = 15 * 1024 * 1024  # 15 MiB cap for .torrent metadata uploads
DEFAULT_SETTINGS = {
    "listen_port": 6881,
    "listen_interface": "0.0.0.0",
    "window_mb": 128,                 # 128 MiB default (configurable 16..512 MiB)
    "max_active_torrents": 2,         # Concurrent active torrents (1..10), each streaming 1 file at a time
    "max_connections": 200,           # 10..1000 peers
    "max_uploads": 8,
    "download_rate_limit_kbps": 0,    # 0 = unlimited
    "upload_rate_limit_kbps": 512,    # 0 = unlimited; balances swarm reciprocity and cloud upload headroom
    "default_conflict_action": "keep_both",
    "enable_dht": True,
    "enable_pex": True,
    "enable_lsd": False,
    "enable_upnp": True,
    "enable_natpmp": True,
    "enable_utp": True,
    "encryption_mode": "enabled",     # disabled | enabled | forced
    "anonymous_mode": False,
    "extra_trackers": "",
    "proxy_type": "none",             # none | socks5 | socks4 | http
    "proxy_hostname": "",
    "proxy_port": 1080,
    "proxy_username": "",
    "proxy_password": "",
    "proxy_peer_connections": True,
    "proxy_tracker_connections": True,
    "proxy_hostnames": True,
    "force_proxy": False,
    "perf_v2_migrated": True,
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
    elif b"file tree" in info and isinstance(info[b"file tree"], dict):
        # BitTorrent v2 (BEP 52) file tree support
        root_dir = _sanitize_rel_path(name)
        v2_entries = []

        def _walk_v2(node, prefix):
            for k, v in node.items():
                if not isinstance(v, dict):
                    continue
                if k == b"" and b"length" in v:
                    v2_entries.append((list(prefix), max(0, int(v.get(b"length") or 0))))
                else:
                    seg = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else str(k)
                    _walk_v2(v, prefix + [seg])

        _walk_v2(info[b"file tree"], [])
        offset = 0
        for idx, (parts, size) in enumerate(v2_entries):
            rel_sub = _sanitize_rel_path("/".join(parts)) if parts else root_dir
            rel_path = _sanitize_rel_path(f"{root_dir}/{rel_sub}") if len(v2_entries) > 1 else rel_sub
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
    window and releases completed prior pieces via Linux fallocate hole-punching.
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

    def __len__(self):
        return self._file_size

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

        abs_start = self._file_offset + self._pos
        ready_len = self._streamer.wait_for_range(abs_start, want, self._file_idx, self._pos)
        if ready_len <= 0:
            return b""

        chunk, self._fd = self._streamer.read_flushed_bytes(
            self._backing_path, self._pos, ready_len, fd=self._fd
        )
        self._pos += len(chunk)

        # Only punch holes strictly on completed prior pieces (aligned to 4 KiB)
        # so we never zero bytes inside a piece libtorrent may still be verifying or seeding
        pl = self._streamer.piece_length
        safe_boundary = ((max(0, self._pos - pl)) // 4096) * 4096
        if safe_boundary > self._punched_up_to and self._fd is not None:
            _punch_hole_fd(self._fd, self._punched_up_to, safe_boundary - self._punched_up_to)
            self._punched_up_to = safe_boundary

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
    """
    Manages the bounded sliding piece window (up to 512 MiB) for a single active
    libtorrent handle, with a background look-ahead prefetcher thread that keeps
    the piece pipeline saturated while destination writes are in flight.
    """

    def __init__(self, manager, job_id: str, handle, tinfo, save_dir: Path, window_bytes: int):
        self.manager = manager
        self.job_id = job_id
        self.handle = handle
        self.tinfo = tinfo
        self.save_dir = save_dir
        self.piece_length = max(16384, int(tinfo.piece_length()))
        self.num_pieces = max(1, int(tinfo.num_pieces()))
        self._win_lock = threading.RLock()
        self.window_bytes = max(8 * 1024 * 1024, int(window_bytes))
        self.window_pieces = max(8, min(512, int(self.window_bytes // self.piece_length) + 4))
        self._active_window_start = -1
        self._active_window_end = -1
        self._active_missing_count = -1
        self._cursor_piece = 0
        self._file_last_piece = max(0, self.num_pieces - 1)
        self._last_stat_ts = 0.0
        self._last_reannounce_ts = time.time()
        self._up_bytes_window = 0
        self._up_rate_ts = time.time()
        self._up_rate = 0
        self._stop_event = threading.Event()
        try:
            # We manage explicit sliding-window piece priorities & graduated deadlines
            # rather than global sequential mode so multi-file selection and look-ahead
            # pipelining across dozens of peers run at maximum throughput.
            self.handle.set_sequential_download(False)
        except Exception:
            pass
        self._prefetch_thread = threading.Thread(
            target=self._prefetch_loop,
            name=f"sagedrive-prefetch-{job_id}",
            daemon=True,
        )
        self._prefetch_thread.start()

    def request_stop(self):
        self._stop_event.set()

    def update_window_bytes(self, new_window_bytes: int):
        with self._win_lock:
            self.window_bytes = max(8 * 1024 * 1024, int(new_window_bytes))
            self.window_pieces = max(8, min(512, int(self.window_bytes // self.piece_length) + 4))
            if self._active_window_start >= 0:
                self.set_window(self._cursor_piece, self._file_last_piece, force=True)

    def _prefetch_loop(self):
        """
        Continuously slides the piece window forward as in-flight pieces complete,
        even while the upload thread is blocked sending a multi-megabyte chunk to
        SMB NAS, Google Drive, or FileJump.
        """
        while not self._stop_event.wait(timeout=0.25):
            try:
                if self._stop_event.is_set():
                    break
                with self._win_lock:
                    cur = self._cursor_piece
                    last_p = self._file_last_piece
                    if self._active_window_start >= 0:
                        self.set_window(cur, last_p, force=False)
                self.refresh_stats(cur, last_p, force=False)
            except Exception:
                pass

    def _check_abort(self):
        if self._stop_event.is_set():
            raise InterruptedError("Torrent transfer paused or cancelled")
        job = self.manager._get_job_ref(self.job_id)
        if not job or job.get("status") in ("paused", "cancelled"):
            raise InterruptedError("Torrent transfer paused or cancelled")

    def file_piece_bounds(self, file_idx: int):
        finfo = self.tinfo.files()
        f_off = int(finfo.file_offset(file_idx))
        f_sz = int(finfo.file_size(file_idx))
        if f_sz <= 0:
            p = max(0, min(self.num_pieces - 1, f_off // self.piece_length))
            return p, p
        first_p = max(0, min(self.num_pieces - 1, f_off // self.piece_length))
        last_p = max(first_p, min(self.num_pieces - 1, (f_off + f_sz - 1) // self.piece_length))
        return first_p, last_p

    def set_window(self, start_piece: int, file_last_piece: int, force: bool = False):
        """
        Keep a strictly bounded sliding window of up to `window_pieces` un-downloaded
        pieces active across peers while NEVER passing an all-zero priority list.
        """
        with self._win_lock:
            start_piece = max(0, min(start_piece, self.num_pieces - 1))
            file_last_piece = max(start_piece, min(file_last_piece, self.num_pieces - 1))
            self._cursor_piece = start_piece
            self._file_last_piece = file_last_piece

            # Advance past already-verified contiguous pieces at the front of the window
            # so completed pieces inside the buffer don't consume active look-ahead slots
            end_piece = min(file_last_piece, start_piece + self.window_pieces - 1)
            missing_pieces = []
            p_scan = start_piece
            max_scan = min(file_last_piece, start_piece + self.window_pieces * 2 - 1)
            while p_scan <= max_scan and len(missing_pieces) < self.window_pieces:
                if not self.handle.have_piece(p_scan):
                    missing_pieces.append(p_scan)
                end_piece = max(end_piece, p_scan)
                p_scan += 1

            missing_in_win = len(missing_pieces)
            if (
                not force
                and start_piece == self._active_window_start
                and end_piece == self._active_window_end
                and missing_in_win == self._active_missing_count
            ):
                return

            priorities = [0] * self.num_pieces
            for p in range(start_piece, end_piece + 1):
                dist = p - start_piece
                if dist <= 1:
                    priorities[p] = 7
                elif dist <= 7:
                    priorities[p] = 6
                elif dist <= 23:
                    priorities[p] = 5
                else:
                    priorities[p] = 4

            # If every piece in the current file's window is already downloaded, keep the next piece
            # at low priority (1) so libtorrent stays in downloading state and keeps seeders connected
            if missing_in_win == 0 and end_piece + 1 < self.num_pieces:
                priorities[end_piece + 1] = 1

            self.handle.prioritize_pieces(priorities)
            # Set graduated piece deadlines across the front 32 missing pieces so libtorrent
            # pipelines block requests across multiple fast seeders in parallel
            for idx, p in enumerate(missing_pieces[:32]):
                try:
                    self.handle.set_piece_deadline(p, 150 + idx * 120)
                except Exception:
                    pass

            self._active_window_start = start_piece
            self._active_window_end = end_piece
            self._active_missing_count = missing_in_win

    def peek_contiguous_ready_bytes(self, abs_start: int, max_want: int, file_idx: int) -> int:
        """
        Return how many contiguous verified bytes starting at `abs_start` are already
        available in the sliding window (up to `max_want`), allowing fast persistent
        SMB writes to batch up to 4 MiB whenever the buffer is ahead.
        """
        piece_idx = abs_start // self.piece_length
        if not self.handle.have_piece(piece_idx):
            return 0
        offset_in_piece = abs_start % self.piece_length
        ready = min(max_want, self.piece_length - offset_in_piece)
        cur_p = piece_idx + 1
        while ready < max_want and cur_p < self.num_pieces and self.handle.have_piece(cur_p):
            ready = min(max_want, ready + self.piece_length)
            cur_p += 1
        return ready

    def _estimate_window_usage(self, cursor_piece: int, file_last_piece: int) -> int:
        end_p = min(file_last_piece, self.num_pieces - 1, max(cursor_piece + self.window_pieces - 1, self._active_window_end))
        buffered = 0
        for p in range(cursor_piece, end_p + 1):
            if self.handle.have_piece(p):
                buffered += self.piece_length
        return min(buffered, self.window_bytes)

    def refresh_stats(self, cursor_piece: int = 0, file_last_piece: int = 0, force: bool = False):
        now = time.time()
        if not force and (now - self._last_stat_ts) < 0.6:
            return
        self._last_stat_ts = now
        try:
            st = self.handle.status()
            dl_rate = int(getattr(st, "download_rate", 0) or 0)
            peer_ul_rate = int(getattr(st, "upload_rate", 0) or 0)
            peers = int(getattr(st, "num_peers", 0) or 0)
            seeds = int(getattr(st, "num_seeds", 0) or 0)
            # If stuck with 0 peers for 15s, trigger tracker/DHT reannounce
            if peers == 0 and (now - self._last_reannounce_ts) > 15.0:
                self._last_reannounce_ts = now
                try:
                    self.handle.force_reannounce()
                    self.handle.force_dht_announce()
                except Exception:
                    pass
        except Exception:
            dl_rate, peer_ul_rate, peers, seeds = 0, 0, 0, 0

        dt = max(0.25, now - self._up_rate_ts)
        if dt >= 1.0:
            self._up_rate = int(self._up_bytes_window / dt)
            self._up_bytes_window = 0
            self._up_rate_ts = now

        win_used = self._estimate_window_usage(cursor_piece, file_last_piece)
        self.manager._update_live_stats(
            self.job_id,
            download_rate=dl_rate,
            peer_upload_rate=peer_ul_rate,
            upload_rate=self._up_rate,
            peers=peers,
            seeds=seeds,
            window_bytes=win_used,
            window_cap_bytes=self.window_bytes,
        )

    def read_flushed_bytes(self, backing_path: Path, file_pos: int, length: int, fd=None):
        """
        Safely open and pread verified piece bytes from libtorrent's sparse file.
        Handles async disk-cache flush latency in libtorrent 1.2 & 2.0 cleanly.
        """
        deadline = time.time() + 25.0
        flushed_once = False
        while True:
            self._check_abort()
            try:
                if fd is None:
                    if not backing_path.exists():
                        if not flushed_once:
                            flushed_once = True
                            try:
                                self.handle.flush_cache()
                            except Exception:
                                pass
                        if time.time() > deadline:
                            raise FileNotFoundError(f"Torrent backing file not flushed to scratch: {backing_path.name}")
                        time.sleep(0.05)
                        continue
                    fd = os.open(str(backing_path), os.O_RDWR)
                chunk = os.pread(fd, length, file_pos)
                if chunk and len(chunk) == length:
                    return chunk, fd
                if chunk and len(chunk) > 0:
                    return chunk, fd
                if not flushed_once:
                    flushed_once = True
                    try:
                        self.handle.flush_cache()
                    except Exception:
                        pass
                if time.time() > deadline:
                    raise RuntimeError(f"Timed out waiting for sparse torrent bytes at offset {file_pos} ({backing_path.name})")
                time.sleep(0.05)
            except FileNotFoundError:
                if time.time() > deadline:
                    raise
                time.sleep(0.05)

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
            time.sleep(0.08)
        self.refresh_stats(piece_idx, file_last_piece)
        return readable_in_piece

    def wait_initial_buffer(self, file_idx: int, target_bytes: int = 4 * 1024 * 1024):
        """Wait until the first piece(s) of a file are verified before opening an HTTP upload stream."""
        finfo = self.tinfo.files()
        f_off = finfo.file_offset(file_idx)
        f_sz = finfo.file_size(file_idx)
        if f_sz <= 0:
            return
        first_p = f_off // self.piece_length
        last_p = (f_off + f_sz - 1) // self.piece_length
        need_end_p = min(last_p, (f_off + min(f_sz, target_bytes) - 1) // self.piece_length)
        self.set_window(first_p, last_p, force=True)
        for p in range(first_p, need_end_p + 1):
            while not self.handle.have_piece(p):
                self._check_abort()
                self.refresh_stats(first_p, last_p)
                time.sleep(0.08)
        self.refresh_stats(first_p, last_p, force=True)

    def on_bytes_streamed(self, file_idx: int, uploaded_bytes: int, delta: int):
        self._up_bytes_window += max(0, int(delta))
        now = time.time()
        dt = max(0.15, now - self._up_rate_ts)
        if dt >= 0.5:
            self._up_rate = int(self._up_bytes_window / dt)
            self._up_bytes_window = 0
            self._up_rate_ts = now
        elif self._up_rate == 0 and self._up_bytes_window > 0:
            self._up_rate = int(self._up_bytes_window / dt)
        self.manager._update_file_progress(self.job_id, file_idx, uploaded_bytes)
        try:
            finfo = self.tinfo.files()
            abs_pos = int(finfo.file_offset(file_idx)) + int(uploaded_bytes)
            cur_piece = max(0, min(self.num_pieces - 1, abs_pos // self.piece_length))
            _, last_piece = self.file_piece_bounds(file_idx)
            self.set_window(cur_piece, last_piece, force=False)
            self.refresh_stats(cur_piece, last_piece, force=True)
        except Exception:
            pass


class TorrentManager:
    def __init__(self, activity_logger=None):
        self._lock = threading.RLock()
        self._install_lock = threading.Lock()
        self._activity_logger = activity_logger
        self._jobs = []
        self._settings = dict(DEFAULT_SETTINGS)
        self._session = None
        self._active_streamers = {}  # job_id -> _ActiveJobStreamer
        self._active_job_ids = set()
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

    @staticmethod
    def _as_bool(val, default=False):
        if isinstance(val, bool):
            return val
        if isinstance(val, (int, float)):
            return bool(val)
        if isinstance(val, str):
            low = val.strip().lower()
            if low in ("1", "true", "yes", "on"):
                return True
            if low in ("0", "false", "no", "off"):
                return False
        return bool(default)

    @staticmethod
    def _parse_extra_trackers(raw_text: str):
        out = []
        seen = set()
        for line in str(raw_text or "").replace(",", "\n").splitlines():
            url = line.strip()
            if not url:
                continue
            low = url.lower()
            if not (low.startswith("udp://") or low.startswith("http://") or low.startswith("https://") or low.startswith("wss://") or low.startswith("ws://")):
                continue
            if url not in seen:
                seen.add(url)
                out.append(url)
            if len(out) >= 50:
                break
        return out

    def _load_settings(self):
        if TORRENT_SETTINGS_FILE.exists():
            try:
                raw = json.loads(TORRENT_SETTINGS_FILE.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    needs_save = False
                    # One-time automatic migration from the old 24 MiB / 60-peer defaults to 128 MiB / 200-peer defaults
                    if not raw.get("perf_v2_migrated"):
                        if int(raw.get("window_mb", 24) or 24) <= 24:
                            raw["window_mb"] = 128
                        if int(raw.get("max_connections", 60) or 60) <= 60:
                            raw["max_connections"] = 200
                        if int(raw.get("max_uploads", 4) or 4) <= 4:
                            raw["max_uploads"] = 8
                        if int(raw.get("upload_rate_limit_kbps", 256) or 256) == 256:
                            raw["upload_rate_limit_kbps"] = 512
                        raw["perf_v2_migrated"] = True
                        needs_save = True
                    merged = dict(DEFAULT_SETTINGS)
                    merged.update(raw)
                    self._settings = self._validate_settings(merged, existing=raw)
                    if needs_save:
                        self._save_settings()
                    return
            except Exception:
                pass
        self._settings = dict(DEFAULT_SETTINGS)

    def _validate_settings(self, raw: dict, existing: dict = None):
        prev = existing or {}
        try:
            listen_port = int(raw.get("listen_port", DEFAULT_SETTINGS["listen_port"]))
        except Exception:
            listen_port = DEFAULT_SETTINGS["listen_port"]
        listen_port = max(1024, min(65535, listen_port))

        listen_interface = re.sub(r"[^0-9a-zA-Z._:\-\[\]]+", "", str(raw.get("listen_interface") or "0.0.0.0").strip())[:128]
        if not listen_interface:
            listen_interface = "0.0.0.0"

        try:
            window_mb = int(raw.get("window_mb", DEFAULT_SETTINGS["window_mb"]))
        except Exception:
            window_mb = DEFAULT_SETTINGS["window_mb"]
        window_mb = max(8, min(512, window_mb))

        try:
            max_active = int(raw.get("max_active_torrents", DEFAULT_SETTINGS["max_active_torrents"]))
        except Exception:
            max_active = DEFAULT_SETTINGS["max_active_torrents"]
        max_active = max(1, min(10, max_active))

        try:
            max_conn = int(raw.get("max_connections", DEFAULT_SETTINGS["max_connections"]))
        except Exception:
            max_conn = DEFAULT_SETTINGS["max_connections"]
        max_conn = max(10, min(1000, max_conn))

        try:
            max_uploads = int(raw.get("max_uploads", DEFAULT_SETTINGS["max_uploads"]))
        except Exception:
            max_uploads = DEFAULT_SETTINGS["max_uploads"]
        max_uploads = max(-1, min(200, max_uploads))

        try:
            dl_limit = int(raw.get("download_rate_limit_kbps", DEFAULT_SETTINGS["download_rate_limit_kbps"]))
        except Exception:
            dl_limit = DEFAULT_SETTINGS["download_rate_limit_kbps"]
        dl_limit = max(0, min(1_000_000, dl_limit))

        try:
            ul_limit = int(raw.get("upload_rate_limit_kbps", DEFAULT_SETTINGS["upload_rate_limit_kbps"]))
        except Exception:
            ul_limit = DEFAULT_SETTINGS["upload_rate_limit_kbps"]
        ul_limit = max(0, min(1_000_000, ul_limit))

        conflict = str(raw.get("default_conflict_action") or "keep_both").strip().lower()
        if conflict not in ("keep_both", "skip", "replace"):
            conflict = "keep_both"

        enc_mode = str(raw.get("encryption_mode") or "enabled").strip().lower()
        if enc_mode not in ("disabled", "enabled", "forced"):
            enc_mode = "enabled"

        proxy_type = str(raw.get("proxy_type") or "none").strip().lower()
        if proxy_type not in ("none", "socks5", "socks4", "http"):
            proxy_type = "none"

        proxy_hostname = re.sub(r"[\s\r\n]+", "", str(raw.get("proxy_hostname") or "").strip())[:255]
        try:
            proxy_port = int(raw.get("proxy_port", DEFAULT_SETTINGS["proxy_port"]))
        except Exception:
            proxy_port = DEFAULT_SETTINGS["proxy_port"]
        proxy_port = max(1, min(65535, proxy_port))

        proxy_username = str(raw.get("proxy_username") or "").strip()[:128]
        if self._as_bool(raw.get("clear_proxy_password"), False):
            proxy_password = ""
        elif "proxy_password" in raw and str(raw.get("proxy_password") or "") != "":
            proxy_password = str(raw.get("proxy_password"))[:256]
        else:
            proxy_password = str(prev.get("proxy_password") or "")

        extra_trackers = "\n".join(self._parse_extra_trackers(raw.get("extra_trackers", "")))

        return {
            "listen_port": listen_port,
            "listen_interface": listen_interface,
            "window_mb": window_mb,
            "max_active_torrents": max_active,
            "max_connections": max_conn,
            "max_uploads": max_uploads,
            "download_rate_limit_kbps": dl_limit,
            "upload_rate_limit_kbps": ul_limit,
            "default_conflict_action": conflict,
            "enable_dht": self._as_bool(raw.get("enable_dht"), DEFAULT_SETTINGS["enable_dht"]),
            "enable_pex": self._as_bool(raw.get("enable_pex"), DEFAULT_SETTINGS["enable_pex"]),
            "enable_lsd": self._as_bool(raw.get("enable_lsd"), DEFAULT_SETTINGS["enable_lsd"]),
            "enable_upnp": self._as_bool(raw.get("enable_upnp"), DEFAULT_SETTINGS["enable_upnp"]),
            "enable_natpmp": self._as_bool(raw.get("enable_natpmp"), DEFAULT_SETTINGS["enable_natpmp"]),
            "enable_utp": self._as_bool(raw.get("enable_utp"), DEFAULT_SETTINGS["enable_utp"]),
            "encryption_mode": enc_mode,
            "anonymous_mode": self._as_bool(raw.get("anonymous_mode"), DEFAULT_SETTINGS["anonymous_mode"]),
            "extra_trackers": extra_trackers,
            "proxy_type": proxy_type,
            "proxy_hostname": proxy_hostname,
            "proxy_port": proxy_port,
            "proxy_username": proxy_username,
            "proxy_password": proxy_password,
            "proxy_peer_connections": self._as_bool(raw.get("proxy_peer_connections"), DEFAULT_SETTINGS["proxy_peer_connections"]),
            "proxy_tracker_connections": self._as_bool(raw.get("proxy_tracker_connections"), DEFAULT_SETTINGS["proxy_tracker_connections"]),
            "proxy_hostnames": self._as_bool(raw.get("proxy_hostnames"), DEFAULT_SETTINGS["proxy_hostnames"]),
            "force_proxy": self._as_bool(raw.get("force_proxy"), DEFAULT_SETTINGS["force_proxy"]),
            "perf_v2_migrated": True,
        }

    def _save_settings(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp = TORRENT_SETTINGS_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._settings, indent=2), encoding="utf-8")
        os.replace(tmp, TORRENT_SETTINGS_FILE)

    def get_settings(self):
        if not LIBTORRENT_AVAILABLE:
            _try_import_libtorrent()
        with self._lock:
            out = dict(self._settings)
            out["proxy_password_set"] = bool(out.get("proxy_password"))
            out["proxy_password"] = ""
            out["engine_available"] = LIBTORRENT_AVAILABLE
            out["engine_version"] = str(LIBTORRENT_VERSION or "")
            out["engine_source"] = str(LIBTORRENT_SOURCE or "")
            out["active_torrents_count"] = len(self._active_job_ids)
            return out

    def update_settings(self, updates: dict, user="admin"):
        with self._lock:
            prev = dict(self._settings)
            merged = dict(self._settings)
            merged.update(updates or {})
            self._settings = self._validate_settings(merged, existing=prev)
            self._save_settings()
            if self._session is not None:
                self._apply_session_settings(self._session)
            new_win_bytes = int(self._settings["window_mb"]) * 1024 * 1024
            active_streamers = list(self._active_streamers.values())
            for j in self._jobs:
                if "stats" in j:
                    j["stats"]["window_cap_bytes"] = new_win_bytes
            self._save_jobs_unlocked()

        for streamer in active_streamers:
            try:
                streamer.update_window_bytes(new_win_bytes)
            except Exception:
                pass
        # Wake worker loop in case max_active_torrents was increased
        self._wake_event.set()

        proxy_desc = (
            f", proxy {self._settings['proxy_type'].upper()}://{self._settings['proxy_hostname']}:{self._settings['proxy_port']}"
            if self._settings["proxy_type"] != "none" and self._settings["proxy_hostname"]
            else ""
        )
        self._log(
            "Torrent Settings Updated",
            "change",
            (
                f"Port {self._settings['listen_port']}, window {self._settings['window_mb']} MiB, "
                f"max active {self._settings['max_active_torrents']}, "
                f"DL {self._settings['download_rate_limit_kbps']} KB/s, UL {self._settings['upload_rate_limit_kbps']} KB/s, "
                f"enc {self._settings['encryption_mode']}{proxy_desc}"
            ),
            drive="Torrents",
            target="Engine Settings",
            user=user,
        )
        return self.get_settings()

    def install_engine(self, user="admin", force_upgrade: bool = False):
        """
        Install or upgrade libtorrent at runtime inside the running Docker container,
        prioritizing the latest prebuilt binary wheel from PyPI (`pip install --upgrade --prefer-binary libtorrent`).
        """
        with self._install_lock:
            prev_version = str(LIBTORRENT_VERSION or "")
            if not force_upgrade and _try_import_libtorrent():
                return {
                    "ok": True,
                    "already_installed": True,
                    "engine_available": True,
                    "engine_version": str(LIBTORRENT_VERSION or ""),
                    "engine_source": str(LIBTORRENT_SOURCE or ""),
                    "method": "existing",
                    "message": f"libtorrent {LIBTORRENT_VERSION} ({LIBTORRENT_SOURCE or 'installed'}) is already active.",
                }

            logs = []
            # 1) Always try latest prebuilt binary wheel from PyPI first
            try:
                pip_cmd = [
                    sys.executable, "-m", "pip", "install",
                    "--no-cache-dir", "--upgrade", "--prefer-binary", "libtorrent",
                ]
                res = subprocess.run(
                    pip_cmd,
                    capture_output=True,
                    text=True,
                    timeout=240,
                    shell=False,
                )
                snippet = ((res.stdout or "") + "\n" + (res.stderr or "")).strip()[-1400:]
                logs.append(f"[pip] exit={res.returncode}\n{snippet}")
                if _try_import_libtorrent(force_reload=True):
                    action_lbl = "Upgraded" if (force_upgrade and prev_version) else "Installed"
                    ver_note = (
                        f"{prev_version} → {LIBTORRENT_VERSION}"
                        if (prev_version and prev_version != LIBTORRENT_VERSION)
                        else str(LIBTORRENT_VERSION)
                    )
                    self._log(
                        f"Torrent Engine {action_lbl}",
                        "change" if force_upgrade else "add",
                        f"{action_lbl} libtorrent ({ver_note}) via PyPI binary wheel",
                        drive="Torrents",
                        target="libtorrent",
                        user=user,
                    )
                    self._wake_event.set()
                    return {
                        "ok": True,
                        "already_installed": False,
                        "engine_available": True,
                        "engine_version": str(LIBTORRENT_VERSION or ""),
                        "engine_source": str(LIBTORRENT_SOURCE or "PyPI wheel"),
                        "method": "pip",
                        "message": f"Successfully installed latest PyPI libtorrent wheel: v{LIBTORRENT_VERSION} ({LIBTORRENT_SOURCE}).",
                        "details": snippet,
                    }
            except Exception as exc:
                logs.append(f"[pip] exception: {exc}")

            # 2) Fallback: Debian/Ubuntu apt-get python3-libtorrent + low-priority .pth bridge
            if shutil.which("apt-get"):
                env = dict(os.environ)
                env["DEBIAN_FRONTEND"] = "noninteractive"
                try:
                    upd = subprocess.run(
                        ["apt-get", "update"],
                        capture_output=True,
                        text=True,
                        timeout=180,
                        shell=False,
                        env=env,
                    )
                    inst = subprocess.run(
                        ["apt-get", "install", "-y", "--no-install-recommends", "python3-libtorrent"],
                        capture_output=True,
                        text=True,
                        timeout=240,
                        shell=False,
                        env=env,
                    )
                    snippet = ((upd.stderr or "") + "\n" + (inst.stdout or "") + "\n" + (inst.stderr or "")).strip()[-1200:]
                    logs.append(f"[apt] exit={inst.returncode}\n{snippet}")
                    try:
                        sp_dirs = site.getsitepackages()
                        if sp_dirs and os.path.isdir("/usr/lib/python3/dist-packages"):
                            pth = Path(sp_dirs[0]) / "zz_debian_dist_packages.pth"
                            pth.write_text("/usr/lib/python3/dist-packages\n", encoding="utf-8")
                    except Exception:
                        pass
                    if _try_import_libtorrent(force_reload=True):
                        self._log(
                            "Torrent Engine Installed",
                            "add",
                            f"Installed python3-libtorrent {LIBTORRENT_VERSION} via apt-get",
                            drive="Torrents",
                            target="libtorrent",
                            user=user,
                        )
                        self._wake_event.set()
                        return {
                            "ok": True,
                            "already_installed": False,
                            "engine_available": True,
                            "engine_version": str(LIBTORRENT_VERSION or ""),
                            "engine_source": str(LIBTORRENT_SOURCE or "Debian apt"),
                            "method": "apt",
                            "message": f"Installed python3-libtorrent {LIBTORRENT_VERSION} via apt.",
                            "details": snippet,
                        }
                except Exception as exc:
                    logs.append(f"[apt] exception: {exc}")

            detail = "\n\n".join(logs)[-1500:]
            self._log(
                "Torrent Engine Install Failed",
                "change",
                "Runtime libtorrent install/upgrade failed",
                drive="Torrents",
                target="libtorrent",
                user=user,
            )
            return {
                "ok": False,
                "engine_available": LIBTORRENT_AVAILABLE,
                "engine_version": str(LIBTORRENT_VERSION or ""),
                "engine_source": str(LIBTORRENT_SOURCE or ""),
                "method": "none",
                "message": "Could not install or upgrade libtorrent at runtime. Rebuild the Docker image (`docker compose build --no-cache`) to bundle the latest PyPI wheel.",
                "details": detail,
            }

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

    def _build_session_settings(self):
        s = self._settings
        iface = s.get("listen_interface") or "0.0.0.0"
        port = int(s.get("listen_port") or 6881)
        if ":" in iface and not iface.startswith("["):
            listen_str = f"[{iface}]:{port}"
        else:
            listen_str = f"{iface}:{port}"

        enc_enum = getattr(lt, "enc_policy", None)
        enc_map = {
            "forced": getattr(enc_enum, "pe_forced", 0) if enc_enum else 0,
            "enabled": getattr(enc_enum, "pe_enabled", 1) if enc_enum else 1,
            "disabled": getattr(enc_enum, "pe_disabled", 2) if enc_enum else 2,
        }
        enc_val = enc_map.get(s.get("encryption_mode", "enabled"), enc_map["enabled"])

        ptype_enum = getattr(lt, "proxy_type_t", None)
        p_none = getattr(ptype_enum, "none", 0) if ptype_enum else 0
        p_socks4 = getattr(ptype_enum, "socks4", 1) if ptype_enum else 1
        p_socks5 = getattr(ptype_enum, "socks5", 2) if ptype_enum else 2
        p_socks5_pw = getattr(ptype_enum, "socks5_pw", 3) if ptype_enum else 3
        p_http = getattr(ptype_enum, "http", 4) if ptype_enum else 4
        p_http_pw = getattr(ptype_enum, "http_pw", 5) if ptype_enum else 5

        ptype_str = s.get("proxy_type", "none")
        phost = (s.get("proxy_hostname") or "").strip()
        puser = s.get("proxy_username") or ""
        ppass = s.get("proxy_password") or ""
        has_auth = bool(puser or ppass)

        if ptype_str == "none" or not phost:
            proxy_type_val = p_none
            phost = ""
            pport = 0
            puser = ""
            ppass = ""
            force_proxy_val = False
        else:
            pport = int(s.get("proxy_port") or 1080)
            if ptype_str == "socks5":
                proxy_type_val = p_socks5_pw if has_auth else p_socks5
            elif ptype_str == "socks4":
                proxy_type_val = p_socks4
            elif ptype_str == "http":
                proxy_type_val = p_http_pw if has_auth else p_http
            else:
                proxy_type_val = p_none
            force_proxy_val = bool(s.get("force_proxy", False))

        utp_enabled = bool(s.get("enable_utp", True))
        max_active = max(1, int(s.get("max_active_torrents") or 2))
        return {
            "listen_interfaces": listen_str,
            "enable_dht": bool(s.get("enable_dht", True)),
            "enable_lsd": bool(s.get("enable_lsd", False)),
            "enable_upnp": bool(s.get("enable_upnp", True)),
            "enable_natpmp": bool(s.get("enable_natpmp", True)),
            "enable_incoming_utp": utp_enabled,
            "enable_outgoing_utp": utp_enabled,
            "connections_limit": int(s.get("max_connections") or 200),
            "unchoke_slots_limit": int(s.get("max_uploads", 8)),
            "download_rate_limit": int(s.get("download_rate_limit_kbps") or 0) * 1024,
            "upload_rate_limit": int(s.get("upload_rate_limit_kbps") or 0) * 1024,
            # High-throughput session pipeline tuning
            "aio_threads": 8,
            "checking_mem_usage": 1024,
            "max_queued_disk_bytes": 64 * 1024 * 1024,
            "send_buffer_watermark": 32 * 1024 * 1024,
            "send_buffer_low_watermark": 1024 * 1024,
            "send_buffer_watermark_factor": 150,
            "request_queue_time": 3,
            "max_out_request_queue": 1500,
            "max_allowed_in_request_queue": 2000,
            "active_downloads": max(8, max_active * 2),
            "active_seeds": max(4, max_active),
            "active_limit": max(32, max_active * 4),
            "torrent_connect_boost": 64,
            "connection_speed": 50,
            "mixed_mode_algorithm": 0,  # prefer_tcp so uTP congestion control never throttles TCP peers
            "in_enc_policy": enc_val,
            "out_enc_policy": enc_val,
            "anonymous_mode": bool(s.get("anonymous_mode", False)),
            "proxy_type": proxy_type_val,
            "proxy_hostname": phost,
            "proxy_port": pport,
            "proxy_username": puser,
            "proxy_password": ppass,
            "proxy_peer_connections": bool(s.get("proxy_peer_connections", True)),
            "proxy_tracker_connections": bool(s.get("proxy_tracker_connections", True)),
            "proxy_hostnames": bool(s.get("proxy_hostnames", True)),
            "force_proxy": force_proxy_val,
        }

    def _apply_session_settings(self, ses):
        pack = self._build_session_settings()
        try:
            ses.apply_settings(pack)
            return
        except Exception:
            # Apply valid keys individually across libtorrent 1.2 / 2.0
            for k, v in pack.items():
                try:
                    ses.apply_settings({k: v})
                except Exception:
                    pass

    def _ensure_session(self):
        if not LIBTORRENT_AVAILABLE and not _try_import_libtorrent():
            raise RuntimeError(
                "libtorrent is not installed in this runtime. Click 'Install / Upgrade libtorrent' in Settings → Torrents or rebuild the Docker container."
            )
        if self._session is None:
            base = {
                "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.status_notification,
            }
            self._session = lt.session(base)
            self._apply_session_settings(self._session)
            if self._settings.get("enable_dht", True):
                try:
                    self._session.add_dht_router("router.bittorrent.com", 6881)
                    self._session.add_dht_router("router.utorrent.com", 6881)
                    self._session.add_dht_router("dht.transmissionbt.com", 6881)
                    self._session.add_dht_router("dht.libtorrent.org", 25401)
                except Exception:
                    pass
        return self._session

    def _start_worker(self):
        if self._worker_started:
            return
        self._worker_started = True
        t = threading.Thread(target=self._worker_loop, name="sagedrive-torrent-scheduler", daemon=True)
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
        if provider not in ("gdrive", "filejump", "smb"):
            raise ValueError("Destination provider must be 'gdrive', 'filejump', or 'smb'")
        account_id = str((destination or {}).get("account_id") or "default").strip() or "default"
        folder_id = str((destination or {}).get("folder_id") or ("/" if provider == "smb" else "root")).strip() or ("/" if provider == "smb" else "root")
        folder_path = str((destination or {}).get("folder_path") or "/").strip() or "/"
        default_acc_name = (
            "Google Drive" if provider == "gdrive"
            else ("FileJump" if provider == "filejump" else "Local SMB NAS")
        )
        account_name = str((destination or {}).get("account_name") or default_acc_name).strip()
        conflict_action = str((destination or {}).get("conflict_action") or self._settings["default_conflict_action"]).strip().lower()
        if conflict_action not in ("keep_both", "skip", "replace"):
            conflict_action = "keep_both"

        if provider == "gdrive" and not gdrive_manager.is_authenticated(account_id=account_id):
            raise ValueError("Selected Google Drive account is not connected")
        if provider == "filejump" and not filejump_manager.is_authenticated(account_id=account_id):
            raise ValueError("Selected FileJump account is not connected")
        if provider == "smb":
            shares = smb_manager.list_shares()
            if not any(s.get("id") == account_id for s in shares):
                raise ValueError("Selected Local SMB share was not found")

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
            "active_file": "",
            "stats": {
                "total_bytes": sum(f["size"] for f in files if f.get("selected", True)),
                "uploaded_bytes": 0,
                "download_rate": 0,
                "upload_rate": 0,
                "peer_upload_rate": 0,
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
            streamer = self._active_streamers.get(job_id)
            if streamer is not None:
                streamer.request_stop()
            self._save_jobs_unlocked()
        self._log("Torrent Paused", "change", f"Paused torrent '{job['name']}'", drive="Torrents", target=job["name"], user=user)
        self._wake_event.set()
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
                    if job["destination"]["provider"] in ("filejump", "smb"):
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
            streamer = self._active_streamers.get(job_id)
            if streamer is not None:
                streamer.request_stop()
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
        self._wake_event.set()
        return True

    def _worker_loop(self):
        while True:
            self._wake_event.wait(timeout=1.5)
            self._wake_event.clear()
            while True:
                next_job_id = None
                with self._lock:
                    max_active = max(1, int(self._settings.get("max_active_torrents") or 2))
                    if len(self._active_job_ids) >= max_active:
                        break
                    # FIFO among queued jobs not already running
                    queued = [
                        j for j in reversed(self._jobs)
                        if j.get("status") == "queued" and j.get("id") not in self._active_job_ids
                    ]
                    if queued:
                        next_job_id = queued[0]["id"]
                        self._active_job_ids.add(next_job_id)
                if not next_job_id:
                    break
                t = threading.Thread(
                    target=self._run_job_wrapper,
                    args=(next_job_id,),
                    name=f"sagedrive-torrent-job-{next_job_id}",
                    daemon=True,
                )
                t.start()

    def _run_job_wrapper(self, job_id: str):
        try:
            self._run_job(job_id)
        finally:
            with self._lock:
                self._active_job_ids.discard(job_id)
                streamer = self._active_streamers.pop(job_id, None)
                if streamer is not None:
                    streamer.request_stop()
            self._wake_event.set()

    def _run_job(self, job_id: str):
        job_snap = self.get_job(job_id)
        if not job_snap or job_snap["status"] != "queued":
            return

        save_dir = SCRATCH_ROOT / job_id
        handle = None
        ses = None
        streamer = None
        try:
            with self._lock:
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
            else:
                atp = lt.parse_magnet_uri(job_snap["magnet_uri"])
                atp.save_path = str(save_dir)
                atp.storage_mode = lt.storage_mode_t.storage_mode_sparse

            if not self._settings.get("enable_pex", True):
                try:
                    tflags = getattr(lt, "torrent_flags", None)
                    disable_pex = getattr(tflags, "disable_pex", None) if tflags else None
                    if disable_pex is not None:
                        atp.flags |= disable_pex
                except Exception:
                    pass

            handle = ses.add_torrent(atp)

            extra_trackers = self._parse_extra_trackers(self._settings.get("extra_trackers", ""))
            for tr_url in extra_trackers:
                try:
                    handle.add_tracker({"url": tr_url, "tier": 1})
                except Exception:
                    pass

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
                time.sleep(0.35)

            tinfo = handle.torrent_file()

            # Populate files list from resolved magnet metadata if not yet populated
            fstorage = tinfo.files()
            first_selected_idx = None
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
                for f in job["files"]:
                    if f.get("selected", True) and f.get("status") not in ("completed", "skipped"):
                        first_selected_idx = int(f["index"])
                        break
                job["status"] = "streaming"
                self._recompute_job_totals(job)
                self._save_jobs_unlocked()

            win_bytes = int(self._settings["window_mb"]) * 1024 * 1024
            streamer = _ActiveJobStreamer(self, job_id, handle, tinfo, save_dir, win_bytes)
            with self._lock:
                self._active_streamers[job_id] = streamer

            # Immediately activate the first file's sliding window so seeders stay connected!
            if first_selected_idx is not None:
                fp_start, fp_end = streamer.file_piece_bounds(first_selected_idx)
                streamer.set_window(fp_start, fp_end, force=True)

            # Stream selected files strictly 1 file at a time within this torrent job
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
                            job["active_file"] = f.get("name") or ""
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
                    job["active_file"] = ""
                    job["completed_at"] = _now_iso()
                    job["updated_at"] = job["completed_at"]
                    job["stats"]["download_rate"] = 0
                    job["stats"]["upload_rate"] = 0
                    job["stats"]["peer_upload_rate"] = 0
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
            if streamer is not None:
                streamer.request_stop()
            with self._lock:
                self._active_streamers.pop(job_id, None)
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
        raw_fp = str(fstorage.file_path(fidx)).replace("\\", "/").lstrip("/")
        backing_path = save_dir / raw_fp

        # Immediately keep this file's sliding window prioritized before any destination API calls
        fp_start, fp_end = streamer.file_piece_bounds(fidx)
        streamer.set_window(fp_start, fp_end, force=True)

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
        elif provider == "smb":
            folder_path = dest.get("folder_path") or folder_id or "/"
            cloud_file_id = self._stream_file_to_smb(
                job_id, streamer, fidx, file_size, file_offset, backing_path,
                folder_path, rel_path, account_id, conflict_action,
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        # Immediately unlink sparse backing file so container scratch stays near zero
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

        chunk_unit = 8 * 1024 * 1024  # 8 MiB (multiple of 256 KiB required by Google Drive)
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
                    data, fd = streamer.read_flushed_bytes(backing_path, cur_read_pos, ready_len, fd=fd)
                    buf.extend(data)
                    cur_read_pos += len(data)

                offset = gdrive_manager.push_resumable_chunk(
                    resumable_uri, bytes(buf), offset, total_size=file_size
                )
                streamer.on_bytes_streamed(fidx, offset, len(buf))

                # Safely punch holes strictly on completed prior pieces
                if fd is not None:
                    safe_end = ((max(0, offset - streamer.piece_length)) // 4096) * 4096
                    if safe_end > punched_up_to:
                        _punch_hole_fd(fd, punched_up_to, safe_end - punched_up_to)
                        punched_up_to = safe_end
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

        # Pre-buffer up to 16 MiB (or full file if smaller) so FileJump's HTTP stream starts hot
        prebuf = min(file_size, 16 * 1024 * 1024, max(4 * 1024 * 1024, streamer.window_bytes // 4))
        if file_size <= streamer.window_bytes and file_size <= 16 * 1024 * 1024:
            prebuf = file_size
        streamer.wait_initial_buffer(fidx, target_bytes=prebuf)
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

    def _stream_file_to_smb(
        self, job_id, streamer, fidx, file_size, file_offset, backing_path,
        base_folder_path, rel_path, share_id, conflict_action,
    ):
        base_norm = smb_manager.sanitize_smb_path(base_folder_path or "/", allow_root=True)
        rel_clean = _sanitize_rel_path(rel_path)
        raw_dest = (f"/{rel_clean}" if base_norm == "/" else f"{base_norm.rstrip('/')}/{rel_clean}")
        resolved_path, should_skip = smb_manager.prepare_upload_target(
            share_id, raw_dest, conflict_action=conflict_action
        )
        if should_skip:
            return resolved_path

        smb_writer = smb_manager.PersistentSMBWriter(share_id, resolved_path)
        if file_size == 0:
            try:
                smb_writer.write_chunk(b"", offset=0, truncate=True)
            finally:
                smb_writer.close()
            return resolved_path

        min_chunk_unit = 1 * 1024 * 1024  # 1 MiB minimum for responsive progress on live downloads
        max_chunk_unit = 4 * 1024 * 1024  # 4 MiB burst when pieces are already buffered in sliding window
        offset = 0
        fd = None
        punched_up_to = 0
        try:
            while offset < file_size:
                streamer._check_abort()
                rem_bytes = file_size - offset
                ready_now = streamer.peek_contiguous_ready_bytes(
                    file_offset + offset, min(max_chunk_unit, rem_bytes), fidx
                )
                target_chunk = min(rem_bytes, max(min_chunk_unit, ready_now))
                buf = bytearray()
                cur_read_pos = offset
                while len(buf) < target_chunk:
                    want = target_chunk - len(buf)
                    ready_len = streamer.wait_for_range(file_offset + cur_read_pos, want, fidx, cur_read_pos)
                    data, fd = streamer.read_flushed_bytes(backing_path, cur_read_pos, ready_len, fd=fd)
                    buf.extend(data)
                    cur_read_pos += len(data)

                smb_writer.write_chunk(
                    bytes(buf), offset=offset, truncate=(offset == 0)
                )
                offset += len(buf)
                streamer.on_bytes_streamed(fidx, offset, len(buf))

                if fd is not None:
                    safe_end = ((max(0, offset - streamer.piece_length)) // 4096) * 4096
                    if safe_end > punched_up_to:
                        _punch_hole_fd(fd, punched_up_to, safe_end - punched_up_to)
                        punched_up_to = safe_end
        finally:
            smb_writer.close()
            if fd is not None:
                try:
                    if file_size > punched_up_to:
                        _punch_hole_fd(fd, punched_up_to, file_size - punched_up_to)
                    os.close(fd)
                except Exception:
                    pass
        return resolved_path


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
