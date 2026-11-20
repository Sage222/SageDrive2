import os, json, time, math, secrets, hashlib, bcrypt, mimetypes, io, re, shutil, struct, subprocess, threading, tempfile, zipfile, queue, requests
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import quote, urlparse, parse_qs, unquote
from flask import Flask, request, jsonify, send_file, send_from_directory, redirect
from flask_cors import CORS
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import auth, smb_manager, gdrive_manager, onedrive_manager, filejump_manager

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, supports_credentials=True, expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"])
auth.bootstrap_admin()

# ── Self-contained Auth 5-Strike / 15-Minute Anti-Hammering Lockout ───────────
_AUTH_MAX_ATTEMPTS = 5
_AUTH_LOCKOUT_SECONDS = 15 * 60  # 15 minutes
_AUTH_UNKNOWN_LOCKOUTS = {}
_auth_lock = threading.Lock()

def _auth_login_with_status(username, password):
    uname = (username or "").strip()
    now = time.time()
    with _auth_lock:
        users = auth._load_users()
        user = users.get(uname)
        record = user if user is not None else _AUTH_UNKNOWN_LOCKOUTS.setdefault(uname or "_anon_", {"failed_attempts": 0, "locked_until": 0})
        locked_until = float(record.get("locked_until", 0) or 0)

        if locked_until > now:
            rem = int(math.ceil(locked_until - now))
            mins = max(1, int(math.ceil(rem / 60)))
            msg = f"Account locked due to {_AUTH_MAX_ATTEMPTS} failed login attempts. Try again in {mins} minute{'s' if mins != 1 else ''} ({rem}s)."
            return None, msg, 429, {"locked": True, "retry_after": rem, "attempts_remaining": 0}

        if locked_until > 0 and locked_until <= now:
            record["locked_until"] = 0
            record["failed_attempts"] = 0
            if user is not None:
                auth._save_users(users)

        if user and bcrypt.checkpw((password or "").encode(), user["hash"].encode()):
            if user.get("failed_attempts") or user.get("locked_until"):
                user["failed_attempts"] = 0
                user["locked_until"] = 0
                auth._save_users(users)
            token = secrets.token_hex(32)
            auth.SESSIONS[token] = {"username": uname, "role": user["role"], "admin_enabled": False, "expires": now + auth.SESSION_TTL}
            return token, None, 200, {"locked": False, "attempts_remaining": _AUTH_MAX_ATTEMPTS}

        fails = int(record.get("failed_attempts", 0) or 0) + 1
        record["failed_attempts"] = fails

        if fails >= _AUTH_MAX_ATTEMPTS:
            record["locked_until"] = now + _AUTH_LOCKOUT_SECONDS
            if user is not None:
                auth._save_users(users)
            msg = f"Account locked for 15 minutes due to {_AUTH_MAX_ATTEMPTS} incorrect login attempts."
            return None, msg, 429, {"locked": True, "retry_after": _AUTH_LOCKOUT_SECONDS, "attempts_remaining": 0}

        if user is not None:
            auth._save_users(users)
        rem_tries = _AUTH_MAX_ATTEMPTS - fails
        msg = f"Invalid credentials ({rem_tries} attempt{'s' if rem_tries != 1 else ''} remaining before 15m lockout)"
        return None, msg, 401, {"locked": False, "attempts_remaining": rem_tries}

auth.login_with_status = _auth_login_with_status

# ── Bounded In-Memory Caches & SMB Path Alias ─────────────────────────────────
_SMB_SIZE_CACHE = {}
_SMB_SIZE_TTL = 60.0
_SMB_SIZE_MAX_ENTRIES = 4000
_PROBE_CACHE = {}
_PROBE_TTL = 600.0
_PROBE_MAX_ENTRIES = 1000

_sanitize_smb_path = smb_manager.sanitize_smb_path


def _prune_main_caches(now=None):
    now = now or time.time()
    for cache_dict, ttl, max_entries in (
        (_SMB_SIZE_CACHE, _SMB_SIZE_TTL, _SMB_SIZE_MAX_ENTRIES),
        (_PROBE_CACHE, _PROBE_TTL, _PROBE_MAX_ENTRIES),
    ):
        expired = [k for k, v in list(cache_dict.items()) if (now - v[0]) >= ttl]
        for k in expired:
            cache_dict.pop(k, None)
        if len(cache_dict) > max_entries:
            oldest = sorted(cache_dict.keys(), key=lambda k: cache_dict[k][0])
            for k in oldest[: len(cache_dict) - max_entries]:
                cache_dict.pop(k, None)

    with _auth_lock:
        expired_locks = [
            k for k, rec in list(_AUTH_UNKNOWN_LOCKOUTS.items())
            if float(rec.get("locked_until", 0) or 0) > 0 and float(rec.get("locked_until", 0)) <= now
        ]
        for k in expired_locks:
            _AUTH_UNKNOWN_LOCKOUTS.pop(k, None)


def _get_smb_file_size(share_id, path):
    norm_path = _sanitize_smb_path(path, allow_root=False)
    key = f"{share_id}:{norm_path}"
    now = time.time()
    _prune_main_caches(now)
    cached = _SMB_SIZE_CACHE.get(key)
    if cached and (now - cached[0]) < _SMB_SIZE_TTL:
        return cached[1]
    sz = smb_manager.get_file_size(share_id, norm_path)
    _SMB_SIZE_CACHE[key] = (now, sz)
    return sz


# ── Internal Loopback HTTP Range Server for FFmpeg & FFprobe ──────────────────
class _InternalMediaRangeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _handle_request(self, send_body=True):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        try:
            if parsed.path.startswith("/smb/"):
                share_id = unquote(parsed.path[len("/smb/"):])
                smb_path = qs.get("path", [""])[0]
                file_size = _get_smb_file_size(share_id, smb_path)
                kind = "smb"
            elif parsed.path.startswith("/gdrive/"):
                file_id = unquote(parsed.path[len("/gdrive/"):])
                account_id = qs.get("account_id", [None])[0]
                meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
                file_size = meta["size"]
                kind = "gdrive"
            elif parsed.path.startswith("/onedrive/"):
                file_id = unquote(parsed.path[len("/onedrive/"):])
                account_id = qs.get("account_id", [None])[0]
                meta = onedrive_manager.get_file_meta(file_id, account_id=account_id)
                file_size = meta["size"]
                kind = "onedrive"
            elif parsed.path.startswith("/filejump/"):
                file_id = unquote(parsed.path[len("/filejump/"):])
                account_id = qs.get("account_id", [None])[0]
                meta = filejump_manager.get_file_meta(file_id, account_id=account_id)
                file_size = meta["size"]
                kind = "filejump"
            else:
                self.send_response(404)
                self.end_headers()
                return

            rng = self.headers.get("Range")
            if rng and file_size > 0 and rng.startswith("bytes="):
                m = re.search(r"bytes=(\d*)-(\d*)", rng)
                if not m:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                if not m.group(1) and m.group(2):
                    suffix = int(m.group(2))
                    start = max(0, file_size - suffix)
                    end = file_size - 1
                else:
                    start = int(m.group(1)) if m.group(1) else 0
                    end = int(m.group(2)) if m.group(2) else file_size - 1
                if start >= file_size or start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return
                end = min(end, file_size - 1)
                length = end - start + 1
                self.send_response(206)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(length))
                self.end_headers()
            else:
                start = 0
                end = max(0, file_size - 1)
                length = file_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Accept-Ranges", "bytes")
                if file_size > 0:
                    self.send_header("Content-Length", str(file_size))
                self.end_headers()

            if not send_body:
                return

            fetch_len = length
            if kind == "smb":
                gen = smb_manager.stream_file_range(share_id, smb_path, start=start, length=fetch_len)
            elif kind == "onedrive":
                end_byte = (start + fetch_len - 1) if fetch_len > 0 else None
                gen = onedrive_manager.stream_file_range(file_id, start=start, end=end_byte, account_id=account_id)
            elif kind == "filejump":
                end_byte = (start + fetch_len - 1) if fetch_len > 0 else None
                gen = filejump_manager.stream_file_range(file_id, start=start, end=end_byte, account_id=account_id)
            else:
                end_byte = (start + fetch_len - 1) if fetch_len > 0 else None
                gen = gdrive_manager.stream_file_range(file_id, start=start, end=end_byte, account_id=account_id)

            try:
                for chunk in gen:
                    if not chunk:
                        continue
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                try:
                    gen.close()
                except Exception:
                    pass
        except Exception:
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def do_GET(self):
        self._handle_request(send_body=True)

_internal_media_server = ThreadingHTTPServer(("127.0.0.1", 0), _InternalMediaRangeHandler)
_INTERNAL_MEDIA_PORT = _internal_media_server.server_port
threading.Thread(target=_internal_media_server.serve_forever, daemon=True).start()

def _internal_smb_url(share_id, path):
    return f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/smb/{quote(str(share_id))}?path={quote(str(path))}"

def _internal_gdrive_url(file_id, account_id=None):
    base = f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/gdrive/{quote(str(file_id))}"
    if account_id:
        return f"{base}?account_id={quote(str(account_id))}"
    return base

def _internal_onedrive_url(file_id, account_id=None):
    base = f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/onedrive/{quote(str(file_id))}"
    if account_id:
        return f"{base}?account_id={quote(str(account_id))}"
    return base

def _internal_filejump_url(file_id, account_id=None):
    base = f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/filejump/{quote(str(file_id))}"
    if account_id:
        return f"{base}?account_id={quote(str(account_id))}"
    return base

MEDIA_MIMES = {
    "mp4": "video/mp4",
    "m4v": "video/mp4",
    "mov": "video/mp4",
    "webm": "video/webm",
    "mkv": "video/mp4",
    "ogv": "video/ogg",
    "avi": "video/x-msvideo",
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "ogg": "audio/ogg",
    "oga": "audio/ogg",
    "opus": "audio/ogg",
    "m4a": "audio/mp4",
    "aac": "audio/aac",
    "flac": "audio/flac",
    "weba": "audio/webm",
    "wma": "audio/x-ms-wma",
    "aiff": "audio/aiff",
    "aif": "audio/aiff",
    "eac3": "audio/eac3",
    "ec3": "audio/eac3",
    "ac3": "audio/ac3",
    "dts": "audio/vnd.dts",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "jfif": "image/jpeg",
    "png": "image/png",
    "apng": "image/apng",
    "gif": "image/gif",
    "webp": "image/webp",
    "svg": "image/svg+xml",
    "bmp": "image/bmp",
    "ico": "image/x-icon",
    "avif": "image/avif",
    "pdf": "application/pdf",
    "txt": "text/plain; charset=utf-8",
    "md": "text/plain; charset=utf-8",
    "log": "text/plain; charset=utf-8",
    "csv": "text/plain; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "xml": "text/xml; charset=utf-8",
    "yaml": "text/plain; charset=utf-8",
    "yml": "text/plain; charset=utf-8",
    "ini": "text/plain; charset=utf-8",
    "conf": "text/plain; charset=utf-8",
    "toml": "text/plain; charset=utf-8",
    "py": "text/plain; charset=utf-8",
    "sh": "text/plain; charset=utf-8",
    "js": "text/plain; charset=utf-8",
    "ts": "text/plain; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "html": "text/html; charset=utf-8",
}

def guess_media_mime(filename, fallback=None):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in MEDIA_MIMES:
        return MEDIA_MIMES[ext]
    if fallback == "video/quicktime":
        return "video/mp4"
    if fallback in ("audio/mp3", "audio/mpeg3", "audio/x-mp3"):
        return "audio/mpeg"
    if fallback in ("audio/x-wav", "audio/wave"):
        return "audio/wav"
    if fallback in ("audio/x-m4a", "audio/m4a"):
        return "audio/mp4"
    if fallback in ("audio/x-flac",):
        return "audio/flac"
    guessed = mimetypes.guess_type(filename)[0]
    if guessed and guessed not in ("application/octet-stream", "video/quicktime"):
        return guessed
    if fallback and fallback not in ("application/octet-stream", "video/quicktime"):
        return fallback
    return "application/octet-stream"

def make_content_disposition(filename, is_download=False):
    disp_type = "attachment" if is_download else "inline"
    safe_ascii = "".join(c if 32 <= ord(c) < 127 and c not in ('"', "\\") else "_" for c in filename)
    encoded = quote(filename)
    return f"{disp_type}; filename=\"{safe_ascii}\"; filename*=UTF-8''{encoded}"

def _stream_and_unlink_tmpfile(tmp_path, chunk_size=262144):
    try:
        with open(tmp_path, "rb") as fp:
            while True:
                data = fp.read(chunk_size)
                if not data:
                    break
                yield data
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

# ── Media Codec Probe & Smart Remux / Transcode ───────────────────────────────
def _parse_duration_val(val):
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val) if (val > 0 and math.isfinite(val)) else 0.0
    s = str(val).strip()
    if not s or s.upper() == "N/A":
        return 0.0
    m = re.match(r"^(\d+):(\d{1,2}):(\d{1,2}(?:\.\d+)?)", s)
    if m:
        try:
            hrs = int(m.group(1))
            mins = int(m.group(2))
            secs = float(m.group(3))
            return hrs * 3600.0 + mins * 60.0 + secs
        except Exception:
            pass
    try:
        v = float(s)
        if v > 0 and math.isfinite(v):
            return v
    except Exception:
        pass
    return 0.0

def _parse_tag_duration(tags):
    if not tags or not isinstance(tags, dict):
        return 0.0
    for k, v in tags.items():
        kl = str(k).lower().strip()
        if "ts" in kl:
            continue
        if kl == "duration" or kl.startswith("duration-") or kl.startswith("duration_"):
            s = str(v or "").strip()
            if ":" in s:
                d = _parse_duration_val(s)
                if d > 0:
                    return d
    return 0.0

def _parse_fps(rate_str):
    if not rate_str:
        return 0.0
    s = str(rate_str).strip()
    if "/" in s:
        parts = s.split("/", 1)
        try:
            num = float(parts[0])
            den = float(parts[1])
            if num > 0 and den > 0:
                return num / den
        except Exception:
            return 0.0
    try:
        v = float(s)
        return v if v > 0 else 0.0
    except Exception:
        return 0.0

def _extract_stream_duration(st, is_video=False):
    if not st or not isinstance(st, dict):
        return 0.0
    d = _parse_duration_val(st.get("duration"))
    if d > 0:
        return d
    tags = st.get("tags") or {}
    td = _parse_tag_duration(tags)
    if td > 0:
        return td
    if is_video:
        nb_frames = 0
        raw_frames = st.get("nb_frames")
        if raw_frames and str(raw_frames).isdigit():
            nb_frames = int(raw_frames)
        else:
            for k, v in tags.items():
                kl = str(k).lower().strip()
                if kl == "number_of_frames" or kl.startswith("number_of_frames-"):
                    if str(v).strip().isdigit():
                        nb_frames = int(str(v).strip())
                        break
        if nb_frames > 0:
            fps = _parse_fps(st.get("avg_frame_rate")) or _parse_fps(st.get("r_frame_rate"))
            if fps > 0:
                return nb_frames / fps
    return 0.0

def _extract_probe_duration(fmt, streams):
    fmt_dur = _parse_duration_val((fmt or {}).get("duration"))
    if fmt_dur <= 0:
        fmt_dur = _parse_tag_duration((fmt or {}).get("tags"))

    non_cover_videos = [
        s for s in (streams or [])
        if s.get("codec_type") == "video"
        and (s.get("codec_name") or "").lower() not in ("mjpeg", "png", "bmp", "gif", "webp")
    ]
    audio_streams = [s for s in (streams or []) if s.get("codec_type") == "audio"]

    video_durs = [d for d in (_extract_stream_duration(s, is_video=True) for s in non_cover_videos) if d > 0]
    audio_durs = [d for d in (_extract_stream_duration(s, is_video=False) for s in audio_streams) if d > 0]

    video_dur = video_durs[0] if video_durs else 0.0
    audio_dur = audio_durs[0] if audio_durs else 0.0

    if non_cover_videos:
        if video_dur > 5:
            if audio_dur > 5 and abs(video_dur - audio_dur) <= 20:
                return max(video_dur, audio_dur)
            if 5 < fmt_dur < video_dur and (video_dur - fmt_dur) <= 30:
                return fmt_dur
            return video_dur
        if audio_dur > 5 and fmt_dur > audio_dur + 20:
            return audio_dur
        if fmt_dur > 0:
            return fmt_dur
        return audio_dur

    if audio_dur > 5 and (fmt_dur <= 0 or fmt_dur > audio_dur + 15):
        return audio_dur
    return fmt_dur if fmt_dur > 0 else audio_dur

def _analyze_probe_data(data, filename=""):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    streams = data.get("streams") or []
    fmt = data.get("format") or {}

    non_cover_videos = [
        s for s in streams
        if s.get("codec_type") == "video"
        and (s.get("codec_name") or "").lower() not in ("mjpeg", "png", "bmp", "gif", "webp")
    ]
    video_streams = non_cover_videos or [s for s in streams if s.get("codec_type") == "video"]
    audio_streams = [s for s in streams if s.get("codec_type") == "audio"]

    v0 = video_streams[0] if video_streams else None
    a0 = audio_streams[0] if audio_streams else None

    video_codec = (v0.get("codec_name") or "").lower() if v0 else ""
    video_pix_fmt = (v0.get("pix_fmt") or "").lower() if v0 else ""
    audio_codec = (a0.get("codec_name") or "").lower() if a0 else ""
    audio_channels = int(a0.get("channels") or 0) if a0 else 0

    has_video = bool(v0)
    has_audio = bool(a0)

    # Audio codecs natively decoded by all browsers in <video>/<audio>
    safe_audio_codecs = {"aac", "mp3", "opus"}
    if ext in ("webm", "ogg", "ogv", "oga"):
        safe_audio_codecs.add("vorbis")
    if not has_video and ext in ("wav", "flac"):
        safe_audio_codecs.update({"pcm_s16le", "pcm_s24le", "pcm_f32le", "pcm_u8", "flac"})

    # EAC3, AC3, DTS, TrueHD, MLP, PCM in video, FLAC/ALAC in video, WMA, MP2, Vorbis in MP4/MKV, or >2ch non-AAC need transcoding
    needs_audio_transcode = False
    if has_audio:
        if audio_codec not in safe_audio_codecs:
            needs_audio_transcode = True
        elif audio_channels > 2 and audio_codec != "aac":
            needs_audio_transcode = True

    is_10bit_h264 = video_codec == "h264" and video_pix_fmt.endswith(("10le", "10be", "12le", "12be"))
    needs_video_transcode = False
    if has_video:
        if video_codec not in ("h264", "hevc", "vp8", "vp9", "av1") or is_10bit_h264:
            needs_video_transcode = True

    non_native_container = ext in ("mkv", "avi", "wmv", "flv", "ts", "m2ts", "mpg", "mpeg", "vob", "divx")
    can_remux_video = has_video and video_codec in ("h264", "hevc") and not is_10bit_h264

    if has_video:
        if needs_video_transcode:
            recommended_mode = "full"
        elif needs_audio_transcode or non_native_container:
            recommended_mode = "remux" if can_remux_video else "full"
        else:
            recommended_mode = "direct"
    else:
        recommended_mode = "audio" if (needs_audio_transcode or ext in ("eac3", "ec3", "ac3", "dts", "wma", "aiff", "aif", "alac", "mka", "mp2")) else "direct"

    audio_tracks_out = []
    for idx, s in enumerate(audio_streams):
        tags = s.get("tags") or {}
        audio_tracks_out.append({
            "index": idx,
            "codec": (s.get("codec_name") or "unknown").lower(),
            "channels": int(s.get("channels") or 0),
            "language": tags.get("language") or tags.get("LANGUAGE") or "",
            "title": tags.get("title") or tags.get("TITLE") or "",
        })

    bitmap_sub_codecs = {"hdmv_pgs_subtitle", "pgssub", "dvd_subtitle", "dvdsub", "dvb_subtitle", "dvbsub", "xsub"}
    subtitle_streams = [s for s in streams if s.get("codec_type") == "subtitle"]
    subtitle_tracks_out = []
    for s_idx, s in enumerate(subtitle_streams):
        scodec = (s.get("codec_name") or "unknown").lower()
        if scodec in bitmap_sub_codecs:
            continue
        tags = s.get("tags") or {}
        disp = s.get("disposition") or {}
        subtitle_tracks_out.append({
            "index": s_idx,
            "stream_index": s.get("index", s_idx),
            "codec": scodec,
            "language": tags.get("language") or tags.get("LANGUAGE") or "",
            "title": tags.get("title") or tags.get("TITLE") or "",
            "forced": bool(disp.get("forced")),
            "default": bool(disp.get("default")),
        })

    duration = _extract_probe_duration(fmt, streams)
    video_fps = 0.0
    if v0:
        try:
            video_fps = _parse_fps(v0.get("avg_frame_rate")) or _parse_fps(v0.get("r_frame_rate"))
            if video_fps < 1.0 or video_fps > 240.0:
                video_fps = 0.0
        except Exception:
            video_fps = 0.0

    return {
        "has_video": has_video,
        "video_codec": video_codec,
        "video_pix_fmt": video_pix_fmt,
        "video_fps": round(video_fps, 3) if video_fps > 0 else 0,
        "has_audio": has_audio,
        "audio_codec": audio_codec,
        "audio_channels": audio_channels,
        "audio_streams": audio_tracks_out,
        "subtitle_streams": subtitle_tracks_out,
        "duration": duration,
        "needs_audio_transcode": needs_audio_transcode,
        "needs_video_transcode": needs_video_transcode,
        "can_remux_video": can_remux_video,
        "recommended_mode": recommended_mode,
    }

def probe_media_info(cache_key, internal_url, filename="", fallback_gen_fn=None):
    cache_key = f"v3:{cache_key}"
    now = time.time()
    _prune_main_caches(now)
    cached = _PROBE_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _PROBE_TTL:
        return cached[1]

    show_entries = "stream=index,codec_type,codec_name,profile,pix_fmt,channels,sample_rate,duration,nb_frames,avg_frame_rate,r_frame_rate:stream_disposition=default,forced:stream_tags:format=format_name,duration:format_tags"
    cmd = [
        "ffprobe",
        "-v", "error",
        "-probesize", "5000000",
        "-analyzeduration", "5000000",
        "-show_entries", show_entries,
        "-of", "json",
        internal_url,
    ]
    data = None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            parsed = json.loads(res.stdout)
            if parsed.get("streams"):
                data = parsed
    except Exception:
        pass

    if not data and fallback_gen_fn is not None:
        try:
            proc = subprocess.Popen(
                [
                    "ffprobe",
                    "-v", "error",
                    "-probesize", "5000000",
                    "-analyzeduration", "5000000",
                    "-show_entries", show_entries,
                    "-of", "json",
                    "pipe:0",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            gen = fallback_gen_fn()
            sent = 0
            try:
                for chunk in gen:
                    if proc.poll() is not None or sent >= 5 * 1024 * 1024:
                        break
                    proc.stdin.write(chunk)
                    sent += len(chunk)
            except Exception:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
                try:
                    gen.close()
                except Exception:
                    pass
            out, _ = proc.communicate(timeout=8)
            if out:
                parsed = json.loads(out.decode("utf-8", errors="ignore"))
                if parsed.get("streams"):
                    data = parsed
        except Exception:
            pass

    info = _analyze_probe_data(data or {}, filename)
    if data and data.get("streams"):
        _PROBE_CACHE[cache_key] = (now, info)
    return info

def _patch_mp4_moov_duration(chunk, duration_sec):
    """
    Patches the ISO BMFF moov header (mvhd, tkhd, mdhd, and mvex/mehd) emitted
    by FFmpeg's -movflags empty_moov so browsers and players know the full
    duration of a live-remuxed or transcoded video immediately from the first chunk.
    """
    if not chunk or not duration_sec or duration_sec <= 0 or not math.isfinite(duration_sec):
        return chunk
    try:
        buf = bytearray(chunk)
        mvhd_ts = [1000]

        def _walk(b, start, end):
            pos = start
            while pos + 8 <= end:
                sz, btype = struct.unpack(">I4s", b[pos:pos+8])
                if sz < 8 or pos + sz > end:
                    break
                if btype == b"mvhd":
                    ver = b[pos+8]
                    if ver == 0 and sz >= 28:
                        ts = struct.unpack(">I", b[pos+20:pos+24])[0] or 1000
                        mvhd_ts[0] = ts
                        scaled = int(round(duration_sec * ts))
                        if 0 < scaled <= 0x7FFFFFFF:
                            struct.pack_into(">I", b, pos+24, scaled)
                    elif ver == 1 and sz >= 40:
                        ts = struct.unpack(">I", b[pos+28:pos+32])[0] or 1000
                        mvhd_ts[0] = ts
                        struct.pack_into(">Q", b, pos+32, int(round(duration_sec * ts)))
                elif btype == b"tkhd":
                    ver = b[pos+8]
                    ts = mvhd_ts[0]
                    if ver == 0 and sz >= 32:
                        scaled = int(round(duration_sec * ts))
                        if 0 < scaled <= 0x7FFFFFFF:
                            struct.pack_into(">I", b, pos+28, scaled)
                    elif ver == 1 and sz >= 44:
                        struct.pack_into(">Q", b, pos+36, int(round(duration_sec * ts)))
                elif btype == b"mdhd":
                    ver = b[pos+8]
                    if ver == 0 and sz >= 28:
                        ts = struct.unpack(">I", b[pos+20:pos+24])[0] or 1000
                        scaled = int(round(duration_sec * ts))
                        if 0 < scaled <= 0x7FFFFFFF:
                            struct.pack_into(">I", b, pos+24, scaled)
                    elif ver == 1 and sz >= 40:
                        ts = struct.unpack(">I", b[pos+28:pos+32])[0] or 1000
                        struct.pack_into(">Q", b, pos+32, int(round(duration_sec * ts)))
                elif btype in (b"moov", b"trak", b"mdia"):
                    _walk(b, pos+8, pos+sz)
                elif btype == b"moof":
                    break
                pos += sz

        _walk(buf, 0, len(buf))
        pos = 0
        while pos + 8 <= len(buf):
            sz, btype = struct.unpack(">I4s", buf[pos:pos+8])
            if sz < 8 or pos + sz > len(buf):
                break
            if btype == b"moov":
                cpos = pos + 8
                cend = pos + sz
                while cpos + 8 <= cend:
                    csz, ctype = struct.unpack(">I4s", buf[cpos:cpos+8])
                    if csz < 8 or cpos + csz > cend:
                        break
                    if ctype == b"mvex":
                        has_mehd = b"mehd" in buf[cpos+8:cpos+csz]
                        if not has_mehd:
                            mehd_dur = min(0xFFFFFFFF, int(round(duration_sec * mvhd_ts[0])))
                            mehd_box = struct.pack(">I4sB3sI", 16, b"mehd", 0, b"\x00\x00\x00", mehd_dur)
                            struct.pack_into(">I", buf, cpos, csz + 16)
                            struct.pack_into(">I", buf, pos, sz + 16)
                            buf[cpos+8:cpos+8] = mehd_box
                        break
                    cpos += csz
                break
            pos += sz
        return bytes(buf)
    except Exception:
        return chunk

def _build_ffmpeg_video_cmd(input_spec, mode="full", video_codec="h264", audio_track=0, start_time=0.0):
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
    if start_time and start_time > 0:
        if mode == "remux":
            cmd += ["-noaccurate_seek"]
        cmd += ["-ss", f"{start_time:.3f}"]
    cmd += ["-i", input_spec]
    cmd += ["-map", "0:V:0", "-map", f"0:a:{max(0, int(audio_track))}?", "-sn", "-dn"]
    if mode == "remux":
        vtag = "hvc1" if video_codec == "hevc" else "avc1"
        cmd += ["-c:v", "copy", "-tag:v", vtag]
    else:
        cmd += [
            "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p",
            "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
        ]
    af_filter = "aresample=async=1" if (mode == "remux" and start_time and start_time > 0) else "aresample=async=1:first_pts=0"
    cmd += [
        "-af", af_filter,
        "-c:a", "aac", "-ac", "2", "-ar", "48000", "-b:a", "192k",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "frag_keyframe+empty_moov+default_base_moof",
        "-f", "mp4",
        "pipe:1",
    ]
    return cmd

def transcode_media_stream(internal_url=None, chunk_iterable_fn=None, filename="", mode="auto", audio_track=0, start_time=0.0, probe_info=None, duration_hint=0.0):
    """
    Streams fragmented MP4 with universal 2-channel stereo AAC audio and patches
    the initial moov header with the true full media duration.
    """
    vcodec = (probe_info or {}).get("video_codec") or "h264"
    can_remux = (probe_info or {}).get("can_remux_video", False)
    total_dur = float((probe_info or {}).get("duration") or duration_hint or 0.0)
    effective_dur = max(0.0, total_dur - float(start_time or 0.0)) if total_dur > 0 else 0.0

    if mode == "auto":
        effective_mode = "remux" if can_remux else "full"
    elif mode in ("remux", "full"):
        effective_mode = mode
    else:
        effective_mode = "full"

    attempts = []
    if internal_url:
        if effective_mode == "remux":
            attempts.append(("url", "remux"))
        attempts.append(("url", "full"))
    if chunk_iterable_fn is not None:
        attempts.append(("pipe", "full"))

    for src_kind, attempt_mode in attempts:
        proc = None
        gen = None
        try:
            if src_kind == "url":
                cmd = _build_ffmpeg_video_cmd(
                    internal_url,
                    mode=attempt_mode,
                    video_codec=vcodec,
                    audio_track=audio_track,
                    start_time=start_time,
                )
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=65536)
            else:
                cmd = _build_ffmpeg_video_cmd(
                    "pipe:0",
                    mode="full",
                    video_codec=vcodec,
                    audio_track=audio_track,
                    start_time=0.0,
                )
                proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=65536)
                gen = chunk_iterable_fn()

                def _feed_stdin(p=proc, g=gen):
                    try:
                        for chunk in g:
                            if p.poll() is not None:
                                break
                            p.stdin.write(chunk)
                    except Exception:
                        pass
                    finally:
                        try:
                            p.stdin.close()
                        except Exception:
                            pass
                        try:
                            g.close()
                        except Exception:
                            pass

                threading.Thread(target=_feed_stdin, daemon=True).start()

            init_buf = bytearray()
            while len(init_buf) < 16384:
                piece = proc.stdout.read(65536 - len(init_buf))
                if not piece:
                    break
                init_buf.extend(piece)
                if b"moof" in init_buf:
                    break

            if not init_buf:
                try:
                    proc.kill()
                except Exception:
                    pass
                continue

            first_chunk = _patch_mp4_moov_duration(bytes(init_buf), effective_dur)
            yield first_chunk
            while True:
                out = proc.stdout.read(65536)
                if not out:
                    break
                yield out
            return
        finally:
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            if gen is not None:
                try:
                    gen.close()
                except Exception:
                    pass

def transcode_stream(chunk_iterable):
    return transcode_media_stream(
        internal_url=None,
        chunk_iterable_fn=lambda: chunk_iterable,
        mode="full",
    )

def transcode_audio_stream(chunk_iterable, internal_url=None, start_time=0.0):
    """
    Transcodes any audio stream (including 5.1/7.1 EAC3, AC3, DTS, FLAC, WMA, ALAC)
    into universal 2-channel stereo MP3.
    """
    proc = None
    gen = None
    try:
        if internal_url:
            cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
            if start_time and start_time > 0:
                cmd += ["-ss", f"{start_time:.3f}"]
            cmd += [
                "-i", internal_url,
                "-vn",
                "-af", "aresample=async=1:first_pts=0",
                "-c:a", "libmp3lame", "-ac", "2", "-ar", "48000", "-b:a", "192k",
                "-f", "mp3",
                "pipe:1",
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                bufsize=65536,
            )
            first = proc.stdout.read(65536)
            if first:
                yield first
                while True:
                    out = proc.stdout.read(65536)
                    if not out:
                        break
                    yield out
                return
            try:
                proc.kill()
            except Exception:
                pass

        gen = chunk_iterable() if callable(chunk_iterable) else chunk_iterable
        proc = subprocess.Popen(
            [
                "ffmpeg",
                "-hide_banner", "-loglevel", "error",
                "-i", "pipe:0",
                "-vn",
                "-af", "aresample=async=1:first_pts=0",
                "-c:a", "libmp3lame", "-ac", "2", "-ar", "48000", "-b:a", "192k",
                "-f", "mp3",
                "pipe:1",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=65536,
        )

        def feed_stdin(p=proc, g=gen):
            try:
                for chunk in g:
                    if p.poll() is not None:
                        break
                    p.stdin.write(chunk)
            except Exception:
                pass
            finally:
                try:
                    p.stdin.close()
                except Exception:
                    pass
                try:
                    g.close()
                except Exception:
                    pass

        threading.Thread(target=feed_stdin, daemon=True).start()
        while True:
            out = proc.stdout.read(65536)
            if not out:
                break
            yield out
    finally:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        if gen is not None:
            try:
                gen.close()
            except Exception:
                pass

def extract_webvtt_subtitles(internal_url, subtitle_track=0, start_time=0.0):
    """
    Extracts an embedded MKV/MP4 subtitle track (SRT/SubRip, ASS/SSA, WebVTT, mov_text)
    and converts it on the fly to WebVTT aligned to start_time (?ss=).
    """
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
    if start_time and start_time > 0:
        cmd += ["-ss", f"{start_time:.3f}"]
    cmd += [
        "-i", internal_url,
        "-map", f"0:s:{max(0, int(subtitle_track))}",
        "-c:s", "webvtt",
        "-f", "webvtt",
        "pipe:1",
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if res.stdout and "WEBVTT" in res.stdout:
            return res.stdout
    except Exception:
        pass
    return "WEBVTT\n\n"

# ── SPA catch-all ─────────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""}, methods=["GET"])
@app.route("/<path:path>", methods=["GET"])
def spa(path):
    static = Path(app.static_folder)
    target = static / path
    if path and target.exists():
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
def api_login():
    body = request.get_json(force=True) or {}
    u = body.get("username","")
    pw = body.get("password","")
    token, err_msg, status_code, meta = auth.login_with_status(u, pw)
    if token:
        theme = auth.get_user_theme(u)
        resp = jsonify({"token": token, "theme": theme, "admin_enabled": False})
        resp.set_cookie("sd_token", token, max_age=auth.SESSION_TTL, path="/", httponly=True, samesite="Lax")
        return resp
    return jsonify({
        "error": err_msg or "Invalid credentials",
        "locked": meta.get("locked", False),
        "retry_after": meta.get("retry_after", 0),
        "attempts_remaining": meta.get("attempts_remaining", 0),
    }), status_code

@app.post("/api/auth/logout")
@auth.require_auth
def api_logout():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    auth.logout(t)
    resp = jsonify({"ok": True})
    resp.delete_cookie("sd_token", path="/")
    return resp

@app.get("/api/auth/me")
@auth.require_auth
def api_me():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    s = auth.get_session(t)
    theme = auth.get_user_theme(s["username"])
    return jsonify({
        "username": s["username"],
        "role": s["role"],
        "theme": theme,
        "admin_enabled": bool(s.get("admin_enabled", False)),
    })

@app.post("/api/auth/admin-mode")
@auth.require_auth
def api_admin_mode():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    b = request.get_json(force=True) or {}
    enabled = bool(b.get("enabled", False))
    pin = str(b.get("pin", "")).strip()
    try:
        state = auth.set_admin_mode(t, enabled, pin=pin)
        return jsonify({"ok": True, "admin_enabled": state})
    except ValueError as e:
        return jsonify({"error": str(e)}), 403
    except PermissionError as e:
        return jsonify({"error": str(e)}), 401

@app.post("/api/auth/theme")
@auth.require_auth
def api_save_theme():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
    if not t:
        t = request.args.get("token", "").strip() or request.cookies.get("sd_token", "")
    s = auth.get_session(t)
    b = request.get_json(force=True) or {}
    try:
        saved = auth.set_user_theme(s["username"], b.get("theme", "obsidian"))
        return jsonify({"ok": True, "theme": saved})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


# ── SMB ───────────────────────────────────────────────────────────────────────
@app.get("/api/smb/shares")
@auth.require_auth
def smb_list_shares():
    return jsonify([{k:v for k,v in s.items() if k != "password"}
                    for s in smb_manager.list_shares()])

@app.post("/api/smb/shares")
@auth.require_admin
def smb_add_share():
    b = request.get_json(force=True) or {}
    try:
        entry = smb_manager.add_share(
            name=b["name"], host=b["host"], share=b["share"],
            username=b.get("username",""), password=b.get("password",""),
            port=int(b.get("port", 445)),
            custom_name=b.get("custom_name", ""))
        return jsonify({k:v for k,v in entry.items() if k != "password"}), 201
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.post("/api/smb/shares/<share_id>/rename")
@auth.require_admin
def smb_rename_share(share_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    try:
        updated = smb_manager.rename_share(share_id, new_name)
        return jsonify({k:v for k,v in updated.items() if k != "password"})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/smb/shares/<share_id>")
@auth.require_admin
def smb_delete_share(share_id):
    smb_manager.remove_share(share_id)
    return jsonify({"ok": True})

@app.get("/api/smb/browse/<share_id>")
@auth.require_auth
def smb_browse(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", "/"), allow_root=True)
        return jsonify(smb_manager.browse(share_id, path))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/probe/<share_id>")
@auth.require_auth
def smb_probe(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", ""), allow_root=False)
        filename = path.split("/")[-1] or "media"
        internal_url = _internal_smb_url(share_id, path)
        info = probe_media_info(
            cache_key=f"smb:{share_id}:{path}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=4 * 1024 * 1024),
        )
        return jsonify(info)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/subtitles/<share_id>")
@auth.require_auth
def smb_subtitles(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", ""), allow_root=False)
        track = int(request.args.get("track", "0") or 0)
        start_time = float(request.args.get("ss", "0") or 0.0)
        internal_url = _internal_smb_url(share_id, path)
        vtt = extract_webvtt_subtitles(internal_url, subtitle_track=track, start_time=start_time)
        resp = app.response_class(vtt, status=200, mimetype="text/vtt; charset=utf-8")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/download/<share_id>")
@auth.require_auth
def smb_download(share_id):
    try:
        path = _sanitize_smb_path(request.args.get("path", ""), allow_root=False)
        filename = path.split("/")[-1] or "download"
        file_size = _get_smb_file_size(share_id, path)
        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_smb_url(share_id, path)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            probe_info = probe_media_info(
                cache_key=f"smb:{share_id}:{path}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=min(file_size, 8 * 1024 * 1024)),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename)
        range_header = request.headers.get("Range")
        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                smb_manager.stream_file_range(share_id, path, start=start, length=length),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/upload/<share_id>")
@auth.require_admin
def smb_upload(share_id):
    dest = request.args.get("path", "/")
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    conflict_action = (request.form.get("conflict_action") or request.args.get("conflict_action") or "replace").strip().lower()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        norm_dest = _sanitize_smb_path(dest, allow_root=True)
        sub_path = (rel_path or f.filename or "").lstrip("/")
        target_path = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + sub_path, allow_root=False)
        saved_path = smb_manager.upload_file(share_id, target_path, f.stream, conflict_action=conflict_action)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{target_path}", None)
        if saved_path:
            _SMB_SIZE_CACHE.pop(f"{share_id}:{saved_path}", None)
        return jsonify({"ok": True, "path": saved_path})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/smb/content/<share_id>")
@auth.require_admin
def smb_save_content(share_id):
    b = request.get_json(force=True) or {}
    raw_path = (b.get("path") or request.args.get("path") or "").strip()
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        target_path = _sanitize_smb_path(raw_path, allow_root=False)
        encoded = str(content).encode("utf-8")
        smb_manager.upload_file(share_id, target_path, io.BytesIO(encoded), conflict_action="replace")
        _SMB_SIZE_CACHE[f"{share_id}:{target_path}"] = (time.time(), len(encoded))
        return jsonify({"ok": True, "path": target_path, "size": len(encoded)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/rename/<share_id>")
@auth.require_admin
def smb_rename(share_id):
    b = request.get_json(force=True) or {}
    old_path = (b.get("path") or "").strip()
    new_name = (b.get("new_name") or b.get("name") or "").strip()
    conflict_action = (b.get("conflict_action") or b.get("conflictAction") or "replace").strip().lower()
    if not old_path or not new_name:
        return jsonify({"error": "path and new_name are required"}), 400
    try:
        norm_old = _sanitize_smb_path(old_path, allow_root=False)
        new_path = smb_manager.rename_path(share_id, norm_old, new_name, conflict_action=conflict_action)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{norm_old}", None)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{new_path}", None)
        return jsonify({"ok": True, "path": new_path})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/zip/<share_id>")
@auth.require_auth
def smb_zip(share_id):
    b = request.get_json(force=True) or {}
    paths = b.get("paths") or []
    if not paths:
        return jsonify({"error": "No paths provided"}), 400
    try:
        clean_paths = [_sanitize_smb_path(p, allow_root=False) for p in paths]
        tmp_path, zip_size = smb_manager.create_zip_tmpfile(share_id, clean_paths)
        archive_name = b.get("name") or "SageDrive_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/smb/delete/<share_id>")
@auth.require_admin
def smb_delete_file(share_id):
    b = request.get_json(force=True) or {}
    try:
        p = _sanitize_smb_path(b.get("path",""), allow_root=False)
        smb_manager.delete_path(share_id, p, b.get("is_dir", False))
        _SMB_SIZE_CACHE.pop(f"{share_id}:{p}", None)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/mkdir/<share_id>")
@auth.require_admin
def smb_mkdir(share_id):
    b = request.get_json(force=True) or {}
    try:
        p = _sanitize_smb_path(b.get("path",""), allow_root=False)
        smb_manager.create_directory(share_id, p)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Google Drive ──────────────────────────────────────────────────────────────
@app.get("/api/gdrive/status")
@auth.require_auth
def gdrive_status():
    accounts = gdrive_manager.list_accounts()
    return jsonify({
        "configured": gdrive_manager.is_configured(),
        "authenticated": gdrive_manager.is_authenticated(),
        "accounts": accounts,
    })

@app.get("/api/gdrive/accounts")
@auth.require_auth
def gdrive_list_accounts():
    return jsonify(gdrive_manager.list_accounts())

@app.post("/api/gdrive/accounts/<account_id>/rename")
@auth.require_admin
def gdrive_rename_account(account_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    try:
        acc = gdrive_manager.rename_account(account_id, new_name)
        return jsonify(acc)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/gdrive/accounts/<account_id>")
@auth.require_admin
def gdrive_delete_account(account_id):
    gdrive_manager.remove_account(account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/gdrive/config")
@auth.require_auth
def gdrive_get_config():
    return jsonify(gdrive_manager.get_config())

@app.post("/api/gdrive/config")
@auth.require_admin
def gdrive_save_config():
    b = request.get_json(force=True) or {}
    cfg = gdrive_manager.save_config(
        b.get("client_id", ""),
        b.get("client_secret", ""),
        b.get("redirect_uri", "")
    )
    return jsonify({"ok": True, "configured": gdrive_manager.is_configured()})

@app.get("/api/gdrive/auth")
@auth.require_admin
def gdrive_auth():
    if not gdrive_manager.is_configured():
        return jsonify({"error": "Google OAuth not configured"}), 400
    custom_name = request.args.get("name", "").strip()
    account_id = request.args.get("account_id", "").strip()
    return jsonify({"url": gdrive_manager.get_auth_url(custom_name=custom_name, account_id=account_id)})

@app.get("/api/gdrive/callback")
def gdrive_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing code", 400
    try:
        gdrive_manager.handle_callback(code, state)
        try:
            _reconcile_smb_proxy()
        except Exception:
            pass
        return redirect("/#gdrive-connected")
    except Exception as e:
        return f"OAuth error: {e}", 500

@app.delete("/api/gdrive/revoke")
@auth.require_admin
def gdrive_revoke():
    account_id = request.args.get("account_id", "").strip() or None
    gdrive_manager.revoke(account_id=account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/gdrive/files")
@auth.require_auth
def gdrive_files():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    try:
        return jsonify(gdrive_manager.list_files(folder_id, account_id=account_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/probe/<file_id>")
@auth.require_auth
def gdrive_probe(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        file_size = meta["size"]
        internal_url = _internal_gdrive_url(file_id, account_id=account_id)
        end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
        info = probe_media_info(
            cache_key=f"gdrive:{account_id or 'default'}:{file_id}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/subtitles/<file_id>")
@auth.require_auth
def gdrive_subtitles(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        track = int(request.args.get("track", "0") or 0)
        start_time = float(request.args.get("ss", "0") or 0.0)
        internal_url = _internal_gdrive_url(file_id, account_id=account_id)
        vtt = extract_webvtt_subtitles(internal_url, subtitle_track=track, start_time=start_time)
        resp = app.response_class(vtt, status=200, mimetype="text/vtt; charset=utf-8")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/download/<file_id>")
@auth.require_auth
def gdrive_download(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        raw_mime = meta["mimeType"]
        file_size = meta["size"]

        # Google Workspace native docs must be exported
        if raw_mime.startswith("application/vnd.google-apps."):
            data, filename, mime = gdrive_manager.download_file(file_id, account_id=account_id)
            return send_file(
                io.BytesIO(data),
                download_name=filename,
                as_attachment=bool(request.args.get("dl")),
                mimetype=mime or "application/octet-stream",
            )

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_gdrive_url(file_id, account_id=account_id)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            end_byte = min(file_size - 1, 8 * 1024 * 1024 - 1) if file_size > 0 else 8 * 1024 * 1024 - 1
            probe_info = probe_media_info(
                cache_key=f"gdrive:{account_id or 'default'}:{file_id}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename, raw_mime)
        range_header = request.headers.get("Range")

        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                gdrive_manager.stream_file_range(file_id, start=start, end=end, account_id=account_id),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                gdrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            if file_size > 0:
                resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except Exception as e:
        print(f"GDRIVE DOWNLOAD ERROR file_id={file_id}: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/upload")
@auth.require_admin
def gdrive_upload():
    folder_id = request.args.get("folder","root")
    account_id = request.args.get("account_id", "").strip() or None
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    conflict_action = (request.form.get("conflict_action") or request.args.get("conflict_action") or "replace").strip().lower()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        gdrive_manager.upload_file(
            folder_id,
            f.filename,
            f.stream,
            f.content_type or "application/octet-stream",
            relative_path=rel_path or None,
            account_id=account_id,
            conflict_action=conflict_action,
        )
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/gdrive/content/<file_id>")
@auth.require_admin
def gdrive_save_content(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        meta = gdrive_manager.get_file_meta(file_id, account_id=account_id)
        mime = guess_media_mime(meta.get("name", "file.txt"), meta.get("mimeType"))
        if mime == "application/octet-stream":
            mime = "text/plain; charset=utf-8"
        encoded = str(content).encode("utf-8")
        updated = gdrive_manager.update_file_content(
            file_id,
            io.BytesIO(encoded),
            mime_type=mime,
            account_id=account_id,
        )
        return jsonify({"ok": True, "size": len(encoded), "file": updated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/rename/<file_id>")
@auth.require_admin
def gdrive_rename(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    new_name = (b.get("name") or b.get("new_name") or "").strip()
    conflict_action = (b.get("conflict_action") or b.get("conflictAction") or "replace").strip().lower()
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    try:
        res = gdrive_manager.rename_file(file_id, new_name, account_id=account_id, conflict_action=conflict_action)
        return jsonify({"ok": True, "file": res})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/zip")
@auth.require_auth
def gdrive_zip():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    ids = b.get("ids") or []
    if not ids:
        return jsonify({"error": "No file IDs provided"}), 400
    try:
        tmp_path, zip_size = gdrive_manager.create_zip_tmpfile(ids, account_id=account_id)
        archive_name = b.get("name") or "GoogleDrive_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/gdrive/delete/<file_id>")
@auth.require_admin
def gdrive_delete(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        gdrive_manager.delete_file(file_id, account_id=account_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/mkdir")
@auth.require_admin
def gdrive_mkdir():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    try:
        fid = gdrive_manager.create_folder(b.get("parent","root"), b.get("name","New Folder"), account_id=account_id)
        return jsonify({"id": fid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Microsoft OneDrive ────────────────────────────────────────────────────────
@app.get("/api/onedrive/status")
@auth.require_auth
def onedrive_status():
    accounts = onedrive_manager.list_accounts()
    return jsonify({
        "configured": onedrive_manager.is_configured(),
        "authenticated": onedrive_manager.is_authenticated(),
        "accounts": accounts,
    })

@app.get("/api/onedrive/accounts")
@auth.require_auth
def onedrive_list_accounts():
    return jsonify(onedrive_manager.list_accounts())

@app.post("/api/onedrive/accounts/<account_id>/rename")
@auth.require_admin
def onedrive_rename_account(account_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    try:
        acc = onedrive_manager.rename_account(account_id, new_name)
        return jsonify(acc)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/onedrive/accounts/<account_id>")
@auth.require_admin
def onedrive_delete_account(account_id):
    onedrive_manager.remove_account(account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/onedrive/config")
@auth.require_auth
def onedrive_get_config():
    return jsonify(onedrive_manager.get_config())

@app.post("/api/onedrive/config")
@auth.require_admin
def onedrive_save_config():
    b = request.get_json(force=True) or {}
    onedrive_manager.save_config(
        b.get("client_id", ""),
        b.get("client_secret", ""),
        b.get("redirect_uri", ""),
        b.get("tenant_id", "common"),
    )
    return jsonify({"ok": True, "configured": onedrive_manager.is_configured()})

@app.get("/api/onedrive/auth")
@auth.require_admin
def onedrive_auth():
    if not onedrive_manager.is_configured():
        return jsonify({"error": "OneDrive OAuth not configured"}), 400
    custom_name = request.args.get("name", "").strip()
    account_id = request.args.get("account_id", "").strip()
    return jsonify({"url": onedrive_manager.get_auth_url(custom_name=custom_name, account_id=account_id)})

@app.get("/api/onedrive/callback")
def onedrive_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing code", 400
    try:
        onedrive_manager.handle_callback(code, state)
        try:
            _reconcile_smb_proxy()
        except Exception:
            pass
        return redirect("/#onedrive-connected")
    except Exception as e:
        return f"OneDrive OAuth error: {e}", 500

@app.delete("/api/onedrive/revoke")
@auth.require_admin
def onedrive_revoke():
    account_id = request.args.get("account_id", "").strip() or None
    onedrive_manager.revoke(account_id=account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/onedrive/files")
@auth.require_auth
def onedrive_files():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    try:
        return jsonify(onedrive_manager.list_files(folder_id, account_id=account_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/onedrive/probe/<file_id>")
@auth.require_auth
def onedrive_probe(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = onedrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        file_size = meta["size"]
        internal_url = _internal_onedrive_url(file_id, account_id=account_id)
        end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
        info = probe_media_info(
            cache_key=f"onedrive:{account_id or 'default'}:{file_id}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: onedrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/onedrive/subtitles/<file_id>")
@auth.require_auth
def onedrive_subtitles(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        track = int(request.args.get("track", "0") or 0)
        start_time = float(request.args.get("ss", "0") or 0.0)
        internal_url = _internal_onedrive_url(file_id, account_id=account_id)
        vtt = extract_webvtt_subtitles(internal_url, subtitle_track=track, start_time=start_time)
        resp = app.response_class(vtt, status=200, mimetype="text/vtt; charset=utf-8")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/onedrive/download/<file_id>")
@auth.require_auth
def onedrive_download(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = onedrive_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        raw_mime = meta["mimeType"]
        file_size = meta["size"]

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_onedrive_url(file_id, account_id=account_id)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            end_byte = min(file_size - 1, 8 * 1024 * 1024 - 1) if file_size > 0 else 8 * 1024 * 1024 - 1
            probe_info = probe_media_info(
                cache_key=f"onedrive:{account_id or 'default'}:{file_id}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: onedrive_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: onedrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: onedrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename, raw_mime)
        range_header = request.headers.get("Range")

        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                onedrive_manager.stream_file_range(file_id, start=start, end=end, account_id=account_id),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                onedrive_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            if file_size > 0:
                resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except Exception as e:
        print(f"ONEDRIVE DOWNLOAD ERROR file_id={file_id}: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.post("/api/onedrive/upload")
@auth.require_admin
def onedrive_upload():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    conflict_action = (request.form.get("conflict_action") or request.args.get("conflict_action") or "replace").strip().lower()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        onedrive_manager.upload_file(
            folder_id,
            f.filename,
            f.stream,
            f.content_type or "application/octet-stream",
            relative_path=rel_path or None,
            account_id=account_id,
            conflict_action=conflict_action,
        )
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/onedrive/content/<file_id>")
@auth.require_admin
def onedrive_save_content(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        meta = onedrive_manager.get_file_meta(file_id, account_id=account_id)
        mime = guess_media_mime(meta.get("name", "file.txt"), meta.get("mimeType"))
        if mime == "application/octet-stream":
            mime = "text/plain; charset=utf-8"
        encoded = str(content).encode("utf-8")
        updated = onedrive_manager.update_file_content(
            file_id,
            io.BytesIO(encoded),
            mime_type=mime,
            account_id=account_id,
        )
        return jsonify({"ok": True, "size": len(encoded), "file": updated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/onedrive/rename/<file_id>")
@auth.require_admin
def onedrive_rename(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    new_name = (b.get("name") or b.get("new_name") or "").strip()
    conflict_action = (b.get("conflict_action") or b.get("conflictAction") or "replace").strip().lower()
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    try:
        res = onedrive_manager.rename_file(file_id, new_name, account_id=account_id, conflict_action=conflict_action)
        return jsonify({"ok": True, "file": res})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/onedrive/zip")
@auth.require_auth
def onedrive_zip():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    ids = b.get("ids") or []
    if not ids:
        return jsonify({"error": "No file IDs provided"}), 400
    try:
        tmp_path, zip_size = onedrive_manager.create_zip_tmpfile(ids, account_id=account_id)
        archive_name = b.get("name") or "OneDrive_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/onedrive/delete/<file_id>")
@auth.require_admin
def onedrive_delete(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        onedrive_manager.delete_file(file_id, account_id=account_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/onedrive/mkdir")
@auth.require_admin
def onedrive_mkdir():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    try:
        fid = onedrive_manager.create_folder(b.get("parent", "root"), b.get("name", "New Folder"), account_id=account_id)
        return jsonify({"id": fid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── FileJump Routes (Multi-Account: API Token + WebDAV) ───────────────────────
@app.get("/api/filejump/status")
@auth.require_auth
def filejump_status():
    return jsonify({
        "configured": filejump_manager.is_configured(),
        "authenticated": filejump_manager.is_authenticated(),
        "accounts": filejump_manager.list_accounts(),
    })

@app.get("/api/filejump/accounts")
@auth.require_auth
def filejump_accounts():
    return jsonify(filejump_manager.list_accounts())

@app.post("/api/filejump/accounts/<account_id>/rename")
@auth.require_admin
def filejump_rename_account(account_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("custom_name") or "").strip()
    if not new_name:
        return jsonify({"error": "Custom name cannot be empty"}), 400
    try:
        updated = filejump_manager.rename_account(account_id, new_name)
        return jsonify(updated)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/filejump/accounts/<account_id>")
@auth.require_admin
def filejump_remove_account(account_id):
    try:
        filejump_manager.remove_account(account_id)
        try:
            _reconcile_smb_proxy()
        except Exception:
            pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/filejump/connect")
@auth.require_admin
def filejump_connect():
    b = request.get_json(force=True) or {}
    auth_type = (b.get("auth_type") or "token").strip().lower()
    api_token = (b.get("api_token") or b.get("password") or b.get("token") or "").strip()
    email = (b.get("email") or b.get("username") or "").strip()
    api_url = (b.get("api_url") or b.get("webdav_url") or "").strip()
    custom_name = (b.get("name") or b.get("custom_name") or "").strip()
    account_id = (b.get("account_id") or "").strip() or None
    try:
        acc = filejump_manager.add_account(
            auth_type=auth_type,
            api_token=api_token,
            email=email,
            api_url=api_url,
            custom_name=custom_name,
            account_id=account_id,
        )
        try:
            _reconcile_smb_proxy()
        except Exception:
            pass
        return jsonify({"ok": True, "account": acc, "accounts": filejump_manager.list_accounts()})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/filejump/revoke")
@auth.require_admin
def filejump_revoke():
    account_id = request.args.get("account_id", "").strip() or None
    filejump_manager.revoke(account_id=account_id)
    try:
        _reconcile_smb_proxy()
    except Exception:
        pass
    return jsonify({"ok": True})

@app.get("/api/filejump/files")
@auth.require_auth
def filejump_files():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    try:
        return jsonify(filejump_manager.list_files(folder_id, account_id=account_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/filejump/probe/<path:file_id>")
@auth.require_auth
def filejump_probe(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = filejump_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        file_size = meta["size"]
        internal_url = _internal_filejump_url(file_id, account_id=account_id)
        end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
        info = probe_media_info(
            cache_key=f"filejump:{account_id or 'default'}:{file_id}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: filejump_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/filejump/subtitles/<path:file_id>")
@auth.require_auth
def filejump_subtitles(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        track = int(request.args.get("track", "0") or 0)
        start_time = float(request.args.get("ss", "0") or 0.0)
        internal_url = _internal_filejump_url(file_id, account_id=account_id)
        vtt = extract_webvtt_subtitles(internal_url, subtitle_track=track, start_time=start_time)
        resp = app.response_class(vtt, status=200, mimetype="text/vtt; charset=utf-8")
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/filejump/download/<path:file_id>")
@auth.require_auth
def filejump_download(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        meta = filejump_manager.get_file_meta(file_id, account_id=account_id)
        filename = meta["name"]
        raw_mime = meta["mimeType"]
        file_size = meta["size"]

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_filejump_url(file_id, account_id=account_id)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            duration_hint = float(request.args.get("duration", "0") or 0.0)
            end_byte = min(file_size - 1, 8 * 1024 * 1024 - 1) if file_size > 0 else 8 * 1024 * 1024 - 1
            probe_info = probe_media_info(
                cache_key=f"filejump:{account_id or 'default'}:{file_id}",
                internal_url=internal_url,
                filename=filename,
                fallback_gen_fn=lambda: filejump_manager.stream_file_range(file_id, start=0, end=end_byte, account_id=account_id),
            )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: filejump_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                    duration_hint=duration_hint,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            start_time = float(request.args.get("ss", "0") or 0.0)
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: filejump_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                    internal_url=internal_url,
                    start_time=start_time,
                ),
                status=200,
                mimetype="audio/mpeg",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        mime = guess_media_mime(filename, raw_mime)
        range_header = request.headers.get("Range")

        if range_header and file_size > 0:
            m = re.search(r"bytes=(\d*)-(\d*)", range_header)
            if not m:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            if not m.group(1) and m.group(2):
                suffix = int(m.group(2))
                start = max(0, file_size - suffix)
                end = file_size - 1
            else:
                start = int(m.group(1)) if m.group(1) else 0
                end = int(m.group(2)) if m.group(2) else file_size - 1

            if start >= file_size or start > end:
                resp = app.response_class("", status=416)
                resp.headers["Content-Range"] = f"bytes */{file_size}"
                return resp

            end = min(end, file_size - 1)
            length = end - start + 1

            resp = app.response_class(
                filejump_manager.stream_file_range(file_id, start=start, end=end, account_id=account_id),
                status=206,
                mimetype=mime,
                direct_passthrough=True,
            )
            resp.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
            resp.headers["Content-Length"] = str(length)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
        else:
            resp = app.response_class(
                filejump_manager.stream_file_range(file_id, start=0, end=None, account_id=account_id),
                status=200,
                mimetype=mime,
                direct_passthrough=True,
            )
            if file_size > 0:
                resp.headers["Content-Length"] = str(file_size)
            resp.headers["Accept-Ranges"] = "bytes"
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp
    except Exception as e:
        print(f"FILEJUMP DOWNLOAD ERROR file_id={file_id}: {e}", flush=True)
        return jsonify({"error": str(e)}), 500

@app.post("/api/filejump/upload")
@auth.require_admin
def filejump_upload():
    folder_id = request.args.get("folder", "root")
    account_id = request.args.get("account_id", "").strip() or None
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    conflict_action = (request.form.get("conflict_action") or request.args.get("conflict_action") or "replace").strip().lower()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        filejump_manager.upload_file(
            folder_id,
            f.filename,
            f.stream,
            f.content_type or "application/octet-stream",
            relative_path=rel_path or None,
            account_id=account_id,
            conflict_action=conflict_action,
        )
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.put("/api/filejump/content/<path:file_id>")
@auth.require_admin
def filejump_save_content(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    content = b.get("content")
    if content is None:
        return jsonify({"error": "content is required"}), 400
    try:
        meta = filejump_manager.get_file_meta(file_id, account_id=account_id)
        mime = guess_media_mime(meta.get("name", "file.txt"), meta.get("mimeType"))
        if mime == "application/octet-stream":
            mime = "text/plain; charset=utf-8"
        encoded = str(content).encode("utf-8")
        updated = filejump_manager.update_file_content(
            file_id,
            io.BytesIO(encoded),
            mime_type=mime,
            account_id=account_id,
        )
        return jsonify({"ok": True, "size": len(encoded), "file": updated})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/filejump/rename/<path:file_id>")
@auth.require_admin
def filejump_rename(file_id):
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    new_name = (b.get("name") or b.get("new_name") or "").strip()
    conflict_action = (b.get("conflict_action") or b.get("conflictAction") or "replace").strip().lower()
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    try:
        res = filejump_manager.rename_file(file_id, new_name, account_id=account_id, conflict_action=conflict_action)
        return jsonify({"ok": True, "file": res})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/filejump/zip")
@auth.require_auth
def filejump_zip():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    ids = b.get("ids") or []
    if not ids:
        return jsonify({"error": "No file IDs provided"}), 400
    try:
        tmp_path, zip_size = filejump_manager.create_zip_tmpfile(ids, account_id=account_id)
        archive_name = b.get("name") or "FileJump_Download.zip"
        resp = app.response_class(
            _stream_and_unlink_tmpfile(tmp_path),
            status=200,
            mimetype="application/zip",
            direct_passthrough=True,
        )
        resp.headers["Content-Length"] = str(zip_size)
        resp.headers["Content-Disposition"] = make_content_disposition(archive_name, True)
        resp.headers["Cache-Control"] = "no-cache"
        return resp
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/filejump/delete/<path:file_id>")
@auth.require_admin
def filejump_delete(file_id):
    account_id = request.args.get("account_id", "").strip() or None
    try:
        filejump_manager.delete_file(file_id, account_id=account_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/filejump/mkdir")
@auth.require_admin
def filejump_mkdir():
    b = request.get_json(force=True) or {}
    account_id = (request.args.get("account_id") or b.get("account_id") or "").strip() or None
    try:
        fid = filejump_manager.create_folder(b.get("parent", "root"), b.get("name", "New Folder"), account_id=account_id)
        return jsonify({"id": fid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Zero-Disk Direct Streaming Upload Sessions (All Drives: SMB, Google Drive, OneDrive, FileJump) ──
_LEGACY_UPLOAD_SESSIONS_DIR = Path(os.environ.get("DATA_DIR", "/app/data")) / "upload_sessions"
try:
    if _LEGACY_UPLOAD_SESSIONS_DIR.exists():
        shutil.rmtree(_LEGACY_UPLOAD_SESSIONS_DIR, ignore_errors=True)
except Exception:
    pass

_UPLOAD_SESSIONS = {}
_upload_sessions_lock = threading.Lock()


class _UploadAbortedError(Exception):
    pass


class _StreamingUploadPipe:
    """
    Zero-disk in-memory byte pipe that streams incoming browser upload chunks
    directly into an outbound HTTP/WebDAV/REST connection (e.g. FileJump)
    without writing anything to container storage.
    """
    def __init__(self, total_size):
        self.total_size = max(0, int(total_size or 0))
        self.bytes_accepted = 0
        self.bytes_transmitted = 0
        self.eof = False
        self.aborted = False
        self.error = None
        self.result = None
        self.worker_done = threading.Event()
        self._cond = threading.Condition()
        self._buf = bytearray()

    def __len__(self):
        return self.total_size

    def write_chunk(self, data: bytes, timeout=600.0):
        if not data:
            return self.bytes_accepted
        mv = memoryview(data)
        pos = 0
        step = 262144  # 256 KiB slices
        deadline = time.time() + timeout
        with self._cond:
            while pos < len(mv):
                if self.aborted:
                    raise _UploadAbortedError("Upload cancelled")
                if self.error is not None:
                    raise self.error
                while len(self._buf) >= 524288 and not self.aborted and self.error is None and not self.worker_done.is_set():
                    rem = deadline - time.time()
                    if rem <= 0:
                        self.aborted = True
                        self._cond.notify_all()
                        raise TimeoutError("Timed out streaming chunk to remote destination")
                    self._cond.wait(timeout=min(1.0, rem))
                if self.aborted:
                    raise _UploadAbortedError("Upload cancelled")
                if self.error is not None:
                    raise self.error
                if self.worker_done.is_set():
                    if self.error is not None:
                        raise self.error
                    raise RuntimeError("Remote upload connection closed unexpectedly")
                take = min(step, len(mv) - pos)
                self._buf.extend(mv[pos:pos + take])
                pos += take
                self.bytes_accepted += take
                if self.total_size > 0 and self.bytes_accepted >= self.total_size:
                    self.eof = True
                self._cond.notify_all()

            while len(self._buf) > 0 and not self.aborted and self.error is None and not self.worker_done.is_set():
                rem = deadline - time.time()
                if rem <= 0:
                    self.aborted = True
                    self._cond.notify_all()
                    raise TimeoutError("Timed out waiting for remote destination to accept chunk")
                self._cond.wait(timeout=min(1.0, rem))

            if self.aborted:
                raise _UploadAbortedError("Upload cancelled")
            if self.error is not None:
                raise self.error
            return self.bytes_accepted

    def read(self, size=65536):
        if size is None or size < 0:
            size = 65536
        with self._cond:
            while len(self._buf) == 0 and not self.eof and not self.aborted and self.error is None:
                self._cond.wait(timeout=1.0)
            if self.aborted:
                raise _UploadAbortedError("Upload cancelled")
            if self.error is not None:
                raise self.error
            if len(self._buf) == 0:
                return b""
            take = min(size, len(self._buf))
            out = bytes(self._buf[:take])
            del self._buf[:take]
            self.bytes_transmitted += len(out)
            self._cond.notify_all()
            return out

    def finish_and_wait(self, timeout=600.0):
        with self._cond:
            self.eof = True
            self._cond.notify_all()
        if not self.worker_done.wait(timeout=timeout):
            self.abort()
            raise TimeoutError("Timed out waiting for remote destination to finalize upload")
        if self.error is not None:
            raise self.error
        return self.result

    def abort(self):
        with self._cond:
            self.aborted = True
            self.eof = True
            self._buf.clear()
            self._cond.notify_all()


def _start_filejump_pipe_worker(sess):
    pipe = _StreamingUploadPipe(sess["totalSize"])
    sess["pipe"] = pipe
    sess["offset"] = 0
    drive_id = sess["driveId"]
    target_parent = sess.get("resolvedParent") or sess["folder"] or "root"
    actual_name = sess.get("resolvedName") or sess["fileName"]
    mime_type = sess["mimeType"]
    total_size = sess["totalSize"]
    conflict_action = sess.get("conflictAction") or "replace"

    def _worker():
        try:
            res = filejump_manager.upload_file(
                target_parent,
                actual_name,
                pipe,
                mime_type,
                relative_path=None,
                account_id=drive_id,
                total_size=total_size,
                conflict_action=conflict_action,
            )
            pipe.result = res
        except Exception as exc:
            with pipe._cond:
                pipe.error = exc
                pipe._cond.notify_all()
        finally:
            pipe.worker_done.set()
            with pipe._cond:
                pipe._cond.notify_all()

    threading.Thread(target=_worker, daemon=True).start()
    return pipe


def _cleanup_expired_upload_sessions():
    now = time.time()
    _prune_main_caches(now)
    expired = [
        sid for sid, s in list(_UPLOAD_SESSIONS.items())
        if now - s.get("updatedAt", s.get("createdAt", now)) > 14400
    ]
    for sid in expired:
        s = _UPLOAD_SESSIONS.pop(sid, None)
        if s and s.get("pipe"):
            try:
                s["pipe"].abort()
            except Exception:
                pass


@app.post("/api/transfers/check-conflicts")
@auth.require_auth
def check_transfer_conflicts():
    """
    Checks a batch of candidate files/folders against a target destination folder
    (including nested relativePaths) and returns any items that already exist.
    """
    b = request.get_json(force=True, silent=True) or {}
    drive_type = str(b.get("driveType") or b.get("drive_type") or "").strip().lower()
    drive_id = str(b.get("driveId") or b.get("drive_id") or "default").strip()
    base_folder = str(b.get("folder") or b.get("path") or ("/" if drive_type == "smb" else "root")).strip()
    items = b.get("items") or []

    if drive_type not in ("smb", "gdrive", "onedrive", "filejump"):
        return jsonify({"error": "Invalid target drive type"}), 400
    if not items:
        return jsonify({"conflicts": []})

    folder_listing_cache = {}
    subpath_id_cache = {(): base_folder}

    def _list_target_folder(fld_id):
        if fld_id in folder_listing_cache:
            return folder_listing_cache[fld_id]
        try:
            if drive_type == "smb":
                entries = smb_manager.browse(drive_id, fld_id)
            elif drive_type == "gdrive":
                entries = gdrive_manager.list_files(fld_id, account_id=drive_id)
            elif drive_type == "onedrive":
                entries = onedrive_manager.list_files(fld_id, account_id=drive_id)
            elif drive_type == "filejump":
                entries = filejump_manager.list_files(fld_id, account_id=drive_id)
            else:
                entries = []
        except Exception:
            entries = []
        by_lower = {str(e.get("name") or "").lower(): e for e in entries if e.get("name")}
        folder_listing_cache[fld_id] = by_lower
        return by_lower

    def _resolve_existing_subfolder(segments_tuple):
        if segments_tuple in subpath_id_cache:
            return subpath_id_cache[segments_tuple]
        parent_tuple = segments_tuple[:-1]
        parent_id = _resolve_existing_subfolder(parent_tuple)
        if parent_id is None:
            subpath_id_cache[segments_tuple] = None
            return None
        seg_name = segments_tuple[-1]
        parent_map = _list_target_folder(parent_id)
        match = parent_map.get(seg_name.lower())
        if match and match.get("type") == "folder":
            resolved = match.get("path") if drive_type == "smb" else match.get("id")
            subpath_id_cache[segments_tuple] = resolved
            return resolved
        subpath_id_cache[segments_tuple] = None
        return None

    conflicts = []
    for idx, it in enumerate(items):
        raw_name = str(it.get("name") or it.get("fileName") or "").strip()
        rel_path = str(it.get("relativePath") or it.get("relative_path") or "").strip()
        if rel_path:
            norm_rel = rel_path.replace("\\", "/").strip("/")
            parts = [p for p in norm_rel.split("/") if p and p not in (".", "..")]
        else:
            parts = [raw_name] if raw_name else []
        if not parts:
            continue
        leaf_name = parts[-1]
        dir_tuple = tuple(parts[:-1])
        target_folder_id = _resolve_existing_subfolder(dir_tuple)
        if target_folder_id is None:
            continue
        listing_map = _list_target_folder(target_folder_id)
        existing = listing_map.get(leaf_name.lower())
        if existing:
            conflicts.append({
                "index": idx,
                "key": rel_path or raw_name,
                "name": leaf_name,
                "relativePath": rel_path or leaf_name,
                "existingId": existing.get("path") if drive_type == "smb" else existing.get("id"),
                "existingType": existing.get("type", "file"),
                "existingSize": existing.get("size", 0),
            })

    return jsonify({"conflicts": conflicts})


@app.post("/api/transfers/upload/init")
@auth.require_admin
def init_resumable_upload():
    b = request.get_json(force=True) or {}
    drive_type = str(b.get("driveType") or b.get("drive_type") or "").strip().lower()
    drive_id = str(b.get("driveId") or b.get("drive_id") or "default").strip()
    folder = str(b.get("folder") or b.get("path") or ("/" if drive_type == "smb" else "root")).strip()
    file_name = str(b.get("fileName") or b.get("filename") or "").strip()
    relative_path = str(b.get("relativePath") or b.get("relative_path") or "").strip()
    total_size = int(b.get("totalSize") if b.get("totalSize") is not None else (b.get("total_size") or 0))
    mime_type = str(b.get("mimeType") or b.get("mime_type") or "application/octet-stream").strip()
    client_key = str(b.get("clientKey") or b.get("client_key") or "").strip()
    conflict_action = str(b.get("conflictAction") or b.get("conflict_action") or "replace").strip().lower()
    if conflict_action not in ("replace", "skip", "keep_both"):
        conflict_action = "replace"

    if drive_type not in ("smb", "gdrive", "onedrive", "filejump"):
        return jsonify({"error": "Invalid target drive type"}), 400
    if not file_name:
        return jsonify({"error": "fileName is required"}), 400

    try:
        with _upload_sessions_lock:
            _cleanup_expired_upload_sessions()
            if client_key:
                session_id = "up_" + hashlib.sha256(
                    f"{drive_type}:{drive_id}:{folder}:{relative_path or file_name}:{total_size}:{client_key}:{conflict_action}".encode("utf-8")
                ).hexdigest()[:24]
            else:
                session_id = f"up_{secrets.token_hex(12)}"

            existing = _UPLOAD_SESSIONS.get(session_id)
            if existing:
                actual_offset = int(existing.get("offset") or 0)
                if drive_type == "filejump":
                    pipe = existing.get("pipe")
                    if pipe and (pipe.error is not None or pipe.aborted or pipe.worker_done.is_set()):
                        existing["pipe"] = None
                        existing["offset"] = 0
                        actual_offset = 0
                elif drive_type == "gdrive" and existing.get("resumableUri"):
                    try:
                        actual_offset = gdrive_manager.query_resumable_offset(existing["resumableUri"], total_size)
                        existing["offset"] = actual_offset
                    except Exception:
                        existing["resumableUri"] = None
                        existing["offset"] = 0
                        actual_offset = 0
                elif drive_type == "onedrive" and existing.get("uploadUrl"):
                    try:
                        actual_offset = onedrive_manager.query_resumable_offset(existing["uploadUrl"], total_size)
                        existing["offset"] = actual_offset
                    except Exception:
                        existing["uploadUrl"] = None
                        existing["offset"] = 0
                        actual_offset = 0
                elif drive_type == "smb" and existing.get("destFull"):
                    try:
                        actual_offset = smb_manager.get_file_size(drive_id, existing["destFull"])
                        existing["offset"] = actual_offset
                    except Exception:
                        existing["offset"] = 0
                        actual_offset = 0

                if 0 < actual_offset <= total_size:
                    existing["updatedAt"] = time.time()
                    return jsonify({
                        "sessionId": session_id,
                        "upload_id": session_id,
                        "offset": actual_offset,
                        "totalSize": total_size,
                        "total_size": total_size,
                        "resumed": True,
                    })

        sess = {
            "sessionId": session_id,
            "driveType": drive_type,
            "driveId": drive_id,
            "folder": folder,
            "fileName": file_name,
            "relativePath": relative_path,
            "totalSize": total_size,
            "mimeType": mime_type or guess_media_mime(file_name),
            "conflictAction": conflict_action,
            "offset": 0,
            "createdAt": time.time(),
            "updatedAt": time.time(),
            "lock": threading.Lock(),
        }

        if drive_type == "smb":
            sub = relative_path if relative_path else file_name
            dest_full = _sanitize_smb_path(folder.rstrip("/") + "/" + sub.lstrip("/"), allow_root=False)
            if conflict_action in ("skip", "keep_both"):
                parent_dir = "/".join(dest_full.split("/")[:-1]) or "/"
                leaf = dest_full.split("/")[-1]
                try:
                    siblings = [e["name"] for e in smb_manager.browse(drive_id, parent_dir)]
                except Exception:
                    siblings = []
                if any(s.lower() == leaf.lower() for s in siblings):
                    if conflict_action == "skip":
                        return jsonify({
                            "sessionId": session_id,
                            "upload_id": session_id,
                            "offset": total_size,
                            "totalSize": total_size,
                            "total_size": total_size,
                            "skipped": True,
                        })
                    elif conflict_action == "keep_both":
                        unique_leaf = smb_manager.generate_unique_name(leaf, siblings)
                        dest_full = _sanitize_smb_path(parent_dir.rstrip("/") + "/" + unique_leaf, allow_root=False)
            sess["destFull"] = dest_full
            if total_size == 0:
                smb_manager.upload_chunk(drive_id, dest_full, b"", offset=0, truncate=True)
        elif drive_type == "gdrive":
            if conflict_action == "skip":
                target_parent, actual_name = gdrive_manager.resolve_upload_target(
                    folder or "root", file_name, relative_path=relative_path or None, account_id=drive_id
                )
                if gdrive_manager.find_items_by_name(target_parent, actual_name, account_id=drive_id):
                    return jsonify({
                        "sessionId": session_id,
                        "upload_id": session_id,
                        "offset": total_size,
                        "totalSize": total_size,
                        "total_size": total_size,
                        "skipped": True,
                    })
            if total_size > 0:
                sess["resumableUri"] = gdrive_manager.start_resumable_upload(
                    folder or "root",
                    file_name,
                    mime_type=sess["mimeType"],
                    total_size=total_size,
                    relative_path=relative_path or None,
                    account_id=drive_id,
                    conflict_action=conflict_action,
                )
        elif drive_type == "onedrive":
            if conflict_action == "skip":
                target_parent, actual_name = onedrive_manager.resolve_upload_target(
                    folder or "root", file_name, relative_path=relative_path or None, account_id=drive_id
                )
                siblings = onedrive_manager.list_files(target_parent, account_id=drive_id)
                if any(s["name"].lower() == actual_name.lower() for s in siblings):
                    return jsonify({
                        "sessionId": session_id,
                        "upload_id": session_id,
                        "offset": total_size,
                        "totalSize": total_size,
                        "total_size": total_size,
                        "skipped": True,
                    })
            if total_size > 0:
                sess["uploadUrl"] = onedrive_manager.start_resumable_upload(
                    folder or "root",
                    file_name,
                    relative_path=relative_path or None,
                    account_id=drive_id,
                    conflict_action=conflict_action,
                )
        elif drive_type == "filejump":
            target_parent, actual_name = filejump_manager.resolve_upload_target(
                folder or "root",
                file_name,
                relative_path=relative_path or None,
                account_id=drive_id,
            )
            if conflict_action in ("skip", "keep_both"):
                try:
                    siblings = filejump_manager.list_files(target_parent, account_id=drive_id)
                except Exception:
                    siblings = []
                if any(s["name"].lower() == actual_name.lower() for s in siblings):
                    if conflict_action == "skip":
                        return jsonify({
                            "sessionId": session_id,
                            "upload_id": session_id,
                            "offset": total_size,
                            "totalSize": total_size,
                            "total_size": total_size,
                            "skipped": True,
                        })
                    elif conflict_action == "keep_both":
                        actual_name = filejump_manager.generate_unique_name(actual_name, [s["name"] for s in siblings])
            sess["resolvedParent"] = target_parent
            sess["resolvedName"] = actual_name

        with _upload_sessions_lock:
            _UPLOAD_SESSIONS[session_id] = sess

        return jsonify({
            "sessionId": session_id,
            "upload_id": session_id,
            "offset": 0,
            "totalSize": total_size,
            "total_size": total_size,
            "resumed": False,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/transfers/upload/status")
@auth.require_auth
def status_resumable_upload():
    session_id = (
        request.args.get("session_id")
        or request.args.get("upload_id")
        or request.args.get("sessionId")
        or ""
    ).strip()
    with _upload_sessions_lock:
        sess = _UPLOAD_SESSIONS.get(session_id)
    if not sess:
        return jsonify({"error": "Upload session not found"}), 404

    try:
        with sess["lock"]:
            drive_type = sess["driveType"]
            total_size = sess.get("totalSize", 0)
            offset = int(sess.get("offset") or 0)
            if drive_type == "filejump":
                pipe = sess.get("pipe")
                if pipe:
                    if pipe.error is not None or pipe.aborted or (pipe.worker_done.is_set() and pipe.bytes_accepted < total_size):
                        sess["pipe"] = None
                        sess["offset"] = 0
                        offset = 0
                    else:
                        offset = pipe.bytes_accepted
                        sess["offset"] = offset
            elif drive_type == "gdrive" and sess.get("resumableUri"):
                try:
                    offset = gdrive_manager.query_resumable_offset(sess["resumableUri"], total_size)
                    sess["offset"] = offset
                except Exception:
                    pass
            elif drive_type == "onedrive" and sess.get("uploadUrl"):
                try:
                    offset = onedrive_manager.query_resumable_offset(sess["uploadUrl"], total_size)
                    sess["offset"] = offset
                except Exception:
                    pass
            elif drive_type == "smb" and sess.get("destFull") and offset > 0:
                try:
                    offset = smb_manager.get_file_size(sess["driveId"], sess["destFull"])
                    sess["offset"] = offset
                except Exception:
                    offset = 0
                    sess["offset"] = 0

            return jsonify({
                "sessionId": session_id,
                "upload_id": session_id,
                "offset": offset,
                "totalSize": total_size,
                "total_size": total_size,
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/transfers/upload/chunk")
@auth.require_admin
def chunk_resumable_upload():
    session_id = (
        request.args.get("session_id")
        or request.args.get("upload_id")
        or request.args.get("sessionId")
        or request.headers.get("X-Upload-Session-Id")
        or ""
    ).strip()
    offset_arg = request.args.get("offset") or request.headers.get("X-Upload-Offset") or "0"
    try:
        expected_offset = int(offset_arg)
        with _upload_sessions_lock:
            sess = _UPLOAD_SESSIONS.get(session_id)
        if not sess:
            return jsonify({"error": "Upload session not found"}), 404

        chunk_bytes = request.get_data(cache=False)
        with sess["lock"]:
            drive_type = sess["driveType"]
            drive_id = sess["driveId"]
            total_size = sess["totalSize"]
            conflict_action = sess.get("conflictAction") or "replace"

            if drive_type == "filejump":
                pipe = sess.get("pipe")
                if pipe and (pipe.error is not None or pipe.aborted or (pipe.worker_done.is_set() and pipe.bytes_accepted < total_size)):
                    sess["pipe"] = None
                    sess["offset"] = 0
                    pipe = None
                if expected_offset == 0:
                    if pipe:
                        pipe.abort()
                    pipe = _start_filejump_pipe_worker(sess)

            current_offset = int(sess.get("offset") or 0)
            if expected_offset != current_offset:
                return jsonify({
                    "error": f"Offset mismatch (expected {current_offset}, got {expected_offset})",
                    "offset": current_offset,
                }), 409

            if drive_type == "smb":
                dest_full = sess["destFull"]
                smb_manager.upload_chunk(
                    drive_id,
                    dest_full,
                    chunk_bytes,
                    offset=expected_offset,
                    truncate=(expected_offset == 0),
                )
                new_offset = expected_offset + len(chunk_bytes)
            elif drive_type == "gdrive":
                if not sess.get("resumableUri"):
                    sess["resumableUri"] = gdrive_manager.start_resumable_upload(
                        sess["folder"] or "root",
                        sess["fileName"],
                        mime_type=sess["mimeType"],
                        total_size=total_size,
                        relative_path=sess["relativePath"] or None,
                        account_id=drive_id,
                        conflict_action=conflict_action,
                    )
                new_offset = gdrive_manager.push_resumable_chunk(
                    sess["resumableUri"],
                    chunk_bytes,
                    expected_offset,
                    total_size=total_size,
                )
            elif drive_type == "onedrive":
                if not sess.get("uploadUrl"):
                    sess["uploadUrl"] = onedrive_manager.start_resumable_upload(
                        sess["folder"] or "root",
                        sess["fileName"],
                        relative_path=sess["relativePath"] or None,
                        account_id=drive_id,
                        conflict_action=conflict_action,
                    )
                new_offset = onedrive_manager.push_resumable_chunk(
                    sess["uploadUrl"],
                    chunk_bytes,
                    expected_offset,
                    total_size=total_size,
                )
            elif drive_type == "filejump":
                pipe = sess.get("pipe")
                if not pipe:
                    pipe = _start_filejump_pipe_worker(sess)
                new_offset = pipe.write_chunk(chunk_bytes)

            sess["offset"] = new_offset
            sess["updatedAt"] = time.time()
            return jsonify({"ok": True, "offset": new_offset})
    except _UploadAbortedError as e:
        return jsonify({"error": str(e)}), 499
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/transfers/upload/complete")
@auth.require_admin
def complete_resumable_upload():
    b = request.get_json(force=True, silent=True) or {}
    session_id = (
        b.get("sessionId")
        or b.get("upload_id")
        or b.get("session_id")
        or request.args.get("session_id")
        or request.args.get("upload_id")
        or ""
    ).strip()
    try:
        with _upload_sessions_lock:
            sess = _UPLOAD_SESSIONS.get(session_id)
        if not sess:
            return jsonify({"error": "Upload session not found"}), 404

        with sess["lock"]:
            drive_type = sess["driveType"]
            drive_id = sess["driveId"]
            folder = sess["folder"]
            file_name = sess["fileName"]
            rel_path = sess.get("relativePath") or ""
            mime_type = sess.get("mimeType") or guess_media_mime(file_name)
            total_size = int(sess.get("totalSize") or 0)
            conflict_action = sess.get("conflictAction") or "replace"

            if drive_type == "smb":
                dest_full = sess.get("destFull")
                if dest_full:
                    _SMB_SIZE_CACHE.pop(f"{drive_id}:{dest_full}", None)
            elif drive_type == "gdrive":
                if total_size == 0 and int(sess.get("offset") or 0) == 0:
                    gdrive_manager.upload_file(
                        folder or "root",
                        file_name,
                        b"",
                        mime_type,
                        relative_path=rel_path or None,
                        account_id=drive_id,
                        total_size=0,
                        conflict_action=conflict_action,
                    )
            elif drive_type == "onedrive":
                if total_size == 0 and int(sess.get("offset") or 0) == 0:
                    onedrive_manager.upload_file(
                        folder or "root",
                        file_name,
                        b"",
                        mime_type,
                        relative_path=rel_path or None,
                        account_id=drive_id,
                        total_size=0,
                        conflict_action=conflict_action,
                    )
            elif drive_type == "filejump":
                pipe = sess.get("pipe")
                if pipe:
                    pipe.finish_and_wait()
                elif total_size == 0:
                    filejump_manager.upload_file(
                        sess.get("resolvedParent") or folder or "root",
                        sess.get("resolvedName") or file_name,
                        b"",
                        mime_type,
                        relative_path=None,
                        account_id=drive_id,
                        total_size=0,
                        conflict_action=conflict_action,
                    )

        with _upload_sessions_lock:
            _UPLOAD_SESSIONS.pop(session_id, None)

        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/transfers/upload/cancel", methods=["POST", "DELETE"])
@auth.require_admin
def cancel_resumable_upload():
    b = request.get_json(force=True, silent=True) or {}
    session_id = (
        b.get("sessionId")
        or b.get("upload_id")
        or b.get("session_id")
        or request.args.get("session_id")
        or request.args.get("upload_id")
        or ""
    ).strip()
    try:
        with _upload_sessions_lock:
            sess = _UPLOAD_SESSIONS.pop(session_id, None)
        if sess:
            drive_type = sess.get("driveType")
            if drive_type == "filejump" and sess.get("pipe"):
                sess["pipe"].abort()
            elif drive_type == "gdrive" and sess.get("resumableUri"):
                gdrive_manager.cancel_resumable_upload(sess["resumableUri"])
            elif drive_type == "onedrive" and sess.get("uploadUrl"):
                onedrive_manager.cancel_resumable_upload(sess["uploadUrl"])
            elif drive_type == "smb" and sess.get("destFull") and int(sess.get("offset") or 0) > 0:
                try:
                    smb_manager.delete_path(sess["driveId"], sess["destFull"], False)
                except Exception:
                    pass
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── Cross-Drive Direct Streaming Transfer & Move (SMB <-> Google Drive <-> OneDrive <-> FileJump) ──
class _GeneratorStreamReader:
    """
    Wraps a chunk generator (such as stream_file_range) into a file-like .read(size)
    stream so cross-drive copies stream directly from source to destination in small
    RAM buffers without touching container disk or loading whole files in memory.
    """
    def __init__(self, gen):
        self._gen = iter(gen)
        self._buf = bytearray()
        self._eof = False

    def read(self, size=65536):
        if size is None or size < 0:
            while not self._eof:
                try:
                    chunk = next(self._gen)
                    if chunk:
                        self._buf.extend(chunk)
                except StopIteration:
                    self._eof = True
            out = bytes(self._buf)
            self._buf.clear()
            return out
        while len(self._buf) < size and not self._eof:
            try:
                chunk = next(self._gen)
                if chunk:
                    self._buf.extend(chunk)
            except StopIteration:
                self._eof = True
        out = bytes(self._buf[:size])
        del self._buf[:size]
        return out


def _read_source_item_tree(src_type, src_drive, item):
    """
    Returns (name, is_folder, children_or_None, open_stream_mime_size_fn).
    """
    if src_type == "smb":
        norm_smb = _sanitize_smb_path(item["path"], allow_root=False)
        name = norm_smb.rstrip("/").split("/")[-1]
        is_folder = item.get("type") == "folder"
        if is_folder:
            children = smb_manager.browse(src_drive, norm_smb)
            return name, True, children, None

        def _open_smb():
            sz = _get_smb_file_size(src_drive, norm_smb)
            gen = smb_manager.stream_file_range(src_drive, norm_smb, start=0, length=sz if sz > 0 else None)
            return _GeneratorStreamReader(gen), guess_media_mime(name), sz

        return name, False, None, _open_smb
    elif src_type == "gdrive":
        fid = item["id"]
        meta = gdrive_manager.get_file_meta(fid, account_id=src_drive)
        name = meta["name"]
        is_folder = item.get("type") == "folder" or meta.get("mimeType") == "application/vnd.google-apps.folder"
        if is_folder:
            children = gdrive_manager.list_files(fid, account_id=src_drive)
            return name, True, children, None

        def _open_gd():
            mime = meta.get("mimeType") or guess_media_mime(name)
            sz = int(meta.get("size") or 0)
            if mime.startswith("application/vnd.google-apps."):
                raw_bytes, _, exp_mime = gdrive_manager.download_file(fid, account_id=src_drive)
                return io.BytesIO(raw_bytes), exp_mime, len(raw_bytes)
            gen = gdrive_manager.stream_file_range(fid, start=0, end=None, account_id=src_drive)
            return _GeneratorStreamReader(gen), mime, sz

        return name, False, None, _open_gd
    elif src_type == "onedrive":
        fid = item["id"]
        meta = onedrive_manager.get_file_meta(fid, account_id=src_drive)
        name = meta["name"]
        is_folder = item.get("type") == "folder" or meta.get("isFolder") or meta.get("mimeType") == "application/vnd.ms-folder"
        if is_folder:
            children = onedrive_manager.list_files(fid, account_id=src_drive)
            return name, True, children, None

        def _open_od():
            mime = meta.get("mimeType") or guess_media_mime(name)
            sz = int(meta.get("size") or 0)
            gen = onedrive_manager.stream_file_range(fid, start=0, end=None, account_id=src_drive)
            return _GeneratorStreamReader(gen), mime, sz

        return name, False, None, _open_od
    elif src_type == "filejump":
        fid = item["id"]
        meta = filejump_manager.get_file_meta(fid, account_id=src_drive)
        name = meta["name"]
        is_folder = item.get("type") == "folder" or meta.get("isFolder") or meta.get("mimeType") == "application/vnd.filejump.folder"
        if is_folder:
            children = filejump_manager.list_files(fid, account_id=src_drive)
            return name, True, children, None

        def _open_fj():
            mime = meta.get("mimeType") or guess_media_mime(name)
            sz = int(meta.get("size") or 0)
            gen = filejump_manager.stream_file_range(fid, start=0, end=None, account_id=src_drive)
            return _GeneratorStreamReader(gen), mime, sz

        return name, False, None, _open_fj
    raise ValueError(f"Unsupported source drive type: {src_type!r}")


def _copy_item_across_drives(src_type, src_drive, item, dest_type, dest_drive, dest_folder, conflict_action="replace"):
    name, is_folder, children, open_fn = _read_source_item_tree(src_type, src_drive, item)
    action = (conflict_action or "replace").strip().lower()
    if is_folder:
        if dest_type == "smb":
            norm_dest = _sanitize_smb_path(dest_folder, allow_root=True)
            next_dest = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + name, allow_root=False)
            smb_manager.create_directory(dest_drive, next_dest)
        elif dest_type == "gdrive":
            next_dest = gdrive_manager.ensure_folder_path(dest_folder, [name], account_id=dest_drive)
        elif dest_type == "onedrive":
            next_dest = onedrive_manager.ensure_folder_path(dest_folder, [name], account_id=dest_drive)
        elif dest_type == "filejump":
            next_dest = filejump_manager.ensure_folder_path(dest_folder, [name], account_id=dest_drive)
        else:
            raise ValueError(f"Unsupported destination drive type: {dest_type!r}")
        for ch in (children or []):
            _copy_item_across_drives(src_type, src_drive, ch, dest_type, dest_drive, next_dest, conflict_action=action)
    else:
        stream_obj, mime, total_size = open_fn()
        if dest_type == "smb":
            norm_dest = _sanitize_smb_path(dest_folder, allow_root=True)
            target_path = _sanitize_smb_path(norm_dest.rstrip("/") + "/" + name, allow_root=False)
            smb_manager.upload_file(dest_drive, target_path, stream_obj, conflict_action=action)
        elif dest_type == "gdrive":
            gdrive_manager.upload_file(dest_folder, name, stream_obj, mime, account_id=dest_drive, total_size=total_size, conflict_action=action)
        elif dest_type == "onedrive":
            onedrive_manager.upload_file(dest_folder, name, stream_obj, mime, account_id=dest_drive, total_size=total_size, conflict_action=action)
        elif dest_type == "filejump":
            filejump_manager.upload_file(dest_folder, name, stream_obj, mime, account_id=dest_drive, total_size=total_size, conflict_action=action)
        else:
            raise ValueError(f"Unsupported destination drive type: {dest_type!r}")


@app.post("/api/transfer")
@auth.require_admin
def transfer_items():
    b = request.get_json(force=True) or {}
    operation = (b.get("operation") or "copy").strip().lower()
    is_move = (operation == "move")
    src_type = b.get("src_type")
    src_drive = b.get("src_drive")
    dest_type = b.get("dest_type")
    dest_drive = b.get("dest_drive")
    dest_folder = b.get("dest_folder") or ("/" if dest_type == "smb" else "root")
    items = b.get("items") or []
    default_conflict_action = (b.get("conflict_action") or b.get("conflictAction") or "replace").strip().lower()

    if not items:
        return jsonify({"error": "No items selected for transfer"}), 400
    valid_types = ("smb", "gdrive", "onedrive", "filejump")
    if src_type not in valid_types or dest_type not in valid_types:
        return jsonify({"error": "Invalid source or destination type"}), 400

    try:
        if dest_type == "smb":
            dest_folder = _sanitize_smb_path(dest_folder, allow_root=True)
        count = 0
        skipped = 0
        for item in items:
            item_action = (item.get("conflict_action") or item.get("conflictAction") or default_conflict_action or "replace").strip().lower()
            if item_action == "skip":
                skipped += 1
                continue
            is_folder = item.get("type") == "folder"
            if is_move and src_type == dest_type and src_drive == dest_drive:
                if src_type == "smb":
                    src_path = _sanitize_smb_path(item["path"], allow_root=False)
                    smb_manager.move_path(src_drive, src_path, dest_folder, conflict_action=item_action)
                    _SMB_SIZE_CACHE.pop(f"{src_drive}:{src_path}", None)
                elif src_type == "gdrive":
                    gdrive_manager.move_file(item["id"], dest_folder, account_id=src_drive, conflict_action=item_action)
                elif src_type == "onedrive":
                    onedrive_manager.move_file(item["id"], dest_folder, account_id=src_drive, conflict_action=item_action)
                elif src_type == "filejump":
                    filejump_manager.move_file(item["id"], dest_folder, account_id=src_drive, conflict_action=item_action)
            else:
                _copy_item_across_drives(src_type, src_drive, item, dest_type, dest_drive, dest_folder, conflict_action=item_action)
                if is_move:
                    if src_type == "smb":
                        src_path = _sanitize_smb_path(item["path"], allow_root=False)
                        smb_manager.delete_path(src_drive, src_path, is_folder)
                        _SMB_SIZE_CACHE.pop(f"{src_drive}:{src_path}", None)
                    elif src_type == "gdrive":
                        gdrive_manager.delete_file(item["id"], account_id=src_drive)
                    elif src_type == "onedrive":
                        onedrive_manager.delete_file(item["id"], account_id=src_drive)
                    elif src_type == "filejump":
                        filejump_manager.delete_file(item["id"], account_id=src_drive)
            count += 1
        return jsonify({
            "ok": True,
            "copied": count,
            "moved": count if is_move else 0,
            "skipped": skipped,
            "operation": "move" if is_move else "copy",
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Multi-Drive SMB Proxy Manager & Credentials (Google Drive + OneDrive + FileJump) ──
_smb_proxy_lock = threading.Lock()
_SMB_MOUNTS_BASE = Path("/mnt/gdrive_mounts")

def _safe_rclone_id(account_id):
    return re.sub(r"[^A-Za-z0-9_]", "_", str(account_id or "default"))

def _get_active_mount_points():
    mounted = set()
    try:
        if Path("/proc/mounts").exists():
            for line in Path("/proc/mounts").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    mounted.add(parts[1])
    except Exception:
        pass
    return mounted

def _unmount_path(mount_path):
    mp = str(mount_path)
    for cmd in (["fusermount", "-uz", mp], ["fusermount3", "-uz", mp], ["umount", "-l", mp]):
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, check=False, capture_output=True, timeout=5)
            except Exception:
                pass
    if mp not in _get_active_mount_points():
        return True
    return False

def _rclone_obscure_password(raw_pw):
    if not raw_pw:
        return ""
    if shutil.which("rclone"):
        try:
            res = subprocess.run(["rclone", "obscure", str(raw_pw)], capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
    return str(raw_pw)

def _reconcile_smb_proxy():
    with _smb_proxy_lock:
        gd_accounts = gdrive_manager._load_accounts_raw()
        od_accounts = onedrive_manager._load_accounts_raw()
        fj_accounts = filejump_manager._load_accounts_raw()
        gd_cfg = gdrive_manager.get_config()
        od_cfg = onedrive_manager.get_config()

        # 1. Write multi-account rclone.conf (Google Drive + OneDrive + FileJump)
        rclone_blocks = []
        for idx, acc in enumerate(gd_accounts):
            d = acc.get("creds") or {}
            if not (d.get("token") or d.get("refresh_token")):
                continue
            rc_id = _safe_rclone_id(acc["id"])
            rclone_token = json.dumps({
                "access_token": d.get("token", ""),
                "token_type": "Bearer",
                "refresh_token": d.get("refresh_token", ""),
                "expiry": "2020-01-01T00:00:00Z",
            })
            client_id = d.get("client_id") or gd_cfg.get("client_id", "")
            client_secret = d.get("client_secret") or gd_cfg.get("client_secret", "")
            block = (
                f"[gdrive_{rc_id}]\n"
                f"type = drive\n"
                f"client_id = {client_id}\n"
                f"client_secret = {client_secret}\n"
                f"scope = drive\n"
                f"token = {rclone_token}\n"
            )
            rclone_blocks.append(block)
            if idx == 0:
                rclone_blocks.append(
                    f"[gdrive]\n"
                    f"type = drive\n"
                    f"client_id = {client_id}\n"
                    f"client_secret = {client_secret}\n"
                    f"scope = drive\n"
                    f"token = {rclone_token}\n"
                )

        for acc in od_accounts:
            d = acc.get("creds") or {}
            if not (d.get("token") or d.get("refresh_token")):
                continue
            rc_id = _safe_rclone_id(acc["id"])
            rclone_token = json.dumps({
                "access_token": d.get("token", ""),
                "token_type": "Bearer",
                "refresh_token": d.get("refresh_token", ""),
                "expiry": d.get("expiry") or "2020-01-01T00:00:00Z",
            })
            client_id = d.get("client_id") or od_cfg.get("client_id", "")
            client_secret = d.get("client_secret") or od_cfg.get("client_secret", "")
            drive_id = acc.get("drive_id", "")
            drive_type = acc.get("drive_type", "personal") or "personal"
            lines = [
                f"[onedrive_{rc_id}]",
                "type = onedrive",
                f"client_id = {client_id}",
                f"client_secret = {client_secret}",
                f"token = {rclone_token}",
            ]
            if drive_id:
                lines.append(f"drive_id = {drive_id}")
            if drive_type:
                lines.append(f"drive_type = {drive_type}")
            rclone_blocks.append("\n".join(lines) + "\n")

        for acc in fj_accounts:
            api_token = acc.get("api_token") or ""
            if not api_token:
                continue
            rc_id = _safe_rclone_id(acc.get("id", "default"))
            auth_type = acc.get("auth_type", "token")
            if auth_type == "webdav":
                dav_url = acc.get("api_url") or filejump_manager.DEFAULT_WEBDAV_BASE
                lines = [
                    f"[filejump_{rc_id}]",
                    "type = webdav",
                    f"url = {dav_url}",
                    "vendor = other",
                    f"user = {acc.get('email', '')}",
                    f"pass = {_rclone_obscure_password(api_token)}",
                ]
            else:
                dav_url = filejump_manager.DEFAULT_WEBDAV_BASE
                lines = [
                    f"[filejump_{rc_id}]",
                    "type = webdav",
                    f"url = {dav_url}",
                    "vendor = other",
                    f"bearer_token = {api_token}",
                ]
            rclone_blocks.append("\n".join(lines) + "\n")

        try:
            os.makedirs("/root/.config/rclone", exist_ok=True)
            Path("/root/.config/rclone/rclone.conf").write_text("\n".join(rclone_blocks))
        except Exception as e:
            print(f"SMB Proxy rclone.conf write warning: {e}", flush=True)

        # 2. Reconcile FUSE mounts under /mnt/gdrive_mounts/<id>
        has_rclone = bool(shutil.which("rclone"))
        try:
            _SMB_MOUNTS_BASE.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        mounted_paths = _get_active_mount_points()
        if "/mnt/gdrive" in mounted_paths:
            _unmount_path("/mnt/gdrive")
            mounted_paths = _get_active_mount_points()

        desired_mounts = {}
        for acc in gd_accounts:
            d = acc.get("creds") or {}
            if bool(acc.get("smb_enabled", True)) and (d.get("token") or d.get("refresh_token")):
                rc_id = _safe_rclone_id(acc["id"])
                mpath = str(_SMB_MOUNTS_BASE / f"gd_{rc_id}")
                desired_mounts[mpath] = f"gdrive_{rc_id}:"

        for acc in od_accounts:
            d = acc.get("creds") or {}
            if bool(acc.get("smb_enabled", True)) and (d.get("token") or d.get("refresh_token")):
                rc_id = _safe_rclone_id(acc["id"])
                mpath = str(_SMB_MOUNTS_BASE / f"od_{rc_id}")
                desired_mounts[mpath] = f"onedrive_{rc_id}:"

        for acc in fj_accounts:
            if bool(acc.get("smb_enabled", True)) and acc.get("api_token"):
                rc_id = _safe_rclone_id(acc.get("id", "default"))
                mpath = str(_SMB_MOUNTS_BASE / f"fj_{rc_id}")
                desired_mounts[mpath] = f"filejump_{rc_id}:"

        for mp in list(mounted_paths):
            if mp.startswith(str(_SMB_MOUNTS_BASE) + "/") and mp not in desired_mounts:
                _unmount_path(mp)

        mounted_paths = _get_active_mount_points()
        if has_rclone:
            try:
                shutil.rmtree("/root/.cache/rclone", ignore_errors=True)
            except Exception:
                pass
            newly_started = False
            for mpath, remote_name in desired_mounts.items():
                if mpath not in mounted_paths:
                    try:
                        os.makedirs(mpath, exist_ok=True)
                        subprocess.run(
                            [
                                "rclone", "mount", remote_name, mpath,
                                "--config", "/root/.config/rclone/rclone.conf",
                                "--allow-other",
                                "--buffer-size", "16M",
                                "--vfs-read-chunk-size", "32M",
                                "--vfs-cache-mode", "off",
                                "--dir-cache-time", "5m",
                                "--daemon",
                            ],
                            check=False,
                            capture_output=True,
                            timeout=10,
                        )
                        newly_started = True
                    except Exception as e:
                        print(f"SMB Proxy rclone mount warning for {remote_name}: {e}", flush=True)
            if newly_started:
                for _ in range(6):
                    time.sleep(0.25)
                    mounted_paths = _get_active_mount_points()
                    if all(mp in mounted_paths for mp in desired_mounts):
                        break

        # 3. Generate /etc/samba/smb.conf with a separate share stanza per enabled Google Drive, OneDrive & FileJump
        smb_conf_lines = [
            "[global]",
            "   workgroup = WORKGROUP",
            "   server string = SageDrive SMB Proxy",
            "   security = user",
            "   map to guest = Never",
            "   log file = /var/log/samba/%m.log",
            "   max log size = 50",
            "   oplocks = no",
            "   kernel oplocks = no",
            "   strict allocate = yes",
            "   ntlm auth = yes",
            "   server min protocol = NT1",
            "",
        ]
        used_share_names = set()
        for acc in gd_accounts:
            if not bool(acc.get("smb_enabled", True)):
                continue
            share_name = gdrive_manager.sanitize_smb_share_name(acc.get("smb_share_name") or "GoogleDrive")
            while share_name.lower() in used_share_names:
                share_name = f"{share_name[:28]}_gd"
            used_share_names.add(share_name.lower())
            rc_id = _safe_rclone_id(acc["id"])
            mpath = str(_SMB_MOUNTS_BASE / f"gd_{rc_id}")
            try:
                os.makedirs(mpath, exist_ok=True)
            except Exception:
                pass
            smb_conf_lines.extend([
                f"[{share_name}]",
                f"   path = {mpath}",
                f"   comment = SageDrive Google Drive - {acc.get('custom_name') or acc.get('name') or share_name}",
                "   valid users = @sambausers",
                "   writable = yes",
                "   browseable = yes",
                "   create mask = 0775",
                "   directory mask = 0775",
                "",
            ])

        for acc in od_accounts:
            if not bool(acc.get("smb_enabled", True)):
                continue
            share_name = onedrive_manager.sanitize_smb_share_name(acc.get("smb_share_name") or "OneDrive")
            while share_name.lower() in used_share_names:
                share_name = f"{share_name[:28]}_od"
            used_share_names.add(share_name.lower())
            rc_id = _safe_rclone_id(acc["id"])
            mpath = str(_SMB_MOUNTS_BASE / f"od_{rc_id}")
            try:
                os.makedirs(mpath, exist_ok=True)
            except Exception:
                pass
            smb_conf_lines.extend([
                f"[{share_name}]",
                f"   path = {mpath}",
                f"   comment = SageDrive OneDrive - {acc.get('custom_name') or acc.get('name') or share_name}",
                "   valid users = @sambausers",
                "   writable = yes",
                "   browseable = yes",
                "   create mask = 0775",
                "   directory mask = 0775",
                "",
            ])

        for acc in fj_accounts:
            if not bool(acc.get("smb_enabled", True)):
                continue
            share_name = filejump_manager.sanitize_smb_share_name(acc.get("smb_share_name") or "FileJump")
            while share_name.lower() in used_share_names:
                share_name = f"{share_name[:28]}_fj"
            used_share_names.add(share_name.lower())
            rc_id = _safe_rclone_id(acc.get("id", "default"))
            mpath = str(_SMB_MOUNTS_BASE / f"fj_{rc_id}")
            try:
                os.makedirs(mpath, exist_ok=True)
            except Exception:
                pass
            smb_conf_lines.extend([
                f"[{share_name}]",
                f"   path = {mpath}",
                f"   comment = SageDrive FileJump - {acc.get('custom_name') or acc.get('name') or share_name}",
                "   valid users = @sambausers",
                "   writable = yes",
                "   browseable = yes",
                "   create mask = 0775",
                "   directory mask = 0775",
                "",
            ])

        smb_conf_text = "\n".join(smb_conf_lines)
        for conf_target in (Path("/etc/samba/smb.conf"), Path("/app/smb.conf")):
            try:
                if conf_target.parent.exists():
                    conf_target.write_text(smb_conf_text)
            except Exception:
                pass

        # 4. Reload or start smbd
        if shutil.which("smbcontrol"):
            try:
                subprocess.run(["smbcontrol", "all", "reload-config"], check=False, capture_output=True, timeout=4)
            except Exception:
                pass
        if shutil.which("pkill"):
            try:
                subprocess.run(["pkill", "-HUP", "smbd"], check=False, capture_output=True, timeout=4)
            except Exception:
                pass

        return _get_smb_proxy_status_unlocked()

def _get_smb_proxy_status_unlocked():
    creds_file = Path(os.environ.get("DATA_DIR", "/app/data")) / "smb_proxy_credentials.json"
    username = "sagedrive"
    configured = False
    if creds_file.exists():
        try:
            d = json.loads(creds_file.read_text())
            username = d.get("username", "sagedrive")
            configured = True
        except Exception:
            pass
    gd_accounts = gdrive_manager._load_accounts_raw()
    od_accounts = onedrive_manager._load_accounts_raw()
    fj_accounts = filejump_manager._load_accounts_raw()
    mounted_paths = _get_active_mount_points()
    has_rclone = bool(shutil.which("rclone"))
    shares = []
    for acc in gd_accounts:
        rc_id = _safe_rclone_id(acc["id"])
        mpath = str(_SMB_MOUNTS_BASE / f"gd_{rc_id}")
        enabled = bool(acc.get("smb_enabled", True))
        is_mounted = (mpath in mounted_paths) if has_rclone else enabled
        shares.append({
            "provider": "gdrive",
            "account_id": acc["id"],
            "account_name": acc.get("custom_name") or acc.get("name") or "Google Drive",
            "email": acc.get("email", ""),
            "smb_enabled": enabled,
            "smb_share_name": acc.get("smb_share_name") or "GoogleDrive",
            "mount_path": mpath,
            "mounted": is_mounted,
        })
    for acc in od_accounts:
        rc_id = _safe_rclone_id(acc["id"])
        mpath = str(_SMB_MOUNTS_BASE / f"od_{rc_id}")
        enabled = bool(acc.get("smb_enabled", True))
        is_mounted = (mpath in mounted_paths) if has_rclone else enabled
        shares.append({
            "provider": "onedrive",
            "account_id": acc["id"],
            "account_name": acc.get("custom_name") or acc.get("name") or "OneDrive",
            "email": acc.get("email", ""),
            "smb_enabled": enabled,
            "smb_share_name": acc.get("smb_share_name") or "OneDrive",
            "mount_path": mpath,
            "mounted": is_mounted,
        })
    for acc in fj_accounts:
        rc_id = _safe_rclone_id(acc.get("id", "default"))
        mpath = str(_SMB_MOUNTS_BASE / f"fj_{rc_id}")
        enabled = bool(acc.get("smb_enabled", True))
        is_mounted = (mpath in mounted_paths) if has_rclone else enabled
        shares.append({
            "provider": "filejump",
            "account_id": acc.get("id", "default"),
            "account_name": acc.get("custom_name") or acc.get("name") or "FileJump",
            "email": acc.get("email", ""),
            "smb_enabled": enabled,
            "smb_share_name": acc.get("smb_share_name") or "FileJump",
            "mount_path": mpath,
            "mounted": is_mounted,
        })
    return {
        "username": username,
        "configured": configured,
        "shares": shares,
    }

@app.get("/api/smb/proxy-credentials")
@auth.require_auth
def get_smb_proxy_creds():
    with _smb_proxy_lock:
        return jsonify(_get_smb_proxy_status_unlocked())

@app.get("/api/smb/proxy-shares")
@auth.require_auth
def get_smb_proxy_shares():
    with _smb_proxy_lock:
        return jsonify(_get_smb_proxy_status_unlocked())

@app.post("/api/smb/proxy-shares/<account_id>")
@auth.require_admin
def update_smb_proxy_share(account_id):
    b = request.get_json(force=True) or {}
    smb_enabled = b.get("smb_enabled") if "smb_enabled" in b else None
    smb_share_name = b.get("smb_share_name") if "smb_share_name" in b else None
    provider = (b.get("provider") or "").strip().lower()
    try:
        od_ids = {a["id"] for a in onedrive_manager._load_accounts_raw()}
        fj_ids = {a["id"] for a in filejump_manager._load_accounts_raw()}
        if provider == "filejump" or account_id in fj_ids or str(account_id).startswith("filejump"):
            updated = filejump_manager.update_account_smb_proxy(
                account_id,
                smb_enabled=smb_enabled,
                smb_share_name=smb_share_name,
            )
        elif provider == "onedrive" or account_id in od_ids or str(account_id).startswith("onedrive"):
            updated = onedrive_manager.update_account_smb_proxy(
                account_id,
                smb_enabled=smb_enabled,
                smb_share_name=smb_share_name,
            )
        else:
            updated = gdrive_manager.update_account_smb_proxy(
                account_id,
                smb_enabled=smb_enabled,
                smb_share_name=smb_share_name,
            )
        status = _reconcile_smb_proxy()
        return jsonify({
            "ok": True,
            "share": updated,
            "shares": status.get("shares", []),
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/proxy-reconcile")
@auth.require_admin
def reconcile_smb_proxy_route():
    try:
        status = _reconcile_smb_proxy()
        return jsonify({"ok": True, **status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/proxy-credentials")
@auth.require_admin
def set_smb_proxy_creds():
    body = request.get_json(force=True) or {}
    username = (body.get("username") or "sagedrive").strip()
    password = (body.get("password") or "").strip()

    if not password:
        return jsonify({"error": "Password is required"}), 400

    creds_file = Path(os.environ.get("DATA_DIR", "/app/data")) / "smb_proxy_credentials.json"
    creds_file.write_text(json.dumps({"username": username, "password": password}, indent=2))

    try:
        subprocess.run(["groupadd", "-f", "sambausers"], check=False)
        subprocess.run(["useradd", "-M", "-s", "/sbin/nologin", "-G", "sambausers", username],
                       check=False, capture_output=True)
        subprocess.run(["usermod", "-aG", "sambausers", username], check=False, capture_output=True)
        proc = subprocess.run(
            ["smbpasswd", "-s", "-a", username],
            input=f"{password}\n{password}\n",
            text=True, capture_output=True
        )
        _reconcile_smb_proxy()
        return jsonify({"ok": True, "message": f"Credentials saved. Reconnect as '{username}'."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Favorite Folders Persistence ──────────────────────────────────────────────
_FAVORITES_FILE = Path(os.environ.get("DATA_DIR", "/app/data")) / "favorites.json"
_favorites_lock = threading.Lock()


def _load_favorites_list() -> list:
    if not _FAVORITES_FILE.exists():
        return []
    try:
        data = json.loads(_FAVORITES_FILE.read_text())
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_favorites_list(favs: list):
    _FAVORITES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _FAVORITES_FILE.write_text(json.dumps(favs, indent=2))


@app.get("/api/favorites")
@auth.require_auth
def get_favorite_folders():
    with _favorites_lock:
        return jsonify(_load_favorites_list())


@app.post("/api/favorites")
@auth.require_auth
def save_favorite_folder():
    body = request.get_json(force=True) or {}
    if isinstance(body.get("favorites"), list):
        with _favorites_lock:
            _save_favorites_list(body["favorites"])
            return jsonify({"ok": True, "favorites": body["favorites"]})

    fav_id = str(body.get("id") or "").strip()
    if not fav_id:
        return jsonify({"error": "Favorite folder id is required"}), 400

    entry = {
        "id": fav_id,
        "name": str(body.get("name") or "Folder").strip() or "Folder",
        "driveType": str(body.get("driveType") or "smb").strip(),
        "driveId": str(body.get("driveId") or "default").strip(),
        "driveName": str(body.get("driveName") or "Drive").strip(),
        "path": str(body.get("path") or "/").strip(),
        "folderId": str(body.get("folderId") or "root").strip(),
        "pathStack": body.get("pathStack") if isinstance(body.get("pathStack"), list) else [],
    }
    with _favorites_lock:
        favs = _load_favorites_list()
        idx = next((i for i, item in enumerate(favs) if item.get("id") == fav_id), -1)
        if idx >= 0:
            favs[idx] = entry
        else:
            favs.append(entry)
        _save_favorites_list(favs)
        return jsonify({"ok": True, "favorites": favs})


@app.delete("/api/favorites")
@auth.require_auth
def delete_favorite_folder():
    body = request.get_json(silent=True) or {}
    fav_id = (request.args.get("id") or body.get("id") or "").strip()
    if not fav_id:
        return jsonify({"error": "Favorite folder id is required"}), 400
    with _favorites_lock:
        favs = [item for item in _load_favorites_list() if item.get("id") != fav_id]
        _save_favorites_list(favs)
        return jsonify({"ok": True, "favorites": favs})


# Trigger initial multi-drive SMB proxy reconciliation in background on startup
threading.Thread(target=lambda: _reconcile_smb_proxy(), daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)

