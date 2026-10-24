import os, json, time, mimetypes, io, re, subprocess, threading, tempfile, zipfile, queue, requests
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import quote, urlparse, parse_qs, unquote
from flask import Flask, request, jsonify, send_file, send_from_directory, redirect
from flask_cors import CORS
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import auth, smb_manager, gdrive_manager

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, supports_credentials=True, expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"])
auth.bootstrap_admin()

# ── Ensure gdrive_manager has token-expiry persistence, 401 retry & meta cache ─
_gd_creds_lock = threading.Lock()
_gd_meta_cache = getattr(gdrive_manager, "_meta_cache", {})
_GD_META_TTL = 120.0
_SMB_SIZE_CACHE = {}
_SMB_SIZE_TTL = 60.0
_PROBE_CACHE = {}
_PROBE_TTL = 600.0

def _gd_parse_expiry(raw_expiry):
    if not raw_expiry:
        return None
    try:
        dt = datetime.fromisoformat(str(raw_expiry).replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return None

def _gd_save_creds(c):
    expiry_str = None
    if getattr(c, "expiry", None) is not None:
        expiry_str = c.expiry.isoformat()
    gdrive_manager.CREDS_FILE.write_text(json.dumps({
        "token": c.token,
        "refresh_token": c.refresh_token,
        "token_uri": c.token_uri,
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "scopes": list(c.scopes or gdrive_manager.SCOPES),
        "expiry": expiry_str,
    }, indent=2))

def _gd_load_creds(force_refresh=False):
    with _gd_creds_lock:
        if not gdrive_manager.CREDS_FILE.exists():
            return None
        d = json.loads(gdrive_manager.CREDS_FILE.read_text())
        cfg = gdrive_manager.get_config()
        expiry_dt = _gd_parse_expiry(d.get("expiry"))
        c = Credentials(
            token=d.get("token"),
            refresh_token=d.get("refresh_token"),
            token_uri=d.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=d.get("client_id", cfg["client_id"]),
            client_secret=d.get("client_secret", cfg["client_secret"]),
            scopes=d.get("scopes", gdrive_manager.SCOPES),
            expiry=expiry_dt,
        )
        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        needs_refresh = (
            force_refresh
            or not c.token
            or expiry_dt is None
            or not c.valid
            or (expiry_dt - now_utc).total_seconds() < 300
        )
        if needs_refresh and c.refresh_token:
            c.refresh(Request())
            _gd_save_creds(c)
        return c if (c.token or c.valid) else None

def _gd_svc():
    c = _gd_load_creds()
    if not c:
        raise RuntimeError("Not authenticated with Google Drive")
    return build("drive", "v3", credentials=c, cache_discovery=False)

def _gd_get_file_meta(file_id):
    now = time.time()
    cached = _gd_meta_cache.get(file_id)
    if cached and (now - cached[0]) < _GD_META_TTL:
        return cached[1]
    svc = _gd_svc()
    meta = svc.files().get(
        fileId=file_id,
        fields="name,mimeType,size",
        supportsAllDrives=True,
    ).execute()
    info = {
        "name": meta.get("name", "download"),
        "mimeType": meta.get("mimeType", "application/octet-stream"),
        "size": int(meta.get("size", 0) or 0),
    }
    _gd_meta_cache[file_id] = (now, info)
    return info

def _gd_open_media_response(file_id, start=None, end=None):
    url = (
        f"https://www.googleapis.com/drive/v3/files/{file_id}"
        f"?alt=media&supportsAllDrives=true&acknowledgeAbuse=true"
    )
    for attempt in range(2):
        c = _gd_load_creds(force_refresh=(attempt > 0))
        if not c:
            raise RuntimeError("Not authenticated with Google Drive")
        headers = {"Authorization": f"Bearer {c.token}"}
        if start is not None and end is not None:
            headers["Range"] = f"bytes={start}-{end}"
        elif start:
            headers["Range"] = f"bytes={start}-"
        r = requests.get(url, headers=headers, stream=True, timeout=(15, 300))
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
            raise RuntimeError(f"Google Drive stream failed ({r.status_code}): {err_body}")
        return r
    raise RuntimeError("Google Drive authentication failed after token refresh")

def _gd_stream_file_range(file_id, start=0, end=None, chunk_size=262144):
    r = _gd_open_media_response(file_id, start=start, end=end)
    def _gen():
        try:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
        finally:
            try:
                r.close()
            except Exception:
                pass
    return _gen()

gdrive_manager._save_creds = _gd_save_creds
gdrive_manager._load_creds = _gd_load_creds
gdrive_manager._svc = _gd_svc
gdrive_manager.get_file_meta = _gd_get_file_meta
gdrive_manager.stream_file_range = _gd_stream_file_range

# ── Ensure smb_manager has fast size cache & clean early-abort stream_file_range ─
def _get_smb_file_size(share_id, path):
    key = f"{share_id}:{path}"
    now = time.time()
    cached = _SMB_SIZE_CACHE.get(key)
    if cached and (now - cached[0]) < _SMB_SIZE_TTL:
        return cached[1]
    sz = smb_manager.get_file_size(share_id, path)
    _SMB_SIZE_CACHE[key] = (now, sz)
    return sz

def _smb_stream_file_range(share_id, path, start=0, length=None, chunk_size=262144):
    q = queue.Queue(maxsize=32)
    sentinel = object()
    aborted = threading.Event()

    class _AbortStream(Exception):
        pass

    class _QueueWriter:
        def __init__(self, max_bytes):
            self.remaining = max_bytes
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
        c = None
        try:
            cfg = smb_manager._cfg(share_id)
            c = smb_manager._conn(cfg)
            writer = _QueueWriter(length)
            if start == 0 and length is None:
                c.retrieveFile(cfg["share"], path, writer)
            else:
                max_len = length if (length is not None and length > 0) else -1
                c.retrieveFileFromOffset(cfg["share"], path, writer, offset=start, max_length=max_len)
            writer.flush()
        except _AbortStream:
            pass
        except Exception as e:
            if not aborted.is_set():
                try:
                    writer.flush()
                except Exception:
                    pass
                try:
                    q.put(e, timeout=1.0)
                except Exception:
                    pass
        finally:
            try:
                q.put(sentinel, timeout=1.0)
            except Exception:
                pass
            if c is not None:
                try:
                    c.close()
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

smb_manager.stream_file_range = _smb_stream_file_range

# ── Internal Loopback HTTP Range Server for FFmpeg & FFprobe ──────────────────
class _InternalMediaRangeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        is_probe = qs.get("probe", [""])[0] == "1"
        try:
            if parsed.path.startswith("/smb/"):
                share_id = unquote(parsed.path[len("/smb/"):])
                smb_path = qs.get("path", [""])[0]
                file_size = _get_smb_file_size(share_id, smb_path)
                kind = "smb"
            elif parsed.path.startswith("/gdrive/"):
                file_id = unquote(parsed.path[len("/gdrive/"):])
                meta = gdrive_manager.get_file_meta(file_id)
                file_size = meta["size"]
                kind = "gdrive"
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

            fetch_len = min(length, 8 * 1024 * 1024) if (is_probe and length > 0) else length
            if kind == "smb":
                gen = smb_manager.stream_file_range(share_id, smb_path, start=start, length=fetch_len)
            else:
                end_byte = (start + fetch_len - 1) if fetch_len > 0 else None
                gen = gdrive_manager.stream_file_range(file_id, start=start, end=end_byte)

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
        except Exception as e:
            try:
                self.send_response(500)
                self.end_headers()
            except Exception:
                pass

_internal_media_server = ThreadingHTTPServer(("127.0.0.1", 0), _InternalMediaRangeHandler)
_INTERNAL_MEDIA_PORT = _internal_media_server.server_port
threading.Thread(target=_internal_media_server.serve_forever, daemon=True).start()

def _internal_smb_url(share_id, path):
    return f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/smb/{quote(str(share_id))}?path={quote(str(path))}"

def _internal_gdrive_url(file_id):
    return f"http://127.0.0.1:{_INTERNAL_MEDIA_PORT}/gdrive/{quote(str(file_id))}"

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

    non_native_container = ext in ("avi", "wmv", "flv", "ts", "m2ts", "mpg", "mpeg", "vob", "divx")
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

    try:
        duration = float(fmt.get("duration") or 0)
    except Exception:
        duration = 0.0

    return {
        "has_video": has_video,
        "video_codec": video_codec,
        "video_pix_fmt": video_pix_fmt,
        "has_audio": has_audio,
        "audio_codec": audio_codec,
        "audio_channels": audio_channels,
        "audio_streams": audio_tracks_out,
        "duration": duration,
        "needs_audio_transcode": needs_audio_transcode,
        "needs_video_transcode": needs_video_transcode,
        "can_remux_video": can_remux_video,
        "recommended_mode": recommended_mode,
    }

def probe_media_info(cache_key, internal_url, filename="", fallback_gen_fn=None):
    now = time.time()
    cached = _PROBE_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _PROBE_TTL:
        return cached[1]

    probe_url = internal_url + ("&" if "?" in internal_url else "?") + "probe=1"
    cmd = [
        "ffprobe",
        "-v", "error",
        "-probesize", "4000000",
        "-analyzeduration", "4000000",
        "-show_entries", "stream=index,codec_type,codec_name,profile,pix_fmt,channels,sample_rate:stream_tags=language,title:format=format_name,duration",
        "-of", "json",
        probe_url,
    ]
    data = None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
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
                    "-probesize", "4000000",
                    "-analyzeduration", "4000000",
                    "-show_entries", "stream=index,codec_type,codec_name,profile,pix_fmt,channels,sample_rate:stream_tags=language,title:format=format_name,duration",
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
                    if proc.poll() is not None or sent >= 4 * 1024 * 1024:
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
            out, _ = proc.communicate(timeout=5)
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

def _build_ffmpeg_video_cmd(input_spec, mode="full", video_codec="h264", audio_track=0, start_time=0.0):
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error"]
    if start_time and start_time > 0:
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
    cmd += [
        "-af", "aresample=async=1:first_pts=0",
        "-c:a", "aac", "-ac", "2", "-ar", "48000", "-b:a", "192k",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "frag_keyframe+empty_moov+default_base_moof",
        "-f", "mp4",
        "pipe:1",
    ]
    return cmd

def transcode_media_stream(internal_url=None, chunk_iterable_fn=None, filename="", mode="auto", audio_track=0, start_time=0.0, probe_info=None):
    """
    Streams fragmented MP4 with universal 2-channel stereo AAC audio.
    When mode='remux' (or mode='auto' with H.264/HEVC video), copies the video
    stream untouched (-c:v copy) while transcoding EAC3/AC3/DTS/etc. audio to
    stereo AAC at 100x realtime speed. Automatically falls back to full libx264
    encoding if stream copy produces no output.
    """
    vcodec = (probe_info or {}).get("video_codec") or "h264"
    can_remux = (probe_info or {}).get("can_remux_video", False)
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

            first_chunk = proc.stdout.read(65536)
            if not first_chunk:
                try:
                    proc.kill()
                except Exception:
                    pass
                continue

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

def transcode_audio_stream(chunk_iterable, internal_url=None):
    """
    Transcodes any audio stream (including 5.1/7.1 EAC3, AC3, DTS, FLAC, WMA, ALAC)
    into universal 2-channel stereo MP3.
    """
    proc = None
    gen = None
    try:
        if internal_url:
            proc = subprocess.Popen(
                [
                    "ffmpeg",
                    "-hide_banner", "-loglevel", "error",
                    "-i", internal_url,
                    "-vn",
                    "-af", "aresample=async=1:first_pts=0",
                    "-c:a", "libmp3lame", "-ac", "2", "-ar", "48000", "-b:a", "192k",
                    "-f", "mp3",
                    "pipe:1",
                ],
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
    print(f"LOGIN DEBUG username={u!r} pass_len={len(pw)} keys={list(body.keys())}", flush=True)
    token = auth.login(u, pw)
    if token:
        resp = jsonify({"token": token})
        resp.set_cookie("sd_token", token, max_age=auth.SESSION_TTL, path="/", samesite="Lax")
        return resp
    return jsonify({"error": "Invalid credentials"}), 401

@app.post("/api/auth/logout")
@auth.require_auth
def api_logout():
    t = request.headers.get("Authorization","").removeprefix("Bearer ").strip()
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
    return jsonify({"username": s["username"], "role": s["role"]})

# ── SMB ───────────────────────────────────────────────────────────────────────
@app.get("/api/smb/shares")
@auth.require_auth
def smb_list_shares():
    return jsonify([{k:v for k,v in s.items() if k != "password"}
                    for s in smb_manager.list_shares()])

@app.post("/api/smb/shares")
@auth.require_auth
def smb_add_share():
    b = request.get_json(force=True) or {}
    try:
        entry = smb_manager.add_share(
            name=b["name"], host=b["host"], share=b["share"],
            username=b.get("username",""), password=b.get("password",""),
            port=int(b.get("port", 445)))
        return jsonify({k:v for k,v in entry.items() if k != "password"}), 201
    except (KeyError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.delete("/api/smb/shares/<share_id>")
@auth.require_auth
def smb_delete_share(share_id):
    smb_manager.remove_share(share_id)
    return jsonify({"ok": True})

@app.get("/api/smb/browse/<share_id>")
@auth.require_auth
def smb_browse(share_id):
    path = request.args.get("path", "/")
    try:
        return jsonify(smb_manager.browse(share_id, path))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/probe/<share_id>")
@auth.require_auth
def smb_probe(share_id):
    path = request.args.get("path", "")
    filename = path.split("/")[-1] or "media"
    try:
        internal_url = _internal_smb_url(share_id, path)
        info = probe_media_info(
            cache_key=f"smb:{share_id}:{path}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=4 * 1024 * 1024),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/smb/download/<share_id>")
@auth.require_auth
def smb_download(share_id):
    path = request.args.get("path", "")
    filename = path.split("/")[-1] or "download"
    try:
        file_size = _get_smb_file_size(share_id, path)
        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_smb_url(share_id, path)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            probe_info = None
            if mode == "auto":
                probe_info = probe_media_info(
                    cache_key=f"smb:{share_id}:{path}",
                    internal_url=internal_url,
                    filename=filename,
                    fallback_gen_fn=lambda: smb_manager.stream_file_range(share_id, path, start=0, length=min(file_size, 4 * 1024 * 1024)),
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
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: smb_manager.stream_file_range(share_id, path, start=0, length=file_size),
                    internal_url=internal_url,
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/upload/<share_id>")
@auth.require_auth
def smb_upload(share_id):
    dest = request.args.get("path", "/")
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        sub_path = rel_path.lstrip("/") if rel_path else f.filename
        target_path = dest.rstrip("/") + "/" + sub_path
        smb_manager.upload_file(share_id, target_path, f.read())
        _SMB_SIZE_CACHE.pop(f"{share_id}:{target_path}", None)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/rename/<share_id>")
@auth.require_auth
def smb_rename(share_id):
    b = request.get_json(force=True) or {}
    old_path = (b.get("path") or "").strip()
    new_name = (b.get("new_name") or "").strip()
    if not old_path or not new_name:
        return jsonify({"error": "path and new_name are required"}), 400
    try:
        new_path = smb_manager.rename_path(share_id, old_path, new_name)
        _SMB_SIZE_CACHE.pop(f"{share_id}:{old_path}", None)
        return jsonify({"ok": True, "path": new_path})
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
        tmp_path, zip_size = smb_manager.create_zip_tmpfile(share_id, paths)
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
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/smb/delete/<share_id>")
@auth.require_auth
def smb_delete_file(share_id):
    b = request.get_json(force=True) or {}
    try:
        p = b.get("path","")
        smb_manager.delete_path(share_id, p, b.get("is_dir", False))
        _SMB_SIZE_CACHE.pop(f"{share_id}:{p}", None)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/smb/mkdir/<share_id>")
@auth.require_auth
def smb_mkdir(share_id):
    b = request.get_json(force=True) or {}
    try:
        smb_manager.create_directory(share_id, b.get("path",""))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Google Drive ──────────────────────────────────────────────────────────────
@app.get("/api/gdrive/status")
@auth.require_auth
def gdrive_status():
    return jsonify({"configured": gdrive_manager.is_configured(),
                    "authenticated": gdrive_manager.is_authenticated()})

@app.get("/api/gdrive/config")
@auth.require_auth
def gdrive_get_config():
    return jsonify(gdrive_manager.get_config())

@app.post("/api/gdrive/config")
@auth.require_auth
def gdrive_save_config():
    b = request.get_json(force=True) or {}
    cfg = gdrive_manager.save_config(
        b.get("client_id", ""),
        b.get("client_secret", ""),
        b.get("redirect_uri", "")
    )
    return jsonify({"ok": True, "configured": gdrive_manager.is_configured()})

@app.get("/api/gdrive/auth")
@auth.require_auth
def gdrive_auth():
    if not gdrive_manager.is_configured():
        return jsonify({"error": "Google OAuth not configured"}), 400
    return jsonify({"url": gdrive_manager.get_auth_url()})

@app.get("/api/gdrive/callback")
def gdrive_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "Missing code", 400
    try:
        gdrive_manager.handle_callback(code, state)
        return redirect("/#gdrive-connected")
    except Exception as e:
        return f"OAuth error: {e}", 500

@app.delete("/api/gdrive/revoke")
@auth.require_auth
def gdrive_revoke():
    gdrive_manager.revoke()
    return jsonify({"ok": True})

@app.get("/api/gdrive/files")
@auth.require_auth
def gdrive_files():
    folder_id = request.args.get("folder", "root")
    try:
        return jsonify(gdrive_manager.list_files(folder_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/probe/<file_id>")
@auth.require_auth
def gdrive_probe(file_id):
    try:
        meta = gdrive_manager.get_file_meta(file_id)
        filename = meta["name"]
        file_size = meta["size"]
        internal_url = _internal_gdrive_url(file_id)
        end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
        info = probe_media_info(
            cache_key=f"gdrive:{file_id}",
            internal_url=internal_url,
            filename=filename,
            fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte),
        )
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.get("/api/gdrive/download/<file_id>")
@auth.require_auth
def gdrive_download(file_id):
    try:
        meta = gdrive_manager.get_file_meta(file_id)
        filename = meta["name"]
        raw_mime = meta["mimeType"]
        file_size = meta["size"]

        # Google Workspace native docs must be exported
        if raw_mime.startswith("application/vnd.google-apps."):
            data, filename, mime = gdrive_manager.download_file(file_id)
            return send_file(
                io.BytesIO(data),
                download_name=filename,
                as_attachment=bool(request.args.get("dl")),
                mimetype=mime or "application/octet-stream",
            )

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))
        internal_url = _internal_gdrive_url(file_id)

        if request.args.get("transcode") == "1":
            mode = request.args.get("mode", "auto")
            audio_track = int(request.args.get("audio_track", "0") or 0)
            start_time = float(request.args.get("ss", "0") or 0.0)
            probe_info = None
            if mode == "auto":
                end_byte = min(file_size - 1, 4 * 1024 * 1024 - 1) if file_size > 0 else 4 * 1024 * 1024 - 1
                probe_info = probe_media_info(
                    cache_key=f"gdrive:{file_id}",
                    internal_url=internal_url,
                    filename=filename,
                    fallback_gen_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=end_byte),
                )
            resp = app.response_class(
                transcode_media_stream(
                    internal_url=internal_url,
                    chunk_iterable_fn=lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None),
                    filename=filename,
                    mode=mode,
                    audio_track=audio_track,
                    start_time=start_time,
                    probe_info=probe_info,
                ),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            resp = app.response_class(
                transcode_audio_stream(
                    lambda: gdrive_manager.stream_file_range(file_id, start=0, end=None),
                    internal_url=internal_url,
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
                gdrive_manager.stream_file_range(file_id, start=start, end=end),
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
                gdrive_manager.stream_file_range(file_id, start=0, end=None),
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
@auth.require_auth
def gdrive_upload():
    folder_id = request.args.get("folder","root")
    rel_path = (request.form.get("relative_path") or request.args.get("relative_path") or "").strip()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        gdrive_manager.upload_file(
            folder_id,
            f.filename,
            f.read(),
            f.content_type or "application/octet-stream",
            relative_path=rel_path or None,
        )
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/rename/<file_id>")
@auth.require_auth
def gdrive_rename(file_id):
    b = request.get_json(force=True) or {}
    new_name = (b.get("name") or b.get("new_name") or "").strip()
    if not new_name:
        return jsonify({"error": "New name is required"}), 400
    try:
        _gd_meta_cache.pop(file_id, None)
        gdrive_manager.rename_file(file_id, new_name)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/zip")
@auth.require_auth
def gdrive_zip():
    b = request.get_json(force=True) or {}
    ids = b.get("ids") or []
    if not ids:
        return jsonify({"error": "No file IDs provided"}), 400
    try:
        tmp_path, zip_size = gdrive_manager.create_zip_tmpfile(ids)
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
@auth.require_auth
def gdrive_delete(file_id):
    try:
        _gd_meta_cache.pop(file_id, None)
        gdrive_manager.delete_file(file_id)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/mkdir")
@auth.require_auth
def gdrive_mkdir():
    b = request.get_json(force=True) or {}
    try:
        fid = gdrive_manager.create_folder(b.get("parent","root"), b.get("name","New Folder"))
        return jsonify({"id": fid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Cross-Drive Transfer (SMB <-> Google Drive & SMB <-> SMB) ─────────────────
def _copy_smb_item_to_gdrive(src_share, smb_path, is_folder, dest_folder_id):
    name = smb_path.rstrip("/").split("/")[-1]
    if is_folder:
        new_folder_id = gdrive_manager.ensure_folder_path(dest_folder_id, [name])
        for child in smb_manager.browse(src_share, smb_path):
            _copy_smb_item_to_gdrive(
                src_share,
                child["path"],
                child["type"] == "folder",
                new_folder_id,
            )
    else:
        data = smb_manager.read_file_bytes(src_share, smb_path)
        mime = guess_media_mime(name)
        gdrive_manager.upload_file(dest_folder_id, name, data, mime)

def _copy_gdrive_item_to_smb(file_id, is_folder, dest_share, dest_smb_dir):
    meta = gdrive_manager.get_file_meta(file_id)
    name = meta["name"]
    target_path = dest_smb_dir.rstrip("/") + "/" + name
    if is_folder or meta["mimeType"] == "application/vnd.google-apps.folder":
        smb_manager.create_directory(dest_share, target_path)
        for child in gdrive_manager.list_files(file_id):
            _copy_gdrive_item_to_smb(
                child["id"],
                child["type"] == "folder",
                dest_share,
                target_path,
            )
    else:
        data, _, _ = gdrive_manager.download_file(file_id)
        smb_manager.upload_file(dest_share, target_path, data)

def _copy_smb_item_to_smb(src_share, smb_path, is_folder, dest_share, dest_smb_dir):
    name = smb_path.rstrip("/").split("/")[-1]
    target_path = dest_smb_dir.rstrip("/") + "/" + name
    if is_folder:
        smb_manager.create_directory(dest_share, target_path)
        for child in smb_manager.browse(src_share, smb_path):
            _copy_smb_item_to_smb(
                src_share,
                child["path"],
                child["type"] == "folder",
                dest_share,
                target_path,
            )
    else:
        data = smb_manager.read_file_bytes(src_share, smb_path)
        smb_manager.upload_file(dest_share, target_path, data)

def _copy_gdrive_item_to_gdrive(file_id, is_folder, dest_folder_id):
    meta = gdrive_manager.get_file_meta(file_id)
    name = meta["name"]
    if is_folder or meta["mimeType"] == "application/vnd.google-apps.folder":
        new_folder_id = gdrive_manager.ensure_folder_path(dest_folder_id, [name])
        for child in gdrive_manager.list_files(file_id):
            _copy_gdrive_item_to_gdrive(
                child["id"],
                child["type"] == "folder",
                new_folder_id,
            )
    else:
        data, _, mime = gdrive_manager.download_file(file_id)
        gdrive_manager.upload_file(dest_folder_id, name, data, mime)

@app.post("/api/transfer")
@auth.require_auth
def transfer_items():
    b = request.get_json(force=True) or {}
    src_type = b.get("src_type")
    src_drive = b.get("src_drive")
    dest_type = b.get("dest_type")
    dest_drive = b.get("dest_drive")
    dest_folder = b.get("dest_folder") or ("/" if dest_type == "smb" else "root")
    items = b.get("items") or []

    if not items:
        return jsonify({"error": "No items selected for transfer"}), 400

    try:
        copied = 0
        for item in items:
            is_folder = item.get("type") == "folder"
            if src_type == "smb" and dest_type == "gdrive":
                _copy_smb_item_to_gdrive(src_drive, item["path"], is_folder, dest_folder)
            elif src_type == "gdrive" and dest_type == "smb":
                _copy_gdrive_item_to_smb(item["id"], is_folder, dest_drive, dest_folder)
            elif src_type == "smb" and dest_type == "smb":
                _copy_smb_item_to_smb(src_drive, item["path"], is_folder, dest_drive, dest_folder)
            elif src_type == "gdrive" and dest_type == "gdrive":
                _copy_gdrive_item_to_gdrive(item["id"], is_folder, dest_folder)
            else:
                return jsonify({"error": "Invalid source or destination type"}), 400
            copied += 1
        return jsonify({"ok": True, "copied": copied})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── SMB Proxy Credentials ─────────────────────────────────────────────────────
@app.get("/api/smb/proxy-credentials")
@auth.require_auth
def get_smb_proxy_creds():
    creds_file = Path(os.environ.get("DATA_DIR", "/app/data")) / "smb_proxy_credentials.json"
    if creds_file.exists():
        d = json.loads(creds_file.read_text())
        return jsonify({"username": d.get("username", "sagedrive"), "configured": True})
    return jsonify({"username": "sagedrive", "configured": False})

@app.post("/api/smb/proxy-credentials")
@auth.require_auth
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
        return jsonify({"ok": True, "message": f"Credentials saved. Reconnect as '{username}'."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
