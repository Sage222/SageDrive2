import os, json, time, mimetypes, io, re, subprocess, threading, tempfile, zipfile, requests
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
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

def transcode_stream(chunk_iterable):
    """
    Pipes raw media chunks from SMB/GDrive into ffmpeg and yields fragmented MP4
    for codecs/containers the browser cannot decode natively.
    """
    proc = subprocess.Popen(
        [
            "ffmpeg",
            "-hide_banner", "-loglevel", "error",
            "-i", "pipe:0",
            "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
            "-c:a", "aac", "-b:a", "160k",
            "-movflags", "frag_keyframe+empty_moov+default_base_moof",
            "-f", "mp4",
            "pipe:1",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=65536,
    )

    def feed_stdin():
        try:
            for chunk in chunk_iterable:
                if proc.poll() is not None:
                    break
                proc.stdin.write(chunk)
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    feeder = threading.Thread(target=feed_stdin, daemon=True)
    feeder.start()

    try:
        while True:
            out = proc.stdout.read(65536)
            if not out:
                break
            yield out
    finally:
        try:
            proc.kill()
        except Exception:
            pass

def transcode_audio_stream(chunk_iterable):
    """
    Pipes raw audio chunks from SMB/GDrive into ffmpeg and yields streaming MP3
    for audio codecs/containers the browser cannot decode natively.
    """
    proc = subprocess.Popen(
        [
            "ffmpeg",
            "-hide_banner", "-loglevel", "error",
            "-i", "pipe:0",
            "-vn",
            "-c:a", "libmp3lame", "-b:a", "192k",
            "-f", "mp3",
            "pipe:1",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        bufsize=65536,
    )

    def feed_stdin():
        try:
            for chunk in chunk_iterable:
                if proc.poll() is not None:
                    break
                proc.stdin.write(chunk)
        except Exception:
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:
                pass

    feeder = threading.Thread(target=feed_stdin, daemon=True)
    feeder.start()

    try:
        while True:
            out = proc.stdout.read(65536)
            if not out:
                break
            yield out
    finally:
        try:
            proc.kill()
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

@app.get("/api/smb/download/<share_id>")
@auth.require_auth
def smb_download(share_id):
    path = request.args.get("path", "")
    filename = path.split("/")[-1] or "download"
    try:
        file_size = smb_manager.get_file_size(share_id, path)
        disposition = make_content_disposition(filename, bool(request.args.get("dl")))

        if request.args.get("transcode") == "1":
            resp = app.response_class(
                transcode_stream(smb_manager.stream_file_range(share_id, path, start=0, length=file_size)),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            resp = app.response_class(
                transcode_audio_stream(smb_manager.stream_file_range(share_id, path, start=0, length=file_size)),
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
        smb_manager.delete_path(share_id, b.get("path",""), b.get("is_dir", False))
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

        if request.args.get("transcode") == "1":
            resp = app.response_class(
                transcode_stream(gdrive_manager.stream_file_range(file_id, start=0, end=None)),
                status=200,
                mimetype="video/mp4",
                direct_passthrough=True,
            )
            resp.headers["Cache-Control"] = "no-cache"
            resp.headers["Content-Disposition"] = disposition
            return resp

        if request.args.get("transcode") == "audio":
            resp = app.response_class(
                transcode_audio_stream(gdrive_manager.stream_file_range(file_id, start=0, end=None)),
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
