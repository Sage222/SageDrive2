import os, json, mimetypes, io, re, subprocess, threading
from pathlib import Path
from urllib.parse import quote
from flask import Flask, request, jsonify, send_file, send_from_directory, redirect
from flask_cors import CORS
import auth, smb_manager, gdrive_manager

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app, supports_credentials=True, expose_headers=["Content-Length", "Content-Range", "Accept-Ranges", "Content-Disposition"])
auth.bootstrap_admin()

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
}

def guess_media_mime(filename, fallback=None):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in MEDIA_MIMES:
        return MEDIA_MIMES[ext]
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
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        smb_manager.upload_file(share_id, dest.rstrip("/") + "/" + f.filename, f.read())
        return jsonify({"ok": True})
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
                as_attachment=bool(request.args.get("dl", True)),
                mimetype=mime or "application/octet-stream",
            )

        disposition = make_content_disposition(filename, bool(request.args.get("dl")))

        if request.args.get("transcode") == "1":
            resp = app.response_class(
                transcode_stream(gdrive_manager.stream_file_range(file_id, start=0, end=file_size - 1 if file_size > 0 else None)),
                status=200,
                mimetype="video/mp4",
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
                gdrive_manager.stream_file_range(file_id, start=0, end=file_size - 1 if file_size > 0 else None),
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
        return jsonify({"error": str(e)}), 500

@app.post("/api/gdrive/upload")
@auth.require_auth
def gdrive_upload():
    folder_id = request.args.get("folder","root")
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file provided"}), 400
    try:
        gdrive_manager.upload_file(folder_id, f.filename, f.read(),
                                   f.content_type or "application/octet-stream")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.delete("/api/gdrive/delete/<file_id>")
@auth.require_auth
def gdrive_delete(file_id):
    try:
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
    # Apply immediately — update the running smbd without full restart
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
