import json, os, time, secrets, bcrypt
from pathlib import Path
from functools import wraps
from flask import request, jsonify

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
SESSIONS: dict = {}
SESSION_TTL = int(os.environ.get("SESSION_TTL_HOURS", "24")) * 3600

def _load_users():
    return json.loads(USERS_FILE.read_text()) if USERS_FILE.exists() else {}

def _save_users(u):
    USERS_FILE.write_text(json.dumps(u, indent=2))

def bootstrap_admin():
    if not _load_users():
        u = os.environ.get("ADMIN_USER", "admin")
        p = os.environ.get("ADMIN_PASS", "changeme")
        h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
        _save_users({u: {"hash": h, "role": "admin"}})

def login(username, password):
    user = _load_users().get(username)
    if user and bcrypt.checkpw(password.encode(), user["hash"].encode()):
        token = secrets.token_hex(32)
        SESSIONS[token] = {"username": username, "role": user["role"], "expires": time.time() + SESSION_TTL}
        return token
    return None

def logout(token):
    SESSIONS.pop(token, None)

def get_session(token):
    s = SESSIONS.get(token)
    if s and s["expires"] > time.time():
        return s
    SESSIONS.pop(token, None)
    return None

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            token = request.args.get("token", "").strip()
        if not token:
            token = request.cookies.get("sd_token", "")
        if not get_session(token):
            return jsonify({"error": "Unauthorised"}), 401
        return f(*args, **kwargs)
    return wrapper
