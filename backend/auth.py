import json, os, time, math, secrets, bcrypt
from pathlib import Path
from functools import wraps
from flask import request, jsonify

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
SESSIONS: dict = {}
SESSION_TTL = int(os.environ.get("SESSION_TTL_HOURS", "24")) * 3600

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60  # 15 minutes (900 seconds)
_UNKNOWN_LOCKOUTS: dict = {}

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

def login_with_status(username, password):
    """
    Authenticates a user with anti-hammering protection:
    5 incorrect login attempts locks the account for 15 minutes (900s).
    Returns (token, error_msg, http_status, meta_dict).
    """
    uname = (username or "").strip()
    now = time.time()
    users = _load_users()
    user = users.get(uname)

    record = user if user is not None else _UNKNOWN_LOCKOUTS.setdefault(uname or "_anon_", {"failed_attempts": 0, "locked_until": 0})
    locked_until = float(record.get("locked_until", 0) or 0)

    if locked_until > now:
        rem = int(math.ceil(locked_until - now))
        mins = max(1, int(math.ceil(rem / 60)))
        msg = f"Account locked due to {MAX_FAILED_ATTEMPTS} failed login attempts. Try again in {mins} minute{'s' if mins != 1 else ''} ({rem}s)."
        return None, msg, 429, {"locked": True, "retry_after": rem, "attempts_remaining": 0}

    if locked_until > 0 and locked_until <= now:
        record["locked_until"] = 0
        record["failed_attempts"] = 0
        if user is not None:
            _save_users(users)

    if user and bcrypt.checkpw((password or "").encode(), user["hash"].encode()):
        if user.get("failed_attempts") or user.get("locked_until"):
            user["failed_attempts"] = 0
            user["locked_until"] = 0
            _save_users(users)
        token = secrets.token_hex(32)
        SESSIONS[token] = {"username": uname, "role": user["role"], "expires": now + SESSION_TTL}
        return token, None, 200, {"locked": False, "attempts_remaining": MAX_FAILED_ATTEMPTS}

    fails = int(record.get("failed_attempts", 0) or 0) + 1
    record["failed_attempts"] = fails

    if fails >= MAX_FAILED_ATTEMPTS:
        record["locked_until"] = now + LOCKOUT_SECONDS
        if user is not None:
            _save_users(users)
        msg = f"Account locked for 15 minutes due to {MAX_FAILED_ATTEMPTS} incorrect login attempts."
        return None, msg, 429, {"locked": True, "retry_after": LOCKOUT_SECONDS, "attempts_remaining": 0}

    if user is not None:
        _save_users(users)
    rem_tries = MAX_FAILED_ATTEMPTS - fails
    msg = f"Invalid credentials ({rem_tries} attempt{'s' if rem_tries != 1 else ''} remaining before 15m lockout)"
    return None, msg, 401, {"locked": False, "attempts_remaining": rem_tries}

def login(username, password):
    token, _, _, _ = login_with_status(username, password)
    return token

def logout(token):
    SESSIONS.pop(token, None)

def get_session(token):
    s = SESSIONS.get(token)
    if s and s["expires"] > time.time():
        return s
    SESSIONS.pop(token, None)
    return None

VALID_THEMES = {"obsidian", "midnight", "amethyst", "emerald", "ember"}
DEFAULT_THEME = "obsidian"

def get_user_theme(username):
    users = _load_users()
    user = users.get((username or "").strip()) or {}
    theme = str(user.get("theme") or DEFAULT_THEME).strip().lower()
    if theme == "dark":
        theme = DEFAULT_THEME
    return theme if theme in VALID_THEMES else DEFAULT_THEME

def set_user_theme(username, theme):
    uname = (username or "").strip()
    clean_theme = str(theme or DEFAULT_THEME).strip().lower()
    if clean_theme not in VALID_THEMES:
        raise ValueError(f"Invalid theme '{theme}'. Choose from: {', '.join(sorted(VALID_THEMES))}")
    users = _load_users()
    if uname not in users:
        raise ValueError("User not found")
    users[uname]["theme"] = clean_theme
    _save_users(users)
    for sess in SESSIONS.values():
        if sess.get("username") == uname:
            sess["theme"] = clean_theme
    return clean_theme

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

