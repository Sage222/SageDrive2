#!/bin/bash
set -e

echo "=== SageDrive Startup ==="

# A) Generate multi-account Rclone config, mount scripts, and dynamic /etc/samba/smb.conf
python3 << 'PYEOF'
import json, os, re, subprocess
from pathlib import Path

data_dir = Path('/app/data')
accounts_file = data_dir / 'gdrive_accounts.json'
token_file = data_dir / 'gdrive_token.json'
config_file = data_dir / 'gdrive_client.json'

cfg = {}
if config_file.exists():
    try:
        cfg = json.loads(config_file.read_text())
    except Exception:
        cfg = {}

accounts = []
if accounts_file.exists():
    try:
        loaded = json.loads(accounts_file.read_text())
        if isinstance(loaded, list):
            accounts = loaded
    except Exception:
        pass

if not accounts and token_file.exists():
    try:
        legacy = json.loads(token_file.read_text())
        if legacy and (legacy.get("token") or legacy.get("refresh_token")):
            accounts = [{
                "id": "default",
                "name": "Google Drive",
                "custom_name": "",
                "email": legacy.get("email", ""),
                "smb_enabled": True,
                "smb_share_name": "GoogleDrive",
                "creds": legacy,
            }]
    except Exception:
        pass

def safe_rclone_id(raw_id):
    return re.sub(r"[^A-Za-z0-9_]", "_", str(raw_id or "default"))

def safe_share_name(raw_name, fallback="GoogleDrive"):
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(raw_name or "").strip()).strip("_-")
    if not cleaned or cleaned.lower() in {"global", "homes", "printers", "print$", "ipc$"}:
        cleaned = fallback
    return cleaned[:32]

rclone_blocks = []
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

os.makedirs('/root/.config/rclone', exist_ok=True)
os.makedirs('/mnt/gdrive_mounts', exist_ok=True)

for idx, acc in enumerate(accounts):
    d = acc.get("creds") or {}
    if not (d.get("token") or d.get("refresh_token")):
        continue
    rc_id = safe_rclone_id(acc.get("id", f"drive_{idx+1}"))
    rclone_token = json.dumps({
        "access_token": d.get("token", ""),
        "token_type": "Bearer",
        "refresh_token": d.get("refresh_token", ""),
        "expiry": "2020-01-01T00:00:00Z"
    })
    cid = d.get("client_id") or cfg.get("client_id", "")
    csec = d.get("client_secret") or cfg.get("client_secret", "")
    rclone_blocks.append(f"""[gdrive_{rc_id}]
type = drive
client_id = {cid}
client_secret = {csec}
scope = drive
token = {rclone_token}
""")
    if idx == 0:
        rclone_blocks.append(f"""[gdrive]
type = drive
client_id = {cid}
client_secret = {csec}
scope = drive
token = {rclone_token}
""")
    if bool(acc.get("smb_enabled", True)):
        share_name = safe_share_name(acc.get("smb_share_name") or ("GoogleDrive" if idx == 0 else f"GoogleDrive_{idx+1}"))
        mpath = f"/mnt/gdrive_mounts/{rc_id}"
        os.makedirs(mpath, exist_ok=True)
        smb_conf_lines.extend([
            f"[{share_name}]",
            f"   path = {mpath}",
            f"   comment = SageDrive - {acc.get('custom_name') or acc.get('name') or share_name}",
            "   valid users = @sambausers",
            "   writable = yes",
            "   browseable = yes",
            "   create mask = 0775",
            "   directory mask = 0775",
            "",
        ])

with open('/root/.config/rclone/rclone.conf', 'w') as f:
    f.write("\n".join(rclone_blocks))

with open('/etc/samba/smb.conf', 'w') as f:
    f.write("\n".join(smb_conf_lines))

mounted_count = 0
for idx, acc in enumerate(accounts):
    d = acc.get("creds") or {}
    if not bool(acc.get("smb_enabled", True)) or not (d.get("token") or d.get("refresh_token")):
        continue
    rc_id = safe_rclone_id(acc.get("id", f"drive_{idx+1}"))
    mpath = f"/mnt/gdrive_mounts/{rc_id}"
    subprocess.run([
        "rclone", "mount", f"gdrive_{rc_id}:", mpath,
        "--config", "/root/.config/rclone/rclone.conf",
        "--allow-other",
        "--buffer-size", "16M",
        "--vfs-read-chunk-size", "32M",
        "--vfs-cache-mode", "writes",
        "--vfs-cache-max-size", "512M",
        "--dir-cache-time", "5m",
        "--daemon"
    ], check=False)
    mounted_count += 1

print(f"✅ Configured {len(accounts)} Google Drive account(s) and mounted {mounted_count} SMB Proxy share(s).")
PYEOF
sleep 2

# C) Create Samba directories
echo "Preparing Samba directories..."
mkdir -p /run/samba /var/lib/samba/private /var/cache/samba /var/log/samba
chmod 755 /run/samba
chmod 700 /var/lib/samba/private

# D) Create Samba user from saved credentials
SMB_CREDS_FILE="/app/data/smb_proxy_credentials.json"
SMB_USER="sagedrive"
SMB_PASS="SageDrive123!"   # default fallback

if [ -f "$SMB_CREDS_FILE" ]; then
    SMB_USER=$(python3 -c "import json; d=json.load(open('$SMB_CREDS_FILE')); print(d.get('username','sagedrive'))")
    SMB_PASS=$(python3 -c "import json; d=json.load(open('$SMB_CREDS_FILE')); print(d.get('password','SageDrive123!'))")
    echo "✅ Loaded SMB credentials for user: $SMB_USER"
else
    echo "⚠️  No SMB credentials file found — using defaults (user: sagedrive, pass: SageDrive123!)"
    echo "    → Go to SageDrive Settings → SMB Proxy to set your own credentials."
fi

# Create the group and OS user (suppress errors if already exists)
groupadd -f sambausers
id "$SMB_USER" &>/dev/null || useradd -M -s /sbin/nologin -G sambausers "$SMB_USER"
usermod -aG sambausers "$SMB_USER" 2>/dev/null || true

# Set the Samba password
(echo "$SMB_PASS"; echo "$SMB_PASS") | smbpasswd -s -a "$SMB_USER"
echo "✅ Samba user '$SMB_USER' configured"

# E) Start Samba
echo "Starting Samba..."
smbd --foreground --no-process-group &
sleep 2

if grep -q ':01BD\|:01bd' /proc/net/tcp6 2>/dev/null || grep -q ':01BD\|:01bd' /proc/net/tcp 2>/dev/null; then
    echo "✅ Samba is listening on port 445"
else
    echo "⚠️  Samba may still be starting (pgrep: $(pgrep -c smbd || echo 0) smbd procs)"
fi

# F) Start SageDrive Flask app
echo "Starting SageDrive web interface on :8080..."
cd /app
exec python3 main.py
