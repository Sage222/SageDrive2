#!/bin/bash
set -e

echo "=== SageDrive Startup ==="

# A) Generate Rclone config
python3 << 'PYEOF'
import json, os
from pathlib import Path

token_file = Path('/app/data/gdrive_token.json')
try:
    d = json.loads(token_file.read_text())
    rclone_token = json.dumps({
        "access_token": d.get("token", ""),
        "token_type": "Bearer",
        "refresh_token": d.get("refresh_token", ""),
        "expiry": "2020-01-01T00:00:00Z"
    })
    conf = f"""[gdrive]
type = drive
client_id = {d.get("client_id", "")}
client_secret = {d.get("client_secret", "")}
scope = drive
token = {rclone_token}
"""
    os.makedirs('/root/.config/rclone', exist_ok=True)
    with open('/root/.config/rclone/rclone.conf', 'w') as f:
        f.write(conf)
    print("✅ Rclone config written successfully!")
except FileNotFoundError:
    print("⚠️  gdrive_token.json not found — Google Drive not yet authenticated.")
except Exception as e:
    print(f"❌ Failed to write rclone config: {e}")
PYEOF

# B) Mount Google Drive via FUSE
mkdir -p /mnt/gdrive
if grep -q "refresh_token" /root/.config/rclone/rclone.conf 2>/dev/null; then
    echo "Mounting Google Drive..."
    rclone mount gdrive: /mnt/gdrive \
        --allow-other \
        --vfs-cache-mode writes \
        --vfs-cache-max-size 512M \
        --dir-cache-time 5m \
        --daemon
    sleep 3
    echo "✅ Google Drive mounted at /mnt/gdrive"
else
    echo "⚠️  Skipping rclone mount — no valid config."
fi

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
