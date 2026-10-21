# SageDrive

SageDrive is a self-hosted, browser-based file manager that gives you unified access to your SMB/NAS shares and Google Drive from a single clean interface.

It also allows you to create a SMB share for your Google Drive essentially forming a SMB proxy of Google Drive for consumption from other devices.

---

## Features

**File Browsing**
- Browse SMB shares (NAS, Windows shares) and Google Drive from the sidebar
- List and grid view modes
- Breadcrumb navigation with click-to-jump support
- Files sorted with folders first, then alphabetically

**File Management**
- Upload files via drag & drop or file picker
- Create new folders
- Delete files and folders
- Download any file with authenticated streaming

**Media Playback**
- Click any video file (mp4, webm, mkv, mov, m4v, ogg) to play it directly in the browser
- Click any audio file (mp3, wav, flac, m4a, aac, opus, ogg) to play it in the browser
- Full seek bar support with range request streaming — works on large files
- Download button available inside the player

**Authentication**
- Username/password login with bcrypt hashed passwords
- Session-based Bearer token auth
- Configurable session TTL
- Auto-logout on token expiry

**Google Drive**
- OAuth2 integration with your own Client ID and Secret
- Browse, upload, download and delete Google Drive files and folders

**Settings**
- Add and remove multiple SMB shares
- Configure Google Drive OAuth credentials
- Connect/disconnect Google Drive
- Light and dark theme toggle

### Self-Hosted & Private
All file access is proxied through your own server — no data touches any third-party service. Designed to run behind your home network or VPN.

### Tech Stack
- **Backend:** Python, Flask, pysmb, Google Drive API
- **Frontend:** Single-file vanilla JS SPA, Lucide icons
- **Deployment:** Docker, Docker Compose

---

## Setup & Installation

### Requirements
- Docker and Docker Compose installed on your host
- Ports 8080 and 445 available

### 1. Clone the repo

```bash
git clone https://github.com/Sage222/SageDrive.git
cd SageDrive
```

### 2. Configure environment variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your_strong_random_secret
ADMIN_USER=admin
ADMIN_PASS=your_admin_password
SESSION_TTL_HOURS=24
```

> **Never use default credentials in production.** Generate a strong `SECRET_KEY` with:
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```

### 3. Start the container

```bash
docker compose up -d
```

SageDrive will be available at `http://your-host:8080`

### 4. Log in

Use the `ADMIN_USER` and `ADMIN_PASS` values from your `.env` file.

---

## Adding an SMB Share

1. Go to **Settings** in the sidebar
2. Click **Add Share**
3. Fill in the details:
   - **Name** — a friendly label shown in the sidebar (e.g. `My NAS`)
   - **Host** — IP address or hostname of your NAS/server (e.g. `10.0.0.10`)
   - **Share** — the SMB share name (e.g. `Media`, not the full path)
   - **Username / Password** — credentials for the SMB share
   - **Port** — default is `445`, change only if your NAS uses a non-standard port
4. Click **Save** — the share appears in the sidebar immediately

### SMB Tips
- On most home NAS devices (Synology, QNAP, TrueNAS) you enable SMB under File Services or Network settings
- The share name is the top-level share, not a subfolder path — browse into subfolders from within SageDrive
- If connection fails, confirm the host is reachable: `ping your-nas-ip` and `nc -zv your-nas-ip 445`

---

## Google Drive Setup

Google Drive access uses OAuth2 with your own Google Cloud credentials, so your files are never routed through any third party.

### 1. Create a Google Cloud project

1. Go to [https://console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project (or select an existing one)
3. Go to **APIs & Services → Library**
4. Search for and enable **Google Drive API**

### 2. Create OAuth credentials

1. Go to **APIs & Services → Credentials**
2. Click **Create Credentials → OAuth 2.0 Client ID**
3. Set Application type to **Web application**
4. Under **Authorised redirect URIs**, add:
Replace `your-host` with your actual IP or domain
5. Click **Create** and copy your **Client ID** and **Client Secret**

### 3. Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen**
2. Set User type to **External** (or Internal if using Google Workspace)
3. Fill in app name and your email
4. Under **Scopes**, add `https://www.googleapis.com/auth/drive`
5. Under **Test users**, add your Google account email

### 4. Connect in SageDrive

1. Open **Settings** in SageDrive
2. Paste your **Client ID**, **Client Secret**, and set the **Redirect URI** to match what you entered in Google Cloud:
3. Click **Save Configuration**
4. Click **Connect Google Drive** — you will be redirected to Google to authorise access
5. After authorising, you are redirected back and Google Drive appears in the sidebar

### Google Drive Tips
- If you see an "app not verified" warning during OAuth, click **Advanced → Go to app** — this is normal for self-hosted apps in test mode
- The OAuth token is stored in memory and will be lost on container restart — you will need to reconnect after a restart. To persist it, ensure `sagedrive-data` volume is retained between restarts (it is by default with Docker named volumes)
- If your SageDrive is only accessible on your LAN, use your LAN IP in the redirect URI (e.g. `http://10.0.0.152:8080/api/gdrive/callback`)

---

## Updating

```bash
cd /opt/SageDrive
git pull
docker compose down && docker compose up -d --build
```

---

## Data & Persistence

All application data (SMB share configs, user accounts, Google Drive tokens) is stored in the `sagedrive-data` Docker named volume, which persists across container restarts and rebuilds.

To back it up:
```bash
docker run --rm -v sagedrive-data:/data -v $(pwd):/backup alpine tar czf /backup/sagedrive-backup.tar.gz /data
```

To restore:
```bash
docker run --rm -v sagedrive-data:/data -v $(pwd):/backup alpine tar xzf /backup/sagedrive-backup.tar.gz -C /
```
