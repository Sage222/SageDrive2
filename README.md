# SageDrive (v1.0)

SageDrive is a self-hosted, browser-based file manager that gives you unified access to multiple SMB/NAS shares and multiple Google Drive accounts from a single clean, responsive interface.

It also allows you to create an SMB share for your Google Drive, essentially forming an SMB proxy of Google Drive (`rclone` + Samba) for consumption from other devices on your network.

Repository: [https://github.com/Sage222/SageDrive2](https://github.com/Sage222/SageDrive2)

---

## Features

### Multi-Storage & Custom Naming
- **Multiple SMB Shares:** Add, browse, and manage any number of SMB/NAS shares simultaneously with automatic unique ID generation.
- **Multiple Google Drives:** Connect and switch between multiple Google Drive accounts simultaneously (`gdrive_accounts.json`), with automatic migration from single-account tokens.
- **Right-Click Custom Names:** Right-click (or tap `⋯` on mobile/tablet) any SMB share or Google Drive in the sidebar to set a custom display name, open it, or manage/disconnect it. Custom names appear across the sidebar, header, transfer modal, and Settings while preserving the underlying host/share path or Google account email as a subtitle.

### File Browsing & Responsive UI
- **Unified Sidebar:** Browse all connected SMB shares and Google Drives from a collapsible sidebar (`[` shortcut or toggle button).
- **Tablet & Mobile Ready:** Slide-over navigation drawer, touch-friendly controls, and adaptive layouts for phones, tablets, and desktops.
- **List & Grid Views with Sorting:** Switch between detailed list view and visual grid view, and sort files and folders by **Name**, **Date**, or **Size** (ascending or descending) using either the topbar sort controls or clickable column headers (`Name`, `Size`, `Modified`) in list view (folders always stay grouped at the top).
- **Breadcrumb Navigation:** Clickable path breadcrumbs for instant directory jumping.

### Advanced File Management
- **Right-Click Context Menus:** Right-click any file or folder for quick actions (Open/Preview, Edit Text/Config, Download, Rename, Copy to…, Move to…, Delete).
- **In-Browser Text & Config File Editor:** View, edit, and save text, code, and configuration files (`.txt`, `.md`, `.json`, `.yaml`, `.yml`, `.xml`, `.csv`, `.ini`, `.conf`, `.toml`, `.py`, `.sh`, `.js`, `.ts`, `.css`, `.html`, `.env`, `.log`, etc.) directly in the browser on both SMB shares and Google Drive accounts, complete with `Ctrl+S` / `Cmd+S` save shortcut, `Tab` indentation, word-wrap toggle, and unsaved change indicators.
- **In-Place Rename:** Rename files and folders directly on both SMB shares and Google Drive.
- **Copy & Move Files/Folders (Same-Drive & Cross-Drive):**
  - **Move Within the Same Drive:** Instant server-side move across folders on the same SMB share (`c.rename`) or the same Google Drive account (`addParents`/`removeParents`).
  - **Cross-Drive Copy & Move (SMB ↔ Google Drive):** Copy or move files and entire nested folders between any SMB share and any connected Google Drive account (or between two SMB shares / two Google Drives) right from the UI.
- **Multi-Select & Batch Operations:** Select multiple items with checkboxes or `Select All` to perform **Batch Copy**, **Batch Move**, **Batch Delete**, or **Batch ZIP Download** (streams a dynamically created `.zip` archive of selected files and folders).
- **Zero-RAM Streaming Uploads & Drag-and-Drop Folders:** Drag and drop individual files or entire nested folder structures directly into the browser; uploads stream directly from the request stream to SMB (`storeFile`) or Google Drive resumable upload chunks (`8MB` chunks) without buffering the full file in container RAM.
- **Progress Tracking:** Real-time upload and download progress bar with transfer speeds and automatic browser save prompts.

### Media Playback & Inline Preview
- **Default Inline Open:** Clicking any supported video, audio, image, PDF, or text/code file opens it directly in the browser without forcing a download.
- **Video & Audio Streaming:** Stream full-length video (`mp4`, `webm`, `mkv`, `mov`, `m4v`, `avi`, `ts`, `ogg`) and audio (`mp3`, `wav`, `flac`, `m4a`, `aac`, `opus`, `ogg`) with HTTP Range request seeking and automatic byte-accurate stream resume on both SMB (`timeout=14400` with reconnect-at-offset) and Google Drive.
- **Automatic Audio Transcoding (EAC3 / AC3 / DTS / TrueHD) with Full Duration & Seeking:** Built-in FFmpeg stream remuxing automatically detects browser-incompatible audio codecs (such as Dolby Digital Plus `eac3`, `ac3`, `dts`) and live-transcodes the audio track to stereo AAC on the fly while copying the H.264/HEVC video stream untouched (`-c:v copy -c:a aac`). The fragmented MP4 `moov` header (`mvhd`, `tkhd`, `mdhd`, `mehd`) is dynamically patched with the probed container/stream duration so long videos display their full duration immediately and support instant seeking (`?ss=`) across the entire timeline.
- **Media Player Controls, Skip Forward/Backward, `1.1x` Speed & Fullscreen Zoom:**
  - **Skip Forward & Backward:** Skip `-30s`, `-10s`, `+10s`, or `+30s` using dedicated buttons, keyboard shortcuts (`ArrowLeft` / `ArrowRight`, `Shift+ArrowLeft` / `Shift+ArrowRight`, `J` / `L`), or the interactive full-duration timeline scrubber (both in normal view and Fullscreen mode).
  - **Playback Speeds (including `1.1x`):** Adjust playback speed across `0.5x`, `0.75x`, `1x`, `1.1x`, `1.25x`, `1.5x`, and `2x`.
  - **Fullscreen Zoom (`100%`, `110%`, `120%`, `130%`):** Scale video playback to `100%`, `110%`, `120%`, or `130%` directly inside Fullscreen mode (with an auto-hiding Fullscreen HUD overlay) or from the modal control bar.
  - **Playlist & Audio Tracks:** Switch between multi-language audio tracks and navigate Next/Previous tracks across the current folder playlist.
- **Image Gallery & Document Viewer:** Inline high-resolution image lightbox with next/prev navigation, plus inline preview/editor for PDFs and text/code/markdown/config files.

### Security & Authentication
- **Anti-Hammering Login Lockout:** Protects against brute-force attacks by tracking failed login attempts. After **5 consecutive failed login attempts**, the account is automatically locked out for **15 minutes** with a live countdown timer on the sign-in screen.
- **Path Traversal Guard:** All SMB file and directory operations strictly normalize paths and reject `..` traversal segments and null bytes.
- **Hardened Session Management:** Username/password authentication with `bcrypt` hashed passwords, `HttpOnly` + `SameSite=Lax` session cookies, Bearer token sessions, full session revocation on logout, and configurable session TTL.

### Tidied Settings Page & Multi-Drive SMB Proxy
- **Dedicated Category Tabs:** Organized into **Google Drives**, **SMB**, **Google OAuth**, **SMB Proxy**, and **Security & About** tabs for clean, focused configuration.
- **Dedicated Google Drives & SMB Tabs:** Manage connected Google Drive accounts and SMB/NAS shares in their own dedicated tabs with inline custom name editing, status badges, and quick **+ Add** buttons.
- **Google OAuth Credentials:** Configure and copy your Google OAuth Client ID, Client Secret, and Authorized Redirect URI in the **Google OAuth** tab.
- **Multi-Drive Google Drive SMB Proxy:**
  - **Separate Network Share per Google Drive:** Expose each connected Google Drive account as its own independent Samba network share (`\\<host>\<ShareName>`) on port `445` via `rclone` FUSE mounts (`/mnt/gdrive_mounts/<account_id>`).
  - **Per-Drive Enable/Disable Toggle:** Turn the SMB Proxy share on or off individually for each connected Google Drive in **Settings → SMB Proxy**.
  - **Custom SMB Share Names:** Assign a custom network share name (e.g. `GoogleDrive`, `PersonalDrive`, `WorkDrive`) per Google Drive in **Settings → SMB Proxy**, complete with per-drive one-click UNC path and PowerShell `net use` command copy buttons.
  - **Live Mount, Memory Tuning & Samba Reload:** Adding, toggling, or renaming a Google Drive's SMB share dynamically reconciles `rclone` mounts (`/mnt/gdrive_mounts/<account_id>` with bounded `--buffer-size 16M` and `--vfs-read-chunk-size 32M`), unmounts any legacy single-drive `/mnt/gdrive` mount at startup, rewrites `/etc/samba/smb.conf`, and reloads Samba (`smbd`) on the fly without requiring a Docker image rebuild or container restart.

### Tech Stack
- **Backend:** Python, Flask, `pysmb`, Google Drive API v3, `ffmpeg` (live audio remuxing), `rclone` + Samba
- **Frontend:** Single-file vanilla JS SPA, Lucide icons, responsive CSS with light & dark themes
- **Deployment:** Docker & Docker Compose (`1G` container memory limit tuned for multi-drive FUSE & FFmpeg remuxing)

---

## Setup & Installation

### Requirements
- Docker and Docker Compose installed on your host
- Ports `8080` (Web UI) and `445` (optional SMB Proxy) available

### 1. Clone the repo

```bash
git clone https://github.com/Sage222/SageDrive2.git
cd SageDrive2
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
*(Note: 5 incorrect login attempts will lock the account for 15 minutes.)*

---

## Adding & Naming SMB Shares

1. Go to **Settings → SMB**
2. Click **+ Add Share**
3. Fill in the details:
   - **Display Name** — a friendly label shown in the sidebar (e.g. `Media NAS`)
   - **Host / IP** — IP address or hostname of your NAS/server (e.g. `10.0.0.10`)
   - **Share Name** — the top-level SMB share name (e.g. `Media`, not a subfolder path)
   - **Username / Password** — credentials for the SMB share (leave blank for guest shares)
   - **Port** — default is `445`
4. Click **Add Share** — the share appears in the sidebar immediately.
5. **Custom Rename:** Right-click any SMB share in the sidebar (or click the edit icon on its card in **Settings**) at any time to give it a custom display name.

---

## Connecting Multiple Google Drives

Google Drive access uses OAuth2 with your own Google Cloud credentials, so your files are never routed through any third party. Once OAuth credentials are saved once, you can connect as many Google Drive accounts as you like.

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
   ```text
   http://your-host:8080/api/gdrive/callback
   ```
   *(Replace `your-host:8080` with your actual IP/hostname and port)*
5. Click **Create** and copy your **Client ID** and **Client Secret**

### 3. Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen**
2. Set User type to **External** (or Internal if using Google Workspace)
3. Fill in app name and your email
4. Under **Scopes**, add `https://www.googleapis.com/auth/drive`
5. Under **Test users**, add the Google account emails you plan to connect

### 4. Connect Accounts in SageDrive

1. Open **Settings → Google OAuth** in SageDrive
2. Paste your **Client ID**, **Client Secret**, and **Redirect URI**, then click **Save Credentials**
3. Click **+ Add Google Drive** (in Settings or under Google Drives)
4. Enter an optional custom label (e.g. `Personal Drive` or `Work Backup`) and continue to Google to select and authorise your account
5. Repeat **+ Add Google Drive** at any time to link additional Google Drive accounts. Right-click any Google Drive in the sidebar to rename or disconnect it.

---

## Multi-Drive SMB Proxy Setup

Each connected Google Drive can be exposed on your local network as its own SMB share on port `445`:

1. Go to **Settings → SMB Proxy**
2. For each connected Google Drive:
   - Use the **SMB Enabled** toggle switch to turn network sharing on or off for that specific drive.
   - Set a **Custom SMB Share Name** (e.g. `PersonalDrive`, `WorkDrive`, `GoogleDrive`) and click **Apply Name**.
   - Click **UNC** or **PowerShell** to copy the exact `\\<host>\<ShareName>` path or `net use` command for that drive.
3. Under **Samba Authentication Credentials**, set the Windows SMB username and password used to authenticate when mapping your drives.

---

## Updating

```bash
cd /opt/SageDrive2
git pull
docker compose down && docker compose up -d --build
```

---

## Data & Persistence

All application data (`users.json`, `smb_shares.json`, `gdrive_accounts.json`, `gdrive_config.json`, and SMB proxy state) is stored in the `sagedrive-data` Docker named volume (`/data`), which persists across container restarts and rebuilds.

To back it up:
```bash
docker run --rm -v sagedrive-data:/data -v $(pwd):/backup alpine tar czf /backup/sagedrive-backup.tar.gz /data
```

To restore:
```bash
docker run --rm -v sagedrive-data:/data -v $(pwd):/backup alpine tar xzf /backup/sagedrive-backup.tar.gz -C /
```
