# SageDrive — OneDrive Integration, Embedded Subtitles & Fullscreen HUD Audio/CC Controls

## 1. Overview
Based on your selections, we will implement three cohesive upgrades across SageDrive (`backend/`, `server.js`, `frontend/public/index.html`, and `README.md`):

1. **Full Microsoft OneDrive Integration + SMB Proxy Sharing**
   - Multi-account Microsoft OneDrive support (Personal & Work/School via Microsoft Graph API v1.0 OAuth2) with full parity alongside Google Drive and SMB shares.
   - Expose connected OneDrive accounts as local Samba network shares through the **rclone + Samba SMB Proxy** right alongside Google Drives.
2. **Embedded MKV / MP4 Subtitle Stream Support**
   - Detect embedded text-based subtitle streams (`subrip`/`srt`, `ass`/`ssa`, `webvtt`, `mov_text`) via `ffprobe` and convert them on the fly to WebVTT via FFmpeg, keeping subtitle timing accurately synchronized across server-side seeks (`?ss=`).
3. **Audio & Subtitle Track Selectors inside the Fullscreen HUD**
   - Add dedicated **Audio Track** and **Subtitles (CC)** selectors directly into the auto-hiding Fullscreen HUD overlay (synced with the modal control bar) so you can switch languages and captions without leaving fullscreen mode.

---

## 2. Detailed Architecture & Changes

### A. Microsoft OneDrive Integration (`backend/onedrive_manager.py`, `backend/main.py`, `server.js`, `frontend/public/index.html`)
- **Multi-Account OAuth2 & Storage (`backend/onedrive_manager.py`):**
  - Store Microsoft Entra / Azure App credentials (`client_id`, `client_secret`, `redirect_uri`, `tenant_id` defaulting to `common`) in `/data/onedrive_config.json` and connected accounts in `/data/onedrive_accounts.json`.
  - Automatic OAuth2 token refresh (`offline_access`, `Files.ReadWrite.All`, `User.Read`) with access token caching and Drive quota lookup (`used`, `total`, `remaining`).
  - Full file & folder operations via Microsoft Graph API v1.0:
    - List folder items (`root` or `items/{item_id}/children`) with pagination, sorting, MIME type detection, and parent breadcrumb resolution.
    - Create folders, rename items, delete items, and read/write UTF-8 text & config files in the browser editor.
    - **Chunked Streaming Uploads (`createUploadSession`):** Stream arbitrarily large file uploads in chunks directly to OneDrive without buffering the entire file in RAM.
    - **HTTP Range Downloads & Media Streaming:** Stream byte ranges directly from OneDrive's pre-authenticated download URL or through the internal HTTP Range media proxy (`_InternalMediaRangeHandler`) so FFmpeg can seek (`-ss`), remux, and transcode OneDrive videos identically to Google Drive and SMB.
- **Cross-Drive Transfers (`SMB ↔ Google Drive ↔ OneDrive`):**
  - Extend the cross-drive transfer engine (`/api/transfer/copy` and Move workflow) to support `onedrive` as both a source and destination across all connected storage types.
- **OneDrive in the SMB Proxy (`backend/proxy_manager.py` & `server.js`):**
  - Extend `ProxyManager` so connected OneDrive accounts are written as `[onedrive_<id>]` sections (`type = onedrive`, `drive_id`, `drive_type`, OAuth token JSON) in `rclone.conf`, mounted via FUSE under `/mnt/gdrive/<share_name>`, and exported as Samba shares in `smb.conf`.
  - Allow toggling SMB Proxy exposure per OneDrive account (`proxy_enabled`) and renaming the exported share name via right-click or Settings.
- **Settings & Sidebar UI (`frontend/public/index.html`):**
  - Add a **OneDrive** section in the left sidebar (with account storage bars, right-click rename, and quick-add button).
  - Add **OneDrive** and **OneDrive OAuth** management in the Settings modal (alongside Google Drives, SMB, Google OAuth, SMB Proxy, and Security & About), including a step-by-step Azure App Registration setup guide.

### B. Embedded MKV / MP4 Subtitle Support (`backend/main.py`, `server.js`, `frontend/public/index.html`)
- **`ffprobe` Subtitle Stream Inspection:**
  - Extend `_analyze_probe_data()` in `backend/main.py` and `probeMediaItem()` in `server.js` to extract all text-based embedded subtitle streams (`subrip`, `srt`, `ass`, `ssa`, `webvtt`, `mov_text`, `text`) with metadata:
    - `subtitle_index` (0-based subtitle stream index for `-map 0:s:<idx>`)
    - `stream_index`
    - `codec`
    - `language` (e.g., `eng`, `jpn`, `spa`)
    - `title` (e.g., `English [Full]`, `Forced`, `SDH`)
- **On-the-Fly WebVTT Subtitle Extraction Endpoints:**
  - Add `/api/smb/subtitles/<share_id>`, `/api/gdrive/subtitles/<file_id>`, and `/api/onedrive/subtitles/<item_id>` taking `?track=<subtitle_index>&ss=<seek_offset>`.
  - Run `ffmpeg -ss <seek_offset> -i <internal_range_url> -map 0:s:<track> -f webvtt pipe:1` so embedded SRT/ASS/SSA/MOV_TEXT tracks are converted cleanly to `text/vtt` on the fly with timestamps automatically aligned to the active playback offset (`state.seekOffset`), ensuring subtitles stay in sync even after jumping forward/backward on remuxed MKV/MP4 streams.

### C. Audio & Subtitle Selectors in Fullscreen HUD (`frontend/public/index.html`)
- **Modal Bar + Fullscreen HUD Synchronization:**
  - Add a **Subtitles (CC)** dropdown (`Off` + detected embedded subtitle tracks) next to the **Audio Track** selector in both the bottom modal player bar and the floating **Fullscreen HUD** (`#video-stage-hud`).
  - Include the **Audio Track** dropdown inside the Fullscreen HUD whenever `probe.audio_streams.length > 1`.
  - Switching either the Audio Track or Subtitle Track from either control bar updates both selectors immediately and applies the selected track at the exact current playback position.

### D. Documentation (`README.md`)
- Update `README.md` with complete documentation for Microsoft OneDrive setup (Azure App Registration & OAuth scopes), OneDrive SMB Proxy sharing, embedded MKV/MP4 subtitle support, and the Fullscreen HUD audio/subtitle controls.
