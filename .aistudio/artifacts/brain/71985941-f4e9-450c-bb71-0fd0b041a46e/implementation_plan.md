# Security, Feature & Performance Upgrades Plan

## 1. Security: Path Traversal Guard & Session Cookie Hardening
- **SMB Path Normalization & Traversal Protection (`backend/main.py` & `backend/smb_manager.py`)**:
  - Add a path sanitizer (`_sanitize_smb_path`) that normalizes slashes, rejects null bytes and `..` path traversal segments across all SMB endpoints (`browse`, `download`, `upload`, `rename`, `delete`, `mkdir`, `zip`, `probe`, and `transfer`).
- **Session Cookie & Auth Hardening (`backend/main.py` & `backend/auth.py`)**:
  - Set `httponly=True` and `samesite="Lax"` on the `sd_token` cookie in `/api/auth/login`.
  - Update `/api/auth/logout` to revoke sessions whether the token is passed via `Authorization` header, `sd_token` cookie, or query parameter.
  - Remove the plaintext `LOGIN DEBUG` console log from `/api/auth/login`.

## 2. Feature: In-Browser Text & Config File Editor
- **Backend Save Endpoints (`backend/main.py`, `backend/smb_manager.py`, `backend/gdrive_manager.py`, `server.js`)**:
  - Add `PUT /api/smb/content/<share_id>` to write updated UTF-8 text content directly to an existing or new file on an SMB share.
  - Add `PUT /api/gdrive/content/<file_id>` (with `account_id` support) to update file contents in-place on Google Drive (`files().update` with `MediaIoBaseUpload`) while preserving the file ID and parent folder.
- **Frontend Editor Modal (`frontend/public/index.html`)**:
  - Upgrade the text/code preview modal with an **Edit / Save** workflow: toggle between read-only view and an editable code/text area (supporting `Tab` indentation, `Ctrl+S` / `Cmd+S` shortcut, unsaved changes indicator, line wrap toggle, and instant save toast feedback).

## 3. Feature: Move Files & Folders in Context Menu
- **Backend Move Support (`backend/main.py`, `backend/smb_manager.py`, `backend/gdrive_manager.py`, `server.js`)**:
  - Extend `/api/transfer` (and add `/api/move`) to support `operation: "move"` (`copy` vs `move`):
    - **Same SMB Share**: Uses native SMB server-side `rename` (`c.rename(share, old_path, new_path)`) for instant zero-copy moves across folders on the same share.
    - **Same Google Drive Account**: Uses native Google Drive API parent reassignment (`files().update(fileId=..., addParents=dest_folder_id, removeParents=old_parents)`) for instant moves.
    - **Cross-Drive / Cross-Share Move (SMB ↔ Google Drive or Share A ↔ Share B)**: Performs a verified recursive transfer to the destination and then deletes the source file/folder only after transfer completion succeeds.
- **Frontend Context Menu & Transfer Modal (`frontend/public/index.html`)**:
  - Add **Move to…** right next to **Copy to…** in the file/folder right-click context menu.
  - Update the Transfer modal to support switching between **Copy** and **Move**, including same-drive folder selection so files/folders can be moved to another folder on the same drive or to a different drive.

## 4. Performance: Zero-RAM Streaming Uploads & Docker/Rclone Tuning
- **Streaming File Uploads (`backend/main.py`, `backend/smb_manager.py`, `backend/gdrive_manager.py`)**:
  - Replace `f.read()` in `/api/smb/upload/<share_id>` and `/api/gdrive/upload` with direct stream forwarding (`f.stream`) so multi-gigabyte uploads stream directly to SMB (`storeFile`) or Google Drive resumable upload chunks (`MediaIoBaseUpload(..., chunksize=8*1024*1024, resumable=True)`) without buffering the entire file in container RAM.
- **Docker Compose & Rclone Memory Tuning (`docker-compose.yml`, `backend/main.py`, `entrypoint.sh`)**:
  - Increase the container memory limit in `docker-compose.yml` from `256M` to `1G`.
  - Add `--buffer-size 16M` and `--vfs-read-chunk-size 32M` to `rclone mount` in `backend/main.py` and `entrypoint.sh` to keep FUSE memory consumption bounded across multiple mounted Google Drives.
- **Documentation (`README.md`)**:
  - Document the new in-browser file editor, Move functionality, streaming upload architecture, and security/memory improvements in `README.md`.
