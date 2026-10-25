# Fix `NameError: name 'shutil' is not defined` in SMB Proxy Reconciliation

## Root Cause
During startup and SMB Proxy reconciliation (`_reconcile_smb_proxy`), `backend/main.py` calls `shutil.which(...)` to detect `rclone`, `fusermount`, `umount`, `smbcontrol`, and `pkill`. However, `shutil` was omitted from the top-level imports in `backend/main.py` (it had only been imported locally inside the `ffprobe`/`ffmpeg` helper functions), causing `_reconcile_smb_proxy()` to raise `NameError: name 'shutil' is not defined` before it could mount `/mnt/gdrive_mounts/<id>` and reload Samba.

## Proposed Changes
1. **Top-Level `shutil` Import (`backend/main.py`)**:
   - Add `shutil` to the top-level standard library import statement on line 1 of `backend/main.py`.
2. **Explicit Rclone Config Flag & Legacy Mount Takeover (`backend/main.py` & `entrypoint.sh`)**:
   - Pass `--config /root/.config/rclone/rclone.conf` explicitly when invoking `rclone mount` in `_reconcile_smb_proxy()` and `entrypoint.sh` so `rclone` always reads the generated multi-drive configuration regardless of process environment variables.
   - Ensure `_reconcile_smb_proxy()` cleanly unmounts any legacy single-drive `/mnt/gdrive` mount left over from an older container `entrypoint.sh`, mounts each enabled Google Drive under `/mnt/gdrive_mounts/<id>`, updates `/etc/samba/smb.conf`, and reloads `smbd`.
3. **Documentation (`README.md`)**:
   - Keep `README.md` synchronized with the multi-drive SMB Proxy reconciliation details.
