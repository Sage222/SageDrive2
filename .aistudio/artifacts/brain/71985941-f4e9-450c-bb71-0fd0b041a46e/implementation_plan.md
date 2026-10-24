# Multi-Drive SMB Proxy (Per-Drive Shares, Custom SMB Names & Live Mount Controls)

Upgrade the SageDrive SMB Proxy so every connected Google Drive account can be individually toggled on or off as its own network SMB share, given a custom SMB share name in Settings, and mounted/unmounted live via `rclone` + Samba without restarting the Docker container.

## User Review & Critical Decisions

> [!IMPORTANT]
> The following architectural and UX choices incorporate your selections from our clarification questions:

- **Confirmed Decision 1 — Separate SMB Share per Google Drive**: Each enabled Google Drive account is mounted to its own dedicated FUSE directory (`/mnt/gdrive/<account_id>`) via `rclone` and exported as an independent `[<ShareName>]` block in Samba (`\\<host>\<ShareName>`).
- **Confirmed Decision 2 — Custom SMB Share Name per Drive in Settings**: In the **SMB Proxy** settings card, each connected Google Drive has an editable **SMB Share Name** input (e.g., `GoogleDrive`, `PersonalDrive`, `WorkDrive`) sanitized for Windows/macOS/Linux network share compatibility.
- **Confirmed Decision 3 — Per-Drive Enable/Disable Toggle**: Each connected Google Drive has an on/off toggle in the **SMB Proxy** section of Settings. Toggling a drive on/off or renaming its SMB share immediately reconciles the `rclone` FUSE mount and reloads Samba (`smbcontrol all reload-config` / `smbd`) live without requiring a container restart.

---

## 1. Overview & Core Concept

- **What It Does**: Transforms the static single-drive boot-time SMB Proxy into a dynamic, multi-account SMB Proxy manager. Users can expose one, several, or all of their connected Google Drive accounts as distinct Windows/macOS/NAS network shares on port `445`.
- **Target Audience / Persona**: Self-hosted home lab and NAS users who connect multiple Google Drive accounts in SageDrive and want to mount specific drives directly in Windows Explorer, macOS Finder, or media players (Plex/Infuse/Kodi) over SMB.
- **Key Value**: Eliminates the single-drive bottleneck (`gdrive_token.json` / `/mnt/gdrive`) and removes the need to restart the Docker container after connecting or reconfiguring a Google Drive.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Viewing SMB Proxy Shares (`Settings → SMB Proxy`)**:
     - The **SMB Proxy — Windows Network Drives** card displays:
       - **Global Samba Credentials**: The shared SMB username & password used to authenticate from Windows Explorer / Finder.
       - **Per-Drive SMB Shares Table/List**: A dedicated row for each connected Google Drive account showing:
         - Drive display name & Google account email.
         - Live status indicator (`Mounted & Shared`, `Disabled`, or `Mount Pending`).
         - **Enable SMB Share** toggle switch.
         - **SMB Share Name** input field (defaults to a clean slug of the drive's name, e.g., `GoogleDrive` for the primary drive, `WorkDrive`, etc.) with a **Save / Apply** button.
         - One-click **Copy UNC Path** (`\\<host>\<smb_share_name>`) and **Copy PowerShell Map Command** (`net use Z: \\<host>\<smb_share_name> /user:<user> <password> /persistent:yes`).
  2. **Toggling or Renaming a Share Live**:
     - Flipping the toggle or updating the SMB share name calls the backend SMB Proxy reconciliation endpoint.
     - The backend writes the updated `rclone.conf`, starts or stops the corresponding `rclone mount` daemon for that account, regenerates `/etc/samba/smb.conf` with a share stanza per enabled drive, and signals `smbd` to reload its configuration immediately.
  3. **Container Startup & Self-Healing**:
     - On container boot (and when the Flask backend starts), SageDrive automatically reconciles all enabled Google Drives from `gdrive_accounts.json` so all configured SMB shares come online automatically.

- **Visual Identity & Theme**:
  - **Aesthetic Direction**: Clean, high-density utilitarian dashboard matching SageDrive's existing dark/light theme variables (`--color-surface`, `--color-surface-offset`, `--color-primary`, `--font-mono`).
  - **Typography & Hierarchy**: Monospace tabular figures (`--font-mono`) for UNC paths (`\\host\ShareName`), mount paths, and PowerShell `net use` commands; crisp sans-serif labels for drive names and controls.
  - **Interactive Feedback**: Instant loading/applying state on the per-drive row while `rclone` mounts the FUSE filesystem, followed by a toast confirmation and live status update.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Backend-Driven Live Reconciliation vs. Boot-Time `entrypoint.sh` Script**
  - *Chosen Approach*: Move `rclone.conf` generation, FUSE mount lifecycle management, and `/etc/samba/smb.conf` generation into a dedicated backend manager that runs both at startup and on-demand via API whenever accounts or SMB proxy settings change.
  - *Why*: Previously, `entrypoint.sh` only ran once when the container started — meaning newly connected Google Drives could never be mounted without restarting the container, and only `gdrive_token.json` was read. Furthermore, because `docker-compose.yml` bind-mounts the backend directly, handling multi-drive reconciliation inside the Python backend ensures existing deployments get multi-drive SMB Proxy support immediately without needing to rebuild the base Docker image.
  - *Alternatives Considered*: Only updating `entrypoint.sh` — rejected because changes in the web UI wouldn't take effect until a manual container restart and would require image rebuilds.

- **Decision 2: Share Name Sanitization & Uniqueness Validation**
  - *Chosen Approach*: Validate SMB share names to allow alphanumeric characters, hyphens, and underscores (`[A-Za-z0-9_-]{1,32}`), prevent reserved names (`global`, `homes`, `printers`, `IPC$`), and enforce case-insensitive uniqueness across all connected Google Drives.
  - *Why*: Prevents invalid `/etc/samba/smb.conf` section headers and Windows Explorer UNC path resolution conflicts.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:
```text
┌───────────────────────────────────────────────────────────────────────────┐
│                   Settings → SMB Proxy UI (Frontend SPA)                  │
│  ┌───────────────────────────────┐  ┌──────────────────────────────────┐  │
│  │ Global Samba Auth Credentials │  │ Per-Drive SMB Share Rows         │  │
│  │ • Username / Password         │  │ • [Toggle] Enable SMB Share      │  │
│  └──────────────┬────────────────┘  │ • [Input]  Custom SMB Share Name │  │
│                 │                   │ • [Copy]   UNC & PowerShell Cmd  │  │
│                 ▼                   └─────────────────┬────────────────┘  │
└─────────────────┼─────────────────────────────────────┼───────────────────┘
                  │ POST /api/smb/proxy-credentials     │ POST /api/smb/proxy-shares
                  ▼                                     ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     SageDrive Backend (SMB Proxy Manager)                 │
│  1. Reads & updates `gdrive_accounts.json` (`smb_enabled`, `smb_share`)   │
│  2. Writes `/root/.config/rclone/rclone.conf` with `[gdrive_<id>]` blocks │
│  3. Mounts enabled drives to `/mnt/gdrive/<id>` via `rclone mount` FUSE   │
│     and unmounts disabled/removed drives (`fusermount -u` / `umount -l`)  │
│  4. Generates `/etc/samba/smb.conf` with `[<smb_share_name>]` stanzas     │
│  5. Reloads Samba (`smbcontrol all reload-config` / `pkill -HUP smbd`)    │
└───────────────────────────────────────────────────────────────────────────┘
```

- **Data Model & State (`gdrive_accounts.json`)**:
  - Each account object in `gdrive_accounts.json` is extended with two optional fields:
    - `smb_enabled` (`boolean`): Defaults to `true` for the first/default drive (preserving backward compatibility) and configurable per drive.
    - `smb_share_name` (`string`): Custom Samba share name (defaults to `GoogleDrive` for the primary drive, or a sanitized unique name such as `GoogleDrive_2` or the sanitized custom drive name).

- **Interactive Component & State Mapping**:
  - `GET /api/smb/proxy-shares`: Returns global Samba credential status plus the list of all connected Google Drives with their `id`, `name`, `email`, `smb_enabled`, `smb_share_name`, and live `mounted` status.
  - `POST /api/smb/proxy-shares/<account_id>`: Updates `smb_enabled` and/or `smb_share_name` for a specific Google Drive account, validates share name uniqueness, triggers live `rclone` + `smb.conf` reconciliation, and returns the updated share state.
  - `POST /api/smb/proxy-reconcile`: Forces a full re-sync of all `rclone` mounts and Samba share definitions.
  - Automatic Hooks: Connecting a new Google Drive, refreshing OAuth tokens, or disconnecting a Google Drive automatically triggers SMB Proxy reconciliation so mounts and shares stay in sync.
  - Documentation Update: `README.md` will also be updated to document the multi-drive SMB Proxy configuration and per-drive share naming.
