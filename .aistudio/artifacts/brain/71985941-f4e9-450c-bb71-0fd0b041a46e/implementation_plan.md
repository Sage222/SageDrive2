# SageDrive Feature & Workflow Expansion Plan

This upgrade equips SageDrive with desktop-grade file management—in-place renaming, multi-select batch actions with streaming ZIP downloads, recursive folder uploads, server-to-server cross-drive transfers between SMB and Google Drive, a right-click context menu, and media player playlist and speed controls.

### User Review & Critical Decisions

> [!IMPORTANT]
> All core feature selections below reflect your confirmed choices and will be implemented across both the Docker production backend and the live preview server so everything stays in sync.

- **Confirmed Decision — File Operations**: In-place rename for files and folders, multi-select checkboxes with batch delete and ZIP download, recursive drag-and-drop folder uploads, and direct cross-drive copy between SMB shares and Google Drive.
- **Confirmed Decision — Media Player Upgrades**: Next/Previous track navigation across media files in the active directory plus playback speed controls (`0.5x` to `2x`).
- **Confirmed Decision — Desktop UI Interaction**: Custom right-click context menu on files and folders in both list and grid views.

---

### 1. Overview & Core Concept

- **What It Does**: Transforms SageDrive from a basic single-file browser into a complete multi-drive workspace where users can manage batches of files, upload whole folder hierarchies, transfer files directly between NAS shares and Google Drive on the server, and step through media playlists without leaving the player.
- **Target Audience / Persona**: Self-hosted home lab and NAS operators managing media libraries, backups, and documents across local SMB servers and Google Drive.
- **Key Value**: Eliminates tedious one-by-one file operations and avoids routing cross-drive transfers through the client browser.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Right-Click Context Menu**: Right-clicking any file or folder card/row opens a floating menu positioned at the cursor (automatically clamped to viewport edges) with instant actions: *Open / Play*, *Download (or Download ZIP)*, *Rename*, *Copy to Drive…*, *Select*, and *Delete*.
  2. **In-Place Rename**: Selecting *Rename* opens a pre-filled modal with the filename stem highlighted so the user can type a new name and press `Enter` to rename on SMB or Google Drive immediately.
  3. **Multi-Select & Batch Action Bar**: Clicking a row/card checkbox (or choosing *Select* from the context menu) activates a contextual batch toolbar in the top action area showing the selected count alongside **Select All**, **Download ZIP**, **Copy to Drive…**, **Delete Selected**, and **Clear**.
  4. **Recursive Folder Drag-and-Drop Upload**: Dropping one or more folders onto the upload dropzone (or clicking *Choose Folder*) recursively traverses all nested files, automatically creates the required subfolder structure on the target SMB share or Google Drive folder, and displays overall + per-file progress in the upload progress bar.
  5. **Cross-Drive Server Transfer**: Choosing *Copy to Drive…* on a single item or multi-selection opens a destination picker modal where the user selects any configured SMB share or Google Drive (and optional target subfolder). The backend streams the file directly from source to destination and reports transfer completion.
  6. **Enhanced Media Player Modal**: Opening any video or audio file detects all sibling media files in the current folder, adding **Previous** and **Next** track buttons, a track position counter (`2 / 8`), an auto-play next toggle, and a segmented **Playback Speed** control (`0.5x`, `0.75x`, `1x`, `1.25x`, `1.5x`, `2x`).
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Clean utilitarian dark/light workspace preserving SageDrive's existing warm-slate surface hierarchy (`--color-bg`, `--color-surface`, `--color-surface-offset`) and deep teal accent (`--color-primary: #01696f` / `#4f98a3`).
  - *Typography & Tabular Discipline*: `JetBrains Mono` and `tabular-nums` for byte counters, transfer speeds, media timestamps, playback speed indicators, and batch selection counts so numbers never jitter during updates.
  - *Component Styling & Layout*: Single-elevation surfaces with `1px solid var(--color-border)`, compact 40px list rows, and smooth `180ms cubic-bezier(.16, 1, .3, 1)` transitions.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Server-Side Cross-Drive Transfer vs. Client Relay**
  - *Chosen Approach*: Perform SMB-to-Google-Drive, Google-Drive-to-SMB, and SMB-to-SMB transfers directly on the backend server via a dedicated `/api/transfer` endpoint.
  - *Why*: Downloading a large NAS file to the browser just to re-upload it to Google Drive wastes local bandwidth and fails if the browser tab closes. Server-side streaming pipes bytes directly between `pysmb` and the Google Drive API.
- **Decision 2: On-the-Fly ZIP Archive Generation for Multi-Select & Folder Downloads**
  - *Chosen Approach*: Stream a dynamically assembled `.zip` archive from the backend (`/api/smb/zip` and `/api/gdrive/zip`) into the existing download progress bar manager.
  - *Why*: Browsers block triggering dozens of simultaneous single-file downloads, whereas a single streamed `.zip` archive preserves folder paths and works seamlessly with the download progress bar.
- **Decision 3: Directory Tree Preservation on Folder Upload**
  - *Chosen Approach*: Use the standard HTML5 `webkitGetAsEntry()` recursive directory reader for drag-and-drop and `<input webkitdirectory>` for the folder picker, passing each file's relative path to the backend so intermediate folders are created automatically.
  - *Why*: Works across all modern desktop browsers without requiring external client libraries.

---

### 4. Technical Architecture & Data Strategy *(Technical Reference)*

- **Architecture & Component Diagram**:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         SageDrive Frontend SPA                             │
│                                                                            │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────┐  │
│  │   File Browser UI    │  │  Context Menu &      │  │  Media Player    │  │
│  │  • List & Grid Views │  │  Batch Action Bar    │  │  Modal           │  │
│  │  • Multi-Select      │  │  • Rename Modal      │  │  • Prev / Next   │  │
│  │    Checkboxes        │  │  • Copy-to-Drive     │  │    Playlist      │  │
│  │  • Folder Dropzone   │  │    Destination Modal │  │  • Speed (0.5-2x)│  │
│  └──────────┬───────────┘  └──────────┬───────────┘  └────────┬─────────┘  │
└─────────────┼─────────────────────────┼───────────────────────┼────────────┘
              │                         │                       │
              ▼                         ▼                       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                        Backend API Layer (REST)                            │
│                                                                            │
│  • POST /api/smb/rename/<id>        • POST /api/gdrive/rename/<file_id>    │
│  • POST /api/smb/zip/<id>           • POST /api/gdrive/zip                 │
│  • POST /api/smb/upload/<id>        • POST /api/gdrive/upload              │
│    (with relative_path tree)          (with relative_path folder cache)    │
│  • POST /api/transfer (SMB ↔ Google Drive & SMB ↔ SMB recursive copy)      │
└─────────────────────────┬─────────────────────────────┬────────────────────┘
                          │                             │
                          ▼                             ▼
           ┌─────────────────────────────┐ ┌─────────────────────────┐
           │     SMB Manager (pysmb)     │ │  Google Drive Manager   │
           │  • rename()                 │ │  • rename_file()        │
           │  • recursive walk & zip     │ │  • recursive walk & zip │
           │  • ensure_parent_dirs()     │ │  • ensure_folder_path() │
           └─────────────────────────────┘ └─────────────────────────┘
```

- **Data Model & State**:
  - `_currentFiles`: Array of file/folder metadata objects in the active directory, used by the browser view, multi-select state, and media playlist filter.
  - `_selectedItems`: `Map` of selected item keys (`path` for SMB, `id` for Google Drive) to item metadata. Automatically cleared when navigating to a different folder or drive.
  - `_mediaPlaylist` & `_mediaIndex`: Filtered list of playable video/audio items from `_currentFiles` and the active index, enabling instant Previous/Next track switching while preserving the chosen `_playbackRate`.
- **Interactive Component & State Mapping**:
  - **Right-Click Context Menu**: Listens to `contextmenu` on file cards/rows, prevents default browser menu, highlights the target item, and renders context-sensitive actions (`Stream` only on media files, `Download ZIP` on folders, `Rename`, `Copy to Drive…`, `Select`, `Delete`). Dismisses on outside click, scroll, or `Escape`.
  - **Rename Flow**: Validates non-empty and changed name, calls `/api/smb/rename/<share_id>` (`{ path, new_name }`) or `/api/gdrive/rename/<file_id>` (`{ name }`), updates the current view, and shows a completion toast.
  - **Batch Delete & ZIP Download**: Iterates selected items for batch deletion or posts selected paths/IDs to `/api/smb/zip/<share_id>` or `/api/gdrive/zip`, piping the response directly into `authedDownload()` so the progress bar tracks the archive download.
  - **Folder Upload Flow**: Collects `[File, relativePath]` pairs from `webkitGetAsEntry()` or `file.webkitRelativePath`, resolves/creates parent subfolders sequentially (caching created folder IDs on Google Drive to avoid duplicate folders), and streams each file with `uploadFileWithProgress()`.
  - **Cross-Drive Copy Flow**: Opens a modal listing available target drives (Google Drive + all configured SMB shares) and lets the user browse/pick a destination folder, then invokes `POST /api/transfer` (`{ src_type, src_drive, items, dest_type, dest_drive, dest_folder }`) which streams files and recursively copies folders between drives.
