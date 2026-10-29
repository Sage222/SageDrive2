# Fix `Lossless.dll` Toggle State & Persistent Docker Storage

Resolve the issue where uploading `Lossless.dll` shows the success toast (`Enabled`) but leaves the **Upscaling & Frame Generation** toggle and controls disabled in the Settings UI, and store `Lossless.dll` inside the mounted Docker volume (`/app/data`) so it persists across `docker compose down && docker compose up -d`.

## User Review & Critical Decisions

> [!NOTE]
> **Do you need `docker compose up --build` or is `docker compose down && docker compose up -d` enough?**
> Because `docker-compose.yml` bind-mounts `./backend/main.py:/app/main.py` and `./frontend/public/index.html:/app/static/index.html` directly into the container, **you do NOT need `--build`**. Once this fix is applied and pulled, a quick `docker compose down && docker compose up -d` (or `docker compose restart`) is all that is needed.

- **Root Cause Identified**:
  1. **API Payload Mismatch (`backend/main.py` vs. Frontend UI)**: The Python Docker backend returned flat fields (`dll_installed: true`, `dll_size`, `dll_sha256`, `dll_arch`, and `sharpness` as `0–100`), whereas the frontend UI (`index.html`) and Node server checked the nested `dll: { provided: true, size, sha256, arch, valid_pe }` object and normalized `0.0–1.0` sharpness. Because `dll.provided` was missing from the Python response, the UI treated the DLL as not loaded (`hasDll = false`) and kept the toggle switch disabled.
  2. **Docker Volume Path (`/app/data` vs. `/data`)**: `docker-compose.yml` mounts `sagedrive-data` at `/app/data` (`auth.DATA_DIR`), whereas `backend/main.py` was saving `Lossless.dll` to `/data/lossless` (with a fallback check so any existing `/data/lossless/Lossless.dll` is automatically migrated to `/app/data/lossless/Lossless.dll`).

## 1. Overview & Core Concept

- **What It Does**: Aligns the Python Flask backend response schema and the frontend normalizer so that uploading `Lossless.dll` immediately unlocks the **Enabled / Off** toggle switch, dropdown selectors, sharpness slider, and in-player `LSFG` button, and persists both `Lossless.dll` and `lossless_config.json` inside `/app/data`.
- **Key Value**: Seamless unlocking and toggling of `Lossless.dll` Upscaling & Frame Generation in Docker deployments without requiring a container image rebuild.

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Upload `Lossless.dll`**: Selecting `Lossless.dll` in **Settings → Upscaling & Frame Gen** verifies the PE header, displays the `DLL Verified & Loaded` badge along with PE architecture, file size, and SHA-256 checksum, and immediately enables the **Upscaling & Frame Generation** toggle switch and all configuration controls.
  2. **Toggle & Adjust Settings**: Clicking the **Enabled / Off** switch, changing Spatial Upscaling (`LS1`, `FSR`, `NIS`, `Anime4K`), Scale Factor (`1.0x–2.0x`), Edge Sharpness (`0–100%`), or `LSFG 3.0` (`2x`, `3x`, `4x`) immediately saves and updates the state without resetting or locking the controls.
  3. **In-Player `LSFG` Toggle**: Clicking `LSFG` next to `BT` in the video player toggles `Lossless.dll` on and off live during playback.

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Unified Payload Schema + Frontend Normalization**
  - *Chosen Approach*: Update `backend/main.py` to return the exact nested `dll: { provided, filename, size, sha256, valid_pe, arch, uploaded_at }` object (plus top-level `dll_installed` for backward compatibility) and support both `0.0–1.0` and `0–100` sharpness values, while also normalizing the response in the frontend `normalizeLosslessConfig()` helper.
  - *Why*: Guarantees the toggle and controls unlock reliably regardless of whether the backend returns nested or flat fields.
- **Decision 2: Persistent Storage in `auth.DATA_DIR` (`/app/data`) with Automatic Migration**
  - *Chosen Approach*: Store `Lossless.dll` at `/app/data/lossless/Lossless.dll` and `lossless_config.json` at `/app/data/lossless_config.json` (matching `sagedrive-data:/app/data` in `docker-compose.yml`), and automatically migrate any file already uploaded to `/data/lossless/Lossless.dll`.
  - *Why*: Ensures your uploaded `Lossless.dll` survives `docker compose down && docker compose up -d`.

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

```
┌────────────────────────────────────────────────────────────────────────────┐
│                   Settings → Upscaling & Frame Gen UI                      │
│  ┌───────────────────────────────┐  ┌───────────────────────────────────┐  │
│  │ Lossless.dll Binary Module    │  │ Upscaling & Frame Gen Controls    │  │
│  │ • Upload / Replace / Remove   │  │ • Enabled / Off Toggle Switch     │  │
│  │ • PE Arch + SHA-256 Display   │  │ • LS1/FSR/NIS/Anime4K + LSFG 3.0  │  │
│  └──────────────┬────────────────┘  └─────────────────┬─────────────────┘  │
└─────────────────┼─────────────────────────────────────┼────────────────────┘
                  │ POST /api/settings/lossless-dll     │ POST /api/settings/lossless
                  ▼                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                Unified Backend Response & Normalization                    │
│  • Returns { enabled, upscale_type, scale_factor, sharpness (0..1),        │
│              frame_gen, performance_mode, hdr_boost, show_fps_overlay,     │
│              dll: { provided: true, arch, size, sha256, valid_pe } }       │
│  • Persisted in /app/data/lossless/Lossless.dll (sagedrive-data volume)    │
└────────────────────────────────────────────────────────────────────────────┘
```
