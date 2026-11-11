# Fix 2x Frame Generation Smoothness, Spatial Scaling & Add `2x FG` HUD Button

This plan resolves the root causes preventing `2x` Frame Generation from looking visibly smoother during video playback, upgrades the `1.25x` / `1.5x` spatial upscaling pass, and adds a dedicated **`2x FG`** button directly to the video player HUD.

## User Review & Critical Decisions

> [!IMPORTANT]
> - **Confirmed Diagnosis**: Motion did not look smoother with `2x` Frame Generation enabled because of two bugs in the WebGL frame pipeline:
>   1. **Mid-Frame Texture Overwrite**: A fallback `player.currentTime` check was running alongside `requestVideoFrameCallback` and triggering a second texture upload ~23ms into each 41.7ms (24fps) frame—overwriting `texPrev` ($F_{N-1}$) with `texCurr` ($F_N$) so both textures contained the exact same frame.
>   2. **Aggressive Fallback to Un-Interpolated Frame on Camera Pans**: The shader clamped optical flow to `±2px` and fell back to `100%` `curr` (zero interpolation) whenever motion exceeded 2 pixels per frame—meaning camera pans and moving subjects dropped back to raw 24fps judder instead of interpolating.
> - **Confirmed HUD Control**: Add a dedicated **`2x FG`** toggle button in the video player HUD so `2x` Frame Generation can be toggled on the fly while watching.

---

## 1. Overview & Core Concept

- **What It Does**: Delivers true `2x` temporal motion fluidity (`24 → 48 FPS`, `25 → 50 FPS`, `30 → 60 FPS`) and crisp `1.25x` / `1.5x` GPU spatial upscaling on Smart TVs, Android tablets/phones, and desktop browsers, with an instant **`2x FG`** toggle button in the video HUD.
- **Key Value**: Eliminates 24fps panning judder by ensuring every intermediate display refresh renders a true temporal midpoint frame ($F_{N-0.5}$) between distinct decoded frames $F_{N-1}$ and $F_N$.

---

## 2. User Experience & Visual Design

- **Video HUD Controls (`LSFG` + `2x FG`)**:
  - **`LSFG` Button**: Toggles the GPU spatial upscaler (`1.25x` / `1.5x` + RCAS sharpening) on or off.
  - **`2x FG` Button**: Dedicated button right next to `LSFG` in the video HUD that toggles `2x` Frame Generation on or off in real time (and automatically activates the GPU pipeline if clicked while off).
- **Live Telemetry Overlay**:
  - Displays the active scale factor, real-time source FPS, and actual generated output FPS (`GPU 1.5x (1080p→1620p) • 2X FG • 24 → 48 FPS`), and automatically hides after 5 seconds of inactivity alongside the bottom HUD.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Strict Decoded-Frame Texture Ring (`texPrev` / `texCurr`)**
  - *Chosen Approach*: Gate texture swaps strictly on `requestVideoFrameCallback` (`metadata.presentedFrames` / `metadata.mediaTime`) when supported, and only use the `player.currentTime` fallback on legacy browsers with a `0.85 × frameInterval` threshold.
  - *Why*: Guarantees `texPrev` always holds decoded frame $F_{N-1}$ and `texCurr` always holds decoded frame $F_N$ for the entire frame duration, never overwriting `texPrev` mid-frame.
- **Decision 2: Coarse-to-Fine Optical Flow with Temporal Midpoint Fallback**
  - *Chosen Approach*: Estimate motion across both coarse (`±4px` / `±8px`) and fine (`±1.5px`) neighborhoods (supporting pans up to `±10px` per frame), select the best-matching bidirectional warp vector, and blend smoothly into a clean temporal midpoint (`mix(prev, curr, 0.5)`) when local flow confidence is low (only snapping to `curr` on true scene cuts where luma delta `> 0.35`).
  - *Why*: Previously, dropping to `curr` on low flow confidence disabled frame generation during camera pans—the exact moment smooth motion is most noticeable. Blending to the temporal midpoint keeps motion continuously smooth at `2x` frame rate without ghosting across scene cuts.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        HTML5 <video> Decoder                            │
│        Fires requestVideoFrameCallback(now, metadata) at 24/30Hz        │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ New Decoded Frame Only
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 WebGL Texture Ring Buffer (GPU VRAM)                    │
│     texPrev ← previous texCurr (Frame N-1)   |   texCurr ← Frame N     │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ Display Refresh Loop (60Hz / 120Hz)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│             WebGL Fragment Shader (Spatial + Temporal Pass)             │
│  • Sub-frame Phase [0.00 .. 0.50): Render Midpoint Frame F_{N-0.5}      │
│    (Coarse-to-Fine Bidirectional Flow Warp + Temporal Midpoint Blend)   │
│  • Sub-frame Phase [0.50 .. 1.00): Render Native Decoded Frame F_N      │
│  • Spatial Pass: 1.25x / 1.5x Edge-Directed Bicubic + AMD RCAS          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Interactive Component & State Mapping
- **`#stage-lsfg-btn` (`LSFG`)**: Toggles `_losslessConfig.enabled` and persists to `/api/settings/upscaling`.
- **`#stage-fg-btn` (`2x FG`)**: Toggles `_losslessConfig.frame_gen` between `'2x'` and `'off'` (auto-enabling `_losslessConfig.enabled` if currently disabled), updates button active states, and persists to `/api/settings/upscaling`.
