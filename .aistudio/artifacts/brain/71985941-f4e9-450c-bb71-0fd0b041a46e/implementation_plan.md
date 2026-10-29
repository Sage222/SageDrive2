# Refine `Lossless.dll` Frame Rate Detection, Native Fallback Quality & Watermark Auto-Hide

Fix the three video playback issues reported with `Lossless.dll` Upscaling & Frame Generation: accurate source framerate detection (e.g. `24 FPS` instead of `120 FPS`), clean restoration of 100% untouched native video quality when turning `LSFG` off (and eliminating canvas downscaling/blurring when active), and syncing the top-left `Lossless.dll` telemetry watermark to auto-hide after 5 seconds alongside the bottom HUD menu.

## User Review & Critical Decisions

> [!IMPORTANT]
> All three issues have been traced to their exact root causes and will be fixed together across the backend probe and frontend video stage.

1. **Why a 24fps movie showed 120fps on the overlay**:
   - The render loop previously measured `player.currentTime !== lastMediaTime` inside `requestAnimationFrame`. Because `player.currentTime` is driven by the browser's audio clock on every monitor refresh tick (`60Hz` or `120Hz`) rather than decoded video frames, a `60Hz`/`120Hz` display caused it to read `60` or `120` as the base framerate.
   - **Fix**: Extract the true video stream framerate (`avg_frame_rate` / `r_frame_rate`, e.g. `23.976` / `24 FPS`) in `/api/*/probe` (`video_fps`) and measure actual decoded video frames via `player.getVideoPlaybackQuality().totalVideoFrames` over a 1-second sliding window. A 24fps movie will now accurately display `24 → 48 FPS` (`2x`), `24 → 72 FPS` (`3x`), or `24 → 96 FPS` (`4x`).

2. **Why turning off `LSFG` inside the movie degraded video quality instead of dropping back to native**:
   - Previously, the `#video-lsfg-canvas` overlay was capping resolution (`1920×1080` / `0.65x`) and alpha-blending (`opacity: 0.36`) over the `<video>` element, and `stopLosslessPipeline()` left CSS filter / canvas state attached when stopping.
   - **Fix**:
     - When `LSFG` is turned **Off**, `stopLosslessPipeline()` now completely strips `filter` and `image-rendering` properties from `<video>`, resets `#video-lsfg-canvas` (`display: none`, `width = 0`, `height = 0`), and hands rendering 100% back to the browser's native hardware video compositor.
     - When `LSFG` is turned **On**, remove the low-res translucent 2D canvas smear over the `<video>` element so the video always renders at 100% full native resolution with a strictly luminance-preserving (`divisor="1"`, zero-sum kernel) spatial sharpening pass.

3. **Why the top `Lossless.dll` watermark stayed visible when the bottom menu disappeared**:
   - `.video-stage.hud-hidden` hid `.video-stage-hud` at the bottom after 5 seconds of inactivity, but did not target `.video-lsfg-telemetry` at the top.
   - **Fix**: Add smooth `opacity` and `transform` transitions to `.video-lsfg-telemetry` and hide `.video-stage.hud-hidden .video-lsfg-telemetry` (`opacity: 0; pointer-events: none; transform: translateY(-8px)`) so the top watermark disappears and reappears in lockstep with the bottom HUD menu after 5 seconds.

## 1. Technical Architecture & Data Strategy *(Technical Reference)*

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        Media Probe (/api/*/probe)                          │
│  • Extracts primary video stream avg_frame_rate / r_frame_rate (e.g. 23.98)│
│  • Returns video_fps alongside video_codec, audio_streams, duration        │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                   Video Stage (#video-stage-container)                     │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ Top Telemetry Badge (#video-lsfg-telemetry)                          │  │
│  │ • Displays true Base FPS → Interpolated FPS (e.g. 24 → 48 FPS)       │  │
│  │ • Auto-hides after 5s via .video-stage.hud-hidden                    │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ Native <video> Element (#active-media-player)                        │  │
│  │ • LSFG OFF: 100% untouched native hardware rendering (filter: none)  │  │
│  │ • LSFG ON:  Full-res luminance-preserving spatial kernel (LS1/FSR)   │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────┘
```
