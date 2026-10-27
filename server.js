import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import zlib from 'zlib';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(cors({ origin: true, credentials: true, exposedHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges', 'Content-Disposition'] }));
app.use(express.json());

// Persistent data directory
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '.data');
const BLOBS_DIR = path.join(DATA_DIR, 'blobs');
fs.mkdirSync(BLOBS_DIR, { recursive: true });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const SHARES_FILE = path.join(DATA_DIR, 'smb_shares.json');
const SMB_FS_FILE = path.join(DATA_DIR, 'smb_fs.json');
const GDRIVE_FS_FILE = path.join(DATA_DIR, 'gdrive_fs.json');
const GDRIVE_CONFIG_FILE = path.join(DATA_DIR, 'gdrive_client.json');
const GDRIVE_CREDS_FILE = path.join(DATA_DIR, 'gdrive_token.json');
const GDRIVE_ACCOUNTS_FILE = path.join(DATA_DIR, 'gdrive_accounts.json');
const ONEDRIVE_FS_FILE = path.join(DATA_DIR, 'onedrive_fs.json');
const ONEDRIVE_CONFIG_FILE = path.join(DATA_DIR, 'onedrive_client.json');
const ONEDRIVE_ACCOUNTS_FILE = path.join(DATA_DIR, 'onedrive_accounts.json');
const SMB_PROXY_FILE = path.join(DATA_DIR, 'smb_proxy_credentials.json');

const SESSION_TTL = (parseInt(process.env.SESSION_TTL_HOURS || '24', 10) || 24) * 3600 * 1000;
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_SECONDS = 15 * 60; // 15 minutes
const unknownLockouts = new Map();

// Disk storage for uploads so large media files don't buffer in memory
const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, BLOBS_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '') || '';
      cb(null, `upload_${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`);
    },
  }),
});

function loadJson(file, fallback) {
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf-8'));
    }
  } catch (_) {}
  return fallback;
}

function saveJson(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error(`Failed saving ${file}:`, err.message);
  }
}

// Pure-Node ZIP archive builder (supports files and folders without external binary dependencies)
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildZipBuffer(entries) {
  // entries: Array<{ arcPath: string, data: Buffer, isDir?: boolean }>
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const rawName = entry.isDir
      ? entry.arcPath.replace(/\/+$/, '') + '/'
      : entry.arcPath.replace(/^\/+/, '');
    const nameBuf = Buffer.from(rawName, 'utf-8');
    const uncompressed = entry.isDir ? Buffer.alloc(0) : (entry.data || Buffer.alloc(0));
    const crc = crc32(uncompressed);
    const compressed = entry.isDir ? Buffer.alloc(0) : zlib.deflateRawSync(uncompressed);
    const method = entry.isDir ? 0 : 8;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4); // version needed
    localHeader.writeUInt16LE(0x0800, 6); // UTF-8 flag
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(0, 10); // mod time
    localHeader.writeUInt16LE(0x21, 12); // mod date
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(uncompressed.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, nameBuf, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0x21, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(uncompressed.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(entry.isDir ? 0x10 : 0, 38);
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralSize = centralParts.reduce((acc, b) => acc + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

function getItemBuffer(item) {
  if (!item) return Buffer.alloc(0);
  if (item.blobPath && fs.existsSync(item.blobPath)) {
    return fs.readFileSync(item.blobPath);
  }
  if (item.data) {
    return Buffer.from(item.data);
  }
  return Buffer.alloc(0);
}

// Accurate MIME type lookup for media streaming and file downloads
function getMimeType(filename, fallbackMime) {
  const ext = String(filename || '').split('.').pop().toLowerCase();
  const mimeMap = {
    mp4: 'video/mp4',
    m4v: 'video/mp4',
    mov: 'video/mp4',
    webm: 'video/webm',
    ogv: 'video/ogg',
    mkv: 'video/webm',
    avi: 'video/x-msvideo',
    mp3: 'audio/mpeg',
    wav: 'audio/wav',
    ogg: 'audio/ogg',
    oga: 'audio/ogg',
    opus: 'audio/ogg',
    m4a: 'audio/mp4',
    aac: 'audio/aac',
    flac: 'audio/flac',
    weba: 'audio/webm',
    wma: 'audio/x-ms-wma',
    aiff: 'audio/aiff',
    aif: 'audio/aiff',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',
    bmp: 'image/bmp',
    ico: 'image/x-icon',
    avif: 'image/avif',
    pdf: 'application/pdf',
    txt: 'text/plain; charset=utf-8',
    md: 'text/plain; charset=utf-8',
    log: 'text/plain; charset=utf-8',
    csv: 'text/plain; charset=utf-8',
    xml: 'text/xml; charset=utf-8',
    yaml: 'text/plain; charset=utf-8',
    yml: 'text/plain; charset=utf-8',
    ini: 'text/plain; charset=utf-8',
    conf: 'text/plain; charset=utf-8',
    toml: 'text/plain; charset=utf-8',
    py: 'text/plain; charset=utf-8',
    sh: 'text/plain; charset=utf-8',
    ts: 'text/plain; charset=utf-8',
    json: 'application/json; charset=utf-8',
    html: 'text/html; charset=utf-8',
    css: 'text/css; charset=utf-8',
    js: 'application/javascript',
    zip: 'application/zip',
  };
  if (mimeMap[ext]) return mimeMap[ext];
  if (fallbackMime && fallbackMime !== 'application/octet-stream' && fallbackMime !== 'video/quicktime') {
    return fallbackMime;
  }
  return 'application/octet-stream';
}

// Generate sample stereo WAV file on disk if not present
const SAMPLE_WAV_PATH = path.join(BLOBS_DIR, 'sample_audio.wav');
const SAMPLE_MP4_PATH = path.join(BLOBS_DIR, 'sample_video.mp4');

function ensureSampleMediaFiles() {
  if (!fs.existsSync(SAMPLE_WAV_PATH)) {
    const sampleRate = 44100;
    const durationSec = 6;
    const numSamples = sampleRate * durationSec;
    const numChannels = 2;
    const bytesPerSample = 2;
    const dataSize = numSamples * numChannels * bytesPerSample;
    const buf = Buffer.alloc(44 + dataSize);

    buf.write('RIFF', 0);
    buf.writeUInt32LE(36 + dataSize, 4);
    buf.write('WAVE', 8);
    buf.write('fmt ', 12);
    buf.writeUInt32LE(16, 16);
    buf.writeUInt16LE(1, 20);
    buf.writeUInt16LE(numChannels, 22);
    buf.writeUInt32LE(sampleRate, 24);
    buf.writeUInt32LE(sampleRate * numChannels * bytesPerSample, 28);
    buf.writeUInt16LE(numChannels * bytesPerSample, 32);
    buf.writeUInt16LE(bytesPerSample * 8, 34);
    buf.write('data', 36);
    buf.writeUInt32LE(dataSize, 40);

    const chords = [
      [261.63, 329.63, 392.00, 493.88],
      [349.23, 440.00, 523.25, 659.25],
    ];
    let offset = 44;
    for (let i = 0; i < numSamples; i++) {
      const t = i / sampleRate;
      const chordIdx = t < 3.0 ? 0 : 1;
      const localT = t % 3.0;
      const env = Math.min(1, localT / 0.08) * Math.exp(-localT * 0.65);
      const freqs = chords[chordIdx];
      let sampleL = 0;
      let sampleR = 0;
      for (let k = 0; k < freqs.length; k++) {
        const f = freqs[k];
        const pan = k / (freqs.length - 1);
        const wave = Math.sin(2 * Math.PI * f * t) + 0.25 * Math.sin(4 * Math.PI * f * t);
        sampleL += wave * (1 - pan * 0.4);
        sampleR += wave * (0.6 + pan * 0.4);
      }
      const valL = Math.max(-1, Math.min(1, (sampleL / freqs.length) * env * 0.6));
      const valR = Math.max(-1, Math.min(1, (sampleR / freqs.length) * env * 0.6));
      buf.writeInt16LE(Math.floor(valL * 32767), offset);
      buf.writeInt16LE(Math.floor(valR * 32767), offset + 2);
      offset += 4;
    }
    fs.writeFileSync(SAMPLE_WAV_PATH, buf);
  }

  if (!fs.existsSync(SAMPLE_MP4_PATH)) {
    try {
      const proc = spawn('ffmpeg', [
        '-y',
        '-f', 'lavfi', '-i', 'testsrc=duration=6:size=640x360:rate=24',
        '-f', 'lavfi', '-i', 'sine=frequency=440:duration=6',
        '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-preset', 'ultrafast',
        '-movflags', '+faststart',
        '-c:a', 'aac', '-b:a', '128k',
        SAMPLE_MP4_PATH,
      ]);
      proc.on('error', () => {});
    } catch (_) {}
  }
}
ensureSampleMediaFiles();

// Persistent Sessions (default to Read-Only mode on startup/login)
const sessionsMap = new Map(Object.entries(loadJson(SESSIONS_FILE, {})));
for (const sess of sessionsMap.values()) {
  if (sess && typeof sess === 'object') {
    sess.admin_enabled = Boolean(sess.admin_enabled);
  }
}
function persistSessions() {
  saveJson(SESSIONS_FILE, Object.fromEntries(sessionsMap.entries()));
}

// Persistent SMB & Google Drive virtual filesystems
const smbFSData = loadJson(SMB_FS_FILE, {});
function saveSmbFS() {
  saveJson(SMB_FS_FILE, smbFSData);
}

const gdriveFSData = loadJson(GDRIVE_FS_FILE, {});
function saveGDriveFS() {
  saveJson(GDRIVE_FS_FILE, gdriveFSData);
}

const onedriveFSData = loadJson(ONEDRIVE_FS_FILE, {});
function saveOneDriveFS() {
  saveJson(ONEDRIVE_FS_FILE, onedriveFSData);
}

function seedGDrive() {
  if (Object.keys(gdriveFSData).length > 0) return;
  const now = new Date().toISOString();
  gdriveFSData['folder-docs'] = {
    id: 'folder-docs',
    name: 'Documents',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.google-apps.folder',
    parent: 'root',
  };
  gdriveFSData['folder-media'] = {
    id: 'folder-media',
    name: 'Media',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.google-apps.folder',
    parent: 'root',
  };

  const readmePath = path.join(BLOBS_DIR, 'gdrive_welcome.txt');
  const readmeContent = Buffer.from(
    'Welcome to SageDrive Google Drive integration.\nYou can upload, download, and stream media files here.\n'
  );
  fs.writeFileSync(readmePath, readmeContent);

  gdriveFSData['file-readme'] = {
    id: 'file-readme',
    name: 'Welcome.txt',
    type: 'file',
    size: readmeContent.length,
    modified: now,
    mimeType: 'text/plain',
    parent: 'root',
    blobPath: readmePath,
  };

  if (fs.existsSync(SAMPLE_WAV_PATH)) {
    const wavSize = fs.statSync(SAMPLE_WAV_PATH).size;
    gdriveFSData['file-sample-audio'] = {
      id: 'file-sample-audio',
      name: 'Sample_Audio.wav',
      type: 'file',
      size: wavSize,
      modified: now,
      mimeType: 'audio/wav',
      parent: 'root',
      blobPath: SAMPLE_WAV_PATH,
    };
  }
  saveGDriveFS();
}
seedGDrive();

function seedOneDrive() {
  if (Object.keys(onedriveFSData).length > 0) return;
  const now = new Date().toISOString();
  onedriveFSData['od-folder-docs'] = {
    id: 'od-folder-docs',
    accountId: 'default',
    name: 'Documents',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.onedrive.folder',
    parent: 'root',
  };
  onedriveFSData['od-folder-media'] = {
    id: 'od-folder-media',
    accountId: 'default',
    name: 'Media',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.onedrive.folder',
    parent: 'root',
  };

  const readmePath = path.join(BLOBS_DIR, 'onedrive_welcome.txt');
  const readmeContent = Buffer.from(
    'Welcome to SageDrive Microsoft OneDrive integration.\nYou can upload, download, edit, and stream media files here.\n'
  );
  fs.writeFileSync(readmePath, readmeContent);

  onedriveFSData['od-file-readme'] = {
    id: 'od-file-readme',
    accountId: 'default',
    name: 'Welcome.txt',
    type: 'file',
    size: readmeContent.length,
    modified: now,
    mimeType: 'text/plain',
    parent: 'root',
    blobPath: readmePath,
  };

  if (fs.existsSync(SAMPLE_WAV_PATH)) {
    onedriveFSData['od-file-sample-audio'] = {
      id: 'od-file-sample-audio',
      accountId: 'default',
      name: 'Sample_Audio.wav',
      type: 'file',
      size: fs.statSync(SAMPLE_WAV_PATH).size,
      modified: now,
      mimeType: 'audio/wav',
      parent: 'root',
      blobPath: SAMPLE_WAV_PATH,
    };
  }
  if (fs.existsSync(SAMPLE_MP4_PATH) && fs.statSync(SAMPLE_MP4_PATH).size > 0) {
    onedriveFSData['od-file-sample-video'] = {
      id: 'od-file-sample-video',
      accountId: 'default',
      name: 'Sample_Video.mp4',
      type: 'file',
      size: fs.statSync(SAMPLE_MP4_PATH).size,
      modified: now,
      mimeType: 'video/mp4',
      parent: 'root',
      blobPath: SAMPLE_MP4_PATH,
    };
  }
  saveOneDriveFS();
}
seedOneDrive();

function ensureShareFS(shareId) {
  if (!smbFSData[shareId]) {
    const now = Math.floor(Date.now() / 1000);
    const readmePath = path.join(BLOBS_DIR, `smb_${shareId}_readme.txt`);
    const noteBuf = Buffer.from('SageDrive NAS Share\nConnected via SageDrive Web Interface.\n');
    fs.writeFileSync(readmePath, noteBuf);

    const shareEntries = {
      '/Documents': {
        name: 'Documents',
        type: 'folder',
        size: 0,
        modified: now,
        path: '/Documents',
      },
      '/Media': {
        name: 'Media',
        type: 'folder',
        size: 0,
        modified: now,
        path: '/Media',
      },
      '/README.txt': {
        name: 'README.txt',
        type: 'file',
        size: noteBuf.length,
        modified: now,
        path: '/README.txt',
        blobPath: readmePath,
        mimeType: 'text/plain',
      },
    };

    if (fs.existsSync(SAMPLE_WAV_PATH)) {
      shareEntries['/Media/Sample_Audio.wav'] = {
        name: 'Sample_Audio.wav',
        type: 'file',
        size: fs.statSync(SAMPLE_WAV_PATH).size,
        modified: now,
        path: '/Media/Sample_Audio.wav',
        blobPath: SAMPLE_WAV_PATH,
        mimeType: 'audio/wav',
      };
    }

    if (fs.existsSync(SAMPLE_MP4_PATH)) {
      shareEntries['/Media/Sample_Video.mp4'] = {
        name: 'Sample_Video.mp4',
        type: 'file',
        size: fs.statSync(SAMPLE_MP4_PATH).size,
        modified: now,
        path: '/Media/Sample_Video.mp4',
        blobPath: SAMPLE_MP4_PATH,
        mimeType: 'video/mp4',
      };
    }

    smbFSData[shareId] = shareEntries;
    saveSmbFS();
  } else {
    const entries = smbFSData[shareId];
    if (
      entries['/Media'] &&
      !entries['/Media/Sample_Video.mp4'] &&
      fs.existsSync(SAMPLE_MP4_PATH) &&
      fs.statSync(SAMPLE_MP4_PATH).size > 0
    ) {
      entries['/Media/Sample_Video.mp4'] = {
        name: 'Sample_Video.mp4',
        type: 'file',
        size: fs.statSync(SAMPLE_MP4_PATH).size,
        modified: Math.floor(Date.now() / 1000),
        path: '/Media/Sample_Video.mp4',
        blobPath: SAMPLE_MP4_PATH,
        mimeType: 'video/mp4',
      };
      saveSmbFS();
    }
  }
  return smbFSData[shareId];
}

// Bootstrap admin user
function bootstrapAdmin() {
  const users = loadJson(USERS_FILE, {});
  if (Object.keys(users).length === 0) {
    const u = (process.env.ADMIN_USER || '').trim() || 'admin';
    const p = (process.env.ADMIN_PASS || '').trim() || 'changeme';
    const hash = bcrypt.hashSync(p, 10);
    users[u] = { hash, role: 'admin' };
    saveJson(USERS_FILE, users);
  }
}
bootstrapAdmin();

function getSession(token) {
  if (!token) return null;
  const s = sessionsMap.get(token);
  if (s && s.expires > Date.now()) {
    return s;
  }
  if (sessionsMap.has(token)) {
    sessionsMap.delete(token);
    persistSessions();
  }
  return null;
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function extractToken(req) {
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  if (req.query.token) {
    return String(req.query.token).trim();
  }
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.sd_token) {
    return cookies.sd_token.trim();
  }
  return '';
}

const ADMIN_PIN = String(process.env.ADMIN_PIN || '0022').trim();

function requireAuth(req, res, next) {
  const token = extractToken(req);
  const session = getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  req.session = session;
  req.token = token;
  next();
}

function requireAdmin(req, res, next) {
  const token = extractToken(req);
  const session = getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  if (!session.admin_enabled) {
    return res.status(403).json({
      error: 'Read-Only Mode is active. Enable Administrator Functions in Settings (PIN required).',
    });
  }
  req.session = session;
  req.token = token;
  next();
}

function makeDispositionHeader(filename, isDownload) {
  const safeAsciiName = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  const encodedName = encodeURIComponent(filename);
  const dispositionType = isDownload ? 'attachment' : 'inline';
  return `${dispositionType}; filename="${safeAsciiName}"; filename*=UTF-8''${encodedName}`;
}

function resolveItemBlobPath(item) {
  if (!item || item.type === 'folder') return null;
  let blobPath = item.blobPath;
  if (!blobPath || !fs.existsSync(blobPath)) {
    if (item.data) {
      blobPath = path.join(BLOBS_DIR, `legacy_${crypto.randomBytes(6).toString('hex')}_${path.basename(item.name)}`);
      fs.writeFileSync(blobPath, Buffer.from(item.data));
      item.blobPath = blobPath;
    } else {
      return null;
    }
  }
  return blobPath;
}

function probeMediaItem(item) {
  return new Promise((resolve) => {
    const filename = (item && item.name) || '';
    const ext = String(filename).includes('.') ? String(filename).split('.').pop().toLowerCase() : '';
    const blobPath = resolveItemBlobPath(item);
    if (!blobPath) {
      return resolve({
        has_video: false,
        video_codec: '',
        video_pix_fmt: '',
        has_audio: false,
        audio_codec: '',
        audio_channels: 0,
        audio_streams: [],
        subtitle_streams: [],
        duration: 0,
        needs_audio_transcode: false,
        needs_video_transcode: false,
        can_remux_video: false,
        recommended_mode: 'direct',
      });
    }

    const ff = spawn('ffprobe', [
      '-v', 'error',
      '-probesize', '10000000',
      '-analyzeduration', '10000000',
      '-show_entries', 'stream=index,codec_type,codec_name,profile,pix_fmt,channels,sample_rate,duration:stream_disposition=default,forced:stream_tags:format=format_name,duration:format_tags',
      '-of', 'json',
      blobPath,
    ]);
    let out = '';
    ff.stdout.on('data', (d) => { out += d.toString(); });
    ff.on('error', () => {
      resolve({
        has_video: false,
        video_codec: '',
        video_pix_fmt: '',
        has_audio: false,
        audio_codec: '',
        audio_channels: 0,
        audio_streams: [],
        subtitle_streams: [],
        duration: 0,
        needs_audio_transcode: false,
        needs_video_transcode: false,
        can_remux_video: false,
        recommended_mode: 'direct',
      });
    });
    ff.on('close', () => {
      let data = {};
      try { data = JSON.parse(out || '{}'); } catch (_) {}
      const streams = Array.isArray(data.streams) ? data.streams : [];
      const fmt = data.format || {};
      const nonCoverVideos = streams.filter(
        (s) => s.codec_type === 'video' && !['mjpeg', 'png', 'bmp', 'gif', 'webp'].includes(String(s.codec_name || '').toLowerCase())
      );
      const videoStreams = nonCoverVideos.length ? nonCoverVideos : streams.filter((s) => s.codec_type === 'video');
      const audioStreams = streams.filter((s) => s.codec_type === 'audio');
      const subtitleStreams = streams.filter((s) => s.codec_type === 'subtitle');
      const v0 = videoStreams[0] || null;
      const a0 = audioStreams[0] || null;
      const videoCodec = v0 ? String(v0.codec_name || '').toLowerCase() : '';
      const videoPixFmt = v0 ? String(v0.pix_fmt || '').toLowerCase() : '';
      const audioCodec = a0 ? String(a0.codec_name || '').toLowerCase() : '';
      const audioChannels = a0 ? parseInt(a0.channels || 0, 10) || 0 : 0;
      const hasVideo = Boolean(v0);
      const hasAudio = Boolean(a0);

      const safeAudio = new Set(['aac', 'mp3', 'opus']);
      if (['webm', 'ogg', 'ogv', 'oga'].includes(ext)) safeAudio.add('vorbis');
      if (!hasVideo && ['wav', 'flac'].includes(ext)) {
        ['pcm_s16le', 'pcm_s24le', 'pcm_f32le', 'pcm_u8', 'flac'].forEach((c) => safeAudio.add(c));
      }

      let needsAudioTranscode = false;
      if (hasAudio) {
        if (!safeAudio.has(audioCodec)) needsAudioTranscode = true;
        else if (audioChannels > 2 && audioCodec !== 'aac') needsAudioTranscode = true;
      }

      const is10BitH264 = videoCodec === 'h264' && /(10le|10be|12le|12be)$/.test(videoPixFmt);
      const needsVideoTranscode = hasVideo && (!['h264', 'hevc', 'vp8', 'vp9', 'av1'].includes(videoCodec) || is10BitH264);
      const nonNativeContainer = ['mkv', 'avi', 'wmv', 'flv', 'ts', 'm2ts', 'mpg', 'mpeg', 'vob', 'divx'].includes(ext);
      const canRemuxVideo = hasVideo && ['h264', 'hevc'].includes(videoCodec) && !is10BitH264;

      let recommendedMode = 'direct';
      if (hasVideo) {
        if (needsVideoTranscode) recommendedMode = 'full';
        else if (needsAudioTranscode || nonNativeContainer) recommendedMode = canRemuxVideo ? 'remux' : 'full';
      } else if (needsAudioTranscode || ['eac3', 'ec3', 'ac3', 'dts', 'wma', 'aiff', 'aif', 'alac', 'mka', 'mp2'].includes(ext)) {
        recommendedMode = 'audio';
      }

      const audioTracksOut = audioStreams.map((s, idx) => {
        const tags = s.tags || {};
        return {
          index: idx,
          codec: String(s.codec_name || 'unknown').toLowerCase(),
          channels: parseInt(s.channels || 0, 10) || 0,
          language: tags.language || tags.LANGUAGE || '',
          title: tags.title || tags.TITLE || '',
        };
      });

      const bitmapSubCodecs = new Set(['hdmv_pgs_subtitle', 'pgssub', 'dvd_subtitle', 'dvdsub', 'dvb_subtitle', 'dvbsub', 'xsub']);
      const subtitleTracksOut = [];
      subtitleStreams.forEach((s, idx) => {
        const scodec = String(s.codec_name || 'unknown').toLowerCase();
        if (bitmapSubCodecs.has(scodec)) return;
        const tags = s.tags || {};
        const disp = s.disposition || {};
        subtitleTracksOut.push({
          index: idx,
          stream_index: s.index !== undefined ? s.index : idx,
          codec: scodec,
          language: tags.language || tags.LANGUAGE || '',
          title: tags.title || tags.TITLE || '',
          forced: Boolean(disp.forced),
          default: Boolean(disp.default),
        });
      });

      const parseDur = (val) => {
        if (!val) return 0;
        const n = parseFloat(val);
        if (Number.isFinite(n) && n > 0 && !String(val).includes(':')) return n;
        const m = /^(\d+):(\d{1,2}):(\d{1,2}(?:\.\d+)?)/.exec(String(val).trim());
        if (m) return parseInt(m[1], 10) * 3600 + parseInt(m[2], 10) * 60 + parseFloat(m[3]);
        return Number.isFinite(n) && n > 0 ? n : 0;
      };
      let maxDur = parseDur(fmt.duration);
      for (const s of streams) {
        maxDur = Math.max(maxDur, parseDur(s.duration));
        const stTags = s.tags || {};
        for (const [k, v] of Object.entries(stTags)) {
          if (String(k).toLowerCase().startsWith('duration')) maxDur = Math.max(maxDur, parseDur(v));
        }
      }

      resolve({
        has_video: hasVideo,
        video_codec: videoCodec,
        video_pix_fmt: videoPixFmt,
        has_audio: hasAudio,
        audio_codec: audioCodec,
        audio_channels: audioChannels,
        audio_streams: audioTracksOut,
        subtitle_streams: subtitleTracksOut,
        duration: maxDur,
        needs_audio_transcode: needsAudioTranscode,
        needs_video_transcode: needsVideoTranscode,
        can_remux_video: canRemuxVideo,
        recommended_mode: recommendedMode,
      });
    });
  });
}

function streamSubtitleResponse(req, res, item) {
  const blobPath = resolveItemBlobPath(item);
  if (!blobPath) {
    res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end('WEBVTT\n\n');
  }
  const track = Math.max(0, parseInt(req.query.track || '0', 10) || 0);
  const startTime = Math.max(0, parseFloat(req.query.ss || '0') || 0);
  const args = ['-hide_banner', '-loglevel', 'error'];
  if (startTime > 0) {
    args.push('-ss', String(startTime));
  }
  args.push('-i', blobPath, '-map', `0:s:${track}`, '-c:s', 'webvtt', '-f', 'webvtt', 'pipe:1');
  const ff = spawn('ffmpeg', args);
  let out = '';
  ff.stdout.on('data', (d) => { out += d.toString('utf-8'); });
  ff.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end('WEBVTT\n\n');
    }
  });
  ff.on('close', () => {
    if (!res.headersSent) {
      res.writeHead(200, { 'Content-Type': 'text/vtt; charset=utf-8', 'Cache-Control': 'no-cache' });
      res.end(out && out.includes('WEBVTT') ? out : 'WEBVTT\n\n');
    }
  });
  req.on('close', () => {
    try { ff.kill('SIGKILL'); } catch (_) {}
  });
}

function patchMp4MoovDuration(chunk, durationSec) {
  if (!chunk || !durationSec || durationSec <= 0 || !Number.isFinite(durationSec)) return chunk;
  try {
    let buf = Buffer.from(chunk);
    let mvhdTs = 1000;
    const walk = (b, start, end) => {
      let pos = start;
      while (pos + 8 <= end) {
        const sz = b.readUInt32BE(pos);
        const btype = b.subarray(pos + 4, pos + 8).toString('ascii');
        if (sz < 8 || pos + sz > end) break;
        if (btype === 'mvhd') {
          const ver = b[pos + 8];
          if (ver === 0 && sz >= 28) {
            mvhdTs = b.readUInt32BE(pos + 20) || 1000;
            b.writeUInt32BE(Math.min(0xFFFFFFFF, Math.round(durationSec * mvhdTs)), pos + 24);
          }
        } else if (btype === 'tkhd') {
          const ver = b[pos + 8];
          if (ver === 0 && sz >= 32) {
            b.writeUInt32BE(Math.min(0xFFFFFFFF, Math.round(durationSec * mvhdTs)), pos + 28);
          }
        } else if (btype === 'mdhd') {
          const ver = b[pos + 8];
          if (ver === 0 && sz >= 28) {
            const ts = b.readUInt32BE(pos + 20) || 1000;
            b.writeUInt32BE(Math.min(0xFFFFFFFF, Math.round(durationSec * ts)), pos + 24);
          }
        } else if (btype === 'moov' || btype === 'trak' || btype === 'mdia') {
          walk(b, pos + 8, pos + sz);
        } else if (btype === 'moof') {
          break;
        }
        pos += sz;
      }
    };
    walk(buf, 0, buf.length);
    return buf;
  } catch (_) {
    return chunk;
  }
}

// Unified streaming & Range response handler for both SMB and Google Drive files
async function streamFileResponse(req, res, item) {
  if (!item || item.type === 'folder') {
    return res.status(404).json({ error: 'File not found' });
  }

  const blobPath = resolveItemBlobPath(item);
  if (!blobPath) {
    return res.status(404).json({ error: 'File content not found on disk' });
  }

  const stat = fs.statSync(blobPath);
  const fileSize = stat.size;
  const filename = item.name || 'download';
  const disposition = makeDispositionHeader(filename, Boolean(req.query.dl));

  if (req.query.transcode === '1') {
    let mode = String(req.query.mode || 'auto');
    const audioTrack = Math.max(0, parseInt(req.query.audio_track || '0', 10) || 0);
    const startTime = parseFloat(req.query.ss || '0') || 0;
    const durationHint = parseFloat(req.query.duration || '0') || 0;
    const probeInfo = await probeMediaItem(item);
    if (mode === 'auto') {
      mode = probeInfo.can_remux_video ? 'remux' : 'full';
    }
    const totalDur = probeInfo.duration || durationHint || 0;
    const effectiveDur = totalDur > 0 ? Math.max(0, totalDur - startTime) : 0;

    res.writeHead(200, {
      'Content-Type': 'video/mp4',
      'Content-Disposition': disposition,
      'Cache-Control': 'no-cache',
    });

    const args = ['-hide_banner', '-loglevel', 'error'];
    if (startTime > 0) {
      if (mode === 'remux') args.push('-noaccurate_seek');
      args.push('-ss', String(startTime));
    }
    args.push('-i', blobPath, '-map', '0:V:0', '-map', `0:a:${audioTrack}?`, '-sn', '-dn');
    if (mode === 'remux') {
      const vtag = probeInfo.video_codec === 'hevc' ? 'hvc1' : 'avc1';
      args.push('-c:v', 'copy', '-tag:v', vtag);
    } else {
      args.push(
        '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p',
        '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p'
      );
    }
    const afFilter = (mode === 'remux' && startTime > 0) ? 'aresample=async=1' : 'aresample=async=1:first_pts=0';
    args.push(
      '-af', afFilter,
      '-c:a', 'aac', '-ac', '2', '-ar', '48000', '-b:a', '192k',
      '-avoid_negative_ts', 'make_zero',
      '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
      '-f', 'mp4',
      'pipe:1'
    );

    const ff = spawn('ffmpeg', args);
    let patchedFirst = false;
    ff.stdout.on('data', (chunk) => {
      if (!patchedFirst) {
        patchedFirst = true;
        res.write(patchMp4MoovDuration(chunk, effectiveDur));
      } else {
        res.write(chunk);
      }
    });
    ff.stdout.on('end', () => res.end());
    req.on('close', () => {
      try { ff.kill('SIGKILL'); } catch (_) {}
    });
    return;
  }

  if (req.query.transcode === 'audio') {
    const startTime = parseFloat(req.query.ss || '0') || 0;
    res.writeHead(200, {
      'Content-Type': 'audio/mpeg',
      'Content-Disposition': disposition,
      'Cache-Control': 'no-cache',
    });
    const args = ['-hide_banner', '-loglevel', 'error'];
    if (startTime > 0) args.push('-ss', String(startTime));
    args.push(
      '-i', blobPath,
      '-vn',
      '-af', 'aresample=async=1:first_pts=0',
      '-c:a', 'libmp3lame', '-ac', '2', '-ar', '48000', '-b:a', '192k',
      '-f', 'mp3',
      'pipe:1'
    );
    const ff = spawn('ffmpeg', args);
    ff.stdout.pipe(res);
    req.on('close', () => {
      try { ff.kill('SIGKILL'); } catch (_) {}
    });
    return;
  }

  const mime = getMimeType(filename, item.mimeType);
  const rangeHeader = req.headers.range;

  if (rangeHeader && fileSize > 0) {
    const m = /bytes=(\d*)-(\d*)/.exec(rangeHeader);
    if (!m) {
      res.setHeader('Content-Range', `bytes */${fileSize}`);
      return res.status(416).end();
    }

    let start = m[1] ? parseInt(m[1], 10) : 0;
    let end = m[2] ? parseInt(m[2], 10) : fileSize - 1;

    if (!m[1] && m[2]) {
      const suffixLength = parseInt(m[2], 10);
      start = Math.max(0, fileSize - suffixLength);
      end = fileSize - 1;
    }

    if (isNaN(start) || isNaN(end) || start >= fileSize || start > end) {
      res.setHeader('Content-Range', `bytes */${fileSize}`);
      return res.status(416).end();
    }

    end = Math.min(end, fileSize - 1);
    const chunkLength = end - start + 1;

    res.writeHead(206, {
      'Content-Range': `bytes ${start}-{end}/${fileSize}`.replace('{end}', String(end)),
      'Accept-Ranges': 'bytes',
      'Content-Length': String(chunkLength),
      'Content-Type': mime,
      'Content-Disposition': disposition,
      'Cache-Control': 'no-cache',
    });

    if (req.method === 'HEAD') {
      return res.end();
    }

    const stream = fs.createReadStream(blobPath, { start, end, highWaterMark: 64 * 1024 });
    req.on('close', () => stream.destroy());
    stream.on('error', () => {
      if (!res.headersSent) res.status(500).end();
      else res.end();
    });
    return stream.pipe(res);
  }

  res.writeHead(200, {
    'Content-Length': String(fileSize),
    'Accept-Ranges': 'bytes',
    'Content-Type': mime,
    'Content-Disposition': disposition,
    'Cache-Control': 'no-cache',
  });

  if (req.method === 'HEAD' || fileSize === 0) {
    return res.end();
  }

  const stream = fs.createReadStream(blobPath, { highWaterMark: 64 * 1024 });
  req.on('close', () => stream.destroy());
  stream.on('error', () => {
    if (!res.headersSent) res.status(500).end();
    else res.end();
  });
  return stream.pipe(res);
}

const VALID_THEMES = new Set(['obsidian', 'midnight', 'amethyst', 'emerald', 'ember']);
const DEFAULT_THEME = 'obsidian';

function getUserTheme(username) {
  const users = loadJson(USERS_FILE, {});
  const user = users[String(username || '').trim()] || {};
  let t = String(user.theme || DEFAULT_THEME).trim().toLowerCase();
  if (t === 'dark') t = DEFAULT_THEME;
  return VALID_THEMES.has(t) ? t : DEFAULT_THEME;
}

// ── Auth (with 5-Strike / 15-Minute Anti-Hammering Lockout) ───────────────────
app.post('/api/auth/login', (req, res) => {
  const body = req.body || {};
  const u = String(body.username || '').trim();
  const pw = String(body.password || '');
  const nowSec = Date.now() / 1000;

  const users = loadJson(USERS_FILE, {});
  const user = users[u];
  const record = user || unknownLockouts.get(u || '_anon_') || { failed_attempts: 0, locked_until: 0 };
  if (!user) unknownLockouts.set(u || '_anon_', record);

  const lockedUntil = Number(record.locked_until || 0);
  if (lockedUntil > nowSec) {
    const rem = Math.ceil(lockedUntil - nowSec);
    const mins = Math.max(1, Math.ceil(rem / 60));
    return res.status(429).json({
      error: `Account locked due to ${MAX_FAILED_ATTEMPTS} failed login attempts. Try again in ${mins} minute${mins !== 1 ? 's' : ''} (${rem}s).`,
      locked: true,
      retry_after: rem,
      attempts_remaining: 0,
    });
  }

  if (lockedUntil > 0 && lockedUntil <= nowSec) {
    record.locked_until = 0;
    record.failed_attempts = 0;
    if (user) saveJson(USERS_FILE, users);
  }

  if (user && bcrypt.compareSync(pw, user.hash)) {
    if (user.failed_attempts || user.locked_until) {
      user.failed_attempts = 0;
      user.locked_until = 0;
      saveJson(USERS_FILE, users);
    }
    const token = crypto.randomBytes(32).toString('hex');
    const theme = getUserTheme(u);
    sessionsMap.set(token, {
      username: u,
      role: user.role,
      theme,
      admin_enabled: false,
      expires: Date.now() + SESSION_TTL,
    });
    persistSessions();
    res.setHeader(
      'Set-Cookie',
      `sd_token=${encodeURIComponent(token)}; Path=/; Max-Age=${Math.floor(SESSION_TTL / 1000)}; HttpOnly; SameSite=Lax`
    );
    return res.json({ token, theme, admin_enabled: false });
  }

  const fails = Number(record.failed_attempts || 0) + 1;
  record.failed_attempts = fails;

  if (fails >= MAX_FAILED_ATTEMPTS) {
    record.locked_until = nowSec + LOCKOUT_SECONDS;
    if (user) saveJson(USERS_FILE, users);
    return res.status(429).json({
      error: `Account locked for 15 minutes due to ${MAX_FAILED_ATTEMPTS} incorrect login attempts.`,
      locked: true,
      retry_after: LOCKOUT_SECONDS,
      attempts_remaining: 0,
    });
  }

  if (user) saveJson(USERS_FILE, users);
  const remTries = MAX_FAILED_ATTEMPTS - fails;
  return res.status(401).json({
    error: `Invalid credentials (${remTries} attempt${remTries !== 1 ? 's' : ''} remaining before 15m lockout)`,
    locked: false,
    attempts_remaining: remTries,
  });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  sessionsMap.delete(req.token);
  persistSessions();
  res.setHeader('Set-Cookie', 'sd_token=; Path=/; Max-Age=0');
  return res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const theme = getUserTheme(req.session.username);
  return res.json({
    username: req.session.username,
    role: req.session.role,
    theme,
    admin_enabled: Boolean(req.session.admin_enabled),
  });
});

app.post('/api/auth/admin-mode', requireAuth, (req, res) => {
  const b = req.body || {};
  const enabled = Boolean(b.enabled);
  const pin = String(b.pin || '').trim();
  if (enabled) {
    if (pin !== ADMIN_PIN) {
      return res.status(403).json({ error: 'Invalid Administrator PIN' });
    }
    req.session.admin_enabled = true;
  } else {
    req.session.admin_enabled = false;
  }
  persistSessions();
  return res.json({ ok: true, admin_enabled: Boolean(req.session.admin_enabled) });
});

app.post('/api/auth/theme', requireAuth, (req, res) => {
  const rawTheme = String((req.body && req.body.theme) || DEFAULT_THEME).trim().toLowerCase();
  if (!VALID_THEMES.has(rawTheme)) {
    return res.status(400).json({ error: `Invalid theme '${rawTheme}'` });
  }
  const users = loadJson(USERS_FILE, {});
  const uname = req.session.username;
  if (!users[uname]) {
    return res.status(404).json({ error: 'User not found' });
  }
  users[uname].theme = rawTheme;
  saveJson(USERS_FILE, users);
  req.session.theme = rawTheme;
  persistSessions();
  return res.json({ ok: true, theme: rawTheme });
});

// ── SMB Helpers & Routes ──────────────────────────────────────────────────────
function listShares() {
  return loadJson(SHARES_FILE, []);
}

function sanitizeSmbPath(rawPath, allowRoot = true) {
  const raw = String(rawPath || '').replace(/\0/g, '').replace(/\\/g, '/').trim();
  const parts = [];
  for (const seg of raw.split('/')) {
    const s = seg.trim();
    if (!s || s === '.') continue;
    if (s === '..') {
      throw new Error("Invalid SMB path: path traversal ('..') is not allowed");
    }
    parts.push(s);
  }
  if (!parts.length) {
    if (allowRoot) return '/';
    throw new Error('SMB path cannot be empty');
  }
  return '/' + parts.join('/');
}

function ensureSmbParentDirs(entries, fullFilePath) {
  const parts = fullFilePath.split('/').filter(Boolean);
  let built = '';
  for (let i = 0; i < parts.length - 1; i++) {
    built += '/' + parts[i];
    if (!entries[built]) {
      entries[built] = {
        name: parts[i],
        type: 'folder',
        size: 0,
        modified: Math.floor(Date.now() / 1000),
        path: built,
      };
    }
  }
}

app.get('/api/smb/shares', requireAuth, (req, res) => {
  const shares = listShares().map(({ password, ...rest }) => rest);
  return res.json(shares);
});

app.post('/api/smb/shares', requireAdmin, (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.host || !b.share) {
    return res.status(400).json({ error: 'name, host, and share are required' });
  }
  let shares = listShares();
  const baseSid = String(b.name).trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'smb_share';
  let sid = baseSid;
  const conflict = shares.find((s) => s.id === sid && (s.host !== b.host || s.share !== b.share));
  if (conflict) {
    sid = `${baseSid}_${crypto.randomBytes(2).toString('hex')}`;
  }
  shares = shares.filter((s) => s.id !== sid);
  const customName = String(b.custom_name || '').trim();
  const dispName = customName || String(b.name).trim();
  const entry = {
    id: sid,
    name: dispName,
    custom_name: customName,
    original_name: String(b.name).trim(),
    host: b.host,
    share: b.share,
    username: b.username || '',
    password: b.password || '',
    port: parseInt(b.port || 445, 10) || 445,
  };
  shares.push(entry);
  saveJson(SHARES_FILE, shares);
  ensureShareFS(sid);
  const { password, ...safeEntry } = entry;
  return res.status(201).json(safeEntry);
});

app.post('/api/smb/shares/:share_id/rename', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const newName = String(b.name || b.custom_name || '').trim();
  if (!newName) {
    return res.status(400).json({ error: 'Custom name cannot be empty' });
  }
  const shares = listShares();
  const target = shares.find((s) => s.id === share_id);
  if (!target) {
    return res.status(404).json({ error: `Share '${share_id}' not found` });
  }
  if (!target.original_name) {
    target.original_name = target.name || target.share;
  }
  target.name = newName;
  target.custom_name = newName;
  saveJson(SHARES_FILE, shares);
  const { password, ...safeEntry } = target;
  return res.json(safeEntry);
});

app.delete('/api/smb/shares/:share_id', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const shares = listShares().filter((s) => s.id !== share_id);
  saveJson(SHARES_FILE, shares);
  delete smbFSData[share_id];
  saveSmbFS();
  return res.json({ ok: true });
});

app.get('/api/smb/browse/:share_id', requireAuth, (req, res) => {
  const { share_id } = req.params;
  const share = listShares().find((s) => s.id === share_id);
  if (!share) {
    return res.status(404).json({ error: `Share '${share_id}' not found` });
  }
  const dirPath = (req.query.path || '/').replace(/\/+$/, '') || '/';
  const entries = ensureShareFS(share_id);
  const results = [];
  for (const [entryPath, item] of Object.entries(entries)) {
    const parentDir = path.posix.dirname(entryPath);
    if (parentDir === dirPath) {
      results.push({
        name: item.name,
        type: item.type,
        size: item.size || 0,
        modified: item.modified,
        path: item.path,
      });
    }
  }
  return res.json(results);
});

app.get('/api/smb/probe/:share_id', requireAuth, async (req, res) => {
  const { share_id } = req.params;
  const filePath = req.query.path || '';
  const entries = ensureShareFS(share_id);
  const item = entries[filePath];
  if (!item) return res.status(404).json({ error: 'File not found' });
  const info = await probeMediaItem(item);
  return res.json(info);
});

app.get('/api/smb/subtitles/:share_id', requireAuth, (req, res) => {
  const { share_id } = req.params;
  const filePath = req.query.path || '';
  const entries = ensureShareFS(share_id);
  const item = entries[filePath];
  if (!item) return res.status(404).json({ error: 'File not found' });
  return streamSubtitleResponse(req, res, item);
});

app.get('/api/smb/download/:share_id', requireAuth, (req, res) => {
  const { share_id } = req.params;
  const filePath = req.query.path || '';
  const entries = ensureShareFS(share_id);
  const item = entries[filePath];
  return streamFileResponse(req, res, item);
});

app.post('/api/smb/upload/:share_id', requireAdmin, upload.single('file'), (req, res) => {
  const { share_id } = req.params;
  const f = req.file;
  if (!f) {
    return res.status(400).json({ error: 'No file provided' });
  }
  try {
    const dest = sanitizeSmbPath(req.query.path || '/', true);
    const relPath = String(req.body?.relative_path || req.query?.relative_path || '').trim().replace(/^\/+/, '');
    const entries = ensureShareFS(share_id);
    const subPath = relPath || f.originalname;
    const fullPath = sanitizeSmbPath(`${dest.replace(/\/+$/, '')}/${subPath}`, false);
    ensureSmbParentDirs(entries, fullPath);
    const actualName = path.posix.basename(fullPath);
    entries[fullPath] = {
      name: actualName,
      type: 'file',
      size: f.size,
      modified: Math.floor(Date.now() / 1000),
      path: fullPath,
      blobPath: f.path,
      mimeType: getMimeType(actualName, f.mimetype),
    };
    saveSmbFS();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.put('/api/smb/content/:share_id', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const rawPath = b.path || req.query.path || '';
  if (b.content === undefined || b.content === null) {
    return res.status(400).json({ error: 'content is required' });
  }
  try {
    const fullPath = sanitizeSmbPath(rawPath, false);
    const entries = ensureShareFS(share_id);
    ensureSmbParentDirs(entries, fullPath);
    const actualName = path.posix.basename(fullPath);
    const buf = Buffer.from(String(b.content), 'utf-8');
    const existing = entries[fullPath];
    const blobPath =
      existing?.blobPath && !existing.blobPath.includes('sample_')
        ? existing.blobPath
        : path.join(BLOBS_DIR, `edit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.txt`);
    fs.writeFileSync(blobPath, buf);
    entries[fullPath] = {
      name: actualName,
      type: 'file',
      size: buf.length,
      modified: Math.floor(Date.now() / 1000),
      path: fullPath,
      blobPath,
      mimeType: getMimeType(actualName, existing?.mimeType || 'text/plain'),
    };
    saveSmbFS();
    return res.json({ ok: true, path: fullPath, size: buf.length });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/api/smb/rename/:share_id', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const oldPath = String(b.path || '').replace(/\/+$/, '');
  const newName = String(b.new_name || '').trim();
  if (!oldPath || !newName) {
    return res.status(400).json({ error: 'path and new_name are required' });
  }
  const entries = ensureShareFS(share_id);
  const item = entries[oldPath];
  if (!item) {
    return res.status(404).json({ error: 'Item not found' });
  }
  const parentDir = path.posix.dirname(oldPath);
  const newPath = parentDir === '/' ? `/${newName}` : `${parentDir}/${newName}`;
  if (entries[newPath] && newPath !== oldPath) {
    return res.status(400).json({ error: 'An item with that name already exists' });
  }

  delete entries[oldPath];
  entries[newPath] = {
    ...item,
    name: newName,
    path: newPath,
    modified: Math.floor(Date.now() / 1000),
  };

  if (item.type === 'folder') {
    const oldPrefix = oldPath + '/';
    const newPrefix = newPath + '/';
    for (const [k, child] of Object.entries(entries)) {
      if (k.startsWith(oldPrefix)) {
        const updatedChildPath = newPrefix + k.slice(oldPrefix.length);
        delete entries[k];
        entries[updatedChildPath] = {
          ...child,
          path: updatedChildPath,
        };
      }
    }
  }

  saveSmbFS();
  return res.json({ ok: true, path: newPath });
});

app.post('/api/smb/zip/:share_id', requireAuth, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const reqPaths = Array.isArray(b.paths) ? b.paths : [];
  if (!reqPaths.length) {
    return res.status(400).json({ error: 'No paths provided' });
  }
  const entries = ensureShareFS(share_id);
  const zipItems = [];

  function addSmbPathToZip(smbPath, arcPrefix) {
    const norm = smbPath.replace(/\/+$/, '');
    const item = entries[norm];
    if (!item) return;
    if (item.type === 'folder') {
      const prefix = norm + '/';
      const children = Object.values(entries).filter((c) => path.posix.dirname(c.path) === norm);
      if (children.length === 0) {
        zipItems.push({ arcPath: arcPrefix, isDir: true });
      } else {
        for (const ch of children) {
          addSmbPathToZip(ch.path, `${arcPrefix}/${ch.name}`);
        }
      }
    } else {
      zipItems.push({
        arcPath: arcPrefix,
        data: getItemBuffer(item),
      });
    }
  }

  for (const p of reqPaths) {
    const norm = String(p || '').replace(/\/+$/, '');
    const base = path.posix.basename(norm) || 'folder';
    addSmbPathToZip(norm, base);
  }

  const zipBuf = buildZipBuffer(zipItems);
  const archiveName = b.name || 'SageDrive_Download.zip';
  res.writeHead(200, {
    'Content-Type': 'application/zip',
    'Content-Length': String(zipBuf.length),
    'Content-Disposition': makeDispositionHeader(archiveName, true),
    'Cache-Control': 'no-cache',
  });
  return res.end(zipBuf);
});

app.delete('/api/smb/delete/:share_id', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const targetPath = b.path || '';
  const entries = ensureShareFS(share_id);
  delete entries[targetPath];
  if (b.is_dir) {
    const prefix = targetPath.replace(/\/+$/, '') + '/';
    for (const k of Object.keys(entries)) {
      if (k.startsWith(prefix)) delete entries[k];
    }
  }
  saveSmbFS();
  return res.json({ ok: true });
});

app.post('/api/smb/mkdir/:share_id', requireAdmin, (req, res) => {
  const { share_id } = req.params;
  const b = req.body || {};
  const rawPath = (b.path || '').replace(/\/+$/, '');
  if (!rawPath) {
    return res.status(400).json({ error: 'Path required' });
  }
  const entries = ensureShareFS(share_id);
  ensureSmbParentDirs(entries, rawPath + '/placeholder');
  saveSmbFS();
  return res.json({ ok: true });
});

// ── Google Drive Helpers & Routes (Multi-Account) ─────────────────────────────
function getGDriveConfig() {
  const defaults = {
    client_id: process.env.GOOGLE_CLIENT_ID || '',
    client_secret: process.env.GOOGLE_CLIENT_SECRET || '',
    redirect_uri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/api/gdrive/callback',
  };
  const stored = loadJson(GDRIVE_CONFIG_FILE, {});
  return {
    client_id: stored.client_id || defaults.client_id,
    client_secret: stored.client_secret || defaults.client_secret,
    redirect_uri: stored.redirect_uri || defaults.redirect_uri,
  };
}

function isGDriveConfigured() {
  const cfg = getGDriveConfig();
  return Boolean(cfg.client_id && cfg.client_secret && cfg.redirect_uri);
}

const RESERVED_SMB_NAMES = new Set(['global', 'homes', 'printers', 'print$', 'ipc$']);

function sanitizeSmbShareName(rawName, fallback = 'GoogleDrive') {
  let cleaned = String(rawName || '')
    .trim()
    .replace(/[^A-Za-z0-9_-]+/g, '_')
    .replace(/^[_-]+|[_-]+$/g, '');
  if (!cleaned || RESERVED_SMB_NAMES.has(cleaned.toLowerCase())) {
    cleaned = fallback;
  }
  return cleaned.slice(0, 32);
}

function ensureSmbProxyFields(accounts) {
  const used = new Set();
  let changed = false;
  accounts.forEach((a, idx) => {
    if (typeof a.smb_enabled !== 'boolean') {
      a.smb_enabled = true;
      changed = true;
    }
    const rawShare = String(a.smb_share_name || '').trim();
    if (!rawShare) {
      const defaultBase =
        idx === 0 || a.id === 'default'
          ? 'GoogleDrive'
          : a.custom_name || a.name || `GoogleDrive_${idx + 1}`;
      let candidate = sanitizeSmbShareName(defaultBase, `GoogleDrive_${idx + 1}`);
      const baseCand = candidate;
      let suffix = 2;
      while (used.has(candidate.toLowerCase())) {
        candidate = `${baseCand.slice(0, 28)}_${suffix}`;
        suffix++;
      }
      a.smb_share_name = candidate;
      changed = true;
    } else {
      let sanitized = sanitizeSmbShareName(rawShare, `GoogleDrive_${idx + 1}`);
      if (used.has(sanitized.toLowerCase())) {
        sanitized = `${sanitized.slice(0, 28)}_${idx + 1}`;
      }
      if (sanitized !== rawShare) {
        a.smb_share_name = sanitized;
        changed = true;
      }
    }
    used.add(a.smb_share_name.toLowerCase());
  });
  return changed;
}

function loadGDriveAccountsRaw() {
  const list = loadJson(GDRIVE_ACCOUNTS_FILE, null);
  if (Array.isArray(list)) {
    if (ensureSmbProxyFields(list)) {
      saveJson(GDRIVE_ACCOUNTS_FILE, list);
    }
    return list;
  }
  const legacy = loadJson(GDRIVE_CREDS_FILE, null);
  if (legacy && legacy.token) {
    const migrated = [
      {
        id: 'default',
        name: 'Google Drive',
        custom_name: '',
        original_name: 'Google Drive',
        email: legacy.email || 'user@gmail.com',
        smb_enabled: true,
        smb_share_name: 'GoogleDrive',
        creds: legacy,
      },
    ];
    saveJson(GDRIVE_ACCOUNTS_FILE, migrated);
    return migrated;
  }
  return [];
}

function saveGDriveAccountsRaw(accounts) {
  ensureSmbProxyFields(accounts);
  saveJson(GDRIVE_ACCOUNTS_FILE, accounts);
  if (accounts.length > 0 && accounts[0].creds) {
    saveJson(GDRIVE_CREDS_FILE, accounts[0].creds);
  } else {
    try {
      if (fs.existsSync(GDRIVE_CREDS_FILE)) fs.unlinkSync(GDRIVE_CREDS_FILE);
    } catch (_) {}
  }
}

function listGDriveAccounts() {
  return loadGDriveAccountsRaw().map((a) => ({
    id: a.id,
    name: a.custom_name || a.name || 'Google Drive',
    custom_name: a.custom_name || '',
    original_name: a.original_name || a.name || 'Google Drive',
    email: a.email || '',
    smb_enabled: Boolean(a.smb_enabled ?? true),
    smb_share_name: a.smb_share_name || 'GoogleDrive',
  }));
}

function resolveGDriveAccountId(rawId) {
  const accounts = loadGDriveAccountsRaw();
  if (!accounts.length) return 'default';
  if (!rawId || rawId === 'root' || rawId === 'default') {
    const def = accounts.find((a) => a.id === 'default');
    return def ? def.id : accounts[0].id;
  }
  const found = accounts.find((a) => a.id === rawId);
  return found ? found.id : accounts[0].id;
}

function isGDriveAuthenticated() {
  return loadGDriveAccountsRaw().length > 0;
}

function ensureGDriveAccountSeeded(accountId) {
  const accId = resolveGDriveAccountId(accountId);
  const hasAny = Object.values(gdriveFSData).some((f) => (f.accountId || 'default') === accId);
  if (hasAny) return;
  const now = new Date().toISOString();
  const suffix = accId === 'default' ? '' : `_${accId}`;
  gdriveFSData[`folder-docs${suffix}`] = {
    id: `folder-docs${suffix}`,
    accountId: accId,
    name: 'Documents',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.google-apps.folder',
    parent: 'root',
  };
  gdriveFSData[`folder-media${suffix}`] = {
    id: `folder-media${suffix}`,
    accountId: accId,
    name: 'Media',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.google-apps.folder',
    parent: 'root',
  };
  const readmePath = path.join(BLOBS_DIR, 'gdrive_welcome.txt');
  if (fs.existsSync(readmePath)) {
    gdriveFSData[`file-readme${suffix}`] = {
      id: `file-readme${suffix}`,
      accountId: accId,
      name: 'Welcome.txt',
      type: 'file',
      size: fs.statSync(readmePath).size,
      modified: now,
      mimeType: 'text/plain',
      parent: 'root',
      blobPath: readmePath,
    };
  }
  if (fs.existsSync(SAMPLE_WAV_PATH)) {
    gdriveFSData[`file-sample-audio${suffix}`] = {
      id: `file-sample-audio${suffix}`,
      accountId: accId,
      name: 'Sample_Audio.wav',
      type: 'file',
      size: fs.statSync(SAMPLE_WAV_PATH).size,
      modified: now,
      mimeType: 'audio/wav',
      parent: 'root',
      blobPath: SAMPLE_WAV_PATH,
    };
  }
  if (fs.existsSync(SAMPLE_MP4_PATH) && fs.statSync(SAMPLE_MP4_PATH).size > 0) {
    gdriveFSData[`file-sample-video${suffix}`] = {
      id: `file-sample-video${suffix}`,
      accountId: accId,
      name: 'Sample_Video.mp4',
      type: 'file',
      size: fs.statSync(SAMPLE_MP4_PATH).size,
      modified: now,
      mimeType: 'video/mp4',
      parent: 'root',
      blobPath: SAMPLE_MP4_PATH,
    };
  }
  saveGDriveFS();
}

function ensureGDriveFolderPath(baseFolderId, parts, accountId = 'default') {
  const accId = resolveGDriveAccountId(accountId);
  let currId = baseFolderId || 'root';
  for (const part of parts) {
    if (!part) continue;
    const existing = Object.values(gdriveFSData).find(
      (f) => (f.accountId || 'default') === accId && f.parent === currId && f.type === 'folder' && f.name === part
    );
    if (existing) {
      currId = existing.id;
    } else {
      const newId = 'folder-' + crypto.randomBytes(6).toString('hex');
      gdriveFSData[newId] = {
        id: newId,
        accountId: accId,
        name: part,
        type: 'folder',
        size: 0,
        modified: new Date().toISOString(),
        mimeType: 'application/vnd.google-apps.folder',
        parent: currId,
      };
      currId = newId;
    }
  }
  return currId;
}

app.get('/api/gdrive/status', requireAuth, (req, res) => {
  return res.json({
    configured: isGDriveConfigured(),
    authenticated: isGDriveAuthenticated(),
    accounts: listGDriveAccounts(),
  });
});

app.get('/api/gdrive/accounts', requireAuth, (req, res) => {
  return res.json(listGDriveAccounts());
});

app.post('/api/gdrive/accounts/:account_id/rename', requireAdmin, (req, res) => {
  const { account_id } = req.params;
  const b = req.body || {};
  const newName = String(b.name || b.custom_name || '').trim();
  if (!newName) {
    return res.status(400).json({ error: 'Custom name cannot be empty' });
  }
  const accounts = loadGDriveAccountsRaw();
  const target = accounts.find(
    (a) => a.id === account_id || ((account_id === 'root' || account_id === 'default') && a === accounts[0])
  );
  if (!target) {
    return res.status(404).json({ error: `Google Drive account '${account_id}' not found` });
  }
  if (!target.original_name) target.original_name = target.name || 'Google Drive';
  target.name = newName;
  target.custom_name = newName;
  saveGDriveAccountsRaw(accounts);
  return res.json({
    id: target.id,
    name: target.name,
    custom_name: target.custom_name,
    email: target.email || '',
  });
});

app.delete('/api/gdrive/accounts/:account_id', requireAdmin, (req, res) => {
  const { account_id } = req.params;
  const accounts = loadGDriveAccountsRaw().filter((a) => a.id !== account_id);
  saveGDriveAccountsRaw(accounts);
  return res.json({ ok: true });
});

app.get('/api/gdrive/config', requireAuth, (req, res) => {
  return res.json(getGDriveConfig());
});

app.post('/api/gdrive/config', requireAdmin, (req, res) => {
  const b = req.body || {};
  const cfg = {
    client_id: String(b.client_id || '').trim(),
    client_secret: String(b.client_secret || '').trim(),
    redirect_uri: String(b.redirect_uri || '').trim() || 'http://localhost:3000/api/gdrive/callback',
  };
  saveJson(GDRIVE_CONFIG_FILE, cfg);
  return res.json({ ok: true, configured: isGDriveConfigured() });
});

app.get('/api/gdrive/auth', requireAdmin, (req, res) => {
  if (!isGDriveConfigured()) {
    return res.status(400).json({ error: 'Google OAuth not configured' });
  }
  const name = encodeURIComponent(String(req.query.name || '').trim());
  const accountId = encodeURIComponent(String(req.query.account_id || '').trim());
  return res.json({
    url: `/api/gdrive/callback?code=preview_oauth_code&name=${name}&account_id=${accountId}`,
  });
});

app.get('/api/gdrive/callback', (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Missing code');
  }
  const cfg = getGDriveConfig();
  const customName = String(req.query.name || '').trim();
  const accountId = String(req.query.account_id || '').trim();
  const accounts = loadGDriveAccountsRaw();
  const creds = {
    token: 'gdrive_access_' + crypto.randomBytes(8).toString('hex'),
    refresh_token: 'gdrive_refresh_' + crypto.randomBytes(8).toString('hex'),
    client_id: cfg.client_id,
    client_secret: cfg.client_secret,
  };

  let target = accountId ? accounts.find((a) => a.id === accountId) : null;
  if (target) {
    target.creds = creds;
    if (customName) {
      target.name = customName;
      target.custom_name = customName;
    }
  } else {
    const newId = accounts.length === 0 ? 'default' : `gdrive_${crypto.randomBytes(3).toString('hex')}`;
    const idx = accounts.length + 1;
    const defaultLabel = idx === 1 ? 'Google Drive' : `Google Drive ${idx}`;
    const dispName = customName || defaultLabel;
    accounts.push({
      id: newId,
      name: dispName,
      custom_name: customName,
      original_name: defaultLabel,
      email: idx === 1 ? 'primary@gmail.com' : `drive${idx}@gmail.com`,
      creds,
    });
    ensureGDriveAccountSeeded(newId);
  }
  saveGDriveAccountsRaw(accounts);
  return res.redirect('/#gdrive-connected');
});

app.delete('/api/gdrive/revoke', requireAdmin, (req, res) => {
  const accountId = String(req.query.account_id || '').trim();
  if (accountId) {
    const accounts = loadGDriveAccountsRaw().filter((a) => a.id !== accountId);
    saveGDriveAccountsRaw(accounts);
  } else {
    saveGDriveAccountsRaw([]);
  }
  return res.json({ ok: true });
});

app.get('/api/gdrive/files', requireAuth, (req, res) => {
  const folderId = req.query.folder || 'root';
  const accId = resolveGDriveAccountId(req.query.account_id);
  ensureGDriveAccountSeeded(accId);

  if (
    accId === 'default' &&
    !gdriveFSData['file-sample-video'] &&
    fs.existsSync(SAMPLE_MP4_PATH) &&
    fs.statSync(SAMPLE_MP4_PATH).size > 0
  ) {
    gdriveFSData['file-sample-video'] = {
      id: 'file-sample-video',
      accountId: 'default',
      name: 'Sample_Video.mp4',
      type: 'file',
      size: fs.statSync(SAMPLE_MP4_PATH).size,
      modified: new Date().toISOString(),
      mimeType: 'video/mp4',
      parent: 'root',
      blobPath: SAMPLE_MP4_PATH,
    };
    saveGDriveFS();
  }

  const out = [];
  for (const f of Object.values(gdriveFSData)) {
    const fAcc = f.accountId || 'default';
    if (fAcc === accId && f.parent === folderId) {
      out.push({
        id: f.id,
        name: f.name,
        type: f.type,
        size: f.size || 0,
        modified: f.modified,
        mimeType: f.mimeType,
      });
    }
  }
  return res.json(out);
});

app.get('/api/gdrive/probe/:file_id', requireAuth, async (req, res) => {
  const f = gdriveFSData[req.params.file_id];
  if (!f) return res.status(404).json({ error: 'File not found' });
  const info = await probeMediaItem(f);
  return res.json(info);
});

app.get('/api/gdrive/subtitles/:file_id', requireAuth, (req, res) => {
  const f = gdriveFSData[req.params.file_id];
  if (!f) return res.status(404).json({ error: 'File not found' });
  return streamSubtitleResponse(req, res, f);
});

app.get('/api/gdrive/download/:file_id', requireAuth, (req, res) => {
  const f = gdriveFSData[req.params.file_id];
  return streamFileResponse(req, res, f);
});

app.post('/api/gdrive/upload', requireAdmin, upload.single('file'), (req, res) => {
  const folderId = req.query.folder || 'root';
  const accId = resolveGDriveAccountId(req.query.account_id);
  const relPath = String(req.body?.relative_path || req.query?.relative_path || '').trim().replace(/^\/+/, '');
  const f = req.file;
  if (!f) {
    return res.status(400).json({ error: 'No file provided' });
  }
  let targetParent = folderId;
  let actualName = f.originalname;
  if (relPath) {
    const parts = relPath.split('/').filter(Boolean);
    if (parts.length > 1) {
      targetParent = ensureGDriveFolderPath(folderId, parts.slice(0, -1), accId);
      actualName = parts[parts.length - 1];
    } else if (parts.length === 1) {
      actualName = parts[0];
    }
  }
  const id = 'file-' + crypto.randomBytes(6).toString('hex');
  gdriveFSData[id] = {
    id,
    accountId: accId,
    name: actualName,
    type: 'file',
    size: f.size,
    modified: new Date().toISOString(),
    mimeType: getMimeType(actualName, f.mimetype),
    parent: targetParent,
    blobPath: f.path,
  };
  saveGDriveFS();
  return res.json({ ok: true });
});

app.put('/api/gdrive/content/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  const b = req.body || {};
  if (b.content === undefined || b.content === null) {
    return res.status(400).json({ error: 'content is required' });
  }
  const item = gdriveFSData[file_id];
  if (!item) {
    return res.status(404).json({ error: 'File not found' });
  }
  const buf = Buffer.from(String(b.content), 'utf-8');
  const blobPath =
    item.blobPath && !item.blobPath.includes('sample_')
      ? item.blobPath
      : path.join(BLOBS_DIR, `gdrive_edit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.txt`);
  fs.writeFileSync(blobPath, buf);
  item.blobPath = blobPath;
  item.size = buf.length;
  item.modified = new Date().toISOString();
  saveGDriveFS();
  return res.json({ ok: true, size: buf.length, file: item });
});

app.post('/api/gdrive/rename/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  const b = req.body || {};
  const newName = String(b.name || b.new_name || '').trim();
  if (!newName) {
    return res.status(400).json({ error: 'New name is required' });
  }
  const item = gdriveFSData[file_id];
  if (!item) {
    return res.status(404).json({ error: 'File not found' });
  }
  item.name = newName;
  item.modified = new Date().toISOString();
  saveGDriveFS();
  return res.json({ ok: true });
});

app.post('/api/gdrive/zip', requireAuth, (req, res) => {
  const b = req.body || {};
  const ids = Array.isArray(b.ids) ? b.ids : [];
  if (!ids.length) {
    return res.status(400).json({ error: 'No file IDs provided' });
  }
  const zipItems = [];

  function addGDriveItemToZip(fid, arcPrefix) {
    const item = gdriveFSData[fid];
    if (!item) return;
    const arcPath = arcPrefix ? `${arcPrefix}/${item.name}` : item.name;
    if (item.type === 'folder') {
      const children = Object.values(gdriveFSData).filter((c) => c.parent === fid);
      if (children.length === 0) {
        zipItems.push({ arcPath, isDir: true });
      } else {
        for (const ch of children) {
          addGDriveItemToZip(ch.id, arcPath);
        }
      }
    } else {
      zipItems.push({
        arcPath,
        data: getItemBuffer(item),
      });
    }
  }

  for (const id of ids) {
    addGDriveItemToZip(id, '');
  }

  const zipBuf = buildZipBuffer(zipItems);
  const archiveName = b.name || 'GoogleDrive_Download.zip';
  res.writeHead(200, {
    'Content-Type': 'application/zip',
    'Content-Length': String(zipBuf.length),
    'Content-Disposition': makeDispositionHeader(archiveName, true),
    'Cache-Control': 'no-cache',
  });
  return res.end(zipBuf);
});

app.delete('/api/gdrive/delete/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  function deleteRecursive(fid) {
    const item = gdriveFSData[fid];
    if (!item) return;
    if (item.type === 'folder') {
      for (const ch of Object.values(gdriveFSData)) {
        if (ch.parent === fid) deleteRecursive(ch.id);
      }
    }
    delete gdriveFSData[fid];
  }
  deleteRecursive(file_id);
  saveGDriveFS();
  return res.json({ ok: true });
});

app.post('/api/gdrive/mkdir', requireAdmin, (req, res) => {
  const b = req.body || {};
  const accId = resolveGDriveAccountId(req.query.account_id || b.account_id);
  const parent = b.parent || 'root';
  const name = b.name || 'New Folder';
  const id = 'folder-' + crypto.randomBytes(6).toString('hex');
  gdriveFSData[id] = {
    id,
    accountId: accId,
    name,
    type: 'folder',
    size: 0,
    modified: new Date().toISOString(),
    mimeType: 'application/vnd.google-apps.folder',
    parent,
  };
  saveGDriveFS();
  return res.json({ id });
});

// ── Microsoft OneDrive Helpers & Routes (Multi-Account) ─────────────────────
function getOneDriveConfig() {
  const defaults = {
    client_id: process.env.ONEDRIVE_CLIENT_ID || '',
    client_secret: process.env.ONEDRIVE_CLIENT_SECRET || '',
    redirect_uri: process.env.ONEDRIVE_REDIRECT_URI || 'http://localhost:3000/api/onedrive/callback',
    tenant_id: process.env.ONEDRIVE_TENANT_ID || 'common',
  };
  const stored = loadJson(ONEDRIVE_CONFIG_FILE, {});
  return {
    client_id: stored.client_id || defaults.client_id,
    client_secret: stored.client_secret || defaults.client_secret,
    redirect_uri: stored.redirect_uri || defaults.redirect_uri,
    tenant_id: stored.tenant_id || defaults.tenant_id || 'common',
  };
}

function isOneDriveConfigured() {
  const cfg = getOneDriveConfig();
  return Boolean(cfg.client_id && cfg.client_secret && cfg.redirect_uri);
}

function ensureOneDriveSmbProxyFields(accounts) {
  const used = new Set();
  for (const gd of loadGDriveAccountsRaw()) {
    if (gd.smb_share_name) used.add(String(gd.smb_share_name).toLowerCase());
  }
  let changed = false;
  accounts.forEach((a, idx) => {
    if (typeof a.smb_enabled !== 'boolean') {
      a.smb_enabled = true;
      changed = true;
    }
    const rawShare = String(a.smb_share_name || '').trim();
    if (!rawShare) {
      const defaultBase =
        idx === 0 || a.id === 'default'
          ? 'OneDrive'
          : a.custom_name || a.name || `OneDrive_${idx + 1}`;
      let candidate = sanitizeSmbShareName(defaultBase, `OneDrive_${idx + 1}`);
      const baseCand = candidate;
      let suffix = 2;
      while (used.has(candidate.toLowerCase())) {
        candidate = `${baseCand.slice(0, 28)}_${suffix}`;
        suffix++;
      }
      a.smb_share_name = candidate;
      changed = true;
    } else {
      let sanitized = sanitizeSmbShareName(rawShare, `OneDrive_${idx + 1}`);
      if (used.has(sanitized.toLowerCase())) {
        sanitized = `${sanitized.slice(0, 28)}_${idx + 1}`;
      }
      if (sanitized !== rawShare) {
        a.smb_share_name = sanitized;
        changed = true;
      }
    }
    used.add(a.smb_share_name.toLowerCase());
  });
  return changed;
}

function loadOneDriveAccountsRaw() {
  const list = loadJson(ONEDRIVE_ACCOUNTS_FILE, null);
  if (Array.isArray(list)) {
    if (ensureOneDriveSmbProxyFields(list)) {
      saveJson(ONEDRIVE_ACCOUNTS_FILE, list);
    }
    return list;
  }
  return [];
}

function saveOneDriveAccountsRaw(accounts) {
  ensureOneDriveSmbProxyFields(accounts);
  saveJson(ONEDRIVE_ACCOUNTS_FILE, accounts);
}

function listOneDriveAccounts() {
  return loadOneDriveAccountsRaw().map((a) => ({
    id: a.id,
    name: a.custom_name || a.name || 'OneDrive',
    custom_name: a.custom_name || '',
    original_name: a.original_name || a.name || 'OneDrive',
    email: a.email || '',
    drive_id: a.drive_id || 'od-drive-default',
    drive_type: a.drive_type || 'personal',
    smb_enabled: Boolean(a.smb_enabled ?? true),
    smb_share_name: a.smb_share_name || 'OneDrive',
  }));
}

function resolveOneDriveAccountId(rawId) {
  const accounts = loadOneDriveAccountsRaw();
  if (!accounts.length) return 'default';
  if (!rawId || rawId === 'root' || rawId === 'default') {
    const def = accounts.find((a) => a.id === 'default');
    return def ? def.id : accounts[0].id;
  }
  const found = accounts.find((a) => a.id === rawId);
  return found ? found.id : accounts[0].id;
}

function isOneDriveAuthenticated() {
  return loadOneDriveAccountsRaw().length > 0;
}

function ensureOneDriveAccountSeeded(accountId) {
  const accId = resolveOneDriveAccountId(accountId);
  const hasAny = Object.values(onedriveFSData).some((f) => (f.accountId || 'default') === accId);
  if (hasAny) return;
  const now = new Date().toISOString();
  const suffix = accId === 'default' ? '' : `_${accId}`;
  onedriveFSData[`od-folder-docs${suffix}`] = {
    id: `od-folder-docs${suffix}`,
    accountId: accId,
    name: 'Documents',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.onedrive.folder',
    parent: 'root',
  };
  onedriveFSData[`od-folder-media${suffix}`] = {
    id: `od-folder-media${suffix}`,
    accountId: accId,
    name: 'Media',
    type: 'folder',
    size: 0,
    modified: now,
    mimeType: 'application/vnd.onedrive.folder',
    parent: 'root',
  };
  const readmePath = path.join(BLOBS_DIR, 'onedrive_welcome.txt');
  if (fs.existsSync(readmePath)) {
    onedriveFSData[`od-file-readme${suffix}`] = {
      id: `od-file-readme${suffix}`,
      accountId: accId,
      name: 'Welcome.txt',
      type: 'file',
      size: fs.statSync(readmePath).size,
      modified: now,
      mimeType: 'text/plain',
      parent: 'root',
      blobPath: readmePath,
    };
  }
  if (fs.existsSync(SAMPLE_WAV_PATH)) {
    onedriveFSData[`od-file-sample-audio${suffix}`] = {
      id: `od-file-sample-audio${suffix}`,
      accountId: accId,
      name: 'Sample_Audio.wav',
      type: 'file',
      size: fs.statSync(SAMPLE_WAV_PATH).size,
      modified: now,
      mimeType: 'audio/wav',
      parent: 'root',
      blobPath: SAMPLE_WAV_PATH,
    };
  }
  if (fs.existsSync(SAMPLE_MP4_PATH) && fs.statSync(SAMPLE_MP4_PATH).size > 0) {
    onedriveFSData[`od-file-sample-video${suffix}`] = {
      id: `od-file-sample-video${suffix}`,
      accountId: accId,
      name: 'Sample_Video.mp4',
      type: 'file',
      size: fs.statSync(SAMPLE_MP4_PATH).size,
      modified: now,
      mimeType: 'video/mp4',
      parent: 'root',
      blobPath: SAMPLE_MP4_PATH,
    };
  }
  saveOneDriveFS();
}

function ensureOneDriveFolderPath(baseFolderId, parts, accountId = 'default') {
  const accId = resolveOneDriveAccountId(accountId);
  let currId = baseFolderId || 'root';
  for (const part of parts) {
    if (!part) continue;
    const existing = Object.values(onedriveFSData).find(
      (f) => (f.accountId || 'default') === accId && f.parent === currId && f.type === 'folder' && f.name === part
    );
    if (existing) {
      currId = existing.id;
    } else {
      const newId = 'od-folder-' + crypto.randomBytes(6).toString('hex');
      onedriveFSData[newId] = {
        id: newId,
        accountId: accId,
        name: part,
        type: 'folder',
        size: 0,
        modified: new Date().toISOString(),
        mimeType: 'application/vnd.onedrive.folder',
        parent: currId,
      };
      currId = newId;
    }
  }
  return currId;
}

app.get('/api/onedrive/status', requireAuth, (req, res) => {
  return res.json({
    configured: isOneDriveConfigured(),
    authenticated: isOneDriveAuthenticated(),
    accounts: listOneDriveAccounts(),
  });
});

app.get('/api/onedrive/accounts', requireAuth, (req, res) => {
  return res.json(listOneDriveAccounts());
});

app.post('/api/onedrive/accounts/:account_id/rename', requireAdmin, (req, res) => {
  const { account_id } = req.params;
  const b = req.body || {};
  const newName = String(b.name || b.custom_name || '').trim();
  if (!newName) {
    return res.status(400).json({ error: 'Custom name cannot be empty' });
  }
  const accounts = loadOneDriveAccountsRaw();
  const target = accounts.find(
    (a) => a.id === account_id || ((account_id === 'root' || account_id === 'default') && a === accounts[0])
  );
  if (!target) {
    return res.status(404).json({ error: `OneDrive account '${account_id}' not found` });
  }
  if (!target.original_name) target.original_name = target.name || 'OneDrive';
  target.name = newName;
  target.custom_name = newName;
  saveOneDriveAccountsRaw(accounts);
  return res.json({
    id: target.id,
    name: target.name,
    custom_name: target.custom_name,
    email: target.email || '',
  });
});

app.delete('/api/onedrive/accounts/:account_id', requireAdmin, (req, res) => {
  const { account_id } = req.params;
  const accounts = loadOneDriveAccountsRaw().filter((a) => a.id !== account_id);
  saveOneDriveAccountsRaw(accounts);
  return res.json({ ok: true });
});

app.get('/api/onedrive/config', requireAuth, (req, res) => {
  return res.json(getOneDriveConfig());
});

app.post('/api/onedrive/config', requireAdmin, (req, res) => {
  const b = req.body || {};
  const cfg = {
    client_id: String(b.client_id || '').trim(),
    client_secret: String(b.client_secret || '').trim(),
    redirect_uri: String(b.redirect_uri || '').trim() || 'http://localhost:3000/api/onedrive/callback',
    tenant_id: String(b.tenant_id || 'common').trim() || 'common',
  };
  saveJson(ONEDRIVE_CONFIG_FILE, cfg);
  return res.json({ ok: true, configured: isOneDriveConfigured() });
});

app.get('/api/onedrive/auth', requireAdmin, (req, res) => {
  if (!isOneDriveConfigured()) {
    return res.status(400).json({ error: 'Microsoft OneDrive OAuth not configured' });
  }
  const name = encodeURIComponent(String(req.query.name || '').trim());
  const accountId = encodeURIComponent(String(req.query.account_id || '').trim());
  return res.json({
    url: `/api/onedrive/callback?code=preview_od_oauth_code&name=${name}&account_id=${accountId}`,
  });
});

app.get('/api/onedrive/callback', (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Missing code');
  }
  const cfg = getOneDriveConfig();
  const customName = String(req.query.name || '').trim();
  const accountId = String(req.query.account_id || '').trim();
  const accounts = loadOneDriveAccountsRaw();
  const creds = {
    access_token: 'onedrive_access_' + crypto.randomBytes(8).toString('hex'),
    refresh_token: 'onedrive_refresh_' + crypto.randomBytes(8).toString('hex'),
    token_type: 'Bearer',
    client_id: cfg.client_id,
    client_secret: cfg.client_secret,
    tenant_id: cfg.tenant_id || 'common',
  };

  let target = accountId ? accounts.find((a) => a.id === accountId) : null;
  if (target) {
    target.creds = creds;
    if (customName) {
      target.name = customName;
      target.custom_name = customName;
    }
  } else {
    const newId = accounts.length === 0 ? 'default' : `onedrive_${crypto.randomBytes(3).toString('hex')}`;
    const idx = accounts.length + 1;
    const defaultLabel = idx === 1 ? 'OneDrive' : `OneDrive ${idx}`;
    const dispName = customName || defaultLabel;
    accounts.push({
      id: newId,
      name: dispName,
      custom_name: customName,
      original_name: defaultLabel,
      email: idx === 1 ? 'user@outlook.com' : `onedrive${idx}@outlook.com`,
      drive_id: `od-drive-${newId}`,
      drive_type: 'personal',
      creds,
    });
    ensureOneDriveAccountSeeded(newId);
  }
  saveOneDriveAccountsRaw(accounts);
  return res.redirect('/#onedrive-connected');
});

app.delete('/api/onedrive/revoke', requireAdmin, (req, res) => {
  const accountId = String(req.query.account_id || '').trim();
  if (accountId) {
    const accounts = loadOneDriveAccountsRaw().filter((a) => a.id !== accountId);
    saveOneDriveAccountsRaw(accounts);
  } else {
    saveOneDriveAccountsRaw([]);
  }
  return res.json({ ok: true });
});

app.get('/api/onedrive/files', requireAuth, (req, res) => {
  const folderId = req.query.folder || 'root';
  const accId = resolveOneDriveAccountId(req.query.account_id);
  ensureOneDriveAccountSeeded(accId);

  const out = [];
  for (const f of Object.values(onedriveFSData)) {
    const fAcc = f.accountId || 'default';
    if (fAcc === accId && f.parent === folderId) {
      out.push({
        id: f.id,
        name: f.name,
        type: f.type,
        size: f.size || 0,
        modified: f.modified,
        mimeType: f.mimeType,
      });
    }
  }
  return res.json(out);
});

app.get('/api/onedrive/probe/:file_id', requireAuth, async (req, res) => {
  const f = onedriveFSData[req.params.file_id];
  if (!f) return res.status(404).json({ error: 'File not found' });
  const info = await probeMediaItem(f);
  return res.json(info);
});

app.get('/api/onedrive/subtitles/:file_id', requireAuth, (req, res) => {
  const f = onedriveFSData[req.params.file_id];
  if (!f) return res.status(404).json({ error: 'File not found' });
  return streamSubtitleResponse(req, res, f);
});

app.get('/api/onedrive/download/:file_id', requireAuth, (req, res) => {
  const f = onedriveFSData[req.params.file_id];
  return streamFileResponse(req, res, f);
});

app.post('/api/onedrive/upload', requireAdmin, upload.single('file'), (req, res) => {
  const folderId = req.query.folder || 'root';
  const accId = resolveOneDriveAccountId(req.query.account_id);
  const relPath = String(req.body?.relative_path || req.query?.relative_path || '').trim().replace(/^\/+/, '');
  const f = req.file;
  if (!f) {
    return res.status(400).json({ error: 'No file provided' });
  }
  let targetParent = folderId;
  let actualName = f.originalname;
  if (relPath) {
    const parts = relPath.split('/').filter(Boolean);
    if (parts.length > 1) {
      targetParent = ensureOneDriveFolderPath(folderId, parts.slice(0, -1), accId);
      actualName = parts[parts.length - 1];
    } else if (parts.length === 1) {
      actualName = parts[0];
    }
  }
  const id = 'od-file-' + crypto.randomBytes(6).toString('hex');
  onedriveFSData[id] = {
    id,
    accountId: accId,
    name: actualName,
    type: 'file',
    size: f.size,
    modified: new Date().toISOString(),
    mimeType: getMimeType(actualName, f.mimetype),
    parent: targetParent,
    blobPath: f.path,
  };
  saveOneDriveFS();
  return res.json({ ok: true });
});

app.put('/api/onedrive/content/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  const b = req.body || {};
  if (b.content === undefined || b.content === null) {
    return res.status(400).json({ error: 'content is required' });
  }
  const item = onedriveFSData[file_id];
  if (!item) {
    return res.status(404).json({ error: 'File not found' });
  }
  const buf = Buffer.from(String(b.content), 'utf-8');
  const blobPath =
    item.blobPath && !item.blobPath.includes('sample_')
      ? item.blobPath
      : path.join(BLOBS_DIR, `onedrive_edit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.txt`);
  fs.writeFileSync(blobPath, buf);
  item.blobPath = blobPath;
  item.size = buf.length;
  item.modified = new Date().toISOString();
  saveOneDriveFS();
  return res.json({ ok: true, size: buf.length, file: item });
});

app.post('/api/onedrive/rename/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  const b = req.body || {};
  const newName = String(b.name || b.new_name || '').trim();
  if (!newName) {
    return res.status(400).json({ error: 'New name is required' });
  }
  const item = onedriveFSData[file_id];
  if (!item) {
    return res.status(404).json({ error: 'File not found' });
  }
  item.name = newName;
  item.modified = new Date().toISOString();
  saveOneDriveFS();
  return res.json({ ok: true });
});

app.post('/api/onedrive/zip', requireAuth, (req, res) => {
  const b = req.body || {};
  const ids = Array.isArray(b.ids) ? b.ids : [];
  if (!ids.length) {
    return res.status(400).json({ error: 'No file IDs provided' });
  }
  const zipItems = [];

  function addOneDriveItemToZip(fid, arcPrefix) {
    const item = onedriveFSData[fid];
    if (!item) return;
    const arcPath = arcPrefix ? `${arcPrefix}/${item.name}` : item.name;
    if (item.type === 'folder') {
      const children = Object.values(onedriveFSData).filter((c) => c.parent === fid);
      if (children.length === 0) {
        zipItems.push({ arcPath, isDir: true });
      } else {
        for (const ch of children) {
          addOneDriveItemToZip(ch.id, arcPath);
        }
      }
    } else {
      zipItems.push({
        arcPath,
        data: getItemBuffer(item),
      });
    }
  }

  for (const id of ids) {
    addOneDriveItemToZip(id, '');
  }

  const zipBuf = buildZipBuffer(zipItems);
  const archiveName = b.name || 'OneDrive_Download.zip';
  res.writeHead(200, {
    'Content-Type': 'application/zip',
    'Content-Length': String(zipBuf.length),
    'Content-Disposition': makeDispositionHeader(archiveName, true),
    'Cache-Control': 'no-cache',
  });
  return res.end(zipBuf);
});

app.delete('/api/onedrive/delete/:file_id', requireAdmin, (req, res) => {
  const { file_id } = req.params;
  function deleteRecursive(fid) {
    const item = onedriveFSData[fid];
    if (!item) return;
    if (item.type === 'folder') {
      for (const ch of Object.values(onedriveFSData)) {
        if (ch.parent === fid) deleteRecursive(ch.id);
      }
    }
    delete onedriveFSData[fid];
  }
  deleteRecursive(file_id);
  saveOneDriveFS();
  return res.json({ ok: true });
});

app.post('/api/onedrive/mkdir', requireAdmin, (req, res) => {
  const b = req.body || {};
  const accId = resolveOneDriveAccountId(req.query.account_id || b.account_id);
  const parent = b.parent || 'root';
  const name = b.name || 'New Folder';
  const id = 'od-folder-' + crypto.randomBytes(6).toString('hex');
  onedriveFSData[id] = {
    id,
    accountId: accId,
    name,
    type: 'folder',
    size: 0,
    modified: new Date().toISOString(),
    mimeType: 'application/vnd.onedrive.folder',
    parent,
  };
  saveOneDriveFS();
  return res.json({ id });
});

// ── Cross-Drive Transfer (SMB <-> Google Drive <-> OneDrive) ─────────────────
function copyBlobFile(srcItem, nameHint) {
  const buf = getItemBuffer(srcItem);
  const ext = path.extname(nameHint || srcItem?.name || '') || '';
  const newBlobPath = path.join(BLOBS_DIR, `copy_${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`);
  fs.writeFileSync(newBlobPath, buf);
  return { blobPath: newBlobPath, size: buf.length };
}

function readSourceNode(srcType, srcDrive, itemRef) {
  if (srcType === 'smb') {
    const entries = ensureShareFS(srcDrive);
    const norm = sanitizeSmbPath(itemRef.path || '', false);
    const item = entries[norm];
    if (!item) return null;
    if (item.type === 'folder') {
      const children = Object.values(entries)
        .filter((c) => path.posix.dirname(c.path) === norm)
        .map((ch) => readSourceNode('smb', srcDrive, { path: ch.path }))
        .filter(Boolean);
      return { name: item.name, type: 'folder', children };
    }
    return { name: item.name, type: 'file', srcItem: item };
  }
  const store = srcType === 'onedrive' ? onedriveFSData : gdriveFSData;
  const fid = itemRef.id;
  const item = store[fid];
  if (!item) return null;
  if (item.type === 'folder') {
    const children = Object.values(store)
      .filter((c) => c.parent === fid)
      .map((ch) => readSourceNode(srcType, srcDrive, { id: ch.id }))
      .filter(Boolean);
    return { name: item.name, type: 'folder', children };
  }
  return { name: item.name, type: 'file', srcItem: item };
}

function writeDestNode(node, destType, destDrive, destFolder) {
  if (!node) return;
  if (destType === 'smb') {
    const entries = ensureShareFS(destDrive);
    const baseDir = (destFolder || '/').replace(/\/+$/, '');
    const targetPath = `${baseDir}/${node.name}`;
    ensureSmbParentDirs(entries, targetPath);
    if (node.type === 'folder') {
      entries[targetPath] = {
        name: node.name,
        type: 'folder',
        size: 0,
        modified: Math.floor(Date.now() / 1000),
        path: targetPath,
      };
      for (const ch of node.children || []) {
        writeDestNode(ch, 'smb', destDrive, targetPath);
      }
    } else {
      const { blobPath, size } = copyBlobFile(node.srcItem, node.name);
      entries[targetPath] = {
        name: node.name,
        type: 'file',
        size,
        modified: Math.floor(Date.now() / 1000),
        path: targetPath,
        blobPath,
        mimeType: getMimeType(node.name, node.srcItem?.mimeType),
      };
    }
  } else if (destType === 'gdrive') {
    const accId = resolveGDriveAccountId(destDrive);
    if (node.type === 'folder') {
      const newFolderId = ensureGDriveFolderPath(destFolder || 'root', [node.name], accId);
      for (const ch of node.children || []) {
        writeDestNode(ch, 'gdrive', accId, newFolderId);
      }
    } else {
      const { blobPath, size } = copyBlobFile(node.srcItem, node.name);
      const id = 'file-' + crypto.randomBytes(6).toString('hex');
      gdriveFSData[id] = {
        id,
        accountId: accId,
        name: node.name,
        type: 'file',
        size,
        modified: new Date().toISOString(),
        mimeType: getMimeType(node.name, node.srcItem?.mimeType),
        parent: destFolder || 'root',
        blobPath,
      };
    }
  } else if (destType === 'onedrive') {
    const accId = resolveOneDriveAccountId(destDrive);
    if (node.type === 'folder') {
      const newFolderId = ensureOneDriveFolderPath(destFolder || 'root', [node.name], accId);
      for (const ch of node.children || []) {
        writeDestNode(ch, 'onedrive', accId, newFolderId);
      }
    } else {
      const { blobPath, size } = copyBlobFile(node.srcItem, node.name);
      const id = 'od-file-' + crypto.randomBytes(6).toString('hex');
      onedriveFSData[id] = {
        id,
        accountId: accId,
        name: node.name,
        type: 'file',
        size,
        modified: new Date().toISOString(),
        mimeType: getMimeType(node.name, node.srcItem?.mimeType),
        parent: destFolder || 'root',
        blobPath,
      };
    }
  }
}

function deleteSmbPathRecursive(shareId, targetPath) {
  const entries = ensureShareFS(shareId);
  const norm = sanitizeSmbPath(targetPath, false);
  delete entries[norm];
  const prefix = norm.replace(/\/+$/, '') + '/';
  for (const k of Object.keys(entries)) {
    if (k.startsWith(prefix)) delete entries[k];
  }
}

function deleteGDriveRecursive(fid) {
  const item = gdriveFSData[fid];
  if (!item) return;
  if (item.type === 'folder') {
    for (const ch of Object.values(gdriveFSData)) {
      if (ch.parent === fid) deleteGDriveRecursive(ch.id);
    }
  }
  delete gdriveFSData[fid];
}

function deleteOneDriveRecursive(fid) {
  const item = onedriveFSData[fid];
  if (!item) return;
  if (item.type === 'folder') {
    for (const ch of Object.values(onedriveFSData)) {
      if (ch.parent === fid) deleteOneDriveRecursive(ch.id);
    }
  }
  delete onedriveFSData[fid];
}

function moveSmbPathSameShare(shareId, oldPath, destDir) {
  const entries = ensureShareFS(shareId);
  const normOld = sanitizeSmbPath(oldPath, false);
  const normDestDir = sanitizeSmbPath(destDir, true);
  const item = entries[normOld];
  if (!item) throw new Error('Source item not found');
  const baseName = path.posix.basename(normOld);
  const newPath = normDestDir === '/' ? `/${baseName}` : `${normDestDir.replace(/\/+$/, '')}/${baseName}`;
  if (newPath === normOld) return newPath;
  if (newPath.startsWith(normOld + '/')) {
    throw new Error('Cannot move a folder into itself');
  }
  ensureSmbParentDirs(entries, newPath);
  delete entries[normOld];
  entries[newPath] = {
    ...item,
    path: newPath,
    modified: Math.floor(Date.now() / 1000),
  };
  if (item.type === 'folder') {
    const oldPrefix = normOld + '/';
    const newPrefix = newPath + '/';
    for (const [k, child] of Object.entries(entries)) {
      if (k.startsWith(oldPrefix)) {
        const updatedChildPath = newPrefix + k.slice(oldPrefix.length);
        delete entries[k];
        entries[updatedChildPath] = {
          ...child,
          path: updatedChildPath,
        };
      }
    }
  }
  return newPath;
}

app.post('/api/transfer', requireAdmin, (req, res) => {
  const b = req.body || {};
  const operation = String(b.operation || 'copy').trim().toLowerCase();
  const isMove = operation === 'move';
  const srcType = b.src_type;
  const srcDrive = b.src_drive;
  const destType = b.dest_type;
  const destDrive = b.dest_drive;
  const destFolder = b.dest_folder || (destType === 'smb' ? '/' : 'root');
  const items = Array.isArray(b.items) ? b.items : [];

  if (!items.length) {
    return res.status(400).json({ error: 'No items selected for transfer' });
  }
  if (!['smb', 'gdrive', 'onedrive'].includes(srcType) || !['smb', 'gdrive', 'onedrive'].includes(destType)) {
    return res.status(400).json({ error: 'Invalid source or destination type' });
  }

  try {
    let count = 0;
    for (const it of items) {
      if (isMove && srcType === 'smb' && destType === 'smb' && srcDrive === destDrive) {
        moveSmbPathSameShare(srcDrive, it.path, destFolder);
      } else if (isMove && srcType === 'gdrive' && destType === 'gdrive' && resolveGDriveAccountId(srcDrive) === resolveGDriveAccountId(destDrive)) {
        const gdItem = gdriveFSData[it.id];
        if (!gdItem) throw new Error('Source file not found');
        if (it.id === destFolder) throw new Error('Cannot move a folder into itself');
        gdItem.parent = destFolder || 'root';
        gdItem.modified = new Date().toISOString();
      } else if (isMove && srcType === 'onedrive' && destType === 'onedrive' && resolveOneDriveAccountId(srcDrive) === resolveOneDriveAccountId(destDrive)) {
        const odItem = onedriveFSData[it.id];
        if (!odItem) throw new Error('Source file not found');
        if (it.id === destFolder) throw new Error('Cannot move a folder into itself');
        odItem.parent = destFolder || 'root';
        odItem.modified = new Date().toISOString();
      } else {
        const node = readSourceNode(srcType, srcDrive, it);
        if (!node) throw new Error('Source item not found');
        writeDestNode(node, destType, destDrive, destFolder);
        if (isMove) {
          if (srcType === 'smb') deleteSmbPathRecursive(srcDrive, it.path);
          else if (srcType === 'gdrive') deleteGDriveRecursive(it.id);
          else if (srcType === 'onedrive') deleteOneDriveRecursive(it.id);
        }
      }
      count++;
    }
    saveSmbFS();
    saveGDriveFS();
    saveOneDriveFS();
    return res.json({
      ok: true,
      copied: count,
      moved: isMove ? count : 0,
      operation: isMove ? 'move' : 'copy',
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// ── Multi-Drive SMB Proxy Credentials & Share Management ─────────────────────
function getSmbProxyStatus() {
  const d = loadJson(SMB_PROXY_FILE, null);
  const username = d && d.username ? d.username : 'sagedrive';
  const configured = Boolean(d);
  const gdAccounts = loadGDriveAccountsRaw();
  const odAccounts = loadOneDriveAccountsRaw();
  const shares = [];

  for (const a of gdAccounts) {
    const rcId = String(a.id || 'default').replace(/[^A-Za-z0-9_]/g, '_');
    const enabled = Boolean(a.smb_enabled ?? true);
    shares.push({
      provider: 'gdrive',
      account_id: a.id,
      account_name: a.custom_name || a.name || 'Google Drive',
      email: a.email || '',
      smb_enabled: enabled,
      smb_share_name: a.smb_share_name || 'GoogleDrive',
      mount_path: `/mnt/gdrive_mounts/${rcId}`,
      mounted: enabled,
    });
  }

  for (const a of odAccounts) {
    const rcId = String(a.id || 'default').replace(/[^A-Za-z0-9_]/g, '_');
    const enabled = Boolean(a.smb_enabled ?? true);
    shares.push({
      provider: 'onedrive',
      account_id: a.id,
      account_name: a.custom_name || a.name || 'OneDrive',
      email: a.email || '',
      smb_enabled: enabled,
      smb_share_name: a.smb_share_name || 'OneDrive',
      mount_path: `/mnt/gdrive_mounts/od_${rcId}`,
      mounted: enabled,
    });
  }

  return { username, configured, shares };
}

app.get('/api/smb/proxy-credentials', requireAuth, (req, res) => {
  return res.json(getSmbProxyStatus());
});

app.get('/api/smb/proxy-shares', requireAuth, (req, res) => {
  return res.json(getSmbProxyStatus());
});

app.post('/api/smb/proxy-shares/:account_id', requireAdmin, (req, res) => {
  const { account_id } = req.params;
  const b = req.body || {};
  const provider = String(b.provider || req.query.provider || '').trim().toLowerCase();
  const gdAccounts = loadGDriveAccountsRaw();
  const odAccounts = loadOneDriveAccountsRaw();

  let targetProvider = provider;
  let target = null;

  if (targetProvider === 'onedrive') {
    target = odAccounts.find(
      (a) => a.id === account_id || ((account_id === 'root' || account_id === 'default') && a === odAccounts[0])
    );
  } else if (targetProvider === 'gdrive') {
    target = gdAccounts.find(
      (a) => a.id === account_id || ((account_id === 'root' || account_id === 'default') && a === gdAccounts[0])
    );
  } else {
    target = gdAccounts.find((a) => a.id === account_id);
    if (target) {
      targetProvider = 'gdrive';
    } else {
      target = odAccounts.find((a) => a.id === account_id);
      if (target) targetProvider = 'onedrive';
    }
  }

  if (!target) {
    return res.status(404).json({ error: `Cloud drive account '${account_id}' not found` });
  }

  if (b.smb_share_name !== undefined) {
    const raw = String(b.smb_share_name || '').trim();
    if (!raw) {
      return res.status(400).json({ error: 'SMB share name cannot be empty' });
    }
    const cleaned = raw.replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^[_-]+|[_-]+$/g, '').slice(0, 32);
    if (!cleaned || RESERVED_SMB_NAMES.has(cleaned.toLowerCase())) {
      return res.status(400).json({ error: `Invalid or reserved SMB share name: '${raw}'` });
    }
    const allOtherShares = [
      ...gdAccounts.filter((a) => !(targetProvider === 'gdrive' && a.id === target.id)),
      ...odAccounts.filter((a) => !(targetProvider === 'onedrive' && a.id === target.id)),
    ];
    const conflict = allOtherShares.find(
      (other) => String(other.smb_share_name || '').toLowerCase() === cleaned.toLowerCase()
    );
    if (conflict) {
      return res.status(400).json({ error: `SMB share name '${cleaned}' is already used by another cloud drive` });
    }
    target.smb_share_name = cleaned;
  }
  if (b.smb_enabled !== undefined) {
    target.smb_enabled = Boolean(b.smb_enabled);
  }

  if (targetProvider === 'onedrive') {
    saveOneDriveAccountsRaw(odAccounts);
  } else {
    saveGDriveAccountsRaw(gdAccounts);
  }

  const status = getSmbProxyStatus();
  const updatedShare = status.shares.find((s) => s.provider === targetProvider && s.account_id === target.id);
  return res.json({
    ok: true,
    share: updatedShare,
    shares: status.shares,
  });
});

app.post('/api/smb/proxy-reconcile', requireAdmin, (req, res) => {
  return res.json({ ok: true, ...getSmbProxyStatus() });
});

app.post('/api/smb/proxy-credentials', requireAdmin, (req, res) => {
  const body = req.body || {};
  const username = String(body.username || 'sagedrive').trim() || 'sagedrive';
  const password = String(body.password || '').trim();
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }
  saveJson(SMB_PROXY_FILE, { username, password });
  return res.json({
    ok: true,
    message: `Credentials saved. Reconnect as '${username}'.`,
  });
});

// ── Static & SPA Catch-all ────────────────────────────────────────────────────
const staticDir = path.join(__dirname, 'frontend', 'public');
app.use(express.static(staticDir));

app.use((req, res) => {
  res.sendFile(path.join(staticDir, 'index.html'));
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`SageDrive server running on http://0.0.0.0:${PORT}`);
});
