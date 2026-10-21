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
const SMB_PROXY_FILE = path.join(DATA_DIR, 'smb_proxy_credentials.json');

const SESSION_TTL = (parseInt(process.env.SESSION_TTL_HOURS || '24', 10) || 24) * 3600 * 1000;

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
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',
    pdf: 'application/pdf',
    txt: 'text/plain; charset=utf-8',
    md: 'text/markdown; charset=utf-8',
    json: 'application/json',
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

// Persistent Sessions
const sessionsMap = new Map(Object.entries(loadJson(SESSIONS_FILE, {})));
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

function makeDispositionHeader(filename, isDownload) {
  const safeAsciiName = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  const encodedName = encodeURIComponent(filename);
  const dispositionType = isDownload ? 'attachment' : 'inline';
  return `${dispositionType}; filename="${safeAsciiName}"; filename*=UTF-8''${encodedName}`;
}

// Unified streaming & Range response handler for both SMB and Google Drive files
function streamFileResponse(req, res, item) {
  if (!item || item.type === 'folder') {
    return res.status(404).json({ error: 'File not found' });
  }

  let blobPath = item.blobPath;
  if (!blobPath || !fs.existsSync(blobPath)) {
    if (item.data) {
      blobPath = path.join(BLOBS_DIR, `legacy_${crypto.randomBytes(6).toString('hex')}_${path.basename(item.name)}`);
      fs.writeFileSync(blobPath, Buffer.from(item.data));
      item.blobPath = blobPath;
    } else {
      return res.status(404).json({ error: 'File content not found on disk' });
    }
  }

  const stat = fs.statSync(blobPath);
  const fileSize = stat.size;
  const filename = item.name || 'download';
  const disposition = makeDispositionHeader(filename, Boolean(req.query.dl));

  if (req.query.transcode === '1') {
    res.writeHead(200, {
      'Content-Type': 'video/mp4',
      'Content-Disposition': disposition,
      'Cache-Control': 'no-cache',
    });
    const ff = spawn('ffmpeg', [
      '-i', blobPath,
      '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p',
      '-c:a', 'aac', '-b:a', '128k',
      '-movflags', 'frag_keyframe+empty_moov+default_base_moof',
      '-f', 'mp4',
      'pipe:1',
    ]);
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

// ── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const body = req.body || {};
  const u = body.username || '';
  const pw = body.password || '';
  const users = loadJson(USERS_FILE, {});
  const user = users[u];
  if (user && bcrypt.compareSync(pw, user.hash)) {
    const token = crypto.randomBytes(32).toString('hex');
    sessionsMap.set(token, {
      username: u,
      role: user.role,
      expires: Date.now() + SESSION_TTL,
    });
    persistSessions();
    res.setHeader(
      'Set-Cookie',
      `sd_token=${encodeURIComponent(token)}; Path=/; Max-Age=${Math.floor(SESSION_TTL / 1000)}; SameSite=Lax`
    );
    return res.json({ token });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  sessionsMap.delete(req.token);
  persistSessions();
  res.setHeader('Set-Cookie', 'sd_token=; Path=/; Max-Age=0');
  return res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  return res.json({ username: req.session.username, role: req.session.role });
});

// ── SMB Helpers & Routes ──────────────────────────────────────────────────────
function listShares() {
  return loadJson(SHARES_FILE, []);
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

app.post('/api/smb/shares', requireAuth, (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.host || !b.share) {
    return res.status(400).json({ error: 'name, host, and share are required' });
  }
  const sid = String(b.name).toLowerCase().replace(/\s+/g, '_');
  const shares = listShares().filter((s) => s.id !== sid);
  const entry = {
    id: sid,
    name: b.name,
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

app.delete('/api/smb/shares/:share_id', requireAuth, (req, res) => {
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

app.get('/api/smb/download/:share_id', requireAuth, (req, res) => {
  const { share_id } = req.params;
  const filePath = req.query.path || '';
  const entries = ensureShareFS(share_id);
  const item = entries[filePath];
  return streamFileResponse(req, res, item);
});

app.post('/api/smb/upload/:share_id', requireAuth, upload.single('file'), (req, res) => {
  const { share_id } = req.params;
  const dest = (req.query.path || '/').replace(/\/+$/, '');
  const relPath = String(req.body?.relative_path || req.query?.relative_path || '').trim().replace(/^\/+/, '');
  const f = req.file;
  if (!f) {
    return res.status(400).json({ error: 'No file provided' });
  }
  const entries = ensureShareFS(share_id);
  const subPath = relPath || f.originalname;
  const fullPath = `${dest}/${subPath}`;
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
});

app.post('/api/smb/rename/:share_id', requireAuth, (req, res) => {
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

app.delete('/api/smb/delete/:share_id', requireAuth, (req, res) => {
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

app.post('/api/smb/mkdir/:share_id', requireAuth, (req, res) => {
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

// ── Google Drive Helpers & Routes ─────────────────────────────────────────────
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

function isGDriveAuthenticated() {
  const creds = loadJson(GDRIVE_CREDS_FILE, null);
  return Boolean(creds && creds.token);
}

function ensureGDriveFolderPath(baseFolderId, parts) {
  let currId = baseFolderId || 'root';
  for (const part of parts) {
    if (!part) continue;
    const existing = Object.values(gdriveFSData).find(
      (f) => f.parent === currId && f.type === 'folder' && f.name === part
    );
    if (existing) {
      currId = existing.id;
    } else {
      const newId = 'folder-' + crypto.randomBytes(6).toString('hex');
      gdriveFSData[newId] = {
        id: newId,
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
  });
});

app.get('/api/gdrive/config', requireAuth, (req, res) => {
  return res.json(getGDriveConfig());
});

app.post('/api/gdrive/config', requireAuth, (req, res) => {
  const b = req.body || {};
  const cfg = {
    client_id: String(b.client_id || '').trim(),
    client_secret: String(b.client_secret || '').trim(),
    redirect_uri: String(b.redirect_uri || '').trim() || 'http://localhost:3000/api/gdrive/callback',
  };
  saveJson(GDRIVE_CONFIG_FILE, cfg);
  return res.json({ ok: true, configured: isGDriveConfigured() });
});

app.get('/api/gdrive/auth', requireAuth, (req, res) => {
  if (!isGDriveConfigured()) {
    return res.status(400).json({ error: 'Google OAuth not configured' });
  }
  return res.json({ url: '/api/gdrive/callback?code=preview_oauth_code' });
});

app.get('/api/gdrive/callback', (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.status(400).send('Missing code');
  }
  const cfg = getGDriveConfig();
  saveJson(GDRIVE_CREDS_FILE, {
    token: 'gdrive_access_' + crypto.randomBytes(8).toString('hex'),
    refresh_token: 'gdrive_refresh_' + crypto.randomBytes(8).toString('hex'),
    client_id: cfg.client_id,
    client_secret: cfg.client_secret,
  });
  return res.redirect('/#gdrive-connected');
});

app.delete('/api/gdrive/revoke', requireAuth, (req, res) => {
  try {
    if (fs.existsSync(GDRIVE_CREDS_FILE)) fs.unlinkSync(GDRIVE_CREDS_FILE);
  } catch (_) {}
  return res.json({ ok: true });
});

app.get('/api/gdrive/files', requireAuth, (req, res) => {
  const folderId = req.query.folder || 'root';
  if (
    !gdriveFSData['file-sample-video'] &&
    fs.existsSync(SAMPLE_MP4_PATH) &&
    fs.statSync(SAMPLE_MP4_PATH).size > 0
  ) {
    gdriveFSData['file-sample-video'] = {
      id: 'file-sample-video',
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
    if (f.parent === folderId) {
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

app.get('/api/gdrive/download/:file_id', requireAuth, (req, res) => {
  const f = gdriveFSData[req.params.file_id];
  return streamFileResponse(req, res, f);
});

app.post('/api/gdrive/upload', requireAuth, upload.single('file'), (req, res) => {
  const folderId = req.query.folder || 'root';
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
      targetParent = ensureGDriveFolderPath(folderId, parts.slice(0, -1));
      actualName = parts[parts.length - 1];
    } else if (parts.length === 1) {
      actualName = parts[0];
    }
  }
  const id = 'file-' + crypto.randomBytes(6).toString('hex');
  gdriveFSData[id] = {
    id,
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

app.post('/api/gdrive/rename/:file_id', requireAuth, (req, res) => {
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

app.delete('/api/gdrive/delete/:file_id', requireAuth, (req, res) => {
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

app.post('/api/gdrive/mkdir', requireAuth, (req, res) => {
  const b = req.body || {};
  const parent = b.parent || 'root';
  const name = b.name || 'New Folder';
  const id = 'folder-' + crypto.randomBytes(6).toString('hex');
  gdriveFSData[id] = {
    id,
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

// ── Cross-Drive Transfer (SMB <-> Google Drive & SMB <-> SMB) ─────────────────
function copyBlobFile(srcItem, nameHint) {
  const buf = getItemBuffer(srcItem);
  const ext = path.extname(nameHint || srcItem?.name || '') || '';
  const newBlobPath = path.join(BLOBS_DIR, `copy_${Date.now()}_${crypto.randomBytes(6).toString('hex')}${ext}`);
  fs.writeFileSync(newBlobPath, buf);
  return { blobPath: newBlobPath, size: buf.length };
}

function copySmbItemToGDrive(srcShare, smbPath, destFolderId) {
  const entries = ensureShareFS(srcShare);
  const norm = smbPath.replace(/\/+$/, '');
  const item = entries[norm];
  if (!item) return;
  if (item.type === 'folder') {
    const newFolderId = ensureGDriveFolderPath(destFolderId, [item.name]);
    const children = Object.values(entries).filter((c) => path.posix.dirname(c.path) === norm);
    for (const ch of children) {
      copySmbItemToGDrive(srcShare, ch.path, newFolderId);
    }
  } else {
    const { blobPath, size } = copyBlobFile(item, item.name);
    const id = 'file-' + crypto.randomBytes(6).toString('hex');
    gdriveFSData[id] = {
      id,
      name: item.name,
      type: 'file',
      size,
      modified: new Date().toISOString(),
      mimeType: getMimeType(item.name, item.mimeType),
      parent: destFolderId || 'root',
      blobPath,
    };
  }
}

function copyGDriveItemToSmb(fileId, destShare, destSmbDir) {
  const item = gdriveFSData[fileId];
  if (!item) return;
  const entries = ensureShareFS(destShare);
  const baseDir = (destSmbDir || '/').replace(/\/+$/, '');
  const targetPath = `${baseDir}/${item.name}`;
  ensureSmbParentDirs(entries, targetPath);

  if (item.type === 'folder') {
    entries[targetPath] = {
      name: item.name,
      type: 'folder',
      size: 0,
      modified: Math.floor(Date.now() / 1000),
      path: targetPath,
    };
    const children = Object.values(gdriveFSData).filter((c) => c.parent === fileId);
    for (const ch of children) {
      copyGDriveItemToSmb(ch.id, destShare, targetPath);
    }
  } else {
    const { blobPath, size } = copyBlobFile(item, item.name);
    entries[targetPath] = {
      name: item.name,
      type: 'file',
      size,
      modified: Math.floor(Date.now() / 1000),
      path: targetPath,
      blobPath,
      mimeType: getMimeType(item.name, item.mimeType),
    };
  }
}

function copySmbItemToSmb(srcShare, smbPath, destShare, destSmbDir) {
  const srcEntries = ensureShareFS(srcShare);
  const destEntries = ensureShareFS(destShare);
  const norm = smbPath.replace(/\/+$/, '');
  const item = srcEntries[norm];
  if (!item) return;
  const baseDir = (destSmbDir || '/').replace(/\/+$/, '');
  const targetPath = `${baseDir}/${item.name}`;
  ensureSmbParentDirs(destEntries, targetPath);

  if (item.type === 'folder') {
    destEntries[targetPath] = {
      name: item.name,
      type: 'folder',
      size: 0,
      modified: Math.floor(Date.now() / 1000),
      path: targetPath,
    };
    const children = Object.values(srcEntries).filter((c) => path.posix.dirname(c.path) === norm);
    for (const ch of children) {
      copySmbItemToSmb(srcShare, ch.path, destShare, targetPath);
    }
  } else {
    const { blobPath, size } = copyBlobFile(item, item.name);
    destEntries[targetPath] = {
      name: item.name,
      type: 'file',
      size,
      modified: Math.floor(Date.now() / 1000),
      path: targetPath,
      blobPath,
      mimeType: getMimeType(item.name, item.mimeType),
    };
  }
}

function copyGDriveItemToGDrive(fileId, destFolderId) {
  const item = gdriveFSData[fileId];
  if (!item) return;
  if (item.type === 'folder') {
    const newFolderId = ensureGDriveFolderPath(destFolderId, [item.name]);
    const children = Object.values(gdriveFSData).filter((c) => c.parent === fileId);
    for (const ch of children) {
      copyGDriveItemToGDrive(ch.id, newFolderId);
    }
  } else {
    const { blobPath, size } = copyBlobFile(item, item.name);
    const id = 'file-' + crypto.randomBytes(6).toString('hex');
    gdriveFSData[id] = {
      id,
      name: item.name,
      type: 'file',
      size,
      modified: new Date().toISOString(),
      mimeType: getMimeType(item.name, item.mimeType),
      parent: destFolderId || 'root',
      blobPath,
    };
  }
}

app.post('/api/transfer', requireAuth, (req, res) => {
  const b = req.body || {};
  const srcType = b.src_type;
  const srcDrive = b.src_drive;
  const destType = b.dest_type;
  const destDrive = b.dest_drive;
  const destFolder = b.dest_folder || (destType === 'smb' ? '/' : 'root');
  const items = Array.isArray(b.items) ? b.items : [];

  if (!items.length) {
    return res.status(400).json({ error: 'No items selected for transfer' });
  }

  try {
    let copied = 0;
    for (const it of items) {
      if (srcType === 'smb' && destType === 'gdrive') {
        copySmbItemToGDrive(srcDrive, it.path, destFolder);
      } else if (srcType === 'gdrive' && destType === 'smb') {
        copyGDriveItemToSmb(it.id, destDrive, destFolder);
      } else if (srcType === 'smb' && destType === 'smb') {
        copySmbItemToSmb(srcDrive, it.path, destDrive, destFolder);
      } else if (srcType === 'gdrive' && destType === 'gdrive') {
        copyGDriveItemToGDrive(it.id, destFolder);
      } else {
        return res.status(400).json({ error: 'Invalid source or destination type' });
      }
      copied++;
    }
    saveSmbFS();
    saveGDriveFS();
    return res.json({ ok: true, copied });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ── SMB Proxy Credentials ─────────────────────────────────────────────────────
app.get('/api/smb/proxy-credentials', requireAuth, (req, res) => {
  const d = loadJson(SMB_PROXY_FILE, null);
  if (d) {
    return res.json({ username: d.username || 'sagedrive', configured: true });
  }
  return res.json({ username: 'sagedrive', configured: false });
});

app.post('/api/smb/proxy-credentials', requireAuth, (req, res) => {
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
