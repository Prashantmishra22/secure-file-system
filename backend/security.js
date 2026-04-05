/**
 * security.js — Threat Detection & Logging Module
 * Handles: malware detection, buffer overflow detection, threat event logging
 */

const fs   = require('fs');
const path = require('path');

const THREATS_FILE = path.join(__dirname, 'threats.json');

// ── DANGEROUS FILE EXTENSIONS (malware / executable) ──────────────────────
const MALWARE_EXTENSIONS = new Set([
  'exe','bat','cmd','sh','ps1','ps2','vbs','vbe','js','jse',
  'wsf','wsh','msi','msp','com','scr','hta','cpl','dll','sys',
  'drv','bin','run','deb','rpm','dmg','jar','class','py','rb',
  'pl','php','asp','aspx','jsp','cgi','pif','lnk','reg','inf',
  'tmp_exec','apk','ipa','xll','xlam','docm','xlsm','pptm'
]);

// ── MAGIC BYTES for common malware signatures ──────────────────────────────
const MAGIC_SIGNATURES = [
  { sig: Buffer.from([0x4D, 0x5A]),             name: 'Windows PE/EXE'    }, // MZ
  { sig: Buffer.from([0x7F, 0x45, 0x4C, 0x46]), name: 'ELF binary'       }, // ELF
  { sig: Buffer.from([0xCA, 0xFE, 0xBA, 0xBE]), name: 'Java class file'  },
  { sig: Buffer.from([0x50, 0x4B, 0x03, 0x04]), name: 'ZIP/JAR archive'  }, // PK
];

// ── MAX ALLOWED SIZES ──────────────────────────────────────────────────────
const MAX_FILENAME_LENGTH = 255;
const MAX_HEADER_SIZE     = 8192;   // 8 KB total header safety check
const MAX_FIELD_VALUE     = 4096;   // 4 KB per header value

/**
 * detectMalware({ originalname, mimetype, buffer })
 * Returns { safe: bool, reason: string }
 */
function detectMalware(file) {
  const name = (file.originalname || '').trim();
  const ext  = name.split('.').pop().toLowerCase();

  // 1. Check extension blacklist
  if (MALWARE_EXTENSIONS.has(ext)) {
    return { safe: false, reason: `Blocked file extension: .${ext}` };
  }

  // 2. Check double extensions (e.g. "invoice.pdf.exe")
  const parts = name.split('.');
  if (parts.length > 2) {
    const innerExt = parts[parts.length - 2].toLowerCase();
    if (MALWARE_EXTENSIONS.has(innerExt)) {
      return { safe: false, reason: `Double-extension camouflage detected: .${innerExt}.${ext}` };
    }
  }

  // 3. Check magic bytes if buffer is available
  if (file.buffer && file.buffer.length >= 4) {
    for (const { sig, name: sigName } of MAGIC_SIGNATURES) {
      if (file.buffer.slice(0, sig.length).equals(sig)) {
        return { safe: false, reason: `Malware signature detected: ${sigName}` };
      }
    }
  }

  // 4. Null byte injection in filename
  if (name.includes('\x00')) {
    return { safe: false, reason: 'Null byte injection in filename' };
  }

  // 5. Path traversal in filename
  if (name.includes('..') || name.includes('/') || name.includes('\\')) {
    return { safe: false, reason: 'Path traversal attempt in filename' };
  }

  return { safe: true, reason: 'OK' };
}

/**
 * detectBufferOverflow(req)
 * Returns { safe: bool, reason: string }
 */
function detectBufferOverflow(req) {
  // 1. Filename length check
  const filename = req.file?.originalname || req.body?.filename || '';
  if (filename.length > MAX_FILENAME_LENGTH) {
    return {
      safe: false,
      reason: `Filename too long: ${filename.length} chars (max ${MAX_FILENAME_LENGTH})`
    };
  }

  // 2. Header value size check
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string' && value.length > MAX_FIELD_VALUE) {
      return {
        safe: false,
        reason: `Oversized header value in '${key}': ${value.length} bytes`
      };
    }
  }

  // 3. Total headers size estimation
  const totalHeaderSize = JSON.stringify(req.headers).length;
  if (totalHeaderSize > MAX_HEADER_SIZE) {
    return {
      safe: false,
      reason: `Total header size too large: ${totalHeaderSize} bytes`
    };
  }

  // 4. Suspicious repeated patterns in body fields (basic pattern)
  const bodyStr = JSON.stringify(req.body || {});
  if (/(.)\1{100,}/.test(bodyStr)) {
    return {
      safe: false,
      reason: 'Repeated character pattern detected (possible overflow attempt)'
    };
  }

  return { safe: true, reason: 'OK' };
}

/**
 * loadThreats() / saveThreats() — persistence helpers
 */
function loadThreats() {
  if (fs.existsSync(THREATS_FILE)) {
    try { return JSON.parse(fs.readFileSync(THREATS_FILE, 'utf8')); } catch { return []; }
  }
  return [];
}

function saveThreats(threats) {
  fs.writeFileSync(THREATS_FILE, JSON.stringify(threats, null, 2));
}

/**
 * logThreat(username, type, detail, ip)
 * Appends a threat event to the threats log
 */
function logThreat(username, type, detail, ip = 'unknown') {
  const threats = loadThreats();
  threats.unshift({
    id:        Date.now(),
    timestamp: new Date().toISOString(),
    username,
    type,      // 'MALWARE' | 'BUFFER_OVERFLOW' | 'BRUTE_FORCE' | 'UNAUTHORIZED'
    detail,
    ip
  });
  // Keep only last 500 entries
  saveThreats(threats.slice(0, 500));
}

/**
 * getThreats(username)
 * Returns threats for a specific user (or all if admin)
 */
function getThreats(username) {
  return loadThreats().filter(t => t.username === username);
}

module.exports = { detectMalware, detectBufferOverflow, logThreat, getThreats };
