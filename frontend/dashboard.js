const BASE = window.location.origin;
const token = sessionStorage.getItem('token');
const currentUser = sessionStorage.getItem('user');
const userRole = sessionStorage.getItem('role');

if (!token || !currentUser) window.location = 'index.html';
document.getElementById('sidebarUser').textContent = currentUser;

// Show admin nav if admin
if (userRole === 'admin') {
  document.getElementById('nav-admin').style.display = 'flex';
  document.getElementById('roleBadge').style.display = 'inline-block';
}

const authHdr = () => ({ 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' });

function esc(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }

function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast show ${type}`;
  setTimeout(() => t.className = 'toast', 3500);
}

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + id).classList.add('active');
  const nav = document.getElementById('nav-' + id);
  if (nav) nav.classList.add('active');
  if (id === 'security') loadSecurityLog();
  if (id === 'twofa') load2FAStatus();
  if (id === 'activity') loadActivity();
  if (id === 'sessions') loadSessions();
  if (id === 'notes') loadNotes();
  if (id === 'admin') loadAdmin();
}

// ── STORAGE ──
function updateStorage(ownedFiles) {
  const usedBytes = ownedFiles.reduce((a, f) => a + (f.size || 0), 0);
  const usedMB = usedBytes / (1024 * 1024);
  const pct = Math.min((usedMB / 50) * 100, 100);
  document.getElementById('storageFill').style.width = pct + '%';
  document.getElementById('storagePercent').textContent = pct.toFixed(1) + '%';
  document.getElementById('storageInfo').textContent = `${usedMB.toFixed(2)} MB of 50 MB used`;
  document.getElementById('storageUsed').innerHTML = `${usedMB.toFixed(2)} <span>MB</span>`;
}

function getFileType(name) {
  const ext = (name || '').split('.').pop().toLowerCase();
  if (['pdf'].includes(ext)) return 'pdf';
  if (['jpg','jpeg','png','gif','webp','svg','bmp'].includes(ext)) return 'img';
  if (['doc','docx','txt','md','xls','xlsx','ppt','pptx','csv'].includes(ext)) return 'doc';
  if (['zip','rar','tar','gz','7z'].includes(ext)) return 'zip';
  return 'file';
}
function fmtSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(2) + ' MB';
}
function fmtDate(iso) { return iso ? new Date(iso).toLocaleString() : '—'; }

function canPreview(name) {
  const ext = (name || '').split('.').pop().toLowerCase();
  return ['jpg','jpeg','png','gif','webp','svg','bmp','pdf','txt','md','csv','json','xml','html','css','js','py','java','c','cpp','log','yml','yaml'].includes(ext);
}

// ── LOAD FILES ──
let allOwned = [], allShared = [];
let fileToDelete = null, fileToShare = null;

async function loadFiles() {
  try {
    const res = await fetch(BASE + '/files', { headers: authHdr() });
    if (res.status === 401) return window.location = 'index.html';
    const data = await res.json();
    allOwned = data.owned || [];
    allShared = data.shared || [];
    document.getElementById('totalFiles').innerHTML = `${allOwned.length} <span>files</span>`;
    updateStorage(allOwned);
    filterFiles();
    renderShared();
  } catch { showToast('Cannot connect to server', 'error'); }
}

function renderFiles(files) {
  const list = document.getElementById('fileList');
  const empty = document.getElementById('emptyState');
  if (!files.length) { list.innerHTML = ''; empty.classList.add('show'); return; }
  empty.classList.remove('show');
  list.innerHTML = files.map((f, i) => {
    const type = getFileType(f.name);
    const ext = esc((f.name.split('.').pop() || '').toUpperCase());
    const name = esc(f.name);
    const previewable = canPreview(f.name);
    return `<div class="file-card" style="animation-delay:${i*0.04}s">
      <div class="file-icon type-${type}">${ext}</div>
      <div class="file-meta">
        <div class="file-name">${name}</div>
        <div class="file-tags">
          <span class="file-tag">Encrypted</span>
          <span class="file-tag">${fmtSize(f.size)}</span>
          ${f.version > 1 ? `<span class="file-tag version">v${f.version}</span>` : ''}
          ${f.sharedWith && f.sharedWith.length ? `<span class="file-tag shared">Shared (${f.sharedWith.length})</span>` : ''}
        </div>
      </div>
      <div class="file-actions">
        ${previewable ? `<button type="button" class="icon-btn btn-preview" onclick="previewFile('${f.id}','${esc(f.name).replace(/'/g,"\\'")}')" title="Preview"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>` : ''}
        ${f.version > 1 ? `<button type="button" class="icon-btn btn-version" onclick="showVersions('${esc(f.name).replace(/'/g,"\\'")}')" title="Versions"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 102.13-9.36L1 10"/></svg></button>` : ''}
        <button type="button" class="icon-btn btn-info" onclick="viewMeta('${f.id}')" title="Metadata"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></button>
        <button type="button" class="icon-btn btn-share-f" onclick="openShare('${f.id}')" title="Share"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.59 13.51l6.83 3.98M15.41 6.51l-6.82 3.98"/></svg></button>
        <button type="button" class="icon-btn btn-download" onclick="downloadFile('${f.id}','${esc(f.name).replace(/'/g,"\\'")}')" title="Download"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>
        <button type="button" class="icon-btn btn-delete" onclick="askDelete('${f.id}')" title="Delete"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </div>
    </div>`;
  }).join('');
}

function renderShared() {
  const list = document.getElementById('sharedFileList');
  const empty = document.getElementById('sharedEmptyState');
  if (!allShared.length) { list.innerHTML = ''; empty.classList.add('show'); return; }
  empty.classList.remove('show');
  list.innerHTML = allShared.map((f, i) => {
    const type = getFileType(f.name); const ext = esc((f.name.split('.').pop()||'').toUpperCase()); const name = esc(f.name);
    const previewable = canPreview(f.name);
    return `<div class="file-card" style="animation-delay:${i*0.04}s">
      <div class="file-icon type-${type}">${ext}</div>
      <div class="file-meta"><div class="file-name">${name}</div><div class="file-tags"><span class="file-tag">From: ${esc(f.owner)}</span><span class="file-tag">${fmtSize(f.size)}</span></div></div>
      <div class="file-actions">
        ${previewable ? `<button type="button" class="icon-btn btn-preview" onclick="previewFile('${f.id}','${esc(f.name).replace(/'/g,"\\'")}')" title="Preview"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>` : ''}
        <button type="button" class="icon-btn btn-info" onclick="viewMeta('${f.id}')" title="Metadata"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></button>
        <button type="button" class="icon-btn btn-download" onclick="downloadFile('${f.id}','${esc(f.name).replace(/'/g,"\\'")}')" title="Download"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>
      </div>
    </div>`;
  }).join('');
}

function filterFiles() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const type = document.getElementById('typeFilter').value;
  renderFiles(allOwned.filter(f => {
    const matchSearch = f.name.toLowerCase().includes(q);
    const matchType = !type || getFileType(f.name) === type;
    return matchSearch && matchType;
  }));
}

// ── UPLOAD ──
function onFileChosen(input) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 5*1024*1024) { input.value=''; return showToast('File must be < 5 MB', 'error'); }
  document.getElementById('fileChosen').textContent = file.name;
  document.getElementById('uploadBtn').disabled = false;
}
const zone = document.getElementById('uploadZone');
zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
zone.addEventListener('drop', e => {
  e.preventDefault(); zone.classList.remove('drag-over');
  const fi = document.getElementById('fileInput');
  if (e.dataTransfer.files.length) { const dt = new DataTransfer(); dt.items.add(e.dataTransfer.files[0]); fi.files = dt.files; onFileChosen(fi); }
});
async function uploadFile() {
  const fi = document.getElementById('fileInput');
  if (!fi.files.length) return;
  const prog = document.getElementById('uploadProgress');
  const btn = document.getElementById('uploadBtn');
  prog.classList.add('show'); btn.disabled = true; btn.textContent = 'Uploading...';
  const fd = new FormData(); fd.append('file', fi.files[0]);
  try {
    const res = await fetch(BASE+'/upload', { method:'POST', headers:{'Authorization':'Bearer '+token}, body:fd });
    const data = await res.json();
    if (res.ok) { showToast('File encrypted & uploaded ✓','success'); fi.value=''; document.getElementById('fileChosen').textContent='No file chosen'; loadFiles(); }
    else showToast(data.error || 'Upload failed', 'error');
  } catch { showToast('Server error during upload', 'error'); }
  finally { prog.classList.remove('show'); btn.disabled=false; btn.textContent='Upload'; }
}

// ── DOWNLOAD ──
function downloadFile(id, name) {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', `${BASE}/download/${id}`);
  xhr.setRequestHeader('Authorization', 'Bearer ' + token);
  xhr.responseType = 'blob';
  xhr.onload = () => { const url = URL.createObjectURL(xhr.response); const a = document.createElement('a'); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url); };
  xhr.onerror = () => showToast('Download failed', 'error');
  xhr.send();
}

// ── DELETE ──
function askDelete(id) { fileToDelete = id; document.getElementById('deleteModal').classList.add('show'); }
async function confirmDelete() {
  const id = fileToDelete; closeModal('deleteModal'); if (!id) return;
  const res = await fetch(`${BASE}/delete/${id}`, { method:'DELETE', headers: authHdr() });
  const d = await res.json();
  showToast(res.ok ? 'File deleted' : (d.error || 'Delete failed'), res.ok ? 'success' : 'error');
  if (res.ok) loadFiles();
}

// ── SHARE ──
function openShare(id) {
  fileToShare = id;
  document.getElementById('shareSearch').value = '';
  document.getElementById('userResults').innerHTML = '';
  const file = allOwned.find(f => f.id === id);
  const sw = file?.sharedWith || [];
  document.getElementById('currentlyShared').innerHTML = sw.length
    ? 'Currently shared with: ' + sw.map(u => `<span class="shared-pill">${u}</span>`).join('')
    : 'Not shared with anyone.';
  document.getElementById('shareModal').classList.add('show');
}
let searchTimer;
async function searchUsers() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    const q = document.getElementById('shareSearch').value.trim();
    if (q.length < 2) { document.getElementById('userResults').innerHTML = ''; return; }
    const res = await fetch(`${BASE}/users/search?q=${encodeURIComponent(q)}`, { headers: authHdr() });
    const users = await res.json();
    document.getElementById('userResults').innerHTML = users.map(u =>
      `<div class="user-result-item" onclick="shareWith('${u.username}')">${u.username}</div>`
    ).join('') || '<div style="padding:8px;color:var(--muted);font-size:12px">No users found</div>';
  }, 300);
}
async function shareWith(username) {
  const res = await fetch(`${BASE}/share/${fileToShare}`, { method:'POST', headers: authHdr(), body: JSON.stringify({ shareWith: username }) });
  const d = await res.json();
  showToast(res.ok ? `Shared with ${username} ✓` : (d.error || 'Share failed'), res.ok ? 'success' : 'error');
  if (res.ok) { loadFiles(); closeModal('shareModal'); }
}

// ── METADATA ──
async function viewMeta(id) {
  try {
    const res = await fetch(`${BASE}/metadata/${id}`, { headers: authHdr() });
    const data = await res.json();
    if (!res.ok) return showToast(data.error || 'Failed', 'error');
    document.getElementById('metaTitle').textContent = data.name;
    document.getElementById('metaTable').innerHTML = `
      <tr><td>File Name</td><td><span>${esc(data.name)}</span></td></tr>
      <tr><td>Size</td><td>${fmtSize(data.size)}</td></tr>
      <tr><td>Type</td><td>${esc(data.mimetype||'—')}</td></tr>
      <tr><td>Owner</td><td>${esc(data.owner)}</td></tr>
      <tr><td>Version</td><td><span>v${data.version||1}</span></td></tr>
      <tr><td>Uploaded</td><td>${fmtDate(data.uploadedAt)}</td></tr>
      <tr><td>Encryption</td><td><span>${esc(data.encryption)}</span></td></tr>
      <tr><td>Shared With</td><td>${data.sharedWith?.length ? data.sharedWith.map(u=>esc(u)).join(', ') : 'Nobody'}</td></tr>
      <tr><td>Access Count</td><td>${data.accessLog ? data.accessLog.length : 0} events</td></tr>`;
    document.getElementById('metaModal').classList.add('show');
  } catch { showToast('Could not fetch metadata', 'error'); }
}

// ── FILE PREVIEW ──
async function previewFile(id, name) {
  document.getElementById('previewTitle').textContent = name;
  document.getElementById('previewContent').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)">Loading preview...</div>';
  document.getElementById('previewModal').classList.add('show');
  try {
    const ext = name.split('.').pop().toLowerCase();
    const mime = ['jpg','jpeg','png','gif','webp','svg','bmp'].includes(ext) ? 'image' : (ext === 'pdf' ? 'pdf' : 'text');
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `${BASE}/preview/${id}`);
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    xhr.responseType = mime === 'text' ? 'text' : 'blob';
    xhr.onload = () => {
      const pc = document.getElementById('previewContent');
      if (mime === 'image') {
        const url = URL.createObjectURL(xhr.response);
        pc.innerHTML = `<img src="${url}" alt="${esc(name)}" style="max-width:100%;border-radius:8px">`;
      } else if (mime === 'pdf') {
        const url = URL.createObjectURL(xhr.response);
        pc.innerHTML = `<iframe src="${url}" style="width:100%;height:600px;border:none;border-radius:8px"></iframe>`;
      } else {
        pc.innerHTML = `<pre>${esc(xhr.response)}</pre>`;
      }
    };
    xhr.onerror = () => { document.getElementById('previewContent').innerHTML = '<div style="color:var(--danger)">Preview failed</div>'; };
    xhr.send();
  } catch { document.getElementById('previewContent').innerHTML = '<div style="color:var(--danger)">Preview failed</div>'; }
}

// ── VERSION HISTORY ──
async function showVersions(fileName) {
  document.getElementById('versionTitle').textContent = `Versions: ${fileName}`;
  document.getElementById('versionList').innerHTML = '<div style="color:var(--muted);padding:20px;text-align:center">Loading...</div>';
  document.getElementById('versionModal').classList.add('show');
  try {
    const res = await fetch(`${BASE}/versions/${encodeURIComponent(fileName)}`, { headers: authHdr() });
    const versions = await res.json();
    document.getElementById('versionList').innerHTML = versions.map(v => `
      <div class="file-card">
        <div class="file-icon type-file" style="font-size:12px;font-weight:800">v${v.version}</div>
        <div class="file-meta">
          <div class="file-name">${v.isLatest ? '✓ Current' : 'Previous version'}</div>
          <div class="file-tags"><span class="file-tag">${fmtSize(v.size)}</span><span class="file-tag">${fmtDate(v.uploadedAt)}</span></div>
        </div>
        <div class="file-actions">
          <button type="button" class="icon-btn btn-download" onclick="downloadFile('${v.id}','${esc(fileName).replace(/'/g,"\\'")}')" title="Download"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg></button>
          ${!v.isLatest ? `<button type="button" class="btn btn-outline" style="font-size:11px;padding:6px 12px" onclick="restoreVersion('${v.id}')">Restore</button>` : ''}
        </div>
      </div>`).join('');
  } catch { showToast('Failed to load versions', 'error'); }
}
async function restoreVersion(id) {
  const res = await fetch(`${BASE}/restore/${id}`, { method:'POST', headers: authHdr() });
  const d = await res.json();
  showToast(res.ok ? d.message : (d.error||'Restore failed'), res.ok ? 'success' : 'error');
  if (res.ok) { closeModal('versionModal'); loadFiles(); }
}

// ── SECURITY LOG ──
async function loadSecurityLog() {
  const list = document.getElementById('threatList');
  const noT = document.getElementById('noThreats');
  list.innerHTML = '<div style="color:var(--muted);padding:20px;font-family:Space Mono,monospace;font-size:12px">Loading...</div>';
  try {
    const res = await fetch(BASE+'/security-log', { headers: authHdr() });
    const threats = await res.json();
    if (!threats.length) { list.innerHTML=''; noT.style.display='block'; return; }
    noT.style.display = 'none';
    list.innerHTML = threats.map(t => `<div class="threat-card"><span class="threat-badge badge-${t.type}">${t.type.replace('_',' ')}</span><div class="threat-detail"><div class="threat-msg">${esc(t.detail)}</div><div class="threat-meta">IP: ${esc(t.ip)}</div></div><div class="threat-time">${fmtDate(t.timestamp)}</div></div>`).join('');
  } catch { list.innerHTML='<div style="color:var(--danger);padding:20px">Could not load security log.</div>'; }
}

// ── 2FA ──
let twoFAEnabled = false;
async function load2FAStatus() {
  const res = await fetch(BASE+'/2fa/status', { headers: authHdr() });
  const data = await res.json();
  twoFAEnabled = data.enabled;
  const pill = document.getElementById('twofaStatus');
  pill.textContent = twoFAEnabled ? 'Enabled' : 'Disabled';
  pill.className = `status-pill ${twoFAEnabled ? 'on' : 'off'}`;
  document.getElementById('twofaSetup').style.display = 'none';
  document.getElementById('twofaEnabled').style.display = twoFAEnabled ? 'block' : 'none';
  document.getElementById('twofaDisabled').style.display = twoFAEnabled ? 'none' : 'block';
}
async function setup2FA() {
  const res = await fetch(BASE+'/2fa/setup', { method:'POST', headers: authHdr() });
  const data = await res.json();
  if (!res.ok) return showToast(data.error||'Setup failed','error');
  document.getElementById('qrWrap').innerHTML = `<img src="${data.qr}" alt="QR Code">`;
  document.getElementById('secretBox').textContent = data.secret;
  document.getElementById('twofaSetup').style.display = 'block';
  document.getElementById('twofaDisabled').style.display = 'none';
}
async function enable2FA() {
  const code = document.getElementById('twofaOTP').value.trim();
  if (!code || code.length !== 6) return showToast('Enter 6-digit code','warn');
  const res = await fetch(BASE+'/2fa/enable', { method:'POST', headers: authHdr(), body: JSON.stringify({token:code}) });
  const data = await res.json();
  showToast(res.ok ? '2FA enabled! ✓' : (data.error||'Invalid code'), res.ok ? 'success' : 'error');
  if (res.ok) load2FAStatus();
}
function cancelSetup() { document.getElementById('twofaSetup').style.display = 'none'; document.getElementById('twofaDisabled').style.display = 'block'; }
async function disable2FA() {
  const pass = document.getElementById('twofaDisablePass').value;
  if (!pass) return showToast('Enter your password','warn');
  const res = await fetch(BASE+'/2fa/disable', { method:'POST', headers: authHdr(), body: JSON.stringify({password:pass}) });
  const data = await res.json();
  showToast(res.ok ? '2FA disabled' : (data.error||'Failed'), res.ok ? 'success' : 'error');
  if (res.ok) { document.getElementById('twofaDisablePass').value=''; load2FAStatus(); }
}

// ── ACTIVITY TIMELINE ──
async function loadActivity() {
  const tl = document.getElementById('activityTimeline');
  const empty = document.getElementById('activityEmpty');
  tl.innerHTML = '<div style="color:var(--muted);padding:20px;text-align:center">Loading...</div>';
  try {
    const res = await fetch(BASE+'/activity', { headers: authHdr() });
    const acts = await res.json();
    if (!acts.length) { tl.innerHTML=''; empty.style.display='block'; return; }
    empty.style.display = 'none';
    const icons = { UPLOAD:'📤', DOWNLOAD:'📥', SHARE:'🔗', UNSHARE:'🔒', DELETE:'🗑️', LOGIN:'🔑', '2FA_ENABLED':'🛡️', '2FA_DISABLED':'⚠️', PASSWORD_CHANGED:'🔐', NOTE_CREATED:'📝', NOTE_DELETED:'🗑️', SESSION_REVOKED:'🖥️', FILE_RESTORED:'♻️' };
    tl.innerHTML = acts.map(a => `<div class="timeline-item"><div class="timeline-event">${icons[a.event]||'📋'} ${a.event.replace(/_/g,' ')}</div><div class="timeline-detail">${esc(a.detail)}</div><div class="timeline-time">${fmtDate(a.timestamp)} · IP: ${esc(a.ip||'—')}</div></div>`).join('');
  } catch { tl.innerHTML='<div style="color:var(--danger);padding:20px">Could not load activity.</div>'; }
}

// ── SESSIONS ──
async function loadSessions() {
  const list = document.getElementById('sessionList');
  list.innerHTML = '<div style="color:var(--muted);padding:20px;text-align:center">Loading...</div>';
  try {
    const res = await fetch(BASE+'/sessions', { headers: authHdr() });
    const sessions = await res.json();
    list.innerHTML = sessions.map(s => {
      const browser = parseBrowser(s.userAgent);
      return `<div class="session-card ${s.isCurrent?'current':''}">
        <div class="session-icon"><svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg></div>
        <div class="session-meta"><div class="session-agent">${esc(browser)} ${s.isCurrent?'<span style="color:var(--accent);font-size:11px">(this session)</span>':''}</div><div class="session-info">IP: ${esc(s.ip)} · ${fmtDate(s.loginAt)}</div></div>
        <div class="session-actions">${!s.isCurrent ? `<button type="button" class="btn btn-danger" style="font-size:11px;padding:8px 14px" onclick="revokeSession('${s.id}')">Revoke</button>` : ''}</div>
      </div>`;
    }).join('');
  } catch { list.innerHTML='<div style="color:var(--danger);padding:20px">Could not load sessions.</div>'; }
}
function parseBrowser(ua) {
  if (!ua) return 'Unknown';
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Safari')) return 'Safari';
  if (ua.includes('Edge')) return 'Edge';
  return ua.substring(0, 40);
}
async function revokeSession(id) {
  const res = await fetch(`${BASE}/sessions/${id}`, { method:'DELETE', headers: authHdr() });
  showToast(res.ok ? 'Session revoked' : 'Failed', res.ok ? 'success' : 'error');
  if (res.ok) loadSessions();
}
async function revokeAllSessions() {
  const res = await fetch(BASE+'/sessions/revoke-all', { method:'POST', headers: authHdr() });
  showToast(res.ok ? 'All other sessions revoked' : 'Failed', res.ok ? 'success' : 'error');
  if (res.ok) loadSessions();
}

// ── NOTES ──
let currentNoteId = null;
async function loadNotes() {
  const grid = document.getElementById('notesGrid');
  const empty = document.getElementById('notesEmpty');
  const editor = document.getElementById('noteEditor');
  if (editor.style.display !== 'none') return;
  grid.innerHTML = '';
  try {
    const res = await fetch(BASE+'/notes', { headers: authHdr() });
    const notes = await res.json();
    grid.style.display = '';
    if (!notes.length) { empty.style.display='block'; return; }
    empty.style.display = 'none';
    grid.innerHTML = notes.map(n => `<div class="note-card" onclick="openNote('${n.id}')"><h4>${esc(n.title)}</h4><div class="note-time">Updated: ${fmtDate(n.updatedAt)}</div><div class="note-lock">🔒 AES-256 ENCRYPTED</div></div>`).join('');
  } catch { grid.innerHTML='<div style="color:var(--danger);padding:20px">Could not load notes.</div>'; }
}
function newNote() {
  currentNoteId = null;
  document.getElementById('noteTitle').value = '';
  document.getElementById('noteContent').value = '';
  document.getElementById('deleteNoteBtn').style.display = 'none';
  document.getElementById('notesGrid').style.display = 'none';
  document.getElementById('notesEmpty').style.display = 'none';
  document.getElementById('noteEditor').style.display = 'block';
}
async function openNote(id) {
  try {
    const res = await fetch(`${BASE}/notes/${id}`, { headers: authHdr() });
    const note = await res.json();
    currentNoteId = id;
    document.getElementById('noteTitle').value = note.title;
    document.getElementById('noteContent').value = note.content;
    document.getElementById('deleteNoteBtn').style.display = 'inline-block';
    document.getElementById('notesGrid').style.display = 'none';
    document.getElementById('notesEmpty').style.display = 'none';
    document.getElementById('noteEditor').style.display = 'block';
  } catch { showToast('Failed to open note', 'error'); }
}
function closeNoteEditor() {
  document.getElementById('noteEditor').style.display = 'none';
  loadNotes();
}
async function saveNote() {
  const title = document.getElementById('noteTitle').value.trim();
  const content = document.getElementById('noteContent').value;
  const body = { title: title || 'Untitled Note', content };
  if (currentNoteId) body.id = currentNoteId;
  const res = await fetch(BASE+'/notes', { method:'POST', headers: authHdr(), body: JSON.stringify(body) });
  const d = await res.json();
  showToast(res.ok ? 'Note saved ✓' : (d.error||'Save failed'), res.ok ? 'success' : 'error');
  if (res.ok && !currentNoteId) currentNoteId = d.id;
}
async function deleteCurrentNote() {
  if (!currentNoteId) return;
  const res = await fetch(`${BASE}/notes/${currentNoteId}`, { method:'DELETE', headers: authHdr() });
  showToast(res.ok ? 'Note deleted' : 'Failed', res.ok ? 'success' : 'error');
  if (res.ok) closeNoteEditor();
}

// ── SETTINGS (Password Change) ──
document.getElementById('newPass')?.addEventListener('input', function() {
  const bar = document.getElementById('pwStrength');
  const val = this.value;
  let score = 0;
  if (val.length >= 8) score++;
  if (val.length >= 12) score++;
  if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
  if (/[0-9]/.test(val)) score++;
  if (/[^A-Za-z0-9]/.test(val)) score++;
  const pct = (score/5)*100;
  const clr = pct < 40 ? 'var(--danger)' : pct < 70 ? 'var(--warn)' : 'var(--accent)';
  bar.innerHTML = `<div class="pw-bar" style="width:${pct}%;background:${clr}"></div>`;
});
async function changePassword() {
  const cur = document.getElementById('currentPass').value;
  const nw = document.getElementById('newPass').value;
  const conf = document.getElementById('confirmPass').value;
  if (!cur || !nw) return showToast('Fill all fields', 'warn');
  if (nw !== conf) return showToast('Passwords do not match', 'error');
  if (nw.length < 8) return showToast('Min 8 characters', 'error');
  const res = await fetch(BASE+'/change-password', { method:'POST', headers: authHdr(), body: JSON.stringify({ currentPassword: cur, newPassword: nw }) });
  const d = await res.json();
  showToast(res.ok ? 'Password changed ✓' : (d.error||'Failed'), res.ok ? 'success' : 'error');
  if (res.ok) { document.getElementById('currentPass').value=''; document.getElementById('newPass').value=''; document.getElementById('confirmPass').value=''; document.getElementById('pwStrength').innerHTML=''; }
}

// ── ADMIN ──
async function loadAdmin() {
  if (userRole !== 'admin') return;
  try {
    const [statsRes, usersRes, threatsRes] = await Promise.all([
      fetch(BASE+'/admin/stats', { headers: authHdr() }),
      fetch(BASE+'/admin/users', { headers: authHdr() }),
      fetch(BASE+'/admin/threats', { headers: authHdr() })
    ]);
    const stats = await statsRes.json();
    const users = await usersRes.json();
    const threats = await threatsRes.json();
    document.getElementById('adminStats').innerHTML = `
      <div class="stat-card"><div class="stat-label">Total Users</div><div class="stat-val">${stats.totalUsers} <span>users</span></div></div>
      <div class="stat-card"><div class="stat-label">Total Files</div><div class="stat-val">${stats.totalFiles} <span>files</span></div></div>
      <div class="stat-card"><div class="stat-label">Security Threats</div><div class="stat-val">${stats.totalThreats} <span>events</span></div></div>
      <div class="stat-card"><div class="stat-label">Storage</div><div class="stat-val">${(stats.totalStorage/(1024*1024)).toFixed(2)} <span>MB</span></div></div>`;
    document.getElementById('adminUserList').innerHTML = users.map(u => `<div class="admin-user-card"><div class="file-icon type-file" style="font-size:14px;font-weight:800">${esc(u.username[0].toUpperCase())}</div><div class="user-info"><div class="file-name">${esc(u.username)}</div><div class="file-tags"><span class="file-tag">${u.role}</span><span class="file-tag">${u.twoFactorEnabled?'2FA ON':'2FA OFF'}</span><span class="file-tag">Joined: ${fmtDate(u.createdAt)}</span></div></div>${u.username !== currentUser ? `<button type="button" class="btn btn-danger" style="font-size:11px;padding:8px 14px" onclick="deleteUser('${esc(u.username)}')">Delete</button>` : '<span style="color:var(--accent);font-family:Space Mono,monospace;font-size:10px">YOU</span>'}</div>`).join('');
    document.getElementById('adminThreatList').innerHTML = threats.length ? threats.map(t => `<div class="threat-card"><span class="threat-badge badge-${t.type}">${t.type.replace('_',' ')}</span><div class="threat-detail"><div class="threat-msg">${esc(t.detail)}</div><div class="threat-meta">User: ${esc(t.username)} · IP: ${esc(t.ip)}</div></div><div class="threat-time">${fmtDate(t.timestamp)}</div></div>`).join('') : '<div style="color:var(--muted);padding:20px;text-align:center">No threats</div>';
  } catch { showToast('Failed to load admin data', 'error'); }
}
async function deleteUser(username) {
  if (!confirm(`Delete user "${username}" and ALL their data? This cannot be undone.`)) return;
  const res = await fetch(`${BASE}/admin/user/${username}`, { method:'DELETE', headers: authHdr() });
  const d = await res.json();
  showToast(res.ok ? d.message : (d.error||'Failed'), res.ok ? 'success' : 'error');
  if (res.ok) loadAdmin();
}

// ── MODAL HELPERS ──
function closeModal(id) { document.getElementById(id).classList.remove('show'); fileToDelete = null; }
document.querySelectorAll('.modal-backdrop').forEach(m => {
  m.addEventListener('click', e => { if (e.target === m) m.classList.remove('show'); });
});

function logout() { sessionStorage.clear(); window.location = 'index.html'; }

// ── INIT ──
loadFiles();
