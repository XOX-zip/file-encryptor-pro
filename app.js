/* ============================================================
 * File Encryptor · Web Pro
 * v3：批量加密 / 解密 + 文本加密 + 工具箱
 * 格式 v2：FENC | ver | cipher | kdfHash | kdfMode | compAlg |
 *          compRounds | padCode | layers | salt(16) | iter(4) | data
 * 兼容解密 v1 旧格式
 * ============================================================ */

const MAGIC = new TextEncoder().encode('FENC');
const VERSION = 2;
const HEADER_LEN = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 16 + 4; // 32
const SALT_LEN = 16;

const ITER_MIN = 10000;
const ITER_MAX = 5000000;

const CIPHER_KEY_LEN = { 1: 16, 2: 24, 3: 32 };
const HASH_NAME = { 1: 'SHA-256', 2: 'SHA-384', 3: 'SHA-512' };
const COMP_FMT = { 1: 'deflate-raw', 2: 'deflate', 3: 'gzip' };

/* 块大小必须 ≤255，否则单字节 padLen 装不下 */
const PAD_SIZES = [0, 16, 64, 128, 192, 255];

/* ---------- DOM 快捷 ---------- */
const $ = (id) => document.getElementById(id);
const themeToggle = $('themeToggle');
const themeButtons = themeToggle.querySelectorAll('button');
const fileInput = $('fileInput');
const folderInput = $('folderInput');
const dropZone = $('dropZone');
const fileList = $('fileList');
const queueCount = $('queueCount');
const passwordInput = $('password');
const togglePwdBtn = $('togglePwdBtn');
const genPwdBtn = $('genPwdBtn');
const pwdMeter = $('pwdMeter');
const pwdHint = $('pwdHint');
const layersInput = $('layers');
const cipherAlgEl = $('cipherAlg');
const kdfHashEl = $('kdfHash');
const kdfModeEl = $('kdfMode');
const iterationsInput = $('iterations');
const compAlgEl = $('compAlg');
const compRoundsInput = $('compRounds');
const compRoundsGroup = $('compRoundsGroup');
const padSizeEl = $('padSize');
const aadTextarea = $('aad');
const hexMode = $('hexMode');
const keepOrigName = $('keepOrigName');
const hideScrollbarEl = $('hideScrollbar');
const encryptBtn = $('encryptBtn');
const decryptBtn = $('decryptBtn');
const autoBtn = $('autoBtn');
const cancelBtn = $('cancelBtn');
const progressBar = $('progressBar');
const progressFill = $('progressFill');
const statusEl = $('status');
const presetHint = $('presetHint');
const downloadGroup = $('downloadGroup');
const downloadAllBtn = $('downloadAllBtn');
const zipDownloadBtn = $('zipDownloadBtn');
const clearResultsBtn = $('clearResultsBtn');

/* ---------- 全局状态 ---------- */
const state = { queue: [], busy: false, cancelled: false, nextId: 1 };

/* ---------- 默认值 / 预设 ---------- */
const DEFAULT_OPTS = {
  layers: 3,
  cipherAlg: 3,
  kdfHash: 1,
  kdfMode: 'hmac',
  iterations: 300000,
  compAlg: 3,
  compRounds: 3,
  padCode: 0,
  aad: '',
};

const PRESETS = {
  fast: {
    label: '快速 · 平衡速度与安全',
    layers: 1, cipherAlg: 3, kdfHash: 1, kdfMode: 'hmac',
    iterations: 100000, compAlg: 2, compRounds: 1, padCode: 0, aad: '',
  },
  standard: {
    label: '标准 · 日常使用推荐',
    layers: 3, cipherAlg: 3, kdfHash: 1, kdfMode: 'hmac',
    iterations: 300000, compAlg: 3, compRounds: 1, padCode: 1, aad: '',
  },
  secure: {
    label: '安全 · 敏感数据',
    layers: 5, cipherAlg: 3, kdfHash: 2, kdfMode: 'hkdf',
    iterations: 600000, compAlg: 3, compRounds: 2, padCode: 3, aad: '',
  },
  extreme: {
    label: '极限 · 最高强度（较慢）',
    layers: 10, cipherAlg: 3, kdfHash: 3, kdfMode: 'hkdf',
    iterations: 1000000, compAlg: 4, compRounds: 5, padCode: 5, aad: '',
  },
};

/* ---------- 主题 ---------- */
function applyTheme(mode) {
  const effective =
    mode === 'system'
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
      : mode;
  document.body.classList.toggle('dark', effective === 'dark');
  themeButtons.forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
  try { localStorage.setItem('fe-theme', mode); } catch (_) {}
}

themeButtons.forEach((btn) => {
  btn.addEventListener('click', () => applyTheme(btn.dataset.mode));
});

(() => {
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const handler = () => {
    let saved = 'system';
    try { saved = localStorage.getItem('fe-theme') || 'system'; } catch (_) {}
    if (saved === 'system') applyTheme('system');
  };
  if (mq.addEventListener) mq.addEventListener('change', handler);
  else if (mq.addListener) mq.addListener(handler);
})();

(() => {
  let saved = 'system';
  try { saved = localStorage.getItem('fe-theme') || 'system'; } catch (_) {}
  applyTheme(saved);
})();

/* ---------- 滚动条开关 ---------- */
function applyScrollbarPref(hide) {
  document.documentElement.classList.toggle('no-scrollbar', hide);
  try { localStorage.setItem('fe-hide-scrollbar', hide ? '1' : '0'); } catch (_) {}
}

(() => {
  let hide = false;
  try { hide = localStorage.getItem('fe-hide-scrollbar') === '1'; } catch (_) {}
  if (hideScrollbarEl) {
    hideScrollbarEl.checked = hide;
    applyScrollbarPref(hide);
    hideScrollbarEl.addEventListener('change', () =>
      applyScrollbarPref(hideScrollbarEl.checked)
    );
  }
})();

/* ---------- 标签页切换 ---------- */
document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) =>
      t.classList.toggle('active', t === tab)
    );
    document.querySelectorAll('.tab-panel').forEach((p) =>
      p.classList.toggle('active', p.dataset.panel === tab.dataset.tab)
    );
  });
});

/* ---------- 工具函数 ---------- */
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function showStatus(msg, type = 'info') {
  statusEl.textContent = msg;
  statusEl.className = `status ${type}`;
}
function clearStatus() {
  statusEl.className = 'status';
  statusEl.textContent = '';
}
function setProgress(ratio, msg) {
  if (ratio <= 0) {
    progressBar.classList.remove('active');
    progressFill.style.width = '0%';
  } else {
    progressBar.classList.add('active');
    progressFill.style.width = `${Math.min(100, Math.round(ratio * 100))}%`;
  }
  if (msg) showStatus(msg, 'info');
}

function ensureCryptoAvailable() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API 不可用。请通过 HTTPS 或 localhost 访问此页面（file:// 不支持）。');
  }
}

/* ---------- Abort 错误 ---------- */
class AbortError extends Error {
  constructor() { super('已取消'); this.name = 'AbortError'; }
}
const makeAbortError = () => new AbortError();

/* ============================================================
 * 队列管理
 * ============================================================ */
function addFiles(files) {
  for (const f of files) {
    state.queue.push({
      id: state.nextId++,
      file: f,
      status: 'pending',
      output: null,
      error: null,
    });
  }
  renderQueue();
}

function removeFromQueue(id) {
  const i = state.queue.findIndex((q) => q.id === id);
  if (i >= 0) {
    state.queue.splice(i, 1);
    renderQueue();
  }
}

function statusIcon(s) {
  return { pending: '📄', processing: '⏳', done: '✅', error: '❌' }[s] || '📄';
}
function statusLabel(item) {
  if (item.status === 'done') return '完成';
  if (item.status === 'error') return '失败';
  if (item.status === 'processing') return '处理中';
  return '待处理';
}

function renderQueue() {
  queueCount.textContent = state.queue.length;
  if (!state.queue.length) {
    fileList.innerHTML =
      '<div class="queue-empty">还没有文件 · 拖拽文件到上方区域或点击选择</div>';
    return;
  }
  fileList.innerHTML = '';
  for (const item of state.queue) {
    const el = document.createElement('div');
    el.className = 'queue-item status-' + item.status;

    const icon = document.createElement('span');
    icon.className = 'qi-icon';
    icon.textContent = statusIcon(item.status);

    const name = document.createElement('span');
    name.className = 'qi-name';
    name.textContent = item.file.name;
    name.title = item.file.name;

    const size = document.createElement('span');
    size.className = 'qi-size';
    size.textContent = formatSize(item.file.size);

    const status = document.createElement('span');
    status.className = 'qi-status';
    status.textContent = statusLabel(item);
    if (item.error) status.title = item.error;

    const actions = document.createElement('span');
    actions.className = 'qi-actions';

    if (item.status === 'done' && item.output) {
      const dl = document.createElement('button');
      dl.className = 'qi-btn';
      dl.textContent = '⬇';
      dl.title = '下载';
      dl.addEventListener('click', () => {
        downloadBlob(new Blob([item.output.data]), item.output.name);
      });
      actions.appendChild(dl);
    }
    if (!state.busy) {
      const rm = document.createElement('button');
      rm.className = 'qi-btn';
      rm.textContent = '✕';
      rm.title = '移除';
      rm.addEventListener('click', () => removeFromQueue(item.id));
      actions.appendChild(rm);
    }

    el.append(icon, name, size, status, actions);
    fileList.appendChild(el);
  }
}

/* ---------- 文件选择 / 拖放 ---------- */
$('addFilesBtn').addEventListener('click', () => fileInput.click());
$('addFolderBtn').addEventListener('click', () => folderInput.click());
dropZone.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', () => {
  if (fileInput.files.length) addFiles([...fileInput.files]);
  fileInput.value = '';
});
folderInput.addEventListener('change', () => {
  if (folderInput.files.length) addFiles([...folderInput.files]);
  folderInput.value = '';
});
$('clearQueueBtn').addEventListener('click', () => {
  if (state.busy) return;
  state.queue = [];
  downloadGroup.style.display = 'none';
  clearStatus();
  setProgress(0);
  renderQueue();
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const files = [...e.dataTransfer.files];
  if (files.length) addFiles(files);
});

/* ============================================================
 * 密码强度 / 显示 / 随机（顶部全局）
 * ============================================================ */
function pwdStrength(pwd) {
  if (!pwd) return { level: 0, label: '—', color: '', pct: 0 };
  let s = 0;
  if (pwd.length >= 8) s++;
  if (pwd.length >= 12) s++;
  if (pwd.length >= 16) s++;
  if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) s++;
  if (/\d/.test(pwd)) s++;
  if (/[^a-zA-Z0-9]/.test(pwd)) s++;
  const levels = [
    { label: '非常弱', color: '#ff3b30', pct: 15 },
    { label: '弱', color: '#ff3b30', pct: 30 },
    { label: '中等', color: '#ff9500', pct: 50 },
    { label: '较强', color: '#ffcc00', pct: 70 },
    { label: '强', color: '#34c759', pct: 85 },
    { label: '非常强', color: '#30d158', pct: 100 },
  ];
  const idx = clamp(Math.floor((s * 5) / 6), 0, 5);
  return { level: s, ...levels[idx] };
}

function updatePwdMeter() {
  const r = pwdStrength(passwordInput.value);
  pwdMeter.style.width = r.pct + '%';
  pwdMeter.style.background = r.color || 'var(--border)';
  pwdHint.textContent = passwordInput.value ? `密码强度：${r.label}` : '密码强度：—';
}
passwordInput.addEventListener('input', updatePwdMeter);
updatePwdMeter();

let pwdVisible = false;
togglePwdBtn.addEventListener('click', () => {
  pwdVisible = !pwdVisible;
  passwordInput.type = pwdVisible ? 'text' : 'password';
  togglePwdBtn.textContent = pwdVisible ? '隐藏' : '显示';
});

genPwdBtn.addEventListener('click', () => {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';
  const sym = '!@#$%^&*()-_=+[]{};:,.?';
  const all = upper + lower + digits + sym;
  const len = 20;
  const arr = new Uint32Array(len);
  crypto.getRandomValues(arr);
  let pwd = '';
  pwd += upper[arr[0] % upper.length];
  pwd += lower[arr[1] % lower.length];
  pwd += digits[arr[2] % digits.length];
  pwd += sym[arr[3] % sym.length];
  for (let i = 4; i < len; i++) pwd += all[arr[i] % all.length];
  const pArr = pwd.split('');
  const shuf = new Uint32Array(pArr.length);
  crypto.getRandomValues(shuf);
  for (let i = pArr.length - 1; i > 0; i--) {
    const j = shuf[i] % (i + 1);
    [pArr[i], pArr[j]] = [pArr[j], pArr[i]];
  }
  passwordInput.value = pArr.join('');
  passwordInput.type = 'text';
  pwdVisible = true;
  togglePwdBtn.textContent = '隐藏';
  updatePwdMeter();
});

/* ---------- 迭代次数预设 ---------- */
document.querySelectorAll('[data-iter]').forEach((btn) => {
  btn.addEventListener('click', () => {
    iterationsInput.value = btn.dataset.iter;
  });
});

/* ---------- 压缩轮数控件 ---------- */
function updateCompRoundsState() {
  const isSuper = parseInt(compAlgEl.value, 10) === 4;
  compRoundsInput.disabled = state.busy || !isSuper;
  compRoundsGroup.style.opacity = isSuper ? '1' : '0.5';
}
compAlgEl.addEventListener('change', updateCompRoundsState);
updateCompRoundsState();

/* ---------- KDF 标签联动 ---------- */
function updateKdfModeLabels() {
  const h = HASH_NAME[parseInt(kdfHashEl.value, 10)] || 'SHA-256';
  const hmacOpt = kdfModeEl.querySelector('option[value="hmac"]');
  const hkdfOpt = kdfModeEl.querySelector('option[value="hkdf"]');
  if (hmacOpt) hmacOpt.textContent = `HMAC-${h}`;
  if (hkdfOpt) hkdfOpt.textContent = `HKDF-${h}`;
}
kdfHashEl.addEventListener('change', updateKdfModeLabels);
updateKdfModeLabels();

/* ---------- 预设 ---------- */
function applyOptions(o) {
  layersInput.value = o.layers;
  cipherAlgEl.value = String(o.cipherAlg);
  kdfHashEl.value = String(o.kdfHash);
  kdfModeEl.value = o.kdfMode;
  iterationsInput.value = o.iterations;
  compAlgEl.value = String(o.compAlg);
  compRoundsInput.value = o.compRounds;
  padSizeEl.value = String(o.padCode);
  aadTextarea.value = o.aad || '';
  updateCompRoundsState();
  updateKdfModeLabels();
}

document.querySelectorAll('[data-preset]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const p = PRESETS[btn.dataset.preset];
    if (!p) return;
    applyOptions(p);
    presetHint.textContent = `已应用预设：${p.label}`;
  });
});

$('resetBtn').addEventListener('click', () => {
  applyOptions(DEFAULT_OPTS);
  presetHint.textContent = '已恢复默认参数';
});

/* ============================================================
 * 字节工具
 * ============================================================ */
function bytesToHex(bytes) {
  const chunks = [];
  const CHUNK = 16384;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    const sub = bytes.subarray(i, i + CHUNK);
    let s = '';
    for (let j = 0; j < sub.length; j++) {
      s += sub[j].toString(16).padStart(2, '0');
    }
    chunks.push(s);
  }
  return chunks.join('');
}

function hexToBytes(str) {
  str = str.replace(/\s+/g, '').trim();
  if (!str.length) throw new Error('十六进制内容为空');
  if (str.length % 2 !== 0) throw new Error('十六进制长度必须为偶数');
  const out = new Uint8Array(str.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(str.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error('十六进制格式不正确');
    out[i] = b;
  }
  return out;
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(str) {
  const binary = atob(str.trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function detectEncodedFormat(arrayBuf) {
  const bytes = new Uint8Array(arrayBuf);
  if (bytes.length >= 4 &&
      bytes[0] === 0x46 && bytes[1] === 0x45 && bytes[2] === 0x4e && bytes[3] === 0x43) {
    return 'binary';
  }
  if (bytes.length >= 8) {
    const hexMagic = '46454e43';
    let ok = true;
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== hexMagic.charCodeAt(i)) { ok = false; break; }
    }
    if (ok) return 'hex';
  }
  return null;
}

function isEncryptedHeader(bytes) {
  if (bytes.length >= 4 && bytes[0] === 0x46 && bytes[1] === 0x45 &&
      bytes[2] === 0x4e && bytes[3] === 0x43) return true;
  if (bytes.length >= 8) {
    const hexMagic = '46454e43';
    for (let i = 0; i < 8; i++) {
      if (bytes[i] !== hexMagic.charCodeAt(i)) return false;
    }
    return true;
  }
  return false;
}

/* ============================================================
 * 读取表单
 * ============================================================ */
function getOptions() {
  const layersRaw = parseInt(layersInput.value, 10);
  const iterRaw = parseInt(iterationsInput.value, 10);
  const compRaw = parseInt(compRoundsInput.value, 10);
  const padRaw = parseInt(padSizeEl.value, 10);
  return {
    password: passwordInput.value,
    layers: clamp(Number.isFinite(layersRaw) && layersRaw > 0 ? layersRaw : 3, 1, 50),
    cipherAlg: parseInt(cipherAlgEl.value, 10) || 3,
    kdfHash: parseInt(kdfHashEl.value, 10) || 1,
    kdfMode: kdfModeEl.value,
    iterations: clamp(Number.isFinite(iterRaw) && iterRaw > 0 ? iterRaw : 300000, ITER_MIN, ITER_MAX),
    compAlg: parseInt(compAlgEl.value, 10) || 0,
    compRounds: clamp(Number.isFinite(compRaw) && compRaw > 0 ? compRaw : 3, 1, 8),
    padCode: Number.isFinite(padRaw) && padRaw >= 0 && padRaw < PAD_SIZES.length ? padRaw : 0,
    aad: aadTextarea.value,
    useHex: !hexMode.checked,
    keepOrigName: keepOrigName.checked,
  };
}

/* ============================================================
 * 密钥派生
 * ============================================================ */
async function deriveMasterKey(password, salt, iterations, hashName) {
  const km = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: hashName },
    km,
    256
  );
  return new Uint8Array(bits);
}

async function deriveLayerKey(masterBytes, layerIndex, kdfMode, hashName, keyLen) {
  const info = new TextEncoder().encode(`FENC-layer-${layerIndex}`);
  if (kdfMode === 'hkdf') {
    const key = await crypto.subtle.importKey(
      'raw', masterBytes, 'HKDF', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: hashName, salt: new Uint8Array(0), info },
      key, 256
    );
    return new Uint8Array(bits).slice(0, keyLen);
  }
  const key = await crypto.subtle.importKey(
    'raw', masterBytes, { name: 'HMAC', hash: hashName }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, info);
  return new Uint8Array(sig).slice(0, keyLen);
}

/* ============================================================
 * AES-GCM 单层
 * ============================================================ */
async function encryptLayer(data, keyBytes, aadBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aadBytes && aadBytes.length) params.additionalData = aadBytes;
  const ct = await crypto.subtle.encrypt(params, key, data);
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

async function decryptLayer(payload, keyBytes, aadBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const iv = payload.subarray(0, 12);
  const ct = payload.subarray(12);
  const params = { name: 'AES-GCM', iv };
  if (aadBytes && aadBytes.length) params.additionalData = aadBytes;
  const pt = await crypto.subtle.decrypt(params, key, ct);
  return new Uint8Array(pt);
}

/* ============================================================
 * 压缩
 * ============================================================ */
async function compressOnce(data, format) {
  const blob = new Blob([data]);
  const cs = new CompressionStream(format);
  const stream = blob.stream().pipeThrough(cs);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

async function decompressOnce(data, format) {
  const blob = new Blob([data]);
  const ds = new DecompressionStream(format);
  const stream = blob.stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

async function superCompress(data, rounds, onProgress) {
  let current = data;
  let actual = 0;
  for (let i = 0; i < rounds; i++) {
    let next;
    try {
      next = await compressOnce(current, 'gzip');
    } catch (e) {
      break;
    }
    if (next.length >= current.length) break;
    current = next;
    actual = i + 1;
    if (onProgress) onProgress((i + 1) / rounds, `超级压缩 ${i + 1}/${rounds} 轮…`);
  }
  return { data: current, rounds: actual };
}

async function superDecompress(data, rounds, onProgress) {
  const safeRounds = clamp(rounds | 0, 0, 8);
  let current = data;
  for (let i = 0; i < safeRounds; i++) {
    current = await decompressOnce(current, 'gzip');
    if (onProgress) onProgress((i + 1) / safeRounds, `解压 ${i + 1}/${safeRounds} 轮…`);
  }
  return current;
}

/* ============================================================
 * 填充
 * ============================================================ */
function padData(data, blockSize) {
  if (blockSize <= 0) return data;
  if (blockSize > 255) blockSize = 255;
  const rem = data.length % blockSize;
  const padLen = rem === 0 ? blockSize : blockSize - rem;
  const out = new Uint8Array(data.length + padLen);
  out.set(data, 0);
  out.fill(padLen, data.length);
  return out;
}

function unpadData(data) {
  if (!data.length) throw new Error('数据为空，无法去除填充');
  const padLen = data[data.length - 1];
  if (padLen < 1 || padLen > data.length) throw new Error('填充无效');
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('填充已损坏');
  }
  return data.slice(0, data.length - padLen);
}

/* ============================================================
 * 核心：字节加密
 * ============================================================ */
async function encryptBytes(rawBytes, opts, onProgress, shouldAbort) {
  ensureCryptoAvailable();
  const {
    password, layers, cipherAlg, kdfHash, kdfMode,
    iterations, compAlg, compRounds, padCode, aad,
  } = opts;

  if (!password) throw new Error('请输入密码');
  if (shouldAbort && shouldAbort()) throw makeAbortError();

  onProgress(0.01, '读取数据…');
  const raw = rawBytes;

  let data = raw;
  let actualRounds = 0;
  if (compAlg === 4) {
    onProgress(0.04, '超级压缩…');
    const res = await superCompress(raw, compRounds, (p, m) =>
      onProgress(0.04 + p * 0.14, m)
    );
    data = res.data;
    actualRounds = res.rounds;
  } else if (compAlg > 0 && COMP_FMT[compAlg]) {
    onProgress(0.06, '压缩数据…');
    data = await compressOnce(raw, COMP_FMT[compAlg]);
    actualRounds = 1;
    onProgress(0.18, '压缩完成');
  }

  if (shouldAbort && shouldAbort()) throw makeAbortError();

  const padSize = PAD_SIZES[padCode] || 0;
  if (padSize > 0) {
    onProgress(0.20, '填充数据…');
    data = padData(data, padSize);
  }

  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const hashName = HASH_NAME[kdfHash] || 'SHA-256';
  const keyLen = CIPHER_KEY_LEN[cipherAlg];
  if (!keyLen) throw new Error('无效的加密算法');

  onProgress(0.22, '派生主密钥（PBKDF2）…');
  const master = await deriveMasterKey(password, salt, iterations, hashName);

  const aadBytes = aad ? new TextEncoder().encode(aad) : undefined;
  let current = data;
  for (let i = 0; i < layers; i++) {
    if (shouldAbort && shouldAbort()) throw makeAbortError();
    const layerKey = await deriveLayerKey(master, i, kdfMode, hashName, keyLen);
    current = await encryptLayer(current, layerKey, aadBytes);
    onProgress(0.25 + ((i + 1) / layers) * 0.65, `加密第 ${i + 1}/${layers} 层…`);
  }

  const header = new Uint8Array(HEADER_LEN);
  let off = 0;
  header.set(MAGIC, off); off += 4;
  header[off++] = VERSION;
  header[off++] = cipherAlg;
  header[off++] = kdfHash;
  header[off++] = kdfMode === 'hkdf' ? 1 : 0;
  const outCompAlg = compAlg === 4 && actualRounds === 0 ? 0 : compAlg;
  header[off++] = outCompAlg;
  header[off++] = actualRounds;
  header[off++] = padCode;
  header[off++] = layers;
  header.set(salt, off); off += 16;
  new DataView(header.buffer).setUint32(off, iterations, false);

  const out = new Uint8Array(HEADER_LEN + current.length);
  out.set(header, 0);
  out.set(current, HEADER_LEN);

  onProgress(1, '加密完成');
  return out;
}

/* ============================================================
 * 核心：字节解密
 * ============================================================ */
async function decryptBytes(encBuffer, password, opts, onProgress, shouldAbort) {
  ensureCryptoAvailable();
  if (!password) throw new Error('请输入密码');
  if (encBuffer.byteLength < 5) throw new Error('文件太小，不是有效的加密文件');
  if (new TextDecoder().decode(encBuffer.subarray(0, 4)) !== 'FENC') {
    throw new Error('不是有效的加密文件（缺少 FENC 标识）');
  }
  const version = encBuffer[4];
  if (version === 1) return decryptV1(encBuffer, password, onProgress, shouldAbort);
  if (version !== VERSION) throw new Error(`不支持的格式版本：${version}`);
  if (encBuffer.byteLength < HEADER_LEN) throw new Error('文件头不完整');

  let off = 5;
  const cipherAlg = encBuffer[off++];
  const kdfHash = encBuffer[off++];
  const kdfModeCode = encBuffer[off++];
  const compAlg = encBuffer[off++];
  const compRounds = encBuffer[off++];
  const padCode = encBuffer[off++];
  const layers = encBuffer[off++];
  const salt = encBuffer.subarray(off, off + SALT_LEN); off += SALT_LEN;
  const iterations = new DataView(
    encBuffer.buffer,
    encBuffer.byteOffset + off,
    4
  ).getUint32(0, false);
  off += 4;

  if (layers < 1 || layers > 50) throw new Error(`层级数异常：${layers}`);
  const keyLen = CIPHER_KEY_LEN[cipherAlg];
  if (!keyLen) throw new Error('未知加密算法');
  const hashName = HASH_NAME[kdfHash];
  if (!hashName) throw new Error('未知 KDF 哈希');
  if (compAlg !== 0 && compAlg !== 4 && !COMP_FMT[compAlg]) {
    throw new Error(`未知压缩算法：${compAlg}`);
  }
  const kdfMode = kdfModeCode === 1 ? 'hkdf' : 'hmac';

  let data = encBuffer.subarray(HEADER_LEN);

  onProgress(0.05, '派生主密钥（PBKDF2）…');
  const master = await deriveMasterKey(password, salt, iterations, hashName);
  const aadBytes = opts.aad ? new TextEncoder().encode(opts.aad) : undefined;

  for (let i = layers - 1; i >= 0; i--) {
    if (shouldAbort && shouldAbort()) throw makeAbortError();
    const layerKey = await deriveLayerKey(master, i, kdfMode, hashName, keyLen);
    try {
      data = await decryptLayer(data, layerKey, aadBytes);
    } catch (e) {
      throw new Error('解密失败：密码 / AAD 错误，或文件已损坏');
    }
    onProgress(0.1 + ((layers - i) / layers) * 0.7, `解密第 ${layers - i}/${layers} 层…`);
  }

  const padSize = PAD_SIZES[padCode] || 0;
  if (padSize > 0) {
    onProgress(0.83, '去除填充…');
    data = unpadData(data);
  }

  if (compAlg === 4 && compRounds > 0) {
    onProgress(0.85, '解压数据…');
    data = await superDecompress(data, compRounds, (p, m) =>
      onProgress(0.85 + p * 0.13, m)
    );
  } else if (compAlg > 0) {
    onProgress(0.9, '解压数据…');
    data = await decompressOnce(data, COMP_FMT[compAlg]);
  }

  onProgress(1, '解密完成');
  return data;
}

/* ============================================================
 * v1 兼容解密
 * ============================================================ */
async function decryptV1(encBuffer, password, onProgress, shouldAbort) {
  const HEADER_V1 = 4 + 1 + 1 + 1 + 16;
  if (encBuffer.byteLength < HEADER_V1) throw new Error('v1 文件头不完整');
  const layers = encBuffer[5];
  if (layers < 1 || layers > 50) throw new Error(`v1 层级数异常：${layers}`);
  const iterCode = encBuffer[6];
  const iterations = { 1: 100000, 2: 300000, 3: 600000 }[iterCode] || 300000;
  const salt = encBuffer.subarray(7, 7 + 16);
  let data = encBuffer.subarray(HEADER_V1);

  onProgress(0.05, '派生主密钥（v1 PBKDF2）…');
  const master = await deriveMasterKey(password, salt, iterations, 'SHA-256');

  for (let i = layers - 1; i >= 0; i--) {
    if (shouldAbort && shouldAbort()) throw makeAbortError();
    const info = new TextEncoder().encode(`FENC-layer-${i}`);
    const hmacKey = await crypto.subtle.importKey(
      'raw', master, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', hmacKey, info);
    const layerKey = new Uint8Array(sig);
    try {
      data = await decryptLayer(data, layerKey, undefined);
    } catch (e) {
      throw new Error('解密失败：密码错误或文件已损坏（v1）');
    }
    onProgress(0.1 + ((layers - i) / layers) * 0.85, `解密第 ${layers - i}/${layers} 层…`);
  }
  onProgress(1, '解密完成（v1）');
  return data;
}

/* ============================================================
 * 单文件包装
 * ============================================================ */
async function encryptOne(file, opts, onProgress, shouldAbort) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const enc = await encryptBytes(bytes, opts, onProgress, shouldAbort);
  let data, name;
  if (opts.useHex) {
    data = new TextEncoder().encode(bytesToHex(enc));
    name = file.name + '.enc.hex';
  } else {
    data = enc;
    name = file.name + '.enc';
  }
  return { name, data };
}

async function decryptOne(file, opts, onProgress, shouldAbort) {
  const arrayBuf = await file.arrayBuffer();
  const detected = detectEncodedFormat(arrayBuf);
  let encBuffer;
  if (detected === 'binary') {
    encBuffer = new Uint8Array(arrayBuf);
  } else if (detected === 'hex') {
    encBuffer = hexToBytes(new TextDecoder().decode(arrayBuf));
  } else if (opts.useHex) {
    encBuffer = hexToBytes(new TextDecoder().decode(arrayBuf));
  } else {
    encBuffer = new Uint8Array(arrayBuf);
  }

  const pt = await decryptBytes(encBuffer, opts.password, opts, onProgress, shouldAbort);

  let name = file.name;
  if (opts.keepOrigName) {
    if (name.endsWith('.enc.hex')) name = name.slice(0, -8);
    else if (name.endsWith('.enc')) name = name.slice(0, -4);
    if (!name) name = 'decrypted_file';
  } else {
    name = file.name + '.dec';
  }
  return { name, data: pt };
}

async function autoProcess(file, opts, onProgress, shouldAbort) {
  const head = new Uint8Array(
    await file.slice(0, Math.min(file.size, 64)).arrayBuffer()
  );
  if (isEncryptedHeader(head)) return decryptOne(file, opts, onProgress, shouldAbort);
  return encryptOne(file, opts, onProgress, shouldAbort);
}

/* ============================================================
 * 下载
 * ============================================================ */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

/* ============================================================
 * ZIP 打包（内置，无依赖）
 * ============================================================ */
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function buildZip(entries) {
  const chunks = [], central = [];
  let offset = 0;
  const enc = new TextEncoder();

  for (const { name, data } of entries) {
    const nameBytes = enc.encode(name);
    const crc = crc32(data);

    const local = new Uint8Array(30 + nameBytes.length);
    const dv = new DataView(local.buffer);
    dv.setUint32(0, 0x04034b50, true);
    dv.setUint16(4, 20, true);
    dv.setUint16(6, 0x0800, true); // UTF-8 标志
    dv.setUint16(8, 0, true);
    dv.setUint16(10, 0, true);
    dv.setUint16(12, 0x21, true);
    dv.setUint32(14, crc, true);
    dv.setUint32(18, data.length, true);
    dv.setUint32(22, data.length, true);
    dv.setUint16(26, nameBytes.length, true);
    dv.setUint16(28, 0, true);
    local.set(nameBytes, 30);
    chunks.push(local, data);

    const cd = new Uint8Array(46 + nameBytes.length);
    const cdv = new DataView(cd.buffer);
    cdv.setUint32(0, 0x02014b50, true);
    cdv.setUint16(4, 20, true);
    cdv.setUint16(6, 20, true);
    cdv.setUint16(8, 0x0800, true);
    cdv.setUint16(10, 0, true);
    cdv.setUint16(12, 0, true);
    cdv.setUint16(14, 0x21, true);
    cdv.setUint32(16, crc, true);
    cdv.setUint32(20, data.length, true);
    cdv.setUint32(24, data.length, true);
    cdv.setUint16(28, nameBytes.length, true);
    cdv.setUint16(30, 0, true);
    cdv.setUint16(32, 0, true);
    cdv.setUint16(34, 0, true);
    cdv.setUint16(36, 0, true);
    cdv.setUint32(38, 0, true);
    cdv.setUint32(42, offset, true);
    cd.set(nameBytes, 46);
    central.push(cd);

    offset += local.length + data.length;
  }

  const centralStart = offset;
  let centralSize = 0;
  for (const c of central) centralSize += c.length;

  const eocd = new Uint8Array(22);
  const edv = new DataView(eocd.buffer);
  edv.setUint32(0, 0x06054b50, true);
  edv.setUint16(8, entries.length, true);
  edv.setUint16(10, entries.length, true);
  edv.setUint32(12, centralSize, true);
  edv.setUint32(16, centralStart, true);

  return new Blob([...chunks, ...central, eocd], { type: 'application/zip' });
}

/* ============================================================
 * 忙碌状态
 * ============================================================ */
const BUSY_DISABLE = [
  fileInput, folderInput, $('addFilesBtn'), $('addFolderBtn'), $('clearQueueBtn'),
  passwordInput, togglePwdBtn, genPwdBtn,
  encryptBtn, decryptBtn, autoBtn,
  layersInput, cipherAlgEl, kdfHashEl, kdfModeEl, iterationsInput,
  compAlgEl, compRoundsInput, padSizeEl, aadTextarea, hexMode, keepOrigName,
  hideScrollbarEl,
];

function setBusy(busy) {
  state.busy = busy;
  for (const el of BUSY_DISABLE) if (el) el.disabled = busy;
  document.querySelectorAll('[data-iter], [data-preset], #resetBtn')
    .forEach((b) => (b.disabled = busy));
  cancelBtn.disabled = !busy;

  if (!busy) {
    updateCompRoundsState();
    updateKdfModeLabels();
    if (!window.crypto || !window.crypto.subtle) {
      encryptBtn.disabled = true;
      decryptBtn.disabled = true;
      autoBtn.disabled = true;
    }
  }
  renderQueue();
}

/* ============================================================
 * 批量执行
 * ============================================================ */
async function runBatch(mode) {
  if (state.busy) return;
  if (!state.queue.length) return showStatus('请先添加文件', 'error');
  const opts = getOptions();
  if (!opts.password) return showStatus('请输入密码', 'error');

  state.cancelled = false;
  setBusy(true);
  downloadGroup.style.display = 'none';
  setProgress(0.001);

  const total = state.queue.length;
  let okCount = 0, errCount = 0;
  const t0 = performance.now();

  state.queue.forEach((q) => {
    q.status = 'pending';
    q.output = null;
    q.error = null;
  });
  renderQueue();

  for (let i = 0; i < state.queue.length; i++) {
    if (state.cancelled) break;
    const item = state.queue[i];
    item.status = 'processing';
    renderQueue();
    showStatus(`处理中 ${i + 1}/${total}：${item.file.name}`, 'info');

    const shouldAbort = () => state.cancelled;
    const onProg = (p, msg) => {
      setProgress(
        (i + p) / total,
        msg ? `${msg} · ${i + 1}/${total}` : undefined
      );
    };

    try {
      let result;
      if (mode === 'encrypt') {
        result = await encryptOne(item.file, opts, onProg, shouldAbort);
      } else if (mode === 'decrypt') {
        result = await decryptOne(item.file, opts, onProg, shouldAbort);
      } else {
        result = await autoProcess(item.file, opts, onProg, shouldAbort);
      }
      item.output = result;
      item.status = 'done';
      okCount++;
    } catch (e) {
      if (e && e.name === 'AbortError') {
        item.status = 'pending';
        break;
      }
      item.error = e.message || String(e);
      item.status = 'error';
      errCount++;
    }
    renderQueue();
  }

  const elapsed = (performance.now() - t0) / 1000;
  setProgress(1);
  setBusy(false);

  const done = state.queue.filter((q) => q.status === 'done' && q.output);
  if (state.cancelled) {
    showStatus(`⏹ 已取消 · 完成 ${okCount} / ${total}（失败 ${errCount}）`, 'info');
  } else if (errCount && !okCount) {
    showStatus(`❌ 全部失败（${errCount} 个），用时 ${elapsed.toFixed(1)}s`, 'error');
  } else if (errCount) {
    showStatus(
      `⚠️ 完成 ${okCount} 个，失败 ${errCount} 个，用时 ${elapsed.toFixed(1)}s`,
      'info'
    );
  } else {
    showStatus(`✅ 全部完成：${okCount} 个文件，用时 ${elapsed.toFixed(1)}s`, 'success');
  }
  if (done.length) downloadGroup.style.display = 'flex';
}

/* ---------- 批量操作按钮 ---------- */
encryptBtn.addEventListener('click', () => runBatch('encrypt'));
decryptBtn.addEventListener('click', () => runBatch('decrypt'));
autoBtn.addEventListener('click', () => runBatch('auto'));

cancelBtn.addEventListener('click', () => {
  state.cancelled = true;
  showStatus('正在取消…', 'info');
});

/* ---------- 下载全部 ---------- */
downloadAllBtn.addEventListener('click', async () => {
  const done = state.queue.filter((q) => q.status === 'done' && q.output);
  for (const item of done) {
    downloadBlob(new Blob([item.output.data]), item.output.name);
    await new Promise((r) => setTimeout(r, 180));
  }
});

zipDownloadBtn.addEventListener('click', () => {
  const done = state.queue.filter((q) => q.status === 'done' && q.output);
  if (!done.length) return;
  const seen = new Set();
  const entries = done.map((q) => {
    let n = q.output.name;
    if (seen.has(n)) {
      const dot = n.lastIndexOf('.');
      const base = dot > 0 ? n.slice(0, dot) : n;
      const ext = dot > 0 ? n.slice(dot) : '';
      let k = 1;
      while (seen.has(`${base}_${k}${ext}`)) k++;
      n = `${base}_${k}${ext}`;
    }
    seen.add(n);
    return { name: n, data: q.output.data };
  });
  const blob = buildZip(entries);
  downloadBlob(blob, `fenc-export-${Date.now()}.zip`);
  showStatus(`📦 已打包 ${entries.length} 个文件`, 'success');
});

clearResultsBtn.addEventListener('click', () => {
  state.queue.forEach((q) => {
    if (q.status === 'done' || q.status === 'error') {
      q.status = 'pending';
      q.output = null;
      q.error = null;
    }
  });
  downloadGroup.style.display = 'none';
  setProgress(0);
  clearStatus();
  renderQueue();
});

/* ============================================================
 * 文本加密 / 解密
 * ============================================================ */
const textInput = $('textInput');
const textOutput = $('textOutput');
const textStatus = $('textStatus');
const textEncodingEl = $('textEncoding');

function setTextStatus(msg, type = 'info') {
  textStatus.textContent = msg;
  textStatus.className = `status ${type}`;
}

$('textEncryptBtn').addEventListener('click', async () => {
  textStatus.className = 'status';
  const text = textInput.value;
  if (!text) return setTextStatus('请输入文本', 'error');
  const opts = getOptions();
  if (!opts.password) return setTextStatus('请输入密码', 'error');
  try {
    const bytes = new TextEncoder().encode(text);
    const enc = await encryptBytes(bytes, opts, () => {});
    const encStr = textEncodingEl.value === 'base64'
      ? bytesToBase64(enc)
      : bytesToHex(enc);
    textOutput.value = encStr;
    setTextStatus(`✅ 加密完成（${text.length} 字符 → ${encStr.length} 字符）`, 'success');
  } catch (e) {
    setTextStatus(`❌ 加密失败：${e.message}`, 'error');
  }
});

$('textDecryptBtn').addEventListener('click', async () => {
  textStatus.className = 'status';
  const text = textInput.value.trim();
  if (!text) return setTextStatus('请输入密文', 'error');
  const opts = getOptions();
  if (!opts.password) return setTextStatus('请输入密码', 'error');
  try {
    const encBytes = textEncodingEl.value === 'base64'
      ? base64ToBytes(text)
      : hexToBytes(text);
    const pt = await decryptBytes(encBytes, opts.password, opts, () => {});
    textOutput.value = new TextDecoder().decode(pt);
    setTextStatus('✅ 解密完成', 'success');
  } catch (e) {
    setTextStatus(`❌ 解密失败：${e.message}`, 'error');
  }
});

$('copyOutputBtn').addEventListener('click', async () => {
  if (!textOutput.value) return setTextStatus('没有可复制的内容', 'error');
  try {
    await navigator.clipboard.writeText(textOutput.value);
    setTextStatus('📋 已复制到剪贴板', 'success');
  } catch (e) {
    setTextStatus('❌ 复制失败：' + e.message, 'error');
  }
});

$('useAsInputBtn').addEventListener('click', () => {
  if (!textOutput.value) return;
  textInput.value = textOutput.value;
  textOutput.value = '';
  setTextStatus('↕ 结果已作为输入', 'info');
});

$('clearTextBtn').addEventListener('click', () => {
  textInput.value = '';
  textOutput.value = '';
  textStatus.className = 'status';
});

/* ============================================================
 * 工具箱：哈希
 * ============================================================ */
const hashInput = $('hashInput');
const hashOutput = $('hashOutput');

document.querySelectorAll('[data-hash]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const text = hashInput.value;
    if (!text) {
      hashOutput.textContent = '请输入文本';
      return;
    }
    try {
      const bytes = new TextEncoder().encode(text);
      let hex;
      if (btn.dataset.hash === 'crc32') {
        hex = crc32(bytes).toString(16).padStart(8, '0');
      } else {
        const buf = await crypto.subtle.digest(btn.dataset.hash, bytes);
        hex = bytesToHex(new Uint8Array(buf));
      }
      hashOutput.textContent = `${btn.dataset.hash}: ${hex}`;
    } catch (e) {
      hashOutput.textContent = '❌ ' + e.message;
    }
  });
});

/* ============================================================
 * 工具箱：密码生成器
 * ============================================================ */
const pwdLenEl = $('pwdLen');
const pwdLenVal = $('pwdLenVal');
pwdLenEl.addEventListener('input', () => {
  pwdLenVal.textContent = pwdLenEl.value;
});

function genPwdFromOpts() {
  const len = parseInt(pwdLenEl.value, 10);
  const groups = [];
  if ($('optUpper').checked) groups.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if ($('optLower').checked) groups.push('abcdefghijklmnopqrstuvwxyz');
  if ($('optDigits').checked) groups.push('0123456789');
  if ($('optSymbols').checked) groups.push('!@#$%^&*()-_=+[]{};:,.?');
  if (!groups.length) return '';
  const all = groups.join('');
  const out = [];
  const rnd = new Uint32Array(len);
  crypto.getRandomValues(rnd);
  for (let i = 0; i < Math.min(groups.length, len); i++) {
    out.push(groups[i][rnd[i] % groups[i].length]);
  }
  for (let i = groups.length; i < len; i++) {
    out.push(all[rnd[i] % all.length]);
  }
  const shuf = new Uint32Array(out.length);
  crypto.getRandomValues(shuf);
  for (let i = out.length - 1; i > 0; i--) {
    const j = shuf[i] % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.join('');
}

$('genPwd2Btn').addEventListener('click', () => {
  $('generatedPwd').value = genPwdFromOpts();
});

$('copyPwdBtn').addEventListener('click', async () => {
  const v = $('generatedPwd').value;
  if (!v) return;
  try { await navigator.clipboard.writeText(v); } catch (_) {}
});

$('generatedPwd').value = genPwdFromOpts();

/* ============================================================
 * 工具箱：随机字节
 * ============================================================ */
$('genRandBtn').addEventListener('click', () => {
  const len = clamp(parseInt($('randLen').value, 10) || 32, 1, 4096);
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  const enc = $('randEncoding').value === 'base64'
    ? bytesToBase64(bytes)
    : bytesToHex(bytes);
  $('randOutput').value = enc;
});

$('copyRandBtn').addEventListener('click', async () => {
  const v = $('randOutput').value;
  if (!v) return;
  try { await navigator.clipboard.writeText(v); } catch (_) {}
});

/* ============================================================
 * 初始化
 * ============================================================ */
updateCompRoundsState();
updatePwdMeter();
updateKdfModeLabels();
renderQueue();

if (!window.crypto || !window.crypto.subtle) {
  showStatus(
    '❌ 当前环境不支持 Web Crypto API（file:// 打开会失败），请使用 HTTPS 或 localhost。',
    'error'
  );
  encryptBtn.disabled = true;
  decryptBtn.disabled = true;
  autoBtn.disabled = true;
}