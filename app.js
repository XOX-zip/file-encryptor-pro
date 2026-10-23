/* ============================================================
 * File Encryptor · Web Pro
 * v2 格式：FENC | ver | cipher | kdfHash | kdfMode | compAlg |
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

/* ★ 修复 #1：块大小必须 ≤255，否则单字节 padLen 装不下 → 填充被截断 → 解密损坏 */
const PAD_SIZES = [0, 16, 64, 128, 192, 255];

/* ---------- DOM ---------- */
const themeToggle = document.getElementById('themeToggle');
const themeButtons = themeToggle.querySelectorAll('button');
const filePicker = document.getElementById('filePicker');
const fileInput = document.getElementById('fileInput');
const fileNameEl = document.getElementById('fileName');
const fileHint = document.getElementById('fileHint');
const passwordInput = document.getElementById('password');
const togglePwdBtn = document.getElementById('togglePwdBtn');
const genPwdBtn = document.getElementById('genPwdBtn');
const pwdMeter = document.getElementById('pwdMeter');
const pwdHint = document.getElementById('pwdHint');
const layersInput = document.getElementById('layers');
const cipherAlgEl = document.getElementById('cipherAlg');
const kdfHashEl = document.getElementById('kdfHash');
const kdfModeEl = document.getElementById('kdfMode');
const iterationsInput = document.getElementById('iterations');
const compAlgEl = document.getElementById('compAlg');
const compRoundsInput = document.getElementById('compRounds');
const compRoundsGroup = document.getElementById('compRoundsGroup');
const padSizeEl = document.getElementById('padSize');
const aadTextarea = document.getElementById('aad');
const hexMode = document.getElementById('hexMode');
const hideScrollbarEl = document.getElementById('hideScrollbar');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const progressBar = document.getElementById('progressBar');
const progressFill = document.getElementById('progressFill');
const statusEl = document.getElementById('status');
const presetHint = document.getElementById('presetHint');

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

/* ★ 修复 #9：兼容旧浏览器的 addEventListener */
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

/* ---------- 工具 ---------- */
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

/* ★ 修复 #4：Web Crypto 可用性检测 */
function ensureCryptoAvailable() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API 不可用。请通过 HTTPS 或 localhost 访问此页面（file:// 不支持）。');
  }
}

/* ---------- 文件选择 ---------- */
fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  if (!file) {
    fileNameEl.textContent = '点击选择文件…';
    filePicker.classList.remove('has-file');
    fileHint.textContent = '';
    return;
  }
  fileNameEl.textContent = `${file.name} · ${formatSize(file.size)}`;
  filePicker.classList.add('has-file');
  if (file.size > 100 * 1024 * 1024) {
    fileHint.textContent = '⚠️ 文件超过 100 MB，浏览器内存可能不足，建议先分割文件。';
  } else if (file.size > 20 * 1024 * 1024) {
    fileHint.textContent = 'ℹ️ 大文件加密速度较慢，请耐心等待。';
  } else {
    fileHint.textContent = '';
  }
});

/* ---------- 密码强度 / 显示 / 随机 ---------- */
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
  const idx = clamp(Math.floor(s * 5 / 6), 0, 5);
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

/* ---------- 超级压缩轮数控件可用性 ---------- */
function updateCompRoundsState() {
  const isSuper = parseInt(compAlgEl.value, 10) === 4;
  compRoundsInput.disabled = !isSuper;
  compRoundsGroup.style.opacity = isSuper ? '1' : '0.5';
}
compAlgEl.addEventListener('change', updateCompRoundsState);
updateCompRoundsState();

/* ★ 修复 #3：随 kdfHash 动态更新 kdfMode 标签 */
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
    const key = btn.dataset.preset;
    const p = PRESETS[key];
    if (!p) return;
    applyOptions(p);
    presetHint.textContent = `已应用预设：${p.label}`;
  });
});

document.getElementById('resetBtn').addEventListener('click', () => {
  applyOptions(DEFAULT_OPTS);
  presetHint.textContent = '已恢复默认参数';
});

/* ---------- 密钥派生 ---------- */
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

/* ---------- AES-GCM 单层 ---------- */
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

/* ---------- 压缩 ---------- */
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
  /* ★ 修复 #6：限制最大轮数，防止畸形头部导致无限循环 */
  const safeRounds = clamp(rounds | 0, 0, 8);
  let current = data;
  for (let i = 0; i < safeRounds; i++) {
    current = await decompressOnce(current, 'gzip');
    if (onProgress) onProgress((i + 1) / safeRounds, `解压 ${i + 1}/${safeRounds} 轮…`);
  }
  return current;
}

/* ---------- 填充（★ 修复 #1：块大小已限制为 ≤255，padLen 一定装得下） ---------- */
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

/* ---------- 十六进制转换 ---------- */
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

/* ★ 修复 #2：自动识别二进制 / 十六进制 */
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

/* ---------- 读取表单 ---------- */
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
  };
}

/* ---------- 加密主流程 ---------- */
async function encryptFile(file, opts, onProgress) {
  ensureCryptoAvailable();
  const {
    password, layers, cipherAlg, kdfHash, kdfMode,
    iterations, compAlg, compRounds, padCode, aad,
  } = opts;

  if (!password) throw new Error('请输入密码');

  onProgress(0.01, '读取文件…');
  const raw = new Uint8Array(await file.arrayBuffer());

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
  /* 若超级压缩实际没生效（一轮都没成功），标 0 表示未压缩 */
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

/* ---------- 解密主流程 ---------- */
async function decryptFile(encBuffer, password, opts, onProgress) {
  ensureCryptoAvailable();
  if (!password) throw new Error('请输入密码');
  if (encBuffer.byteLength < 5) throw new Error('文件太小，不是有效的加密文件');
  if (new TextDecoder().decode(encBuffer.subarray(0, 4)) !== 'FENC') {
    throw new Error('不是有效的加密文件（缺少 FENC 标识）');
  }
  const version = encBuffer[4];
  if (version === 1) return decryptV1(encBuffer, password, onProgress);
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
  /* ★ 修复 #5：未知压缩算法防护 */
  if (compAlg !== 0 && compAlg !== 4 && !COMP_FMT[compAlg]) {
    throw new Error(`未知压缩算法：${compAlg}`);
  }
  const kdfMode = kdfModeCode === 1 ? 'hkdf' : 'hmac';

  let data = encBuffer.subarray(HEADER_LEN);

  onProgress(0.05, '派生主密钥（PBKDF2）…');
  const master = await deriveMasterKey(password, salt, iterations, hashName);

  const aadBytes = opts.aad ? new TextEncoder().encode(opts.aad) : undefined;

  for (let i = layers - 1; i >= 0; i--) {
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

/* ---------- v1 兼容解密 ---------- */
async function decryptV1(encBuffer, password, onProgress) {
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

/* ---------- 下载 ---------- */
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

/* ---------- 忙碌态 ---------- */
function setBusy(busy) {
  encryptBtn.disabled = busy;
  decryptBtn.disabled = busy;
  fileInput.disabled = busy;
  passwordInput.disabled = busy;
  layersInput.disabled = busy;
  cipherAlgEl.disabled = busy;
  kdfHashEl.disabled = busy;
  kdfModeEl.disabled = busy;
  iterationsInput.disabled = busy;
  compAlgEl.disabled = busy;
  compRoundsInput.disabled = busy || compAlgEl.value !== '4';
  padSizeEl.disabled = busy;
  aadTextarea.disabled = busy;
  hexMode.disabled = busy;
  hideScrollbarEl.disabled = busy;
  document.querySelectorAll('[data-iter], [data-preset], #resetBtn').forEach((b) => {
    b.disabled = busy;
  });
}

/* ---------- 加密按钮 ---------- */
encryptBtn.addEventListener('click', async () => {
  clearStatus();
  const file = fileInput.files[0];
  if (!file) return showStatus('请先选择文件', 'error');
  const opts = getOptions();
  if (!opts.password) return showStatus('请输入密码', 'error');

  try {
    setBusy(true);
    setProgress(0.01, '准备…');
    const encrypted = await encryptFile(file, opts, (p, m) => setProgress(p, m));

    let blob, name;
    if (opts.useHex) {
      setProgress(0.97, '转换为十六进制…');
      const hexStr = bytesToHex(encrypted);
      blob = new Blob([hexStr], { type: 'text/plain;charset=utf-8' });
      name = file.name + '.enc.hex';
    } else {
      setProgress(0.97, '打包二进制…');
      blob = new Blob([encrypted], { type: 'application/octet-stream' });
      name = file.name + '.enc';
    }
    downloadBlob(blob, name);
    setProgress(0);
    showStatus(
      `✅ 加密完成，已下载：${name}（原始 ${formatSize(file.size)} → 输出 ${formatSize(blob.size)}）`,
      'success'
    );
  } catch (err) {
    console.error(err);
    setProgress(0);
    showStatus(`❌ 加密失败：${err.message}`, 'error');
  } finally {
    setBusy(false);
  }
});

/* ---------- 解密按钮 ---------- */
decryptBtn.addEventListener('click', async () => {
  clearStatus();
  const file = fileInput.files[0];
  if (!file) return showStatus('请先选择文件', 'error');
  const opts = getOptions();
  if (!opts.password) return showStatus('请输入密码', 'error');

  try {
    setBusy(true);
    setProgress(0.01, '读取文件…');
    const arrayBuf = await file.arrayBuffer();
    let encBuffer;

    /* ★ 修复 #2：按头部 magic 自动识别二进制 / 十六进制 */
    const detected = detectEncodedFormat(arrayBuf);
    if (detected === 'binary') {
      encBuffer = new Uint8Array(arrayBuf);
    } else if (detected === 'hex') {
      setProgress(0.04, '解析十六进制…');
      const text = new TextDecoder().decode(arrayBuf);
      encBuffer = hexToBytes(text);
    } else if (opts.useHex) {
      const text = new TextDecoder().decode(arrayBuf);
      encBuffer = hexToBytes(text);
    } else {
      encBuffer = new Uint8Array(arrayBuf);
    }

    const decrypted = await decryptFile(encBuffer, opts.password, opts, (p, m) =>
      setProgress(p, m)
    );

    let originalName = file.name;
    if (originalName.endsWith('.enc.hex')) originalName = originalName.slice(0, -8);
    else if (originalName.endsWith('.enc')) originalName = originalName.slice(0, -4);
    if (!originalName) originalName = 'decrypted_file';

    const blob = new Blob([decrypted], { type: 'application/octet-stream' });
    downloadBlob(blob, originalName);
    setProgress(0);
    showStatus(`✅ 解密完成，已下载：${originalName}（${formatSize(blob.size)}）`, 'success');
  } catch (err) {
    console.error(err);
    setProgress(0);
    showStatus(`❌ 解密失败：${err.message}`, 'error');
  } finally {
    setBusy(false);
  }
});

/* ---------- 初始化 ---------- */
updateCompRoundsState();
updatePwdMeter();
updateKdfModeLabels();
if (!window.crypto || !window.crypto.subtle) {
  showStatus('❌ 当前环境不支持 Web Crypto API（file:// 打开会失败），请使用 HTTPS 或 localhost。', 'error');
  encryptBtn.disabled = true;
  decryptBtn.disabled = true;
}