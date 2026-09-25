// 纯 Web Crypto 辅助函数，环境无关（浏览器 / Web Worker / Node 均可运行）。

const te = new TextEncoder();

export const VERIFY_TOKEN = 'encnotes-verify-v1';
export const PBKDF2_ITERATIONS = 210000;

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function b64e(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== 'undefined') return Buffer.from(arr).toString('base64');
  let s = '';
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s);
}

export function b64d(s) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(s, 'base64'));
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

// 用户密码 -> KEK（密钥加密密钥，AES-GCM 256，不可导出）
export async function deriveKEK(password, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// 数据密钥（真正加密笔记的密钥），可导出以便被 KEK 包裹存储
export async function generateDataKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// 用 KEK 包裹数据密钥 -> { iv, ct }（base64）
export async function wrapKey(dataKey, kek) {
  const raw = await crypto.subtle.exportKey('raw', dataKey);
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw);
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

export async function unwrapKey(wrapped, kek) {
  const raw = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64d(wrapped.iv) },
    kek,
    b64d(wrapped.ct)
  );
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// 用数据密钥加密任意 JSON 值
export async function encryptJSON(dataKey, value) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dataKey, te.encode(JSON.stringify(value)));
  return { iv: b64e(iv), ct: b64e(new Uint8Array(ct)) };
}

export async function decryptJSON(dataKey, record) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64d(record.iv) },
    dataKey,
    b64d(record.ct)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}
