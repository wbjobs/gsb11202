/*
 * crypto-core.js — 纯加密原语，不依赖 DOM / IndexedDB。
 * 浏览器（主线程或 Worker，通过 importScripts / <script>）与 Node（require）通用。
 *
 * 密钥分层：
 *   用户密码 --PBKDF2--> KEK（密钥加密密钥，只留在 Worker 内存）
 *   KEK --AES-GCM wrap--> DEK（数据加密密钥，可有多代，支持轮换）
 *   DEK --AES-GCM--> 笔记密文
 */
(function (global) {
  'use strict';

  var PBKDF2_ITERATIONS = 310000; // OWASP 推荐（PBKDF2-HMAC-SHA256）
  var VERIFY_PLAINTEXT = 'vault-verify-v1';
  var KEY_VERSION = 1;

  var textEncoder = new TextEncoder();
  var textDecoder = new TextDecoder();

  function randomBytes(len) {
    return crypto.getRandomValues(new Uint8Array(len));
  }

  function bufToB64(buf) {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function b64ToBuf(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function randomId() {
    var bytes = randomBytes(16);
    var hex = '';
    for (var i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex;
  }

  // 密码 -> KEK（不可导出，只在内存中使用）
  async function deriveKek(password, saltB64, iterations) {
    var base = await crypto.subtle.importKey(
      'raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64ToBuf(saltB64), iterations: iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  async function generateDek() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function wrapDek(dek, kek) {
    var iv = randomBytes(12);
    var wrapped = await crypto.subtle.wrapKey('raw', dek, kek, { name: 'AES-GCM', iv: iv });
    return { iv: bufToB64(iv.buffer ? iv.buffer : iv), wrapped: bufToB64(wrapped) };
  }

  async function unwrapDek(payload, kek) {
    return crypto.subtle.unwrapKey(
      'raw', b64ToBuf(payload.wrapped), kek,
      { name: 'AES-GCM', iv: b64ToBuf(payload.iv) },
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptText(key, plaintext) {
    var iv = randomBytes(12);
    var ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv }, key, textEncoder.encode(plaintext)
    );
    return { v: KEY_VERSION, iv: bufToB64(iv.buffer ? iv.buffer : iv), ct: bufToB64(ct) };
  }

  async function decryptText(key, payload) {
    var pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBuf(payload.iv) }, key, b64ToBuf(payload.ct)
    );
    return textDecoder.decode(pt);
  }

  async function makeVerifyToken(kek) {
    return encryptText(kek, VERIFY_PLAINTEXT);
  }

  // 用 KEK 尝试解密校验串：失败即密码错误
  async function checkVerifyToken(kek, token) {
    try {
      return (await decryptText(kek, token)) === VERIFY_PLAINTEXT;
    } catch (e) {
      return false;
    }
  }

  var CryptoCore = {
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    randomId: randomId,
    deriveKek: deriveKek,
    generateDek: generateDek,
    wrapDek: wrapDek,
    unwrapDek: unwrapDek,
    encryptText: encryptText,
    decryptText: decryptText,
    makeVerifyToken: makeVerifyToken,
    checkVerifyToken: checkVerifyToken,
    bufToB64: bufToB64,
    b64ToBuf: b64ToBuf,
    randomBytes: randomBytes
  };

  global.CryptoCore = CryptoCore;
  if (typeof module !== 'undefined' && module.exports) module.exports = CryptoCore;
})(typeof self !== 'undefined' ? self : globalThis);
