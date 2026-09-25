/*
 * crypto-worker.js — 加密操作集 + Worker 接线。
 * KEK 与所有 DEK 只存在于本模块状态里，主线程只接触密文与被包裹的密钥。
 * 在 Worker 中自动接上 onmessage；在主线程/Node 中可作为 CryptoOps 工厂被复用（降级路径）。
 */
(function (global) {
  'use strict';

  if (typeof CryptoCore === 'undefined') {
    if (typeof importScripts === 'function') importScripts('crypto-core.js');
    else if (typeof require !== 'undefined') global.CryptoCore = require('./crypto-core.js');
  }

  // 每个实例独立持有 KEK / DEK 状态
  function createCryptoOps() {
    var kek = null;
    var deks = new Map(); // keyId -> CryptoKey

    async function handle(op, p) {
      switch (op) {
        case 'initVault': {
          var salt = CryptoCore.bufToB64(CryptoCore.randomBytes(16).buffer);
          kek = await CryptoCore.deriveKek(p.password, salt, CryptoCore.PBKDF2_ITERATIONS);
          var verify = await CryptoCore.makeVerifyToken(kek);
          var dek = await CryptoCore.generateDek();
          var keyId = CryptoCore.randomId();
          deks.clear();
          deks.set(keyId, dek);
          var wrapped = await CryptoCore.wrapDek(dek, kek);
          return { salt: salt, iterations: CryptoCore.PBKDF2_ITERATIONS, verify: verify, keyId: keyId, wrapped: wrapped };
        }

        case 'unlock': {
          var k = await CryptoCore.deriveKek(p.password, p.salt, p.iterations);
          var ok = await CryptoCore.checkVerifyToken(k, p.verify);
          if (!ok) return { ok: false };
          kek = k;
          deks.clear();
          return { ok: true };
        }

        case 'loadKey':
          deks.set(p.keyId, await CryptoCore.unwrapDek(p.wrapped, kek));
          return { loaded: p.keyId };

        case 'newKey': {
          var newDek = await CryptoCore.generateDek();
          var newKeyId = CryptoCore.randomId();
          deks.set(newKeyId, newDek);
          return { keyId: newKeyId, wrapped: await CryptoCore.wrapDek(newDek, kek) };
        }

        case 'encrypt':
          if (!deks.has(p.keyId)) throw new Error('密钥未加载: ' + p.keyId);
          return CryptoCore.encryptText(deks.get(p.keyId), p.plaintext);

        case 'decrypt':
          if (!deks.has(p.keyId)) throw new Error('密钥未加载: ' + p.keyId);
          return CryptoCore.decryptText(deks.get(p.keyId), p.payload);

        case 'changePassword': {
          var newSalt = CryptoCore.bufToB64(CryptoCore.randomBytes(16).buffer);
          var newKek = await CryptoCore.deriveKek(p.newPassword, newSalt, CryptoCore.PBKDF2_ITERATIONS);
          var rewrapped = [];
          for (var entry of deks.entries()) {
            rewrapped.push({ keyId: entry[0], wrapped: await CryptoCore.wrapDek(entry[1], newKek) });
          }
          kek = newKek;
          return {
            salt: newSalt,
            iterations: CryptoCore.PBKDF2_ITERATIONS,
            verify: await CryptoCore.makeVerifyToken(newKek),
            keys: rewrapped
          };
        }

        case 'lock':
          kek = null;
          deks.clear();
          return { locked: true };

        default:
          throw new Error('unknown op: ' + op);
      }
    }

    return { handle: handle };
  }

  global.createCryptoOps = createCryptoOps;

  // 仅在 Worker 上下文中接消息
  if (typeof self !== 'undefined' && typeof importScripts === 'function' && typeof document === 'undefined') {
    var ops = createCryptoOps();
    self.onmessage = async function (e) {
      var msg = e.data;
      try {
        var result = await ops.handle(msg.op, msg.payload || {});
        self.postMessage({ id: msg.id, ok: true, result: result });
      } catch (err) {
        self.postMessage({ id: msg.id, ok: false, error: String((err && err.message) || err) });
      }
    };
  }

  if (typeof module !== 'undefined' && module.exports) module.exports = { createCryptoOps: createCryptoOps };
})(typeof self !== 'undefined' ? self : globalThis);
