/*
 * crypto-client.js — 主线程侧的加密客户端。
 * WorkerCrypto：通过 Web Worker 执行（密钥不出 Worker，且不阻塞 UI）。
 * DirectCrypto：Worker 不可用时的降级实现（同接口，直接在主线程跑）。
 */
(function (global) {
  'use strict';

  function WorkerCrypto(workerUrl) {
    this._worker = new Worker(workerUrl);
    this._seq = 0;
    this._pending = new Map();
    var self = this;
    this._worker.onmessage = function (e) {
      var msg = e.data;
      var entry = self._pending.get(msg.id);
      if (!entry) return;
      self._pending.delete(msg.id);
      if (msg.ok) entry.resolve(msg.result);
      else entry.reject(new Error(msg.error));
    };
    this._worker.onerror = function (e) {
      var err = new Error('加密 Worker 异常: ' + (e.message || 'unknown'));
      self._pending.forEach(function (entry) { entry.reject(err); });
      self._pending.clear();
    };
  }
  WorkerCrypto.prototype.call = function (op, payload) {
    var id = ++this._seq;
    var self = this;
    return new Promise(function (resolve, reject) {
      self._pending.set(id, { resolve: resolve, reject: reject });
      self._worker.postMessage({ id: id, op: op, payload: payload || {} });
    });
  };
  WorkerCrypto.prototype.terminate = function () { this._worker.terminate(); };

  function DirectCrypto() {
    if (typeof createCryptoOps !== 'function') throw new Error('CryptoOps 未加载');
    this._ops = createCryptoOps();
  }
  DirectCrypto.prototype.call = function (op, payload) { return this._ops.handle(op, payload || {}); };
  DirectCrypto.prototype.terminate = function () {};

  var CryptoClient = { WorkerCrypto: WorkerCrypto, DirectCrypto: DirectCrypto };
  global.CryptoClient = CryptoClient;
  if (typeof module !== 'undefined' && module.exports) module.exports = CryptoClient;
})(typeof self !== 'undefined' ? self : globalThis);
