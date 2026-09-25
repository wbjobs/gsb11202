/*
 * store.js — 存储抽象层。
 * IdbStore：IndexedDB 持久化；MemoryStore：隐私模式 / IDB 不可用时的降级（不持久化）。
 * 两者暴露同一组异步 API，Vault 不关心底层是哪一种。
 */
(function (global) {
  'use strict';

  var DB_NAME = 'encrypted-notes';
  var DB_VERSION = 1;
  var STORES = ['meta', 'keys', 'notes', 'backup'];

  // 统一的配额错误类型，UI 层据此降级
  function QuotaExceededError(message) {
    var e = new Error(message || '存储空间不足（配额已满）');
    e.name = 'QuotaExceededError';
    return e;
  }

  function isQuotaError(err) {
    return err && (err.name === 'QuotaExceededError' || err.name === 'NS_ERROR_DOM_QUOTA_REACHED');
  }

  function wrapRequest(req) {
    return new Promise(function (resolve, reject) {
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () {
        reject(isQuotaError(req.error) ? QuotaExceededError() : req.error);
      };
    });
  }

  function IdbStore(db) { this._db = db; }

  IdbStore.prototype._tx = function (storeName, mode, fn) {
    var tx = this._db.transaction(storeName, mode);
    var result = fn(tx.objectStore(storeName));
    return result;
  };

  IdbStore.prototype.get = function (storeName, id) {
    return this._tx(storeName, 'readonly', function (s) { return wrapRequest(s.get(id)); });
  };
  IdbStore.prototype.getAll = function (storeName) {
    return this._tx(storeName, 'readonly', function (s) { return wrapRequest(s.getAll()); });
  };
  IdbStore.prototype.put = function (storeName, obj) {
    return this._tx(storeName, 'readwrite', function (s) { return wrapRequest(s.put(obj)); });
  };
  IdbStore.prototype.del = function (storeName, id) {
    return this._tx(storeName, 'readwrite', function (s) { return wrapRequest(s.delete(id)); });
  };
  IdbStore.prototype.clear = function (storeName) {
    return this._tx(storeName, 'readwrite', function (s) { return wrapRequest(s.clear()); });
  };
  IdbStore.prototype.close = function () { this._db.close(); };

  IdbStore.open = function () {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function (e) {
        var db = e.target.result;
        STORES.forEach(function (name) {
          if (!db.objectStoreNames.contains(name)) db.createObjectStore(name, { keyPath: 'id' });
        });
      };
      req.onsuccess = function () { resolve(new IdbStore(req.result)); };
      req.onerror = function () { reject(req.error); };
      req.onblocked = function () { reject(new Error('数据库被其他标签页占用')); };
    });
  };

  // 探测 IndexedDB 是否真的可用（隐私模式下可能能打开但写入失败）
  IdbStore.probe = async function () {
    if (typeof indexedDB === 'undefined') return false;
    try {
      var store = await IdbStore.open();
      await store.put('meta', { id: '__probe__', t: Date.now() });
      await store.del('meta', '__probe__');
      store.close();
      return true;
    } catch (e) {
      return false;
    }
  };

  // 内存降级实现：API 与 IdbStore 完全一致，页面关闭即丢失
  // 注意：读写均做结构化克隆，与 IndexedDB 的存储语义保持一致，
  // 避免调用方后续修改对象时“穿透”污染已持久化的数据（如轮换 journal 检查点）。
  function MemoryStore() {
    this._maps = {};
    STORES.forEach(function (n) { this._maps[n] = new Map(); }, this);
  }
  MemoryStore.prototype.get = async function (s, id) {
    var v = this._maps[s].get(id);
    return v === undefined ? undefined : structuredClone(v);
  };
  MemoryStore.prototype.getAll = async function (s) {
    return Array.from(this._maps[s].values()).map(function (v) { return structuredClone(v); });
  };
  MemoryStore.prototype.put = async function (s, obj) { this._maps[s].set(obj.id, structuredClone(obj)); };
  MemoryStore.prototype.del = async function (s, id) { this._maps[s].delete(id); };
  MemoryStore.prototype.clear = async function (s) { this._maps[s].clear(); };
  MemoryStore.prototype.close = function () {};

  var Store = {
    IdbStore: IdbStore,
    MemoryStore: MemoryStore,
    QuotaExceededError: QuotaExceededError,
    isQuotaError: isQuotaError,
    // 自动选择：IDB 可用用 IDB，否则降级内存并标记原因
    openBest: async function () {
      if (await IdbStore.probe()) {
        return { store: await IdbStore.open(), persistent: true };
      }
      return { store: new MemoryStore(), persistent: false };
    }
  };

  global.Store = Store;
  if (typeof module !== 'undefined' && module.exports) module.exports = Store;
})(typeof self !== 'undefined' ? self : globalThis);
