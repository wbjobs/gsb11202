// 存储适配器：IndexedDB（持久化）与内存（隐私模式降级）实现同一接口。
// 接口：get/put/del/getAll/clear(store, ...)，均为 Promise。

export const STORES = ['meta', 'keys', 'notes', 'backup'];

export function isQuotaError(e) {
  return !!e && (e.name === 'QuotaExceededError' || e.name === 'NS_ERROR_DOM_QUOTA_REACHED');
}

export class MemoryStore {
  constructor() {
    this.maps = new Map();
    this.persistent = false;
  }
  _s(name) {
    if (!this.maps.has(name)) this.maps.set(name, new Map());
    return this.maps.get(name);
  }
  async get(store, key) {
    const v = this._s(store).get(key);
    return v === undefined ? undefined : structuredClone(v);
  }
  async put(store, key, val) {
    this._s(store).set(key, structuredClone(val));
  }
  async del(store, key) {
    this._s(store).delete(key);
  }
  async getAll(store) {
    return [...this._s(store).values()].map((v) => structuredClone(v));
  }
  async clear(store) {
    this._s(store).clear();
  }
  async close() {}
}

export class IDBStore {
  static open(name = 'encnotes', timeoutMs = 3000) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(err);
        }
      };
      const timer = setTimeout(() => fail(new Error('idb-open-timeout')), timeoutMs);
      let req;
      try {
        req = indexedDB.open(name, 1);
      } catch (e) {
        return fail(e);
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        for (const s of STORES) if (!db.objectStoreNames.contains(s)) db.createObjectStore(s);
      };
      req.onsuccess = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(new IDBStore(req.result));
      };
      req.onerror = () => fail(req.error || new Error('idb-open-failed'));
      req.onblocked = () => fail(new Error('idb-open-blocked'));
    });
  }

  constructor(db) {
    this.db = db;
    this.persistent = true;
  }

  _req(store, mode, make) {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(store, mode);
      const req = make(tx.objectStore(store));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  get(store, key) {
    return this._req(store, 'readonly', (os) => os.get(key));
  }
  put(store, key, val) {
    return this._req(store, 'readwrite', (os) => os.put(val, key));
  }
  del(store, key) {
    return this._req(store, 'readwrite', (os) => os.delete(key));
  }
  getAll(store) {
    return this._req(store, 'readonly', (os) => os.getAll());
  }
  clear(store) {
    return this._req(store, 'readwrite', (os) => os.clear());
  }
  close() {
    this.db.close();
  }
}
