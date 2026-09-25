// Web Worker：所有加解密与数据库操作都在这里执行，不阻塞 UI。
// IndexedDB 不可用（隐私模式等）时自动降级为内存存储。

import { Vault } from './vault.js';
import { IDBStore, MemoryStore } from './store.js';

let vault = null;

async function ensureVault() {
  if (vault) return vault;
  let store;
  try {
    store = await IDBStore.open();
  } catch {
    store = new MemoryStore(); // 隐私模式降级：数据仅保存在内存
  }
  vault = new Vault(store, { onEvent: (e) => postMessage({ event: e }) });
  return vault;
}

const handlers = {
  async status() {
    return (await ensureVault()).status();
  },
  async setup({ password }) {
    return (await ensureVault()).setup(password);
  },
  async unlock({ password }) {
    return (await ensureVault()).unlock(password);
  },
  async lock() {
    (await ensureVault()).lock();
    return { ok: true };
  },
  async listNotes() {
    return (await ensureVault()).listNotes();
  },
  async getNote({ id }) {
    return (await ensureVault()).getNote(id);
  },
  async saveNote({ id, title, body }) {
    return (await ensureVault()).saveNote({ id, title, body });
  },
  async deleteNote({ id }) {
    return (await ensureVault()).deleteNote(id);
  },
  async rotateKeys() {
    return (await ensureVault()).rotateKeys();
  },
  async changePassword({ oldPassword, newPassword }) {
    return (await ensureVault()).changePassword(oldPassword, newPassword);
  },
  async exportOutbox() {
    return (await ensureVault()).exportOutbox();
  },
  async retryOutbox() {
    return (await ensureVault()).retryOutbox();
  },
};

onmessage = async (e) => {
  const { id, cmd, args } = e.data;
  try {
    const h = handlers[cmd];
    if (!h) throw new Error(`未知命令: ${cmd}`);
    const result = await h(args || {});
    postMessage({ id, ok: true, result });
  } catch (err) {
    postMessage({ id, ok: false, error: { code: err.code || 'ERROR', message: err.message || String(err) } });
  }
};
