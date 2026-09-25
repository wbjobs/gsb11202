// Vault 核心：密钥派生/校验、加解密、密钥轮换（可断点续传）、
//  schema 迁移（失败回滚）、配额降级。环境无关，存储通过适配器注入。

import {
  VERIFY_TOKEN,
  PBKDF2_ITERATIONS,
  randomBytes,
  b64e,
  b64d,
  deriveKEK,
  generateDataKey,
  wrapKey,
  unwrapKey,
  encryptJSON,
  decryptJSON,
} from './crypto.js';
import { isQuotaError } from './store.js';

export const CURRENT_SCHEMA = 2;

export const E = {
  WRONG_PASSWORD: 'WRONG_PASSWORD',
  LOCKED: 'LOCKED',
  NOT_INITIALIZED: 'NOT_INITIALIZED',
  ALREADY_INITIALIZED: 'ALREADY_INITIALIZED',
  QUOTA: 'QUOTA_EXCEEDED',
  MIGRATION: 'MIGRATION_FAILED',
};

export class VaultError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// schema 迁移表：MIGRATIONS[v] 把数据从 v 升级到 v+1。
// v1 -> v2：旧版明文笔记 {id,title,body} 迁移为加密记录。
const MIGRATIONS = {
  1: async (vault) => {
    const notes = await vault.store.getAll('notes');
    const key = vault.dataKeys.get(vault.currentVersion);
    for (const n of notes) {
      if (n.ct) continue; // 已是加密记录
      const enc = await encryptJSON(key, { title: n.title ?? '', body: n.body ?? '' });
      await vault.store.put('notes', n.id, {
        id: n.id,
        v: vault.currentVersion,
        ...enc,
        createdAt: n.createdAt ?? Date.now(),
        updatedAt: n.updatedAt ?? Date.now(),
      });
    }
  },
};

export class Vault {
  constructor(store, opts = {}) {
    this.store = store;
    this.onEvent = opts.onEvent || (() => {});
    this.pbkdf2Iterations = opts.pbkdf2Iterations || PBKDF2_ITERATIONS;
    this.rotationBatchSize = opts.rotationBatchSize || 25;
    this.kek = null;
    this.dataKeys = new Map(); // version -> CryptoKey
    this.currentVersion = null;
    this.degraded = false; // 配额降级：写入转入内存 outbox
    this.outbox = new Map(); // id -> 加密记录（尚未落盘）
  }

  get locked() {
    return !this.kek;
  }

  _requireUnlocked() {
    if (this.locked) throw new VaultError(E.LOCKED, '保险库已锁定');
  }

  async status() {
    const initialized = !!(await this.store.get('meta', 'verify'));
    return {
      initialized,
      locked: this.locked,
      persistent: this.store.persistent,
      degraded: this.degraded,
      schemaVersion: (await this.store.get('meta', 'schemaVersion')) ?? null,
      rotation: (await this.store.get('meta', 'rotation')) ?? null,
      currentKeyVersion: this.currentVersion,
      outboxCount: this.outbox.size,
    };
  }

  // 首次初始化：由密码派生 KEK，生成首个数据密钥
  async setup(password) {
    if (await this.store.get('meta', 'verify')) {
      throw new VaultError(E.ALREADY_INITIALIZED, '保险库已初始化');
    }
    const salt = randomBytes(16);
    this.kek = await deriveKEK(password, salt, this.pbkdf2Iterations);
    const dataKey = await generateDataKey();
    this.dataKeys.set(1, dataKey);
    this.currentVersion = 1;
    await this.store.put('meta', 'salt', b64e(salt));
    await this.store.put('meta', 'verify', await encryptJSON(this.kek, VERIFY_TOKEN));
    await this.store.put('keys', '1', { version: 1, wrapped: await wrapKey(dataKey, this.kek), createdAt: Date.now() });
    await this.store.put('meta', 'currentKeyVersion', 1);
    await this.store.put('meta', 'schemaVersion', CURRENT_SCHEMA);
    return this.status();
  }

  async unlock(password) {
    const saltB64 = await this.store.get('meta', 'salt');
    const verify = await this.store.get('meta', 'verify');
    if (!saltB64 || !verify) throw new VaultError(E.NOT_INITIALIZED, '保险库尚未初始化');
    const kek = await deriveKEK(password, b64d(saltB64), this.pbkdf2Iterations);
    let check;
    try {
      check = await decryptJSON(kek, verify);
    } catch {
      throw new VaultError(E.WRONG_PASSWORD, '密码错误');
    }
    if (check !== VERIFY_TOKEN) throw new VaultError(E.WRONG_PASSWORD, '密码错误');
    this.kek = kek;
    this.dataKeys.clear();
    for (const k of await this.store.getAll('keys')) {
      this.dataKeys.set(k.version, await unwrapKey(k.wrapped, kek));
    }
    this.currentVersion = await this.store.get('meta', 'currentKeyVersion');
    await this._migrate(); // 解锁后先做 schema 迁移（失败会回滚并抛错）
    return this.status();
  }

  lock() {
    this.kek = null;
    this.dataKeys.clear();
    this.currentVersion = null;
    this.outbox.clear();
    this.degraded = false;
  }

  // ---------- 笔记 ----------

  async listNotes() {
    this._requireUnlocked();
    const notes = await this.store.getAll('notes');
    const out = [];
    for (const n of notes) {
      const key = this.dataKeys.get(n.v);
      if (!key) continue;
      try {
        const p = await decryptJSON(key, n);
        out.push({ id: n.id, title: p.title, updatedAt: n.updatedAt, keyVersion: n.v });
      } catch {
        out.push({ id: n.id, title: '（无法解密）', updatedAt: n.updatedAt, keyVersion: n.v });
      }
    }
    out.sort((a, b) => b.updatedAt - a.updatedAt);
    return out;
  }

  async getNote(id) {
    this._requireUnlocked();
    const n = (await this.store.get('notes', id)) || this.outbox.get(id);
    if (!n) return null;
    const p = await decryptJSON(this.dataKeys.get(n.v), n);
    return { id: n.id, title: p.title, body: p.body, updatedAt: n.updatedAt, keyVersion: n.v };
  }

  async saveNote({ id, title, body }) {
    this._requireUnlocked();
    const now = Date.now();
    const noteId = id || `n-${now.toString(36)}-${b64e(randomBytes(4)).replace(/[+/=]/g, '')}`;
    const existing = await this.store.get('notes', noteId).catch(() => null);
    const enc = await encryptJSON(this.dataKeys.get(this.currentVersion), { title, body });
    const rec = {
      id: noteId,
      v: this.currentVersion,
      ...enc,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    try {
      await this.store.put('notes', noteId, rec);
      this.outbox.delete(noteId);
      return { ok: true, id: noteId };
    } catch (e) {
      if (isQuotaError(e)) {
        // 配额不足 -> 降级：保留在内存 outbox，提示用户导出/重试
        this.degraded = true;
        this.outbox.set(noteId, rec);
        this.onEvent({ type: 'degraded', reason: 'quota', noteId });
        return { ok: false, id: noteId, code: E.QUOTA };
      }
      throw e;
    }
  }

  async deleteNote(id) {
    this._requireUnlocked();
    this.outbox.delete(id);
    await this.store.del('notes', id);
    return { ok: true };
  }

  // 导出配额降级期间未落盘的笔记（明文 JSON，供用户下载备份）
  async exportOutbox() {
    this._requireUnlocked();
    const out = [];
    for (const rec of this.outbox.values()) {
      const p = await decryptJSON(this.dataKeys.get(rec.v), rec);
      out.push({ id: rec.id, title: p.title, body: p.body, updatedAt: rec.updatedAt });
    }
    return out;
  }

  // 空间恢复后重试落盘
  async retryOutbox() {
    this._requireUnlocked();
    const failed = [];
    for (const [id, rec] of this.outbox) {
      try {
        await this.store.put('notes', id, rec);
        this.outbox.delete(id);
      } catch (e) {
        if (isQuotaError(e)) failed.push(id);
        else throw e;
      }
    }
    if (this.outbox.size === 0) this.degraded = false;
    return { ok: failed.length === 0, remaining: failed.length };
  }

  // ---------- 密钥轮换（可断点续传） ----------

  // 生成新版本数据密钥并逐批重加密旧笔记；每批落盘后写检查点。
  // 中断（关闭页面/异常）后再次调用即可从检查点继续。
  async rotateKeys() {
    this._requireUnlocked();
    let rot = await this.store.get('meta', 'rotation');
    if (!rot) {
      const newVersion = this.currentVersion + 1;
      const dataKey = await generateDataKey();
      await this.store.put('keys', String(newVersion), {
        version: newVersion,
        wrapped: await wrapKey(dataKey, this.kek),
        createdAt: Date.now(),
      });
      this.dataKeys.set(newVersion, dataKey);
      rot = { newVersion, done: 0, startedAt: Date.now() };
      await this.store.put('meta', 'rotation', rot); // 检查点：轮换开始
      this.onEvent({ type: 'rotation-started', newVersion });
    }
    const newVersion = rot.newVersion;
    const newKey = this.dataKeys.get(newVersion);
    if (!newKey) throw new VaultError(E.MIGRATION, `缺少轮换目标密钥 v${newVersion}`);

    for (;;) {
      const all = await this.store.getAll('notes');
      const pending = all.filter((n) => n.v !== newVersion).slice(0, this.rotationBatchSize);
      if (pending.length === 0) break;
      for (const rec of pending) {
        const oldKey = this.dataKeys.get(rec.v);
        if (!oldKey) throw new VaultError(E.MIGRATION, `笔记 ${rec.id} 引用了不存在的密钥 v${rec.v}`);
        const plain = await decryptJSON(oldKey, rec);
        const enc = await encryptJSON(newKey, plain);
        await this.store.put('notes', rec.id, { ...rec, v: newVersion, ...enc });
        rot.done++;
      }
      rot.updatedAt = Date.now();
      await this.store.put('meta', 'rotation', rot); // 检查点：每批提交一次
      this.onEvent({ type: 'rotation-progress', done: rot.done, newVersion });
      await sleep(0); // 让出事件循环，避免长时间阻塞
    }

    // 全部重加密完成：切换当前版本，退役旧密钥，清除检查点
    await this.store.put('meta', 'currentKeyVersion', newVersion);
    for (const v of [...this.dataKeys.keys()]) {
      if (v !== newVersion) {
        await this.store.del('keys', String(v));
        this.dataKeys.delete(v);
      }
    }
    await this.store.del('meta', 'rotation');
    this.currentVersion = newVersion;
    this.onEvent({ type: 'rotation-complete', newVersion, total: rot.done });
    return { ok: true, newVersion, rotated: rot.done };
  }

  // 修改密码：重新派生 KEK 并重新包裹所有数据密钥（数据密钥本身不变）
  async changePassword(oldPassword, newPassword) {
    this._requireUnlocked();
    const saltB64 = await this.store.get('meta', 'salt');
    const oldKek = await deriveKEK(oldPassword, b64d(saltB64), this.pbkdf2Iterations);
    const verify = await this.store.get('meta', 'verify');
    try {
      if ((await decryptJSON(oldKek, verify)) !== VERIFY_TOKEN) throw 0;
    } catch {
      throw new VaultError(E.WRONG_PASSWORD, '原密码错误');
    }
    const newSalt = randomBytes(16);
    const newKek = await deriveKEK(newPassword, newSalt, this.pbkdf2Iterations);
    for (const [version, dataKey] of this.dataKeys) {
      await this.store.put('keys', String(version), {
        version,
        wrapped: await wrapKey(dataKey, newKek),
        createdAt: Date.now(),
      });
    }
    await this.store.put('meta', 'salt', b64e(newSalt));
    await this.store.put('meta', 'verify', await encryptJSON(newKek, VERIFY_TOKEN));
    this.kek = newKek;
    return { ok: true };
  }

  // ---------- schema 迁移（失败回滚） ----------

  async _migrate() {
    let v = await this.store.get('meta', 'schemaVersion');
    if (v == null) {
      const hasLegacyData = (await this.store.getAll('notes')).length > 0;
      v = hasLegacyData ? 1 : CURRENT_SCHEMA;
      if (!hasLegacyData) {
        await this.store.put('meta', 'schemaVersion', CURRENT_SCHEMA);
        return;
      }
    }
    while (v < CURRENT_SCHEMA) {
      const up = MIGRATIONS[v];
      if (!up) throw new VaultError(E.MIGRATION, `缺少从 schema v${v} 的迁移路径`);
      // 迁移前备份受影响的数据
      const backup = { notes: await this.store.getAll('notes'), schemaVersion: v };
      await this.store.put('backup', `mig-${v}`, backup);
      try {
        await up(this);
        await this.store.put('meta', 'schemaVersion', v + 1);
        await this.store.del('backup', `mig-${v}`);
        this.onEvent({ type: 'migration-complete', from: v, to: v + 1 });
        v++;
      } catch (err) {
        // 回滚：恢复备份，schema 版本保持不变
        await this.store.clear('notes');
        for (const n of backup.notes) await this.store.put('notes', n.id, n);
        await this.store.put('meta', 'schemaVersion', v);
        await this.store.del('backup', `mig-${v}`);
        this.onEvent({ type: 'migration-rollback', from: v, error: String(err && err.message) });
        throw new VaultError(E.MIGRATION, `迁移 v${v}->v${v + 1} 失败，已回滚：${err && err.message}`);
      }
    }
  }
}
