/*
 * vault.js — 保险库编排层。
 * 负责：解锁校验、笔记存取、可续跑密钥轮换（journal 检查点）、
 *       旧数据迁移（备份 + 失败回滚）、配额不足降级。
 * 不依赖 DOM；store 与 crypto 均通过构造注入，便于测试。
 */
(function (global) {
  'use strict';

  var ROTATION_BATCH = 20; // 每批处理后写一次检查点，中断最多重做一批

  function WrongPasswordError() {
    var e = new Error('密码错误');
    e.name = 'WrongPasswordError';
    return e;
  }

  // hooks: { onProgress(phase, done, total), onQuotaDegraded(err) }
  function Vault(store, crypto, hooks) {
    this._store = store;
    this._crypto = crypto;
    this._hooks = hooks || {};
    this._config = null;
  }

  Vault.prototype._progress = function (phase, done, total) {
    if (this._hooks.onProgress) this._hooks.onProgress(phase, done, total);
  };

  // ---------- 元数据 ----------

  Vault.hasVault = async function (store) {
    return !!(await store.get('meta', 'config'));
  };

  Vault.prototype._getConfig = async function () {
    if (!this._config) this._config = await this._store.get('meta', 'config');
    return this._config;
  };

  Vault.prototype._saveConfig = async function () {
    await this._store.put('meta', this._config);
  };

  // ---------- 创建 / 解锁 / 锁定 ----------

  Vault.prototype.create = async function (password) {
    var init = await this._crypto.call('initVault', { password: password });
    this._config = {
      id: 'config',
      salt: init.salt,
      iterations: init.iterations,
      verify: init.verify,
      currentKeyId: init.keyId,
      createdAt: Date.now()
    };
    await this._store.put('meta', this._config);
    await this._store.put('keys', { id: init.keyId, wrapped: init.wrapped, createdAt: Date.now() });
  };

  // 返回 { resumedRotation, rolledBackMigration }
  Vault.prototype.unlock = async function (password) {
    var config = await this._store.get('meta', 'config');
    if (!config) throw new Error('保险库不存在');
    var res = await this._crypto.call('unlock', {
      password: password, salt: config.salt, iterations: config.iterations, verify: config.verify
    });
    if (!res.ok) throw WrongPasswordError();
    this._config = config;

    // 把所有已包裹的 DEK 装入加密端
    var keys = await this._store.getAll('keys');
    for (var i = 0; i < keys.length; i++) {
      await this._crypto.call('loadKey', { keyId: keys[i].id, wrapped: keys[i].wrapped });
    }

    // 上次迁移中途崩溃 -> 用备份回滚到一致状态
    var rolledBackMigration = false;
    if (await this._store.get('meta', 'migration')) {
      await this._rollbackMigration();
      rolledBackMigration = true;
    }

    // 上次轮换中断 -> 由调用方决定是否续跑（journal 仍在）
    var resumedRotation = !!(await this._store.get('meta', 'rotation'));
    return { resumedRotation: resumedRotation, rolledBackMigration: rolledBackMigration };
  };

  Vault.prototype.lock = async function () {
    await this._crypto.call('lock');
    this._config = null;
  };

  // ---------- 笔记存取 ----------

  Vault.prototype.listNotes = async function () {
    var notes = await this._store.getAll('notes');
    return notes
      .map(function (n) { return { id: n.id, updatedAt: n.updatedAt, legacy: n.v === 0 }; })
      .sort(function (a, b) { return b.updatedAt - a.updatedAt; });
  };

  Vault.prototype.getNote = async function (id) {
    var note = await this._store.get('notes', id);
    if (!note) return null;
    if (note.v === 0) return { id: note.id, text: note.text, updatedAt: note.updatedAt, legacy: true };
    var config = await this._getConfig();
    var text = await this._crypto.call('decrypt', { keyId: note.keyId, payload: note });
    return { id: note.id, text: text, updatedAt: note.updatedAt, legacy: false, keyId: note.keyId, currentKeyId: config.currentKeyId };
  };

  // 保存（新建或更新）。配额不足时先清理可释放空间重试一次，仍失败则触发降级钩子。
  Vault.prototype.saveNote = async function (id, text) {
    var config = await this._getConfig();
    var noteId = id || CryptoCore.randomId();
    var ct = await this._crypto.call('encrypt', { keyId: config.currentKeyId, plaintext: text });
    var record = {
      id: noteId, v: 1, keyId: config.currentKeyId,
      iv: ct.iv, ct: ct.ct, updatedAt: Date.now()
    };
    try {
      await this._store.put('notes', record);
    } catch (e) {
      if (!Store.isQuotaError(e)) throw e;
      await this._freeSpace();
      try {
        await this._store.put('notes', record);
      } catch (e2) {
        if (Store.isQuotaError(e2) && this._hooks.onQuotaDegraded) this._hooks.onQuotaDegraded(e2);
        throw e2;
      }
    }
    return noteId;
  };

  Vault.prototype.deleteNote = async function (id) {
    await this._store.del('notes', id);
  };

  // 释放空间：清掉迁移备份与已退役的旧密钥
  Vault.prototype._freeSpace = async function () {
    try { await this._store.clear('backup'); } catch (e) { /* 忽略 */ }
    try { await this._store.del('meta', 'migration'); } catch (e) { /* 忽略 */ }
  };

  // 导出全部明文（供配额降级时用户自救备份）
  Vault.prototype.exportAll = async function () {
    var notes = await this._store.getAll('notes');
    var out = [];
    for (var i = 0; i < notes.length; i++) {
      var n = notes[i];
      var text = n.v === 0 ? n.text : await this._crypto.call('decrypt', { keyId: n.keyId, payload: n });
      out.push({ id: n.id, text: text, updatedAt: n.updatedAt });
    }
    return JSON.stringify({ exportedAt: new Date().toISOString(), notes: out }, null, 2);
  };

  // ---------- 密钥轮换（可中断续跑） ----------

  Vault.prototype.hasPendingRotation = async function () {
    return !!(await this._store.get('meta', 'rotation'));
  };

  // 生成/续跑轮换。journal 记录 newKeyId 与剩余待处理笔记 id，
  // 每批写完更新一次检查点；崩溃后再次调用本方法即可从断点继续。
  Vault.prototype.rotateKey = async function () {
    var config = await this._getConfig();
    var journal = await this._store.get('meta', 'rotation');
    var newKeyId;

    if (journal) {
      newKeyId = journal.newKeyId; // 续跑：沿用已生成的新密钥
    } else {
      var nk = await this._crypto.call('newKey');
      newKeyId = nk.keyId;
      await this._store.put('keys', { id: newKeyId, wrapped: nk.wrapped, createdAt: Date.now() });
      var notes = await this._store.getAll('notes');
      journal = {
        id: 'rotation',
        newKeyId: newKeyId,
        remainingIds: notes.filter(function (n) { return n.v !== 0; }).map(function (n) { return n.id; }),
        total: notes.length,
        startedAt: Date.now()
      };
      await this._store.put('meta', journal);
    }

    var total = journal.total || journal.remainingIds.length;
    while (journal.remainingIds.length > 0) {
      var batch = journal.remainingIds.splice(0, ROTATION_BATCH);
      for (var i = 0; i < batch.length; i++) {
        var note = await this._store.get('notes', batch[i]);
        if (!note || note.v === 0) continue;
        if (note.keyId === newKeyId) continue; // 幂等：已处理过的跳过
        var pt = await this._crypto.call('decrypt', { keyId: note.keyId, payload: note });
        var ct = await this._crypto.call('encrypt', { keyId: newKeyId, plaintext: pt });
        await this._store.put('notes', {
          id: note.id, v: 1, keyId: newKeyId, iv: ct.iv, ct: ct.ct, updatedAt: note.updatedAt
        });
      }
      await this._store.put('meta', journal); // 检查点
      this._progress('rotate', total - journal.remainingIds.length, total);
    }

    // 完成：切换当前密钥、清理 journal、退役不再被引用的旧密钥
    config.currentKeyId = newKeyId;
    await this._saveConfig();
    await this._store.del('meta', 'rotation');
    await this._retireUnusedKeys();
    this._progress('rotate', total, total);
    return { newKeyId: newKeyId };
  };

  Vault.prototype._retireUnusedKeys = async function () {
    var config = await this._getConfig();
    var notes = await this._store.getAll('notes');
    var inUse = {};
    notes.forEach(function (n) { if (n.keyId) inUse[n.keyId] = true; });
    inUse[config.currentKeyId] = true;
    var keys = await this._store.getAll('keys');
    for (var i = 0; i < keys.length; i++) {
      if (!inUse[keys[i].id]) await this._store.del('keys', keys[i].id);
    }
  };

  // ---------- 旧数据迁移（备份 + 回滚） ----------

  Vault.prototype.countLegacyNotes = async function () {
    var notes = await this._store.getAll('notes');
    return notes.filter(function (n) { return n.v === 0; }).length;
  };

  // 把 v0 明文笔记迁移为 v1 密文。先整体备份，任一步失败即回滚。
  Vault.prototype.migrateLegacy = async function () {
    var config = await this._getConfig();
    var notes = await this._store.getAll('notes');
    var legacy = notes.filter(function (n) { return n.v === 0; });
    if (legacy.length === 0) return { migrated: 0 };

    // 1) 备份 + 标记迁移开始（崩溃后 unlock 会据此回滚）
    await this._store.clear('backup');
    for (var i = 0; i < legacy.length; i++) await this._store.put('backup', legacy[i]);
    await this._store.put('meta', { id: 'migration', status: 'in-progress', startedAt: Date.now() });

    // 2) 逐条加密迁移
    try {
      for (var j = 0; j < legacy.length; j++) {
        var n = legacy[j];
        var ct = await this._crypto.call('encrypt', { keyId: config.currentKeyId, plaintext: n.text });
        await this._store.put('notes', {
          id: n.id, v: 1, keyId: config.currentKeyId, iv: ct.iv, ct: ct.ct, updatedAt: n.updatedAt
        });
        this._progress('migrate', j + 1, legacy.length);
      }
    } catch (e) {
      await this._rollbackMigration();
      throw e;
    }

    // 3) 提交：清备份、清标记
    await this._store.clear('backup');
    await this._store.del('meta', 'migration');
    return { migrated: legacy.length };
  };

  Vault.prototype._rollbackMigration = async function () {
    var backup = await this._store.getAll('backup');
    for (var i = 0; i < backup.length; i++) await this._store.put('notes', backup[i]);
    await this._store.clear('backup');
    await this._store.del('meta', 'migration');
  };

  // ---------- 修改密码（重新包裹所有 DEK，笔记密文不动） ----------

  Vault.prototype.changePassword = async function (newPassword) {
    var res = await this._crypto.call('changePassword', { newPassword: newPassword });
    var config = await this._getConfig();
    config.salt = res.salt;
    config.iterations = res.iterations;
    config.verify = res.verify;
    await this._saveConfig();
    for (var i = 0; i < res.keys.length; i++) {
      var key = await this._store.get('keys', res.keys[i].keyId);
      if (key) {
        key.wrapped = res.keys[i].wrapped;
        await this._store.put('keys', key);
      }
    }
  };

  global.Vault = Vault;
  global.WrongPasswordError = WrongPasswordError;
  if (typeof module !== 'undefined' && module.exports) module.exports = { Vault: Vault, WrongPasswordError: WrongPasswordError };
})(typeof self !== 'undefined' ? self : globalThis);
