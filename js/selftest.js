/*
 * selftest.js — 浏览器端验收自测。
 * 使用真实 WorkerCrypto；存储用 MemoryStore（隔离、可故障注入），
 * 另附 IndexedDB 真实读写与隐私模式探测。
 */
(function () {
  'use strict';

  var out = document.getElementById('out');
  var passed = 0, failed = 0;

  function h2(t) { var el = document.createElement('h2'); el.textContent = t; out.appendChild(el); }
  function assert(cond, name) {
    var el = document.createElement('div');
    el.className = cond ? 'pass' : 'fail';
    el.textContent = (cond ? '✔ PASS ' : '✘ FAIL ') + name;
    out.appendChild(el);
    cond ? passed++ : failed++;
  }
  function info(t) { var el = document.createElement('div'); el.textContent = '  ' + t; out.appendChild(el); }

  function newCrypto() { return new CryptoClient.WorkerCrypto('js/crypto-worker.js'); }

  function faulty(store, rules) {
    return {
      get: function (s, id) { return store.get(s, id); },
      getAll: function (s) { return store.getAll(s); },
      del: function (s, id) { return store.del(s, id); },
      clear: function (s) { return store.clear(s); },
      put: async function (s, obj) {
        if (rules.onPut && rules.onPut(s, obj)) throw rules.error();
        return store.put(s, obj);
      }
    };
  }

  async function main() {
    // ---- 0. 环境 ----
    h2('[0] 环境探测');
    assert(!!(window.crypto && crypto.subtle), 'Web Crypto 可用（安全上下文）');
    assert(typeof Worker !== 'undefined', 'Web Worker 可用');
    var idbOk = await Store.IdbStore.probe();
    info('IndexedDB 持久化: ' + (idbOk ? '可用' : '不可用 → 应用将自动降级为内存存储（隐私模式路径）'));
    assert(true, 'openBest 选择结果: ' + (await Store.openBest()).persistent);

    // ---- 1. 创建 / 解锁 / 密码错误 ----
    h2('[1] 创建 / 解锁 / 密码错误');
    var store = new Store.MemoryStore();
    var vault = new Vault(store, newCrypto());
    await vault.create('correct-horse');
    var noteId = await vault.saveNote(null, '第一条秘密笔记');
    await vault.lock();
    vault = new Vault(store, newCrypto());
    var wrongMsg = null;
    try { await vault.unlock('wrong'); } catch (e) { wrongMsg = e.name + ': ' + e.message; }
    assert(wrongMsg === 'WrongPasswordError: 密码错误', '错误密码给出明确提示 (' + wrongMsg + ')');
    await vault.unlock('correct-horse');
    assert((await vault.getNote(noteId)).text === '第一条秘密笔记', '解锁后笔记可解密');

    // ---- 2. 静态加密 ----
    h2('[2] 静态加密');
    var raw = await store.getAll('notes');
    assert(!JSON.stringify(raw).includes('秘密笔记'), '存储层不含明文');

    // ---- 3. 密钥轮换 ----
    h2('[3] 密钥轮换');
    var rotated = await vault.rotateKey();
    assert((await vault.getNote(noteId)).text === '第一条秘密笔记', '轮换后旧笔记可解');
    var nid2 = await vault.saveNote(null, '新笔记');
    assert((await store.get('notes', nid2)).keyId === rotated.newKeyId, '新笔记使用新密钥');
    assert((await store.getAll('keys')).length === 1, '旧密钥已退役');

    // ---- 4. 轮换中断续跑 ----
    h2('[4] 轮换中断续跑');
    store = new Store.MemoryStore();
    vault = new Vault(store, newCrypto());
    await vault.create('pw');
    var ids = [];
    for (var i = 0; i < 50; i++) ids.push(await vault.saveNote(null, '批量笔记-' + i));
    var puts = 0;
    var crashStore = faulty(store, {
      onPut: function (s) { return s === 'notes' && ++puts > 2; },
      error: function () { return new Error('simulated crash'); }
    });
    var crashVault = new Vault(crashStore, vault._crypto);
    crashVault._config = await store.get('meta', 'config');
    var crashed = false;
    try { await crashVault.rotateKey(); } catch (e) { crashed = true; }
    assert(crashed, '轮换中途崩溃（模拟断电）');
    vault = new Vault(store, newCrypto());
    var unlockRes = await vault.unlock('pw');
    assert(unlockRes.resumedRotation, '重新解锁检测到未完成轮换');
    var resume = await vault.rotateKey();
    var allOk = true;
    for (var j = 0; j < ids.length; j++) {
      if (!(await vault.getNote(ids[j])).text.startsWith('批量笔记-')) allOk = false;
    }
    assert(allOk, '续跑后全部 50 条笔记可解');
    assert((await store.getAll('notes')).every(function (n) { return n.keyId === resume.newKeyId; }), '全部笔记已切换到新密钥');

    // ---- 5. 迁移：成功 / 失败回滚 / 崩溃回滚 ----
    h2('[5] 旧数据迁移');
    store = new Store.MemoryStore();
    vault = new Vault(store, newCrypto());
    await vault.create('pw');
    for (var k = 0; k < 5; k++) await store.put('notes', { id: 'legacy-' + k, v: 0, text: '明文遗留-' + k, updatedAt: k });
    assert((await vault.countLegacyNotes()) === 5, '识别遗留明文笔记');
    await vault.migrateLegacy();
    assert((await vault.getNote('legacy-3')).text === '明文遗留-3', '迁移后内容可解');
    assert(!JSON.stringify(await store.getAll('notes')).includes('明文遗留'), '迁移后存储层无明文');

    for (var m = 5; m < 10; m++) await store.put('notes', { id: 'legacy-' + m, v: 0, text: '第二批明文-' + m, updatedAt: m });
    var migPuts = 0;
    var failStore = faulty(store, {
      onPut: function (s, o) { return s === 'notes' && o.v === 1 && ++migPuts > 2; },
      error: function () { return Store.QuotaExceededError(); }
    });
    var failVault = new Vault(failStore, vault._crypto);
    failVault._config = await store.get('meta', 'config');
    var migErr = null;
    try { await failVault.migrateLegacy(); } catch (e) { migErr = e; }
    assert(migErr && migErr.name === 'QuotaExceededError', '迁移中途失败并抛出');
    var restored = (await store.getAll('notes')).filter(function (n) { return n.v === 0 && n.id >= 'legacy-5'; });
    assert(restored.length === 5 && restored.every(function (n) { return n.text.startsWith('第二批明文-'); }), '回滚后遗留笔记恢复原始明文');

    await store.put('notes', { id: 'legacy-x', v: 0, text: '崩溃现场', updatedAt: 99 });
    await store.put('backup', { id: 'legacy-x', v: 0, text: '崩溃现场', updatedAt: 99 });
    await store.put('meta', { id: 'migration', status: 'in-progress', startedAt: Date.now() });
    await store.put('notes', { id: 'legacy-x', v: 1, keyId: 'broken', iv: 'AA', ct: 'AA', updatedAt: 99 });
    vault = new Vault(store, newCrypto());
    var crashUnlock = await vault.unlock('pw');
    assert(crashUnlock.rolledBackMigration === true, '解锁时检测到崩溃的迁移并回滚');
    assert((await store.get('notes', 'legacy-x')).text === '崩溃现场', '坏记录已被备份还原');

    // ---- 6. 配额不足降级 ----
    h2('[6] 配额不足降级');
    var degraded = false;
    var quotaStore = faulty(store, {
      onPut: function (s) { return s === 'notes'; },
      error: function () { return Store.QuotaExceededError(); }
    });
    var quotaVault = new Vault(quotaStore, vault._crypto, { onQuotaDegraded: function () { degraded = true; } });
    quotaVault._config = await store.get('meta', 'config');
    var quotaErr = null;
    try { await quotaVault.saveNote(null, '写不进去'); } catch (e) { quotaErr = e; }
    assert(quotaErr && quotaErr.name === 'QuotaExceededError', '写入抛出配额错误');
    assert(degraded, '触发降级钩子');
    assert((await quotaVault.exportAll()).includes('崩溃现场'), '配额满时仍可导出全部明文备份');

    // ---- 7. 隐私模式路径（内存存储）----
    h2('[7] 隐私模式降级路径');
    var memVault = new Vault(new Store.MemoryStore(), newCrypto());
    await memVault.create('pw');
    var mid = await memVault.saveNote(null, '隐私模式笔记');
    assert((await memVault.getNote(mid)).text === '隐私模式笔记', '内存存储下功能完整可用');

    // ---- 8. 性能 ----
    h2('[8] 性能');
    var perfVault = new Vault(new Store.MemoryStore(), newCrypto());
    var t0 = performance.now();
    await perfVault.create('pw');
    var deriveMs = Math.round(performance.now() - t0);
    t0 = performance.now();
    var pids = [];
    for (var p = 0; p < 100; p++) pids.push(await perfVault.saveNote(null, '性能测试笔记内容-' + p));
    var writeMs = Math.round(performance.now() - t0);
    t0 = performance.now();
    for (var q = 0; q < pids.length; q++) await perfVault.getNote(pids[q]);
    var readMs = Math.round(performance.now() - t0);
    t0 = performance.now();
    await perfVault.rotateKey();
    var rotateMs = Math.round(performance.now() - t0);
    info('派生密钥 ' + deriveMs + 'ms | 写 100 条 ' + writeMs + 'ms | 读 100 条 ' + readMs + 'ms | 轮换 100 条 ' + rotateMs + 'ms');
    assert(writeMs < 5000 && readMs < 5000 && rotateMs < 10000, '性能在可接受范围');

    var summary = document.getElementById('summary');
    summary.textContent = '结果: ' + passed + ' 通过, ' + failed + ' 失败';
    summary.className = failed ? 'fail' : 'pass';
  }

  main().catch(function (e) {
    var el = document.createElement('div');
    el.className = 'fail';
    el.textContent = '未捕获异常: ' + (e && e.stack || e);
    out.appendChild(el);
  });
})();
