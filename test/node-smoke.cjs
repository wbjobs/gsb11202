/*
 * node-smoke.cjs — 用 MemoryStore + DirectCrypto 在 Node 中验证 Vault 核心逻辑。
 * 覆盖验收标准：密码错误提示 / 轮换后旧笔记可解 / 新笔记用新密钥 /
 * 轮换中断可续 / 迁移失败可回滚 / 配额不足有降级 / 隐私模式（内存存储）可用 / 性能。
 */
'use strict';

const CryptoCore = require('../js/crypto-core.js');
const Store = require('../js/store.js');
const { createCryptoOps } = require('../js/crypto-worker.js');
const { Vault } = require('../js/vault.js');

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log('  PASS', name); }
  else { failed++; console.log('  FAIL', name); }
}

function newCrypto() {
  const ops = createCryptoOps();
  return { call: (op, p) => ops.handle(op, p || {}) };
}

// 故障注入存储：包装 MemoryStore，按规则抛错
function faulty(store, rules) {
  return {
    get: (s, id) => store.get(s, id),
    getAll: (s) => store.getAll(s),
    del: (s, id) => store.del(s, id),
    clear: (s) => store.clear(s),
    put: async (s, obj) => {
      if (rules.onPut && rules.onPut(s, obj)) throw rules.error();
      return store.put(s, obj);
    }
  };
}

async function main() {
  // ---- 1. 创建、解锁、密码错误 ----
  console.log('\n[1] 创建 / 解锁 / 密码错误');
  let store = new Store.MemoryStore();
  let vault = new Vault(store, newCrypto());
  await vault.create('correct-horse');
  const noteId = await vault.saveNote(null, '第一条秘密笔记');
  await vault.lock();
  vault = new Vault(store, newCrypto());
  let wrongMsg = null;
  try { await vault.unlock('wrong-password'); } catch (e) { wrongMsg = e.name + ': ' + e.message; }
  assert(wrongMsg === 'WrongPasswordError: 密码错误', '错误密码给出明确提示 (' + wrongMsg + ')');
  const unlockRes = await vault.unlock('correct-horse');
  assert(unlockRes.resumedRotation === false, '正确密码解锁成功');
  assert((await vault.getNote(noteId)).text === '第一条秘密笔记', '解锁后笔记可解密');

  // ---- 2. 静态加密：存储层无明文 ----
  console.log('\n[2] 静态加密');
  const raw = await store.getAll('notes');
  assert(!JSON.stringify(raw).includes('秘密笔记'), '存储层不含明文');
  assert(raw[0].v === 1 && raw[0].ct && raw[0].keyId, '密文信封格式 (v1 + keyId + ct)');

  // ---- 3. 密钥轮换：旧笔记可解、新笔记用新密钥 ----
  console.log('\n[3] 密钥轮换');
  const oldKeyId = raw[0].keyId;
  let rotated = await vault.rotateKey();
  assert(rotated.newKeyId !== oldKeyId, '生成了新密钥');
  assert((await vault.getNote(noteId)).text === '第一条秘密笔记', '轮换后旧笔记可解');
  const noteId2 = await vault.saveNote(null, '轮换后的新笔记');
  const raw2 = await store.get('notes', noteId2);
  assert(raw2.keyId === rotated.newKeyId, '新笔记使用新密钥');
  const keysLeft = await store.getAll('keys');
  assert(keysLeft.length === 1 && keysLeft[0].id === rotated.newKeyId, '旧密钥已退役清理');

  // ---- 4. 轮换中断可续跑 ----
  console.log('\n[4] 轮换中断续跑');
  store = new Store.MemoryStore();
  vault = new Vault(store, newCrypto());
  await vault.create('pw');
  const ids = [];
  for (let i = 0; i < 50; i++) ids.push(await vault.saveNote(null, '批量笔记-' + i));
  // 故障：轮换写第 3 条笔记时“断电”
  let puts = 0;
  const crashStore = faulty(store, {
    onPut: (s) => s === 'notes' && ++puts > 2,
    error: () => new Error(' simulated crash ')
  });
  const crashVault = new Vault(crashStore, vault._crypto); // 同一 crypto 会话
  let crashed = false;
  try { await crashVault.rotateKey(); } catch (e) { crashed = true; }
  assert(crashed, '轮换中途崩溃（模拟断电）');
  assert(await new Vault(store, newCrypto()).unlock('pw').then(r => r.resumedRotation), '重新解锁检测到未完成轮换');
  // 新会话续跑
  vault = new Vault(store, newCrypto());
  await vault.unlock('pw');
  const resume = await vault.rotateKey();
  let allOk = true;
  for (const id of ids) {
    const n = await vault.getNote(id);
    if (!n.text.startsWith('批量笔记-')) allOk = false;
  }
  assert(allOk, '续跑后全部 50 条笔记可解');
  const rawAll = await store.getAll('notes');
  assert(rawAll.every(n => n.keyId === resume.newKeyId), '全部笔记已切换到新密钥');
  assert(!(await store.get('meta', 'rotation')), 'journal 已清理');

  // ---- 5. 旧数据迁移：成功 + 失败回滚 + 崩溃回滚 ----
  console.log('\n[5] 旧数据迁移');
  store = new Store.MemoryStore();
  vault = new Vault(store, newCrypto());
  await vault.create('pw');
  // 注入 v0 明文遗留笔记
  for (let i = 0; i < 5; i++) await store.put('notes', { id: 'legacy-' + i, v: 0, text: '明文遗留-' + i, updatedAt: i });
  assert((await vault.countLegacyNotes()) === 5, '识别出 5 条遗留明文笔记');
  const mig = await vault.migrateLegacy();
  assert(mig.migrated === 5, '迁移完成 5 条');
  assert((await vault.getNote('legacy-3')).text === '明文遗留-3', '迁移后内容可解');
  assert(!JSON.stringify(await store.getAll('notes')).includes('明文遗留'), '迁移后存储层无明文');

  // 失败回滚：迁移写第 3 条时抛配额错误
  await store.del('meta', 'migration');
  for (let i = 5; i < 10; i++) await store.put('notes', { id: 'legacy-' + i, v: 0, text: '第二批明文-' + i, updatedAt: i });
  let migPuts = 0;
  const failStore = faulty(store, {
    onPut: (s, o) => s === 'notes' && o.v === 1 && ++migPuts > 2,
    error: () => Store.QuotaExceededError()
  });
  const failVault = new Vault(failStore, vault._crypto);
  failVault._config = await store.get('meta', 'config');
  let migErr = null;
  try { await failVault.migrateLegacy(); } catch (e) { migErr = e; }
  assert(migErr && migErr.name === 'QuotaExceededError', '迁移中途失败并抛出');
  const afterRollback = await store.getAll('notes');
  const legacyBack = afterRollback.filter(n => n.v === 0 && n.id >= 'legacy-5');
  assert(legacyBack.length === 5 && legacyBack.every(n => n.text.startsWith('第二批明文-')), '回滚后遗留笔记恢复为原始明文');
  assert(!(await store.get('meta', 'migration')) && (await store.getAll('backup')).length === 0, '迁移标记与备份已清理');

  // 崩溃回滚：备份+标记已写、只迁移了一部分时“进程死亡”，重新解锁自动回滚
  await store.put('notes', { id: 'legacy-x', v: 0, text: '崩溃现场', updatedAt: 99 });
  await store.put('backup', { id: 'legacy-x', v: 0, text: '崩溃现场', updatedAt: 99 });
  await store.put('meta', { id: 'migration', status: 'in-progress', startedAt: Date.now() });
  await store.put('notes', { id: 'legacy-x', v: 1, keyId: 'broken', iv: 'AA', ct: 'AA', updatedAt: 99 }); // 写了一半的坏记录
  vault = new Vault(store, newCrypto());
  const crashUnlock = await vault.unlock('pw');
  assert(crashUnlock.rolledBackMigration === true, '解锁时检测到崩溃的迁移并回滚');
  assert((await store.get('notes', 'legacy-x')).text === '崩溃现场', '坏记录已被备份还原');

  // ---- 6. 配额不足降级 ----
  console.log('\n[6] 配额不足降级');
  let degraded = false;
  const quotaStore = faulty(store, {
    onPut: (s) => s === 'notes',
    error: () => Store.QuotaExceededError()
  });
  const quotaVault = new Vault(quotaStore, vault._crypto, { onQuotaDegraded: () => { degraded = true; } });
  quotaVault._config = await store.get('meta', 'config');
  let quotaErr = null;
  try { await quotaVault.saveNote(null, '写不进去'); } catch (e) { quotaErr = e; }
  assert(quotaErr && quotaErr.name === 'QuotaExceededError', '写入抛出配额错误');
  assert(degraded, '触发降级钩子（UI 可展示导出/降级提示）');
  const exported = await quotaVault.exportAll();
  assert(exported.includes('崩溃现场'), '配额满时仍可导出全部明文备份');

  // ---- 7. 隐私模式（内存存储，不持久化）----
  console.log('\n[7] 隐私模式降级路径');
  const memStore = new Store.MemoryStore(); // openBest 在 IDB 不可用时返回的同类型
  const memVault = new Vault(memStore, newCrypto());
  await memVault.create('pw');
  const mid = await memVault.saveNote(null, '隐私模式笔记');
  assert((await memVault.getNote(mid)).text === '隐私模式笔记', '内存存储下功能完整可用');

  // ---- 8. 修改密码 ----
  console.log('\n[8] 修改密码');
  await memVault.changePassword('new-pw');
  await memVault.lock();
  let oldPwFails = false;
  try { await new Vault(memStore, newCrypto()).unlock('pw'); } catch (e) { oldPwFails = e.name === 'WrongPasswordError'; }
  assert(oldPwFails, '旧密码失效');
  const relogin = new Vault(memStore, newCrypto());
  await relogin.unlock('new-pw');
  assert((await relogin.getNote(mid)).text === '隐私模式笔记', '新密码可解全部笔记');

  // ---- 9. 性能 ----
  console.log('\n[9] 性能');
  const perfStore = new Store.MemoryStore();
  const perfVault = new Vault(perfStore, newCrypto());
  let t0 = Date.now();
  await perfVault.create('pw');
  const deriveMs = Date.now() - t0;
  t0 = Date.now();
  const pids = [];
  for (let i = 0; i < 100; i++) pids.push(await perfVault.saveNote(null, '性能测试笔记内容-' + i));
  const writeMs = Date.now() - t0;
  t0 = Date.now();
  for (const id of pids) await perfVault.getNote(id);
  const readMs = Date.now() - t0;
  t0 = Date.now();
  await perfVault.rotateKey();
  const rotateMs = Date.now() - t0;
  console.log(`  派生密钥 ${deriveMs}ms | 写 100 条 ${writeMs}ms | 读 100 条 ${readMs}ms | 轮换 100 条 ${rotateMs}ms`);
  assert(writeMs < 5000 && readMs < 5000 && rotateMs < 10000, '性能在可接受范围');

  console.log(`\n结果: ${passed} 通过, ${failed} 失败`);
  process.exit(failed ? 1 : 0);
}

main().catch(e => { console.error('未捕获异常:', e); process.exit(1); });
