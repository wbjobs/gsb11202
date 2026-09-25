// 冒烟测试：在 Node 中用内存存储 + 故障注入验证全部验收标准。
// 运行：node test/smoke.mjs

import assert from 'node:assert/strict';
import { Vault, E } from '../src/vault.js';
import { MemoryStore } from '../src/store.js';
import { deriveKEK, generateDataKey, wrapKey, encryptJSON, b64e, randomBytes } from '../src/crypto.js';

const OPTS = { pbkdf2Iterations: 1000, rotationBatchSize: 5 }; // 测试加速

// 故障注入包装器：可让接下来 N 次 put 抛 QuotaExceededError
class FaultStore {
  constructor(inner) {
    this.inner = inner;
    this.failNextPuts = 0;
  }
  get persistent() {
    return this.inner.persistent;
  }
  injectQuotaError(n = 1) {
    this.failNextPuts = n;
  }
  async get(...a) { return this.inner.get(...a); }
  async getAll(...a) { return this.inner.getAll(...a); }
  async del(...a) { return this.inner.del(...a); }
  async clear(...a) { return this.inner.clear(...a); }
  async put(store, key, val) {
    if (this.failNextPuts > 0) {
      this.failNextPuts--;
      const e = new Error('模拟配额不足');
      e.name = 'QuotaExceededError';
      throw e;
    }
    return this.inner.put(store, key, val);
  }
}

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(['PASS', name]);
  } catch (err) {
    results.push(['FAIL', `${name}: ${err.message}`]);
    console.error(err);
  }
}

async function freshVault(store = new MemoryStore()) {
  const v = new Vault(store, OPTS);
  await v.setup('pw-123456');
  return v;
}

async function seedNotes(vault, n, prefix = 'note') {
  for (let i = 0; i < n; i++) {
    await vault.saveNote({ id: `${prefix}-${i}`, title: `标题${i}`, body: `内容${i}` });
  }
}

// 1. 加密存储：落盘数据必须是密文
await test('加密存储：落盘为密文，无明文泄漏', async () => {
  const store = new MemoryStore();
  const v = await freshVault(store);
  await v.saveNote({ id: 'a', title: '秘密标题XYZ', body: '秘密正文ABC' });
  const raw = await store.get('notes', 'a');
  const dump = JSON.stringify(raw);
  assert.ok(raw.ct && raw.iv, '应存储密文与 IV');
  assert.ok(!dump.includes('秘密标题XYZ') && !dump.includes('秘密正文ABC'), '落盘数据不得包含明文');
  const note = await v.getNote('a');
  assert.equal(note.body, '秘密正文ABC');
});

// 2. 密码错误有提示
await test('密码错误：抛出 WRONG_PASSWORD', async () => {
  const store = new MemoryStore();
  await freshVault(store);
  const v2 = new Vault(store, OPTS);
  await assert.rejects(() => v2.unlock('wrong-pw'), (e) => e.code === E.WRONG_PASSWORD);
  const v3 = new Vault(store, OPTS);
  await v3.unlock('pw-123456'); // 正确密码可解锁
});

// 3. 密钥轮换：旧笔记可解、新笔记用新密钥
await test('密钥轮换：旧笔记可解，新笔记用新密钥', async () => {
  const v = await freshVault();
  await seedNotes(v, 12);
  const before = await v.getNote('note-0');
  const res = await v.rotateKeys();
  assert.equal(res.newVersion, 2);
  assert.equal(res.rotated, 12);
  // 旧笔记仍可解密
  const after = await v.getNote('note-0');
  assert.deepEqual({ title: after.title, body: after.body }, { title: before.title, body: before.body });
  assert.equal(after.keyVersion, 2);
  // 旧密钥已退役
  assert.equal(v.dataKeys.size, 1);
  // 新笔记使用新密钥
  await v.saveNote({ id: 'new', title: 't', body: 'b' });
  assert.equal((await v.getNote('new')).keyVersion, 2);
});

// 4. 轮换中断可续（模拟进程崩溃：换 Vault 实例从检查点恢复）
await test('轮换中断：换实例后可从检查点续传完成', async () => {
  const store = new FaultStore(new MemoryStore());
  const v = await freshVault(store);
  await seedNotes(v, 12);
  // 轮换进行到一半时注入故障（第 2 批笔记写入失败）-> 中断
  const origPut = store.inner.put.bind(store.inner);
  let puts = 0;
  store.inner.put = async (...a) => {
    // put 顺序：keys(1)、rotation 起始检查点(2)、第 1 批 5 条笔记(3-7)、批检查点(8)、第 2 批首条(9) -> 在第 9 次崩溃
    if (++puts === 9) { const e = new Error('模拟崩溃'); e.name = 'QuotaExceededError'; throw e; }
    return origPut(...a);
  };
  await assert.rejects(() => v.rotateKeys());
  // 检查点已保存
  const rot = await store.get('meta', 'rotation');
  assert.ok(rot && rot.newVersion === 2 && rot.done > 0, '中断后应存在轮换检查点');
  // 模拟重启：全新 Vault 实例解锁同一存储
  const v2 = new Vault(store, OPTS);
  await v2.unlock('pw-123456');
  const st = await v2.status();
  assert.ok(st.rotation, '重启后应能检测到未完成的轮换');
  // 混合状态下旧笔记（v1）与新笔记（v2）都可解
  assert.ok((await v2.getNote('note-0')).body.startsWith('内容'));
  // 续传完成
  const res = await v2.rotateKeys();
  assert.equal(res.rotated, 12);
  for (let i = 0; i < 12; i++) {
    const n = await v2.getNote(`note-${i}`);
    assert.equal(n.body, `内容${i}`);
    assert.equal(n.keyVersion, 2);
  }
});

// 5. 迁移失败可回滚
await test('迁移失败：自动回滚，数据与版本号不变', async () => {
  // 构造 v1 旧库：明文笔记 + 无 schemaVersion
  const inner = new MemoryStore();
  const salt = randomBytes(16);
  const kek = await deriveKEK('pw-123456', salt, OPTS.pbkdf2Iterations);
  const dk = await generateDataKey();
  await inner.put('meta', 'salt', b64e(salt));
  await inner.put('meta', 'verify', await encryptJSON(kek, 'encnotes-verify-v1'));
  await inner.put('keys', '1', { version: 1, wrapped: await wrapKey(dk, kek), createdAt: Date.now() });
  await inner.put('meta', 'currentKeyVersion', 1);
  await inner.put('notes', 'old-1', { id: 'old-1', title: '旧标题', body: '旧正文', updatedAt: 1 });

  // 第一次解锁：迁移过程中注入故障 -> 应回滚
  const store = new FaultStore(inner);
  const v1 = new Vault(store, OPTS);
  // 让迁移中对 notes 的第一次写入失败
  const origPut = inner.put.bind(inner);
  let intercepted = false;
  inner.put = async (s, k, val) => {
    if (!intercepted && s === 'notes') {
      intercepted = true;
      const e = new Error('模拟迁移写入失败');
      e.name = 'QuotaExceededError';
      throw e;
    }
    return origPut(s, k, val);
  };
  await assert.rejects(() => v1.unlock('pw-123456'), (e) => e.code === E.MIGRATION);
  // 回滚验证：明文笔记原样保留，schemaVersion 未前进到 2
  const raw = await inner.get('notes', 'old-1');
  assert.equal(raw.body, '旧正文');
  assert.notEqual(await inner.get('meta', 'schemaVersion'), 2);
  // 故障解除后重试：迁移成功
  const v2 = new Vault(store, OPTS);
  await v2.unlock('pw-123456');
  assert.equal(await inner.get('meta', 'schemaVersion'), 2);
  const migrated = await v2.getNote('old-1');
  assert.equal(migrated.body, '旧正文');
  const rawAfter = await inner.get('notes', 'old-1');
  assert.ok(rawAfter.ct, '迁移后应为密文');
});

// 6. 配额不足有降级
await test('配额不足：写入降级到内存 outbox，可导出、可重试', async () => {
  const store = new FaultStore(new MemoryStore());
  const v = await freshVault(store);
  store.injectQuotaError(1);
  const res = await v.saveNote({ id: 'q1', title: '降级笔记', body: '未落盘内容' });
  assert.equal(res.ok, false);
  assert.equal(res.code, E.QUOTA);
  assert.equal(v.degraded, true);
  assert.equal(await store.get('notes', 'q1'), undefined, '失败写入不得落盘');
  // 降级期间笔记仍可读（来自 outbox）
  assert.equal((await v.getNote('q1')).body, '未落盘内容');
  // 可导出明文备份
  const exported = await v.exportOutbox();
  assert.equal(exported.length, 1);
  assert.equal(exported[0].body, '未落盘内容');
  // 空间恢复后重试落盘
  const retry = await v.retryOutbox();
  assert.equal(retry.ok, true);
  assert.equal(v.degraded, false);
  assert.ok((await store.get('notes', 'q1')).ct, '重试后应落盘为密文');
});

// 7. 隐私模式不崩（内存存储全功能）
await test('隐私模式降级：内存存储全生命周期可用', async () => {
  const store = new MemoryStore();
  assert.equal(store.persistent, false);
  const v = new Vault(store, OPTS);
  const st = await v.setup('pw-123456');
  assert.equal(st.persistent, false);
  await seedNotes(v, 3);
  await v.rotateKeys();
  assert.equal((await v.getNote('note-2')).body, '内容2');
  await v.changePassword('pw-123456', 'pw-new');
  v.lock();
  await v.unlock('pw-new');
  assert.equal((await v.listNotes()).length, 3);
});

// 8. 修改密码后旧密码失效、数据不丢
await test('修改密码：旧密码失效，新密码可解全部数据', async () => {
  const store = new MemoryStore();
  const v = await freshVault(store);
  await seedNotes(v, 3);
  await v.changePassword('pw-123456', 'pw-new');
  v.lock();
  const bad = new Vault(store, OPTS);
  await assert.rejects(() => bad.unlock('pw-123456'), (e) => e.code === E.WRONG_PASSWORD);
  const good = new Vault(store, OPTS);
  await good.unlock('pw-new');
  assert.equal((await good.getNote('note-1')).body, '内容1');
});

// 9. 性能可接受
await test('性能：200 条笔记加解密与轮换在可接受时间内完成', async () => {
  const v = await freshVault();
  let t0 = performance.now();
  await seedNotes(v, 200);
  const tSave = performance.now() - t0;
  t0 = performance.now();
  await v.listNotes();
  const tList = performance.now() - t0;
  t0 = performance.now();
  await v.rotateKeys();
  const tRotate = performance.now() - t0;
  console.log(`    200 条: 保存 ${tSave.toFixed(0)}ms, 列表解密 ${tList.toFixed(0)}ms, 轮换 ${tRotate.toFixed(0)}ms`);
  assert.ok(tSave < 10000 && tList < 5000 && tRotate < 10000, '性能超出可接受范围');
});

// 汇总
let failed = 0;
for (const [status, name] of results) {
  if (status === 'FAIL') failed++;
  console.log(`${status === 'PASS' ? '✅' : '❌'} ${name}`);
}
console.log(`\n${results.length - failed}/${results.length} 通过`);
process.exit(failed ? 1 : 0);
