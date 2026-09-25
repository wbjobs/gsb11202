# 加密笔记（encnotes）

纯前端本地加密笔记工具。所有加解密在 Web Worker 中完成，数据落盘到 IndexedDB，永不离开本机。

## 运行

```bash
npm start          # 或 python3 -m http.server 8080
# 打开 http://localhost:8080
```

> 必须通过 HTTP 访问（ES Module 与 Worker 不支持 file://）。

## 测试

```bash
npm test           # Node 冒烟测试，覆盖全部验收标准
```

## 架构

```
index.html / styles.css     UI
src/app.js                  主线程：界面与 RPC 客户端（不接触密钥）
src/worker.js               Web Worker：RPC 服务端，IDB 不可用时降级内存存储
src/vault.js                核心：密钥派生/轮换/迁移/配额降级（环境无关）
src/crypto.js               Web Crypto 封装（PBKDF2 + AES-GCM）
src/store.js                IndexedDB 适配器 + 内存适配器（同一接口）
test/smoke.mjs              Node 冒烟测试（内存存储 + 故障注入）
```

## 加密设计

- **密码 → KEK**：PBKDF2-SHA256（21 万次迭代，随机盐）派生 AES-GCM-256 密钥加密密钥，不落盘、不可导出。
- **数据密钥**：随机 AES-GCM-256，按版本管理，被 KEK 包裹后存入 `keys` 表；笔记只被数据密钥加密。
- **密码校验**：用 KEK 加密固定令牌作为验证值，解密失败即密码错误。
- **笔记记录**：`{id, v: 密钥版本, iv, ct, createdAt, updatedAt}`，标题与正文一起加密。

## 关键行为

| 场景 | 行为 |
| --- | --- |
| 密码错误 | 验证令牌解密失败 → `WRONG_PASSWORD`，界面提示 |
| 密钥轮换 | 生成新版本数据密钥，分批（25 条/批）重加密，每批写检查点 |
| 轮换中断 | 检查点保留在 `meta.rotation`，下次解锁提示续传，混合版本笔记均可解 |
| 轮换完成 | 切换 `currentKeyVersion`，退役旧密钥，新笔记用新密钥 |
| 数据迁移 | 迁移前备份到 `backup` 表，失败自动回滚并恢复版本号 |
| 配额不足 | 捕获 `QuotaExceededError` → 降级：更改暂存内存 outbox，可导出明文备份、可重试落盘 |
| 隐私模式 | IndexedDB 打开失败/超时 → 自动切换内存存储并显示横幅，功能不崩 |
| 性能 | 加解密全部在 Worker；轮换分批并让出事件循环；200 条笔记轮换约 0.1s |

## 验收标准对照

`npm test` 中 9 个用例逐一对应：加密存储、密码错误提示、轮换后旧笔记可解 + 新笔记用新密钥、
轮换中断跨实例续传、迁移失败回滚、配额降级（导出/重试）、隐私模式全功能、修改密码、性能基准。
