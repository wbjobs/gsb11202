# 加密笔记（本地加密笔记工具）

纯前端应用：所有数据在本地加密存储，密钥由用户密码派生，永不离开内存中的加密上下文。

## 运行

需要通过 HTTP 访问（Web Crypto 要求安全上下文；`localhost` 即可）：

```bash
cd 本目录
python3 -m http.server 8000
# 打开 http://localhost:8000/           —— 应用
# 打开 http://localhost:8000/selftest.html —— 浏览器端验收自测
```

## 技术架构

- **Web Crypto**：PBKDF2-HMAC-SHA256（31 万次迭代）从密码派生 KEK；AES-GCM-256 加密笔记与包裹密钥
- **Web Worker**（`js/crypto-worker.js`）：KEK 与所有 DEK 只存在于 Worker 内存，加解密不阻塞 UI；Worker 不可用时降级为主线程同接口实现（`js/crypto-client.js`）
- **IndexedDB**（`js/store.js`）：`meta`（配置/轮换日志/迁移标记）、`keys`（包裹后的 DEK）、`notes`（密文信封）、`backup`（迁移备份）四个对象仓库；隐私模式自动降级为内存存储并提示

### 密钥分层

```
用户密码 --PBKDF2--> KEK（密钥加密密钥）
KEK --AES-GCM wrap--> DEK（数据加密密钥，可多代并存，支持轮换）
DEK --AES-GCM--> 笔记密文（信封含 keyId，轮换可幂等续跑）
```

## 关键机制

- **密码错误**：解锁时用 KEK 解密校验串，失败即报「密码错误」
- **密钥轮换可续跑**：轮换前写入 journal（新密钥 ID + 待处理笔记清单），每 20 条写一次检查点；中断后下次解锁自动从断点继续；单条笔记信封自带 keyId，重复处理幂等
- **迁移回滚**：迁移前把全部遗留明文笔记复制到 `backup` 并写迁移标记；任一步失败立即回滚；迁移中途崩溃时，下次解锁检测到标记自动用备份还原
- **配额不足**：捕获 `QuotaExceededError`，先清理备份/退役密钥重试一次，仍失败则进入降级模式（提示 + 一键导出全部明文备份）
- **隐私模式**：探测 IndexedDB 真实可写性，不可写时降级为内存存储并显示「不持久化」横幅，功能完整可用
- **修改密码**：重新派生 KEK 并重新包裹所有 DEK，笔记密文无需改动

## 验收标准对照

| 标准 | 实现 | 验证 |
|---|---|---|
| 轮换后旧笔记可解 | 信封 keyId + 多代 DEK 并存 | `test/node-smoke.cjs` [3] |
| 新笔记用新密钥 | 保存时取 `config.currentKeyId` | [3] |
| 密码错误有提示 | 校验串解密失败 → `WrongPasswordError` | [1] |
| 轮换中断可续 | journal 检查点 + 幂等重放 | [4] |
| 迁移失败可回滚 | backup 仓库 + 标记 + 解锁时自动回滚 | [5] |
| 配额不足有降级 | 清理重试 → 降级横幅 + 导出 | [6] |
| 隐私模式不崩 | 内存存储降级 + 横幅提示 | [7] |
| 性能可接受 | Worker 异步 + 批量检查点 | [9] |

## 测试

```bash
node test/node-smoke.cjs   # Node 核心逻辑测试（30 项断言）
# 浏览器打开 selftest.html  # 真实 Worker + Web Crypto 环境复测
```

## 文件结构

```
index.html            应用入口
selftest.html         浏览器端验收自测
css/style.css         样式
js/crypto-core.js     加密原语（PBKDF2 / AES-GCM / 密钥包裹）
js/crypto-worker.js   加密操作集 + Worker 接线（密钥不出 Worker）
js/crypto-client.js   Worker / 主线程降级两种客户端
js/store.js           IndexedDB + 内存降级存储
js/vault.js           编排层：解锁、轮换、迁移、配额处理
js/app.js             UI 逻辑
test/node-smoke.cjs   Node 冒烟测试
```
