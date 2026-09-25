// 主线程 UI：通过 RPC 与 worker 通信，自身不接触任何密钥与明文落盘逻辑。

const worker = new Worker('src/worker.js', { type: 'module' });

let seq = 0;
const pending = new Map();
worker.onmessage = (e) => {
  const { id, ok, result, error, event } = e.data;
  if (event) return handleEvent(event);
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  ok ? p.resolve(result) : p.reject(error);
};
worker.onerror = (e) => showBanner('error', `后台线程错误：${e.message || '未知'}`);

function rpc(cmd, args) {
  return new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, cmd, args });
  });
}

const $ = (sel) => document.querySelector(sel);
const state = { notes: [], currentId: null, initialized: false, saveTimer: null, dirty: false };

// ---------- 横幅 ----------

function showBanner(kind, html, actions = []) {
  const el = document.createElement('div');
  el.className = `banner ${kind === 'error' ? 'warn' : kind}`;
  const span = document.createElement('span');
  span.innerHTML = html;
  el.appendChild(span);
  for (const a of actions) {
    const btn = document.createElement('button');
    btn.textContent = a.label;
    btn.onclick = () => a.onClick(el);
    el.appendChild(btn);
  }
  $('#banners').appendChild(el);
  return el;
}

function handleEvent(ev) {
  if (ev.type === 'degraded') {
    showBanner('warn', '⚠️ 存储空间不足，已进入降级模式：新更改暂存于内存，请导出备份或清理空间后重试。', [
      { label: '导出未保存更改', onClick: () => exportOutbox() },
      { label: '重试保存', onClick: (el) => retryOutbox(el) },
    ]);
    setSaveStatus('降级中：更改未落盘');
  } else if (ev.type === 'rotation-started') {
    rotationBanner(`密钥轮换中（新密钥 v${ev.newVersion}）…`);
  } else if (ev.type === 'rotation-progress') {
    rotationBanner(`密钥轮换中，已处理 ${ev.done} 条…`);
  } else if (ev.type === 'rotation-complete') {
    rotationBanner(null);
    showBanner('info', `✅ 密钥轮换完成，共重加密 ${ev.total} 条笔记，当前密钥 v${ev.newVersion}。`);
    refreshList();
  } else if (ev.type === 'migration-rollback') {
    showBanner('warn', `⚠️ 数据迁移失败，已自动回滚到旧版本（${ev.error}）。`);
  } else if (ev.type === 'migration-complete') {
    showBanner('info', `数据已从 v${ev.from} 迁移到 v${ev.to}。`);
  }
}

let rotationEl = null;
function rotationBanner(text) {
  if (text === null) {
    rotationEl?.remove();
    rotationEl = null;
    return;
  }
  if (!rotationEl) rotationEl = showBanner('info', '');
  rotationEl.querySelector('span').textContent = `🔄 ${text}`;
}

// ---------- 锁屏 ----------

async function boot() {
  const st = await rpc('status');
  state.initialized = st.initialized;
  if (!st.persistent) {
    showBanner('warn', '⚠️ 当前处于隐私/无痕模式或浏览器禁用了 IndexedDB，数据仅保存在内存中，关闭页面后将丢失。');
  }
  if (st.locked) {
    showLockScreen(st);
  } else {
    showMainScreen(st);
  }
}

function showLockScreen(st) {
  $('#lock-screen').classList.remove('hidden');
  $('#main-screen').classList.add('hidden');
  $('#lock-subtitle').textContent = st.initialized ? '输入密码解锁' : '首次使用，请设置密码';
  $('#password-confirm').classList.toggle('hidden', st.initialized);
  $('#unlock-btn').textContent = st.initialized ? '解锁' : '创建并解锁';
  $('#password').focus();
}

async function showMainScreen(st) {
  $('#lock-screen').classList.add('hidden');
  $('#main-screen').classList.remove('hidden');
  if (st.rotation) {
    // 上次轮换被中断，提示续传
    showBanner('warn', `⚠️ 检测到上次密钥轮换未完成（目标密钥 v${st.rotation.newVersion}，已处理 ${st.rotation.done} 条）。`, [
      { label: '继续轮换', onClick: async (el) => { el.remove(); await rpc('rotateKeys'); } },
      { label: '稍后', onClick: (el) => el.remove() },
    ]);
  }
  await refreshList();
}

async function submitPassword() {
  const pw = $('#password').value;
  const errEl = $('#lock-error');
  errEl.classList.add('hidden');
  if (!pw) return;
  try {
    let st;
    if (state.initialized) {
      st = await rpc('unlock', { password: pw });
    } else {
      if (pw !== $('#password-confirm').value) {
        errEl.textContent = '两次输入的密码不一致';
        errEl.classList.remove('hidden');
        return;
      }
      st = await rpc('setup', { password: pw });
      state.initialized = true;
    }
    $('#password').value = '';
    $('#password-confirm').value = '';
    showMainScreen(st);
  } catch (e) {
    if (e.code === 'WRONG_PASSWORD') {
      errEl.textContent = '密码错误，请重试';
    } else if (e.code === 'MIGRATION_FAILED') {
      errEl.textContent = `数据迁移失败（已回滚）：${e.message}`;
    } else {
      errEl.textContent = e.message || '解锁失败';
    }
    errEl.classList.remove('hidden');
  }
}

// ---------- 笔记列表与编辑 ----------

async function refreshList() {
  state.notes = await rpc('listNotes');
  const ul = $('#note-list');
  ul.innerHTML = '';
  for (const n of state.notes) {
    const li = document.createElement('li');
    li.dataset.id = n.id;
    if (n.id === state.currentId) li.classList.add('active');
    const title = document.createElement('span');
    title.textContent = n.title || '（无标题）';
    const time = document.createElement('span');
    time.className = 'time';
    time.textContent = new Date(n.updatedAt).toLocaleString();
    li.append(title, time);
    li.onclick = () => openNote(n.id);
    ul.appendChild(li);
  }
}

async function openNote(id) {
  await flushSave();
  const note = await rpc('getNote', { id });
  if (!note) return;
  state.currentId = id;
  $('#editor-empty').classList.add('hidden');
  $('#editor-form').classList.remove('hidden');
  $('#note-title').value = note.title;
  $('#note-body').value = note.body;
  document.querySelectorAll('#note-list li').forEach((li) => li.classList.toggle('active', li.dataset.id === id));
  setSaveStatus('');
}

function setSaveStatus(text) {
  $('#save-status').textContent = text;
}

function scheduleSave() {
  state.dirty = true;
  setSaveStatus('编辑中…');
  clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(flushSave, 600);
}

async function flushSave() {
  if (!state.dirty || !state.currentId) return;
  state.dirty = false;
  clearTimeout(state.saveTimer);
  const res = await rpc('saveNote', {
    id: state.currentId,
    title: $('#note-title').value,
    body: $('#note-body').value,
  });
  if (res.ok) {
    setSaveStatus(`已保存 ${new Date().toLocaleTimeString()}`);
  } else if (res.code === 'QUOTA_EXCEEDED') {
    setSaveStatus('降级中：更改未落盘');
  }
  refreshList();
}

async function exportOutbox() {
  const items = await rpc('exportOutbox');
  if (!items.length) return;
  const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `encnotes-unsaved-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function retryOutbox(el) {
  const res = await rpc('retryOutbox');
  if (res.ok) {
    el?.remove();
    showBanner('info', '✅ 存储空间已恢复，未保存的更改已落盘。');
    setSaveStatus('');
  } else {
    showBanner('warn', `存储空间仍然不足，还有 ${res.remaining} 条未保存。`);
  }
}

// ---------- 事件绑定 ----------

$('#unlock-btn').onclick = submitPassword;
$('#password').addEventListener('keydown', (e) => e.key === 'Enter' && submitPassword());
$('#password-confirm').addEventListener('keydown', (e) => e.key === 'Enter' && submitPassword());

$('#new-note-btn').onclick = async () => {
  await flushSave();
  const res = await rpc('saveNote', { title: '', body: '' });
  state.currentId = res.id;
  await refreshList();
  await openNote(res.id);
  $('#note-title').focus();
};

$('#note-title').addEventListener('input', scheduleSave);
$('#note-body').addEventListener('input', scheduleSave);

$('#delete-note-btn').onclick = async () => {
  if (!state.currentId || !confirm('确定删除这条笔记吗？')) return;
  await rpc('deleteNote', { id: state.currentId });
  state.currentId = null;
  $('#editor-form').classList.add('hidden');
  $('#editor-empty').classList.remove('hidden');
  refreshList();
};

$('#rotate-btn').onclick = async () => {
  if (!confirm('轮换密钥将生成新的数据密钥并重加密全部笔记，过程中可以安全中断。继续吗？')) return;
  try {
    await rpc('rotateKeys');
  } catch (e) {
    showBanner('warn', `密钥轮换中断：${e.message}。下次解锁时可继续。`);
  }
};

$('#passwd-btn').onclick = async () => {
  const oldPassword = prompt('请输入当前密码：');
  if (oldPassword == null) return;
  const newPassword = prompt('请输入新密码（至少 6 位）：');
  if (newPassword == null) return;
  if (newPassword.length < 6) return alert('新密码太短');
  try {
    await rpc('changePassword', { oldPassword, newPassword });
    showBanner('info', '✅ 密码已修改。');
  } catch (e) {
    alert(e.code === 'WRONG_PASSWORD' ? '原密码错误' : `修改失败：${e.message}`);
  }
};

$('#lock-btn').onclick = async () => {
  await flushSave();
  await rpc('lock');
  state.currentId = null;
  $('#note-title').value = '';
  $('#note-body').value = '';
  boot();
};

boot();
