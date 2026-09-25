/*
 * app.js — UI  wiring：锁屏/创建、笔记列表与编辑、轮换进度、迁移、配额与隐私模式降级提示。
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  var store, crypto, vault;
  var persistent = true;
  var currentNoteId = null;
  var saveTimer = null;
  var busy = false;

  // ---------- 通用 UI ----------

  function show(el) { $(el).classList.remove('hidden'); }
  function hide(el) { $(el).classList.add('hidden'); }

  var toastTimer = null;
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.classList.add('hidden'); }, 3000);
  }

  function setBusy(b) {
    busy = b;
    ['new-note-btn', 'rotate-btn', 'migrate-btn', 'passwd-btn', 'export-btn', 'lock-btn'].forEach(function (id) {
      $(id).disabled = b;
    });
  }

  function showProgress(label) {
    $('progress-label').textContent = label;
    $('progress-bar').style.width = '0%';
    show('progress-area');
  }
  function updateProgress(done, total) {
    var pct = total ? Math.round((done / total) * 100) : 0;
    $('progress-bar').style.width = pct + '%';
    $('progress-label').textContent = $('progress-label').textContent.replace(/ \d+\/\d+$/, '') + ' ' + done + '/' + total;
  }
  function hideProgress() { hide('progress-area'); }

  // ---------- 启动 ----------

  async function boot() {
    if (!window.crypto || !crypto.subtle) {
      $('fatal-msg').textContent = '当前环境不支持 Web Crypto（需要 HTTPS 或 localhost 等安全上下文）。';
      show('fatal');
      return;
    }

    // 存储：优先 IndexedDB，隐私模式下降级为内存存储
    try {
      var best = await Store.openBest();
      store = best.store;
      persistent = best.persistent;
    } catch (e) {
      store = new Store.MemoryStore();
      persistent = false;
    }

    // 加密：优先 Worker，失败降级为主线程直接执行
    try {
      crypto = new CryptoClient.WorkerCrypto('js/crypto-worker.js');
    } catch (e) {
      crypto = new CryptoClient.DirectCrypto();
    }

    vault = new Vault(store, crypto, {
      onProgress: function (phase, done, total) { updateProgress(done, total); },
      onQuotaDegraded: function () {
        show('quota-banner');
        toast('存储空间不足，已进入降级模式');
      }
    });

    if (!persistent) show('privacy-banner');

    var exists = await Vault.hasVault(store);
    if (exists) {
      $('lock-subtitle').textContent = '输入密码解锁你的加密笔记。';
      $('lock-hint').textContent = persistent ? '' : '隐私模式：若此前未导出，数据已随页面关闭丢失。';
    } else {
      $('lock-subtitle').textContent = '首次使用，请设置主密码。';
      $('unlock-btn').textContent = '创建保险库';
      show('password-confirm');
      $('lock-hint').textContent = '密码用于派生加密密钥，请务必牢记——忘记密码无法恢复数据。';
    }
    show('lock-screen');
    $('password-input').focus();

    $('unlock-btn').onclick = onUnlockSubmit;
    $('password-input').onkeydown = $('password-confirm').onkeydown = function (e) {
      if (e.key === 'Enter') onUnlockSubmit();
    };
  }

  async function onUnlockSubmit() {
    var pw = $('password-input').value;
    var errEl = $('lock-error');
    errEl.classList.add('hidden');
    if (!pw) { errEl.textContent = '请输入密码'; errEl.classList.remove('hidden'); return; }
    $('unlock-btn').disabled = true;
    $('unlock-btn').textContent = '派生密钥中…';
    try {
      var exists = await Vault.hasVault(store);
      if (!exists) {
        if (pw !== $('password-confirm').value) {
          errEl.textContent = '两次输入的密码不一致';
          errEl.classList.remove('hidden');
          return;
        }
        await vault.create(pw);
        enterMain();
        toast('保险库已创建');
      } else {
        var res = await vault.unlock(pw);
        enterMain();
        if (res.rolledBackMigration) toast('检测到中断的迁移，已回滚到一致状态');
        if (res.resumedRotation) {
          toast('检测到中断的密钥轮换，正在继续…');
          runRotation();
        }
      }
    } catch (e) {
      if (e.name === 'WrongPasswordError') {
        errEl.textContent = '密码错误，请重试';
      } else {
        errEl.textContent = '解锁失败：' + e.message;
      }
      errEl.classList.remove('hidden');
    } finally {
      $('unlock-btn').disabled = false;
      $('unlock-btn').textContent = (await Vault.hasVault(store)) ? '解锁' : '创建保险库';
    }
  }

  function enterMain() {
    hide('lock-screen');
    show('main-screen');
    $('mode-badge').textContent = persistent ? '本地持久化' : '隐私模式·不持久化';
    if (!persistent) show('privacy-banner');
    refreshNoteList();
    refreshLegacyCount();
  }

  // ---------- 笔记列表与编辑 ----------

  async function refreshNoteList() {
    var notes = await vault.listNotes();
    var list = $('note-list');
    list.innerHTML = '';
    notes.forEach(function (n) {
      var div = document.createElement('div');
      div.className = 'note-item' + (n.id === currentNoteId ? ' active' : '');
      div.dataset.id = n.id;
      var title = document.createElement('div');
      title.textContent = '笔记 ' + n.id.slice(0, 6);
      var time = document.createElement('div');
      time.className = 'time';
      time.textContent = new Date(n.updatedAt).toLocaleString();
      if (n.legacy) {
        var tag = document.createElement('span');
        tag.className = 'legacy-tag';
        tag.textContent = ' · 未加密';
        time.appendChild(tag);
      }
      div.appendChild(title);
      div.appendChild(time);
      div.onclick = function () { openNote(n.id); };
      list.appendChild(div);
    });
  }

  async function openNote(id) {
    await flushSave();
    var note = await vault.getNote(id);
    if (!note) return;
    currentNoteId = id;
    hide('empty-state');
    show('editor');
    show('editor-footer');
    $('editor').value = note.text;
    $('save-status').textContent = note.legacy ? '未加密的旧数据，保存后将加密' : '';
    document.querySelectorAll('.note-item').forEach(function (el) {
      el.classList.toggle('active', el.dataset.id === id);
    });
  }

  async function flushSave() {
    if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; await saveCurrentNote(); }
  }

  async function saveCurrentNote() {
    if (!currentNoteId) return;
    var text = $('editor').value;
    try {
      await vault.saveNote(currentNoteId, text);
      $('save-status').textContent = '已加密保存 ' + new Date().toLocaleTimeString();
      refreshNoteList();
      refreshLegacyCount();
    } catch (e) {
      if (Store.isQuotaError(e)) {
        $('save-status').textContent = '保存失败：存储空间不足';
      } else {
        $('save-status').textContent = '保存失败：' + e.message;
      }
    }
  }

  $('editor').addEventListener('input', function () {
    $('save-status').textContent = '编辑中…';
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveCurrentNote, 600);
  });

  $('new-note-btn').onclick = async function () {
    if (busy) return;
    await flushSave();
    try {
      var id = await vault.saveNote(null, '');
      await refreshNoteList();
      await openNote(id);
      $('editor').focus();
    } catch (e) {
      if (Store.isQuotaError(e)) show('quota-banner');
      else toast('新建失败：' + e.message);
    }
  };

  $('delete-note-btn').onclick = async function () {
    if (!currentNoteId || !confirm('确定删除这条笔记？')) return;
    await vault.deleteNote(currentNoteId);
    currentNoteId = null;
    hide('editor'); hide('editor-footer'); show('empty-state');
    refreshNoteList();
  };

  // ---------- 密钥轮换 ----------

  async function runRotation() {
    if (busy) return;
    setBusy(true);
    showProgress('密钥轮换中（可安全关闭页面，下次解锁会继续）');
    try {
      await vault.rotateKey();
      toast('密钥轮换完成，全部笔记已用新密钥重新加密');
    } catch (e) {
      toast('轮换中断：' + e.message + '（下次解锁可继续）');
    } finally {
      hideProgress();
      setBusy(false);
      refreshNoteList();
    }
  }
  $('rotate-btn').onclick = runRotation;

  // ---------- 旧数据迁移 ----------

  async function refreshLegacyCount() {
    var n = await vault.countLegacyNotes();
    if (n > 0) {
      $('legacy-count').textContent = n;
      show('migrate-btn');
    } else {
      hide('migrate-btn');
    }
  }

  $('migrate-btn').onclick = async function () {
    if (busy) return;
    setBusy(true);
    showProgress('迁移旧数据中');
    try {
      var res = await vault.migrateLegacy();
      toast('迁移完成：' + res.migrated + ' 条旧笔记已加密');
    } catch (e) {
      if (Store.isQuotaError(e)) {
        show('quota-banner');
        toast('迁移失败：空间不足，已回滚全部更改');
      } else {
        toast('迁移失败：' + e.message + '，已回滚全部更改');
      }
    } finally {
      hideProgress();
      setBusy(false);
      refreshNoteList();
      refreshLegacyCount();
    }
  };

  // ---------- 修改密码 ----------

  $('passwd-btn').onclick = function () {
    $('new-password').value = $('new-password-confirm').value = '';
    hide('passwd-error');
    show('passwd-modal');
    $('new-password').focus();
  };
  $('passwd-cancel').onclick = function () { hide('passwd-modal'); };
  $('passwd-ok').onclick = async function () {
    var pw = $('new-password').value;
    var errEl = $('passwd-error');
    if (!pw) { errEl.textContent = '请输入新密码'; errEl.classList.remove('hidden'); return; }
    if (pw !== $('new-password-confirm').value) { errEl.textContent = '两次输入不一致'; errEl.classList.remove('hidden'); return; }
    $('passwd-ok').disabled = true;
    try {
      await vault.changePassword(pw);
      hide('passwd-modal');
      toast('密码已修改，密钥已重新包裹');
    } catch (e) {
      errEl.textContent = '修改失败：' + e.message;
      errEl.classList.remove('hidden');
    } finally {
      $('passwd-ok').disabled = false;
    }
  };

  // ---------- 导出 / 锁定 ----------

  async function doExport() {
    await flushSave();
    var json = await vault.exportAll();
    var blob = new Blob([json], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'notes-backup-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(a.href);
    toast('已导出（明文 JSON，请妥善保管）');
  }
  $('export-btn').onclick = doExport;
  $('quota-export-btn').onclick = doExport;

  $('lock-btn').onclick = async function () {
    await flushSave();
    await vault.lock();
    location.reload();
  };

  boot().catch(function (e) {
    $('fatal-msg').textContent = '启动失败：' + e.message;
    show('fatal');
  });
})();
