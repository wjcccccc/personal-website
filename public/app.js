/* ─── State ────────────────────────────────────────────────────────────────── */
let currentUser = null;
let csrfToken = null;

/* ─── Init ─────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', async () => {
  await fetchCsrfToken();
  await fetchMe();
  loadMessages();

  const msgInput = document.getElementById('message-input');
  if (msgInput) {
    msgInput.addEventListener('input', () => {
      document.getElementById('char-count').textContent = `${msgInput.value.length} / 1000`;
    });
  }

  const fortuneRecent = document.getElementById('fortune-recent');
  if (fortuneRecent) {
    fortuneRecent.addEventListener('input', () => {
      document.getElementById('fortune-char-count').textContent = `${fortuneRecent.value.length} / 300`;
    });
  }
});

/* ─── CSRF ─────────────────────────────────────────────────────────────────── */
async function fetchCsrfToken() {
  try {
    const res = await fetch('/api/csrf-token');
    const data = await res.json();
    csrfToken = data.token;
  } catch {
    csrfToken = null;
  }
}

// Attach CSRF token to every state-changing request
function csrfHeaders(extra = {}) {
  return { ...extra, 'X-CSRF-Token': csrfToken || '' };
}

/* ─── Auth ─────────────────────────────────────────────────────────────────── */
async function fetchMe() {
  try {
    const res = await fetch('/api/me');
    const data = await res.json();
    if (data.loggedIn) {
      currentUser = data;
      renderLoggedIn(data);
    } else {
      renderLoggedOut();
    }
  } catch {
    renderLoggedOut();
  }
}

function renderLoggedIn(user) {
  document.getElementById('nav-auth').innerHTML = `
    <span style="color:var(--text-muted);font-size:0.85rem">嗨，<strong style="color:var(--accent)">${escHtml(user.username)}</strong></span>
    <button class="btn btn-danger btn-sm" onclick="logout()">登出</button>
  `;

  const panel = document.getElementById('user-panel');
  panel.classList.remove('hidden');
  document.getElementById('user-name-display').textContent = user.username;
  document.getElementById('user-avatar-img').src = user.avatarPath || 'images/default-avatar.svg';

  document.getElementById('message-form-area').classList.remove('hidden');
  document.getElementById('login-prompt').classList.add('hidden');
}

function renderLoggedOut() {
  currentUser = null;
  document.getElementById('nav-auth').innerHTML = `
    <button class="btn btn-outline" onclick="openModal('login-modal')">登入</button>
    <button class="btn btn-primary" onclick="openModal('register-modal')">註冊</button>
  `;
  document.getElementById('user-panel').classList.add('hidden');
  document.getElementById('message-form-area').classList.add('hidden');
  document.getElementById('login-prompt').classList.remove('hidden');
}

async function login(e) {
  e.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errorEl = document.getElementById('login-error');

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showFormError(errorEl, data.error || '登入失敗');
      return;
    }

    // Refresh CSRF token after session regeneration
    await fetchCsrfToken();
    currentUser = data;
    renderLoggedIn(data);
    closeModal('login-modal');
    showToast('登入成功！', 'success');
    loadMessages();
  } catch {
    showFormError(errorEl, '網路錯誤，請稍後再試');
  }
}

async function register(e) {
  e.preventDefault();
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const avatarFile = document.getElementById('reg-avatar').files[0];
  const errorEl = document.getElementById('reg-error');

  const formData = new FormData();
  formData.append('username', username);
  formData.append('password', password);
  if (avatarFile) formData.append('avatar', avatarFile);

  try {
    const res = await fetch('/api/register', { method: 'POST', body: formData });
    const data = await res.json();

    if (!res.ok) {
      showFormError(errorEl, data.error || '註冊失敗');
      return;
    }

    // Refresh CSRF token after session regeneration
    await fetchCsrfToken();
    currentUser = data;
    renderLoggedIn(data);
    closeModal('register-modal');
    showToast('註冊成功！歡迎加入', 'success');
    loadMessages();
  } catch {
    showFormError(errorEl, '網路錯誤，請稍後再試');
  }
}

async function logout() {
  await fetch('/api/logout', {
    method: 'POST',
    headers: csrfHeaders(),
  });
  csrfToken = null;
  await fetchCsrfToken();
  renderLoggedOut();
  showToast('已登出', 'success');
  loadMessages();
}

async function uploadAvatar(input) {
  const file = input.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('avatar', file);

  try {
    const res = await fetch('/api/upload-avatar', {
      method: 'POST',
      headers: csrfHeaders(),
      body: formData,
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || '上傳失敗', 'error');
      return;
    }

    document.getElementById('user-avatar-img').src = data.avatarPath;
    if (currentUser) currentUser.avatarPath = data.avatarPath;
    showToast('頭貼更新成功！', 'success');
    loadMessages();
  } catch {
    showToast('上傳失敗', 'error');
  }
}

/* ─── Messages ─────────────────────────────────────────────────────────────── */
async function loadMessages() {
  const list = document.getElementById('messages-list');
  try {
    const res = await fetch('/api/messages');
    const messages = await res.json();

    if (messages.length === 0) {
      list.innerHTML = '<div class="no-messages">還沒有留言，來第一個留言吧！</div>';
      return;
    }

    list.innerHTML = messages.map(renderMessage).join('');
  } catch {
    list.innerHTML = '<div class="no-messages">載入失敗，請重新整理頁面。</div>';
  }
}

function renderMessage(msg) {
  const avatar = msg.avatar_path || 'images/default-avatar.svg';
  const time = formatTime(msg.created_at);
  const canDelete = currentUser && currentUser.username === msg.username;
  const id = parseInt(msg.id, 10);

  return `
    <div class="message-item" id="msg-${id}">
      <img class="message-avatar" src="${escAttr(avatar)}" alt="${escAttr(msg.username)}"
           onerror="this.src='images/default-avatar.svg'" />
      <div class="message-body">
        <div class="message-header">
          <span class="message-username">${escHtml(msg.username)}</span>
          <span class="message-time">${time}</span>
          ${canDelete ? `<button class="message-delete" onclick="deleteMessage(${id})">刪除</button>` : ''}
        </div>
        <div class="message-content">${escHtml(msg.content)}</div>
      </div>
    </div>
  `;
}

async function postMessage() {
  const input = document.getElementById('message-input');
  const content = input.value.trim();
  if (!content) return;

  try {
    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ content }),
    });
    const data = await res.json();

    if (!res.ok) {
      showToast(data.error || '發送失敗', 'error');
      return;
    }

    input.value = '';
    document.getElementById('char-count').textContent = '0 / 1000';
    showToast('留言成功！', 'success');
    loadMessages();
  } catch {
    showToast('發送失敗', 'error');
  }
}

async function deleteMessage(id) {
  if (!confirm('確定要刪除這則留言嗎？')) return;

  try {
    const res = await fetch(`/api/messages/${id}`, {
      method: 'DELETE',
      headers: csrfHeaders(),
    });

    if (res.ok) {
      document.getElementById(`msg-${id}`)?.remove();
      showToast('留言已刪除', 'success');
      const list = document.getElementById('messages-list');
      if (list.children.length === 0) {
        list.innerHTML = '<div class="no-messages">還沒有留言，來第一個留言吧！</div>';
      }
    } else {
      const data = await res.json();
      showToast(data.error || '刪除失敗', 'error');
    }
  } catch {
    showToast('刪除失敗', 'error');
  }
}

/* ─── Modals ───────────────────────────────────────────────────────────────── */
function openModal(id) {
  document.getElementById(id)?.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeModal(id) {
  document.getElementById(id)?.classList.add('hidden');
  document.body.style.overflow = '';
  const modal = document.getElementById(id);
  if (modal) {
    modal.querySelectorAll('.form-error').forEach(el => {
      el.textContent = '';
      el.classList.add('hidden');
    });
  }
}

function closeModalOnOverlay(e, id) {
  if (e.target === e.currentTarget) closeModal(id);
}

function switchModal(from, to) {
  closeModal(from);
  openModal(to);
}

function showFormError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

/* ─── Toast ────────────────────────────────────────────────────────────────── */
let toastTimer;
function showToast(msg, type = 'success') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `toast toast-${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add('hidden'), 3000);
}

/* ─── AI Fortune Telling ───────────────────────────────────────────────────── */
async function getFortune() {
  const name    = document.getElementById('fortune-name').value.trim();
  const zodiac  = document.getElementById('fortune-zodiac').value;
  const recent  = document.getElementById('fortune-recent').value.trim();
  const resultEl = document.getElementById('fortune-result');
  const outputEl = document.getElementById('fortune-output');
  const errorEl  = document.getElementById('fortune-error');
  const btnText  = document.getElementById('fortune-btn-text');
  const btn      = document.querySelector('#ai-fortune .btn-primary');

  errorEl.classList.add('hidden');
  resultEl.classList.add('hidden');

  if (!name || !zodiac || !recent) {
    errorEl.textContent = '請填寫所有欄位';
    errorEl.classList.remove('hidden');
    return;
  }

  btnText.textContent = '占卜中…';
  btn.disabled = true;

  try {
    const res = await fetch('/api/ai/fortune', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, zodiac, recent }),
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || 'AI 占卜失敗';
      errorEl.classList.remove('hidden');
      return;
    }

    outputEl.textContent = data.fortune;
    resultEl.classList.remove('hidden');
    resultEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch {
    errorEl.textContent = '網路錯誤，請稍後再試';
    errorEl.classList.remove('hidden');
  } finally {
    btnText.textContent = '✦ 開始占卜';
    btn.disabled = false;
  }
}

/* ─── Utils ────────────────────────────────────────────────────────────────── */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escAttr(str) {
  return escHtml(str);
}

function formatTime(isoStr) {
  const date = new Date(isoStr.replace(' ', 'T') + 'Z');
  const now = new Date();
  const diff = (now - date) / 1000;

  if (diff < 60) return '剛剛';
  if (diff < 3600) return `${Math.floor(diff / 60)} 分鐘前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小時前`;

  return date.toLocaleDateString('zh-TW', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });
}
