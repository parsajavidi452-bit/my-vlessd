// worker.js
// VLESS-over-WebSocket proxy for Cloudflare Workers.
// Each user is identified by a UUID and stored in the "USERS" KV namespace as:
//   { "label": "...", "expiry": <ms epoch>, "quota": <bytes|0 for unlimited>, "used": <bytes> }
//
// Deployed automatically by cli.js — you normally don't need to edit this file.

import { connect } from 'cloudflare:sockets';

const FLUSH_THRESHOLD = 64 * 1024; // bytes buffered before writing usage back to KV

function uuidBytesToString(bytes, offset) {
  const hex = [];
  for (let i = 0; i < 16; i++) {
    hex.push(bytes[offset + i].toString(16).padStart(2, '0'));
  }
  return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
}

function parseVlessHeader(arrayBuffer) {
  const view = new Uint8Array(arrayBuffer);
  if (view.length < 24) return null;

  let offset = 0;
  const version = view[offset]; offset += 1;
  const uuid = uuidBytesToString(view, offset); offset += 16;

  const addonLen = view[offset]; offset += 1;
  offset += addonLen; // addons are not used, skip them

  offset += 1; // command byte (1=tcp, 2=udp) — this build only proxies TCP

  const port = (view[offset] << 8) | view[offset + 1]; offset += 2;

  const addrType = view[offset]; offset += 1;
  let address = '';

  if (addrType === 1) {
    address = view.slice(offset, offset + 4).join('.');
    offset += 4;
  } else if (addrType === 2) {
    const len = view[offset]; offset += 1;
    address = new TextDecoder().decode(view.slice(offset, offset + len));
    offset += len;
  } else if (addrType === 3) {
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((view[offset + i * 2] << 8) | view[offset + i * 2 + 1]).toString(16));
    }
    address = parts.join(':');
    offset += 16;
  } else {
    return null;
  }

  const initialPayload = view.slice(offset);
  return { version, uuid, port, address, initialPayload };
}

async function loadUser(env, uuid) {
  const raw = await env.USERS.get(uuid);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function saveUsage(env, uuid, record) {
  try {
    await env.USERS.put(uuid, JSON.stringify(record));
  } catch {
    // KV write failed (e.g. free-tier daily write limit) — usage tracking
    // for this flush is lost, but the connection keeps working.
  }
}

function buildVlessLink({ uuid, host, label }) {
  const params = new URLSearchParams({ type: 'ws', security: 'tls', sni: host, host, path: '/' });
  return `vless://${uuid}@${host}:443?${params.toString()}#${encodeURIComponent(label || 'user')}`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

const ADMIN_KEY = '__admin_password_hash__';

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function checkAdminAuth(request, env) {
  const hash = await env.USERS.get(ADMIN_KEY);
  if (!hash) return false;
  const password = request.headers.get('X-Admin-Password') || '';
  return (await sha256Hex(password)) === hash;
}

async function handleAdminApi(request, env, url) {
  if (url.pathname === '/admin/api/status' && request.method === 'GET') {
    const hash = await env.USERS.get(ADMIN_KEY);
    return json({ ok: true, needsSetup: !hash });
  }

  if (url.pathname === '/admin/api/setup' && request.method === 'POST') {
    const existing = await env.USERS.get(ADMIN_KEY);
    if (existing) return json({ ok: false, error: 'قبلاً یه رمز ادمین ست شده' }, 400);
    const body = await request.json().catch(() => ({}));
    const password = (body.password || '').toString();
    if (password.length < 6) return json({ ok: false, error: 'رمز باید حداقل ۶ کاراکتر باشه' }, 400);
    await env.USERS.put(ADMIN_KEY, await sha256Hex(password));
    return json({ ok: true });
  }

  if (url.pathname === '/admin/api/login' && request.method === 'POST') {
    const hash = await env.USERS.get(ADMIN_KEY);
    const body = await request.json().catch(() => ({}));
    if (hash && (await sha256Hex(body.password || '')) === hash) return json({ ok: true });
    return json({ ok: false, error: 'رمز اشتباهه' }, 401);
  }

  if (!(await checkAdminAuth(request, env))) return json({ ok: false, error: 'نیاز به ورود مجدد' }, 401);

  if (url.pathname === '/admin/api/users' && request.method === 'GET') {
    const list = await env.USERS.list();
    const users = [];
    for (const k of list.keys) {
      if (k.name === ADMIN_KEY) continue;
      const raw = await env.USERS.get(k.name);
      if (!raw) continue;
      const record = JSON.parse(raw);
      users.push({ uuid: k.name, ...record, link: buildVlessLink({ uuid: k.name, host: url.host, label: record.label }) });
    }
    users.sort((a, b) => (b.created || 0) - (a.created || 0));
    return json({ ok: true, users });
  }

  if (url.pathname === '/admin/api/users' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const days = Number(body.days) > 0 ? Number(body.days) : 30;
    const quotaGb = Number(body.quotaGb) > 0 ? Number(body.quotaGb) : 0;
    const label = (body.label || 'user').toString().slice(0, 60);

    const uuid = crypto.randomUUID();
    const record = {
      label,
      expiry: Date.now() + days * 24 * 60 * 60 * 1000,
      quota: quotaGb > 0 ? Math.round(quotaGb * 1024 * 1024 * 1024) : 0,
      used: 0,
      created: Date.now(),
    };
    await env.USERS.put(uuid, JSON.stringify(record));
    return json({ ok: true, uuid, ...record, link: buildVlessLink({ uuid, host: url.host, label }) });
  }

  const delMatch = url.pathname.match(/^\/admin\/api\/users\/([0-9a-fA-F-]{36})$/);
  if (delMatch && request.method === 'DELETE') {
    await env.USERS.delete(delMatch[1]);
    return json({ ok: true });
  }

  return json({ ok: false, error: 'not found' }, 404);
}

function adminPage() {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل کانفیگ VLESS</title>
<style>
  :root {
    --bg: #0b1210;
    --panel: #101a17;
    --line: #1e2b27;
    --text: #dce8e3;
    --muted: #7c968d;
    --accent: #35d0a0;
    --accent-dim: #1c6b52;
    --danger: #e0645a;
    --mono: 'SFMono-Regular', Consolas, 'Courier New', monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, 'Segoe UI', Tahoma, sans-serif;
    min-height: 100vh; padding: 20px 14px 60px;
  }
  .wrap { max-width: 620px; margin: 0 auto; }
  h1 { font-size: 19px; font-weight: 700; letter-spacing: .2px; margin: 6px 0 2px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 22px; }
  .card {
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    padding: 18px; margin-bottom: 16px;
  }
  label { display: block; font-size: 12px; color: var(--muted); margin: 12px 0 5px; }
  input {
    width: 100%; background: #0c1613; border: 1px solid var(--line); color: var(--text);
    border-radius: 6px; padding: 10px 11px; font-size: 14px; font-family: inherit;
  }
  input:focus { outline: none; border-color: var(--accent-dim); }
  button {
    background: var(--accent); color: #06110d; border: none; border-radius: 6px;
    padding: 11px 16px; font-size: 14px; font-weight: 700; cursor: pointer; width: 100%;
    margin-top: 14px;
  }
  button:active { opacity: .85; }
  button.secondary { background: transparent; border: 1px solid var(--line); color: var(--text); font-weight: 600; }
  button.danger { background: transparent; border: 1px solid var(--danger); color: var(--danger); width: auto; padding: 6px 10px; font-size: 12px; margin-top: 0; }
  .row { display: flex; gap: 10px; }
  .row > div { flex: 1; }
  .msg { font-size: 12.5px; margin-top: 10px; color: var(--danger); min-height: 1em; }
  .user {
    border: 1px solid var(--line); border-radius: 8px; padding: 12px; margin-top: 10px;
    background: #0c1613;
  }
  .user-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  .user-label { font-weight: 700; font-size: 14px; }
  .user-meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .link-box {
    margin-top: 8px; font-family: var(--mono); font-size: 11px; word-break: break-all;
    background: #08110f; border: 1px solid var(--line); border-radius: 6px; padding: 8px;
    color: var(--accent); cursor: pointer;
  }
  .empty { color: var(--muted); font-size: 13px; text-align: center; padding: 20px 0; }
  .bar { height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; margin-top: 8px; }
  .bar > div { height: 100%; background: var(--accent); }
  #app-setup, #app-login, #app-panel { display: none; }
</style>
</head>
<body>
<div class="wrap">
  <h1>پنل کانفیگ VLESS</h1>
  <div class="sub">ساخت کاربر با تاریخ انقضا و سقف حجم مشخص</div>

  <div id="app-setup" class="card">
    <div class="sub" style="margin-bottom:10px">اولین بازدیده — یه رمز ادمین برای خودت بساز</div>
    <label>رمز ادمین جدید (حداقل ۶ کاراکتر)</label>
    <input id="setup-pw" type="password" placeholder="یه رمز قوی انتخاب کن">
    <button onclick="doSetup()">ساخت رمز و ورود</button>
    <div class="msg" id="setup-msg"></div>
  </div>

  <div id="app-login" class="card">
    <label>رمز ادمین</label>
    <input id="pw" type="password" placeholder="رمزی که خودت ساختی">
    <button onclick="login()">ورود</button>
    <div class="msg" id="login-msg"></div>
  </div>

  <div id="app-panel">
    <div class="card">
      <label>برچسب (اسم کاربر)</label>
      <input id="f-label" placeholder="مثلاً: گوشی من">
      <div class="row">
        <div>
          <label>مدت اعتبار (روز)</label>
          <input id="f-days" type="number" value="30" min="1">
        </div>
        <div>
          <label>سقف حجم (گیگابایت، ۰ = نامحدود)</label>
          <input id="f-quota" type="number" value="50" min="0">
        </div>
      </div>
      <button onclick="createUser()">ساخت کاربر</button>
      <div class="msg" id="create-msg"></div>
    </div>

    <div class="card">
      <div class="sub" style="margin-bottom:8px">کاربرها</div>
      <div id="users"></div>
    </div>
  </div>
</div>

<script>
  function authHeader() {
    return { 'X-Admin-Password': localStorage.getItem('adminPassword') || '' };
  }

  function show(id) {
    ['app-setup', 'app-login', 'app-panel'].forEach(x => {
      document.getElementById(x).style.display = x === id ? 'block' : 'none';
    });
  }

  async function doSetup() {
    const pw = document.getElementById('setup-pw').value;
    const res = await fetch('/admin/api/setup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw })
    });
    const data = await res.json();
    if (data.ok) {
      localStorage.setItem('adminPassword', pw);
      show('app-panel');
      loadUsers();
    } else {
      document.getElementById('setup-msg').textContent = data.error || 'خطا';
    }
  }

  async function login() {
    const pw = document.getElementById('pw').value;
    const res = await fetch('/admin/api/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw })
    });
    const data = await res.json();
    if (data.ok) {
      localStorage.setItem('adminPassword', pw);
      show('app-panel');
      loadUsers();
    } else {
      document.getElementById('login-msg').textContent = data.error || 'خطا';
    }
  }

  function fmtDate(ms) { return new Date(ms).toLocaleDateString('fa-IR') + ' ' + new Date(ms).toLocaleTimeString('fa-IR', {hour:'2-digit', minute:'2-digit'}); }
  function fmtGb(bytes) { return (bytes / 1024 / 1024 / 1024).toFixed(2); }

  async function loadUsers() {
    const res = await fetch('/admin/api/users', { headers: authHeader() });
    if (res.status === 401) { logout(); return; }
    const data = await res.json();
    const el = document.getElementById('users');
    if (!data.users.length) { el.innerHTML = '<div class="empty">هنوز کاربری نساختی</div>'; return; }
    el.innerHTML = data.users.map(u => {
      const pct = u.quota ? Math.min(100, (u.used / u.quota) * 100) : 0;
      const expired = u.expiry < Date.now();
      return \`<div class="user">
        <div class="user-top">
          <div>
            <div class="user-label">\${u.label}</div>
            <div class="user-meta">\${expired ? '⛔ منقضی شده' : 'تا ' + fmtDate(u.expiry)} · \${fmtGb(u.used)} / \${u.quota ? fmtGb(u.quota) + ' GB' : 'نامحدود'}</div>
          </div>
          <button class="danger" onclick="delUser('\${u.uuid}')">حذف</button>
        </div>
        \${u.quota ? '<div class="bar"><div style="width:' + pct + '%"></div></div>' : ''}
        <div class="link-box" onclick="copyLink(this)">\${u.link}</div>
      </div>\`;
    }).join('');
  }

  function copyLink(el) {
    navigator.clipboard.writeText(el.textContent).then(() => {
      const orig = el.style.color;
      el.style.color = '#fff';
      setTimeout(() => { el.style.color = orig; }, 300);
    });
  }

  async function createUser() {
    const label = document.getElementById('f-label').value || 'user';
    const days = document.getElementById('f-days').value;
    const quotaGb = document.getElementById('f-quota').value;
    const res = await fetch('/admin/api/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ label, days, quotaGb })
    });
    const data = await res.json();
    if (!data.ok) { document.getElementById('create-msg').textContent = data.error || 'خطا'; return; }
    document.getElementById('f-label').value = '';
    document.getElementById('create-msg').textContent = '';
    loadUsers();
  }

  async function delUser(uuid) {
    await fetch('/admin/api/users/' + uuid, { method: 'DELETE', headers: authHeader() });
    loadUsers();
  }

  function logout() {
    localStorage.removeItem('adminPassword');
    show('app-login');
  }

  (async function boot() {
    const statusRes = await fetch('/admin/api/status');
    const status = await statusRes.json();

    if (status.needsSetup) { show('app-setup'); return; }

    const stored = localStorage.getItem('adminPassword');
    if (stored) {
      const res = await fetch('/admin/api/users', { headers: { 'X-Admin-Password': stored } });
      if (res.ok) { show('app-panel'); loadUsers(); return; }
    }
    show('app-login');
  })();
</script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/admin') {
      return new Response(adminPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (url.pathname.startsWith('/admin/api/')) {
      return handleAdminApi(request, env, url);
    }

    const upgrade = request.headers.get('Upgrade');
    if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
      // Anyone browsing to the worker's URL directly just sees a plain page.
      return new Response('Not found', { status: 404 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    let remoteSocket = null;
    let userUuid = null;
    let userRecord = null;
    let pendingUsage = 0;
    let headerParsed = false;

    const closeAll = () => {
      try { server.close(); } catch {}
      try { remoteSocket && remoteSocket.close(); } catch {}
    };

    const flushUsage = async () => {
      if (pendingUsage > 0 && userUuid && userRecord) {
        userRecord.used = (userRecord.used || 0) + pendingUsage;
        pendingUsage = 0;
        await saveUsage(env, userUuid, userRecord);
      }
    };

    server.addEventListener('message', async (event) => {
      try {
        const data = event.data;
        const buf = typeof data === 'string'
          ? new TextEncoder().encode(data).buffer
          : data;

        if (!headerParsed) {
          const parsed = parseVlessHeader(buf);
          if (!parsed) { closeAll(); return; }

          userUuid = parsed.uuid;
          userRecord = await loadUser(env, userUuid);
          const now = Date.now();

          if (!userRecord) { closeAll(); return; }
          if (userRecord.expiry && now > userRecord.expiry) { closeAll(); return; }
          if (userRecord.quota && (userRecord.used || 0) >= userRecord.quota) { closeAll(); return; }

          headerParsed = true;
          remoteSocket = connect({ hostname: parsed.address, port: parsed.port });

          const writer = remoteSocket.writable.getWriter();
          if (parsed.initialPayload.length > 0) {
            await writer.write(parsed.initialPayload);
            pendingUsage += parsed.initialPayload.length;
          }
          writer.releaseLock();

          // VLESS response header: version byte + zero addons
          server.send(new Uint8Array([parsed.version, 0x00]));

          const reader = remoteSocket.readable.getReader();
          (async () => {
            try {
              while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                server.send(value);
                pendingUsage += value.byteLength;
                if (pendingUsage >= FLUSH_THRESHOLD) {
                  await flushUsage();
                  if (userRecord.quota && userRecord.used >= userRecord.quota) { closeAll(); return; }
                }
              }
            } catch {
              // remote connection dropped
            } finally {
              await flushUsage();
              closeAll();
            }
          })();
          return;
        }

        if (remoteSocket) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(buf);
          writer.releaseLock();
          pendingUsage += buf.byteLength;
          if (pendingUsage >= FLUSH_THRESHOLD) {
            await flushUsage();
            if (userRecord.quota && userRecord.used >= userRecord.quota) { closeAll(); return; }
          }
        }
      } catch {
        closeAll();
      }
    });

    server.addEventListener('close', async () => {
      await flushUsage();
      closeAll();
    });

    server.addEventListener('error', async () => {
      await flushUsage();
      closeAll();
    });

    return new Response(null, { status: 101, webSocket: client });
  },
};
