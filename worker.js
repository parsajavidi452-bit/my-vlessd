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

const CONNECT_IPS = [
  { value: '', label: 'خودکار (دامنه، پیشنهادی)' },
  { value: '104.16.0.1', label: 'آی‌پی ثابت کلادفلر — ۱' },
  { value: '172.64.0.1', label: 'آی‌پی ثابت کلادفلر — ۲' },
  { value: '162.158.0.1', label: 'آی‌پی ثابت کلادفلر — ۳' },
  { value: '1.1.1.1', label: 'آی‌پی ثابت کلادفلر — ۴ (1.1.1.1)' },
];

function buildVlessLink({ uuid, host, label, connectIp }) {
  const address = connectIp || host;
  const params = new URLSearchParams({ type: 'ws', security: 'tls', sni: host, host, path: '/' });
  return `vless://${uuid}@${address}:443?${params.toString()}#${encodeURIComponent(label || 'user')}`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
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

  if (url.pathname === '/admin/api/ip-options' && request.method === 'GET') {
    return json({ ok: true, options: CONNECT_IPS });
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
      users.push({ uuid: k.name, ...record, link: buildVlessLink({ uuid: k.name, host: url.host, label: record.label, connectIp: record.connectIp }) });
    }
    users.sort((a, b) => (b.created || 0) - (a.created || 0));
    return json({ ok: true, users });
  }

  if (url.pathname === '/admin/api/users' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const days = Number(body.days) > 0 ? Number(body.days) : 30;
    const quotaGb = Number(body.quotaGb) > 0 ? Number(body.quotaGb) : 0;
    const label = (body.label || 'user').toString().slice(0, 60);
    const connectIp = CONNECT_IPS.some(o => o.value === body.connectIp) ? body.connectIp : '';

    const uuid = crypto.randomUUID();
    const record = {
      label,
      expiry: Date.now() + days * 24 * 60 * 60 * 1000,
      quota: quotaGb > 0 ? Math.round(quotaGb * 1024 * 1024 * 1024) : 0,
      used: 0,
      created: Date.now(),
      connectIp,
    };
    await env.USERS.put(uuid, JSON.stringify(record));
    return json({ ok: true, uuid, ...record, link: buildVlessLink({ uuid, host: url.host, label, connectIp }) });
  }

  const delMatch = url.pathname.match(/^\/admin\/api\/users\/([0-9a-fA-F-]{36})$/);
  if (delMatch && request.method === 'DELETE') {
    await env.USERS.delete(delMatch[1]);
    return json({ ok: true });
  }

  if (delMatch && request.method === 'PATCH') {
    const uuid = delMatch[1];
    const raw = await env.USERS.get(uuid);
    if (!raw) return json({ ok: false, error: 'کاربر پیدا نشد' }, 404);
    const record = JSON.parse(raw);
    const body = await request.json().catch(() => ({}));

    if (body.label) record.label = body.label.toString().slice(0, 60);
    if (Number(body.days) > 0) record.expiry = Date.now() + Number(body.days) * 24 * 60 * 60 * 1000;
    if (body.quotaGb !== undefined) {
      const q = Number(body.quotaGb);
      record.quota = q > 0 ? Math.round(q * 1024 * 1024 * 1024) : 0;
    }
    if (body.resetUsage) record.used = 0;
    if (CONNECT_IPS.some(o => o.value === body.connectIp)) record.connectIp = body.connectIp;

    await env.USERS.put(uuid, JSON.stringify(record));
    return json({ ok: true, uuid, ...record, link: buildVlessLink({ uuid, host: url.host, label: record.label, connectIp: record.connectIp }) });
  }

  return json({ ok: false, error: 'not found' }, 404);
}

function icon(name) {
  const icons = {
    plus: '<path d="M12 5v14M5 12h14"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    clock: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    database: '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
    lock: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
    edit: '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM19 14h2v2h-2zM14 19h2v2h-2zM19 19h2v2h-2z"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${icons[name] || ''}</svg>`;
}

function adminPage() {
  const BUILD_TAG = 'v5';
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل VLESS</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap');

  :root {
    --bg: #080e14;
    --bg2: #0c141c;
    --panel: #101b26;
    --panel2: #0d1720;
    --line: #1c2b38;
    --text: #e7eef4;
    --muted: #7189a0;
    --accent: #22d3ee;
    --accent2: #818cf8;
    --good: #34d399;
    --warn: #fbbf24;
    --bad: #fb7185;
    --radius: 16px;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background:
      radial-gradient(1100px 500px at 15% -10%, rgba(34,211,238,.15), transparent 60%),
      radial-gradient(900px 500px at 100% 0%, rgba(129,140,248,.14), transparent 55%),
      var(--bg);
    color: var(--text);
    font-family: 'Vazirmatn', -apple-system, 'Segoe UI', Tahoma, sans-serif;
    min-height: 100vh;
    padding: 22px 14px 70px;
  }
  .wrap { max-width: 640px; margin: 0 auto; }

  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .brand .mark {
    width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    box-shadow: 0 6px 20px -4px rgba(34,211,238,.5);
    color: #06131a;
  }
  .brand .mark svg { width: 18px; height: 18px; }
  h1 { font-size: 20px; font-weight: 800; margin: 0; letter-spacing: -.2px; }
  .sub { color: var(--muted); font-size: 13px; margin: 4px 0 22px 44px; }

  .card {
    background: linear-gradient(180deg, var(--panel), var(--panel2));
    border: 1px solid var(--line); border-radius: var(--radius);
    padding: 20px; margin-bottom: 14px;
    box-shadow: 0 10px 30px -18px rgba(0,0,0,.6);
  }
  .card-title { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 14px; margin-bottom: 4px; }
  .card-title svg { width: 16px; height: 16px; color: var(--accent); }

  label { display: block; font-size: 12px; color: var(--muted); margin: 14px 0 6px; font-weight: 500; }
  input, select {
    width: 100%; background: #08121a; border: 1px solid var(--line); color: var(--text);
    border-radius: 10px; padding: 12px 13px; font-size: 14.5px; font-family: inherit;
    transition: border-color .15s;
    appearance: none; -webkit-appearance: none;
  }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  select {
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%237189a0' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
    background-repeat: no-repeat; background-position: left 12px center; background-size: 16px;
    padding-left: 34px;
  }

  button {
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #061019; border: none; border-radius: 10px;
    padding: 13px 16px; font-size: 14.5px; font-weight: 700; cursor: pointer; width: 100%;
    margin-top: 16px; display: flex; align-items: center; justify-content: center; gap: 7px;
    transition: transform .1s, opacity .1s;
  }
  button svg { width: 16px; height: 16px; }
  button:active { transform: scale(.98); opacity: .92; }
  button.ghost {
    background: transparent; border: 1px solid var(--line); color: var(--text);
    font-weight: 600; margin-top: 0;
  }
  button.icon-btn {
    width: 34px; height: 34px; padding: 0; margin-top: 0; border-radius: 9px;
    background: rgba(251,113,133,.12); color: var(--bad); border: 1px solid rgba(251,113,133,.25);
    flex-shrink: 0;
  }
  button.icon-btn svg { width: 15px; height: 15px; }

  .row { display: flex; gap: 10px; }
  .row > div { flex: 1; }
  .msg { font-size: 12.5px; margin-top: 10px; color: var(--bad); min-height: 1em; }
  .hint { font-size: 11.5px; color: var(--muted); margin-top: 6px; line-height: 1.6; }

  .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 14px; }
  .stat {
    background: linear-gradient(180deg, var(--panel), var(--panel2));
    border: 1px solid var(--line); border-radius: 14px; padding: 14px 12px; text-align: center;
  }
  .stat svg { width: 16px; height: 16px; color: var(--accent); margin-bottom: 6px; }
  .stat .num { font-size: 19px; font-weight: 800; }
  .stat .lbl { font-size: 10.5px; color: var(--muted); margin-top: 2px; }

  .user {
    border: 1px solid var(--line); border-radius: 14px; padding: 14px; margin-top: 10px;
    background: var(--panel2);
  }
  .user-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; }
  .user-label { font-weight: 700; font-size: 14.5px; }
  .badge {
    display: inline-block; font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 20px;
    margin-right: 6px; vertical-align: middle;
  }
  .badge.on { background: rgba(52,211,153,.15); color: var(--good); }
  .badge.off { background: rgba(251,113,133,.15); color: var(--bad); }
  .user-meta { color: var(--muted); font-size: 12px; margin-top: 5px; display: flex; gap: 12px; flex-wrap: wrap; }
  .user-meta span { display: inline-flex; align-items: center; gap: 4px; }
  .user-meta svg { width: 12px; height: 12px; }

  .bar { height: 7px; background: #08121a; border-radius: 4px; overflow: hidden; margin-top: 10px; border: 1px solid var(--line); }
  .bar > div { height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent2)); border-radius: 4px; transition: width .3s; }

  .link-box {
    margin-top: 10px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 10.5px; word-break: break-all;
    background: #08121a; border: 1px dashed var(--line); border-radius: 10px; padding: 10px 12px;
    color: var(--accent); cursor: pointer; display: flex; align-items: center; gap: 8px;
  }
  .link-box svg { width: 13px; height: 13px; flex-shrink: 0; color: var(--muted); }
  .link-box.copied { border-color: var(--good); color: var(--good); }

  .empty { color: var(--muted); font-size: 13px; text-align: center; padding: 30px 0; }
  .empty svg { width: 28px; height: 28px; margin-bottom: 8px; opacity: .5; }

  .toast {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%) translateY(20px);
    background: var(--panel); border: 1px solid var(--line); color: var(--text);
    padding: 11px 18px; border-radius: 10px; font-size: 13px; font-weight: 600;
    opacity: 0; transition: all .25s; pointer-events: none; z-index: 50;
    box-shadow: 0 10px 30px -10px rgba(0,0,0,.7);
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .toast.good { border-color: rgba(52,211,153,.4); }
  .toast.bad { border-color: rgba(251,113,133,.4); }

  .top-actions { display: flex; justify-content: flex-end; margin-bottom: 10px; }
  .top-actions button { width: auto; padding: 8px 14px; font-size: 12.5px; }

  .user-actions { display: flex; gap: 6px; flex-shrink: 0; }
  button.icon-btn.neutral { background: rgba(129,140,248,.12); color: var(--accent2); border-color: rgba(129,140,248,.25); }

  .edit-panel {
    margin-top: 10px; padding-top: 10px; border-top: 1px dashed var(--line);
    display: none;
  }
  .edit-panel.open { display: block; }
  .edit-panel label { margin: 8px 0 5px; }
  .edit-panel .row { margin-bottom: 0; }
  .edit-panel .checkbox-row { display: flex; align-items: center; gap: 7px; margin-top: 10px; font-size: 12.5px; color: var(--muted); }
  .edit-panel .checkbox-row input { width: auto; }
  .edit-panel button { font-size: 12.5px; padding: 9px; }

  .qr-wrap { display: none; margin-top: 10px; text-align: center; }
  .qr-wrap.open { display: block; }
  .qr-wrap img { width: 160px; height: 160px; border-radius: 10px; background: #fff; padding: 8px; }

  .version-footer { text-align: center; color: var(--muted); font-size: 10.5px; margin-top: 20px; opacity: .6; }

  #app-setup, #app-login, #app-panel { display: none; animation: fadeIn .25s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <div class="mark">${icon('zap')}</div>
    <h1>پنل VLESS</h1>
  </div>
  <div class="sub">ساخت و مدیریت کاربر با انقضا و سقف حجم</div>

  <div id="app-setup" class="card">
    <div class="card-title">${icon('lock')} اولین ورود</div>
    <div class="hint">یه رمز برای خودت بساز تا فقط خودت به این پنل دسترسی داشته باشی.</div>
    <label>رمز ادمین جدید (حداقل ۶ کاراکتر)</label>
    <input id="setup-pw" type="password" placeholder="یه رمز قوی انتخاب کن">
    <button onclick="doSetup()">${icon('check')} ساخت رمز و ورود</button>
    <div class="msg" id="setup-msg"></div>
  </div>

  <div id="app-login" class="card">
    <div class="card-title">${icon('lock')} ورود</div>
    <label>رمز ادمین</label>
    <input id="pw" type="password" placeholder="رمزی که خودت ساختی">
    <button onclick="login()">${icon('check')} ورود</button>
    <div class="msg" id="login-msg"></div>
  </div>

  <div id="app-panel">
    <div class="top-actions">
      <button class="ghost" onclick="logout()">${icon('logout')} خروج</button>
    </div>

    <div class="stats">
      <div class="stat">${icon('users')}<div class="num" id="st-total">0</div><div class="lbl">کل کاربر</div></div>
      <div class="stat">${icon('check')}<div class="num" id="st-active">0</div><div class="lbl">فعال</div></div>
      <div class="stat">${icon('database')}<div class="num" id="st-traffic">0</div><div class="lbl">گیگ مصرفی</div></div>
    </div>

    <div class="card">
      <div class="card-title">${icon('plus')} ساخت کاربر جدید</div>
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
      <label>آی‌پی اتصال</label>
      <select id="f-ip"></select>
      <div class="hint">این فقط نقطه‌ی اتصال ظاهریه؛ مسیر واقعی ترافیک همیشه از شبکه‌ی خود کلادفلر می‌گذره — گزینه‌ی «خودکار» برای اکثر کاربرا بهترین انتخابه.</div>
      <button onclick="createUser()">${icon('plus')} ساخت کاربر</button>
      <div class="msg" id="create-msg"></div>
    </div>

    <div class="card">
      <div class="card-title">${icon('users')} کاربرها</div>
      <div id="users"></div>
    </div>

    <div class="version-footer">build ${BUILD_TAG}</div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
  function authHeader() {
    return { 'X-Admin-Password': localStorage.getItem('adminPassword') || '' };
  }

  function show(id) {
    ['app-setup', 'app-login', 'app-panel'].forEach(x => {
      document.getElementById(x).style.display = x === id ? 'block' : 'none';
    });
  }

  function toast(msg, kind) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast show' + (kind ? ' ' + kind : '');
    clearTimeout(window.__toastTimer);
    window.__toastTimer = setTimeout(() => { el.className = 'toast'; }, 2200);
  }

  async function loadIpOptions() {
    const res = await fetch('/admin/api/ip-options');
    const data = await res.json();
    const sel = document.getElementById('f-ip');
    sel.innerHTML = data.options.map(o => \`<option value="\${o.value}">\${o.label}</option>\`).join('');
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
      loadIpOptions();
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
      loadIpOptions();
      loadUsers();
    } else {
      document.getElementById('login-msg').textContent = data.error || 'خطا';
    }
  }

  function fmtDate(ms) {
    return new Date(ms).toLocaleDateString('fa-IR') + ' ' + new Date(ms).toLocaleTimeString('fa-IR', {hour:'2-digit', minute:'2-digit'});
  }
  function fmtGb(bytes) { return (bytes / 1024 / 1024 / 1024).toFixed(2); }

  async function loadUsers() {
    const res = await fetch('/admin/api/users', { headers: authHeader() });
    if (res.status === 401) { logout(); return; }
    const data = await res.json();
    const el = document.getElementById('users');

    document.getElementById('st-total').textContent = data.users.length;
    document.getElementById('st-active').textContent = data.users.filter(u => u.expiry > Date.now()).length;
    document.getElementById('st-traffic').textContent = data.users.reduce((s, u) => s + (u.used || 0), 0) / 1024 / 1024 / 1024 | 0;

    if (!data.users.length) {
      el.innerHTML = \`<div class="empty">\${icon2('users')}<div>هنوز کاربری نساختی</div></div>\`;
      return;
    }

    el.innerHTML = data.users.map(u => {
      const pct = u.quota ? Math.min(100, (u.used / u.quota) * 100) : 0;
      const expired = u.expiry < Date.now();
      const daysLeft = Math.max(0, Math.ceil((u.expiry - Date.now()) / 86400000));
      return \`<div class="user" data-uuid="\${u.uuid}">
        <div class="user-top">
          <div>
            <div class="user-label">
              <span class="badge \${expired ? 'off' : 'on'}">\${expired ? 'منقضی' : 'فعال'}</span>
              \${u.label}
            </div>
            <div class="user-meta">
              <span>${icon('clock')} تا \${fmtDate(u.expiry)}</span>
              <span>${icon('database')} \${fmtGb(u.used)} / \${u.quota ? fmtGb(u.quota) + ' GB' : 'نامحدود'}</span>
            </div>
          </div>
          <div class="user-actions">
            <button class="icon-btn neutral" onclick="toggleQr(this)">${icon('qr')}</button>
            <button class="icon-btn neutral" onclick="toggleEdit(this)">${icon('edit')}</button>
            <button class="icon-btn" onclick="delUser('\${u.uuid}')">${icon('trash')}</button>
          </div>
        </div>
        \${u.quota ? '<div class="bar"><div style="width:' + pct + '%"></div></div>' : ''}
        <div class="link-box" onclick="copyLink(this)">${icon('copy')}<span>\${u.link}</span></div>

        <div class="qr-wrap"><img loading="lazy" src="https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=\${encodeURIComponent(u.link)}" alt="QR"></div>

        <div class="edit-panel">
          <label>برچسب</label>
          <input class="e-label" value="\${u.label}">
          <div class="row">
            <div>
              <label>تمدید به مدت (روز، از الان)</label>
              <input class="e-days" type="number" placeholder="\${daysLeft}" min="1">
            </div>
            <div>
              <label>سقف حجم جدید (GB، ۰=نامحدود)</label>
              <input class="e-quota" type="number" value="\${u.quota ? (u.quota / 1024 / 1024 / 1024).toFixed(0) : 0}" min="0">
            </div>
          </div>
          <div class="checkbox-row">
            <input type="checkbox" class="e-reset" id="reset-\${u.uuid}">
            <label for="reset-\${u.uuid}" style="margin:0">ریست مصرف به صفر</label>
          </div>
          <button onclick="saveEdit(this, '\${u.uuid}')">${icon('check')} ذخیره تغییرات</button>
        </div>
      </div>\`;
    }).join('');
  }

  function toggleQr(btn) {
    const wrap = btn.closest('.user').querySelector('.qr-wrap');
    wrap.classList.toggle('open');
  }

  function toggleEdit(btn) {
    const panel = btn.closest('.user').querySelector('.edit-panel');
    panel.classList.toggle('open');
  }

  async function saveEdit(btn, uuid) {
    const card = btn.closest('.user');
    const label = card.querySelector('.e-label').value;
    const days = card.querySelector('.e-days').value;
    const quotaGb = card.querySelector('.e-quota').value;
    const resetUsage = card.querySelector('.e-reset').checked;

    const res = await fetch('/admin/api/users/' + uuid, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ label, days, quotaGb, resetUsage })
    });
    const data = await res.json();
    if (!data.ok) { toast(data.error || 'خطا', 'bad'); return; }
    toast('تغییرات ذخیره شد', 'good');
    loadUsers();
  }

  function icon2() {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg>';
  }

  function copyLink(el) {
    const text = el.querySelector('span').textContent;
    navigator.clipboard.writeText(text).then(() => {
      el.classList.add('copied');
      toast('لینک کپی شد', 'good');
      setTimeout(() => el.classList.remove('copied'), 900);
    });
  }

  async function createUser() {
    const label = document.getElementById('f-label').value || 'user';
    const days = document.getElementById('f-days').value;
    const quotaGb = document.getElementById('f-quota').value;
    const connectIp = document.getElementById('f-ip').value;
    const res = await fetch('/admin/api/users', {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...authHeader() },
      body: JSON.stringify({ label, days, quotaGb, connectIp })
    });
    const data = await res.json();
    if (!data.ok) { document.getElementById('create-msg').textContent = data.error || 'خطا'; return; }
    document.getElementById('f-label').value = '';
    document.getElementById('create-msg').textContent = '';
    toast('کاربر ساخته شد', 'good');
    loadUsers();
  }

  async function delUser(uuid) {
    await fetch('/admin/api/users/' + uuid, { method: 'DELETE', headers: authHeader() });
    toast('کاربر حذف شد', 'bad');
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
      if (res.ok) {
        show('app-panel');
        loadIpOptions();
        loadUsers();
        return;
      }
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
      return new Response(adminPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, must-revalidate' },
      });
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
