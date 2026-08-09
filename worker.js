/**
 * Leviko Panel — Cloudflare Worker
 * VLESS over WebSocket · D1 user management · Admin dashboard
 * Original source — not derived from Nahan / Zeus / TrexBridge
 */

import { connect } from "cloudflare:sockets";

const LV = {
  VERSION: "1.0.0",
  PANEL_PATH: "/leviko",
  SUB_PATH: "/sub",
  WS_PATH: "/lv",
  BINDING: "DB",
};

/* ───────────────── helpers ───────────────── */
const enc = new TextEncoder();
const dec = new TextDecoder();

function uuid() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function parseUUID(buf) {
  if (buf.byteLength < 17) return null;
  const u = new Uint8Array(buf);
  if (u[0] !== 0) return null;
  const h = [...u.slice(1, 17)].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extra },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

/* ───────────────── database ───────────────── */
const Schema = {
  async ensure(db) {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        uuid TEXT UNIQUE NOT NULL,
        limit_gb REAL DEFAULT 0,
        used_gb REAL DEFAULT 0,
        expiry_days INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        is_active INTEGER DEFAULT 1,
        remark TEXT DEFAULT '',
        last_active INTEGER DEFAULT 0
      )`),
    ]);
  },

  async getSetting(db, key) {
    const row = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
    return row ? row.value : null;
  },

  async setSetting(db, key, value) {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(key, value).run();
  },
};

/* ───────────────── auth ───────────────── */
async function checkSession(request, db) {
  const hash = await Schema.getSetting(db, "panel_pass");
  if (!hash) return { needSetup: true };
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/lv_session=([^;]+)/);
  if (!m) return { ok: false };
  const expected = await sha256(hash + "|leviko");
  return { ok: m[1] === expected };
}

function sessionCookie(token) {
  return `lv_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`;
}

/* ───────────────── VLESS proxy core ───────────────── */
async function handleVless(request, env) {
  const upgrade = request.headers.get("Upgrade");
  if (upgrade !== "websocket") {
    return new Response("Expected WebSocket", { status: 426 });
  }

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  let remote = null;
  let userUuid = null;
  let username = null;
  let earlyData = null;
  let headerDone = false;
  let bytesUp = 0;
  let bytesDown = 0;

  const url = new URL(request.url);
  const ed = url.searchParams.get("ed");
  if (ed) {
    try {
      const raw = atob(ed.replace(/-/g, "+").replace(/_/g, "/"));
      earlyData = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    } catch (_) {}
  }

  const flushTraffic = async () => {
    if (!username || (bytesUp === 0 && bytesDown === 0)) return;
    try {
      const add = (bytesUp + bytesDown) / (1024 * 1024 * 1024);
      await env.DB.prepare(
        "UPDATE users SET used_gb = used_gb + ?, last_active = ? WHERE username = ?"
      )
        .bind(add, Date.now(), username)
        .run();
    } catch (_) {}
    bytesUp = 0;
    bytesDown = 0;
  };

  const processHeader = async (chunk) => {
    const id = parseUUID(chunk);
    if (!id) {
      server.close(1002, "bad header");
      return false;
    }
    userUuid = id;

    let user;
    try {
      user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(id).first();
    } catch (_) {
      server.close(1011, "db");
      return false;
    }

    if (!user || user.is_active !== 1) {
      server.close(1008, "inactive");
      return false;
    }
    if (user.limit_gb > 0 && user.used_gb >= user.limit_gb) {
      server.close(1008, "quota");
      return false;
    }
    if (user.expiry_days > 0) {
      const exp = user.created_at + user.expiry_days * 86400000;
      if (Date.now() > exp) {
        server.close(1008, "expired");
        return false;
      }
    }

    username = user.username;

    // VLESS address parse (minimal: skip options, read addr type)
    let offset = 17; // ver + uuid
    if (chunk.byteLength <= offset) return true;
    const u8 = new Uint8Array(chunk);
    const optLen = u8[offset];
    offset += 1 + optLen;
    if (chunk.byteLength <= offset + 3) return true;

    const cmd = u8[offset];
    offset += 1;
    const port = (u8[offset] << 8) | u8[offset + 1];
    offset += 2;
    const atyp = u8[offset++];
    let host = "";

    if (atyp === 1) {
      // IPv4
      host = `${u8[offset]}.${u8[offset + 1]}.${u8[offset + 2]}.${u8[offset + 3]}`;
      offset += 4;
    } else if (atyp === 2) {
      const len = u8[offset++];
      host = dec.decode(u8.slice(offset, offset + len));
      offset += len;
    } else if (atyp === 3) {
      const parts = [];
      for (let i = 0; i < 8; i++) {
        parts.push(((u8[offset] << 8) | u8[offset + 1]).toString(16));
        offset += 2;
      }
      host = parts.join(":");
    } else {
      server.close(1002, "atyp");
      return false;
    }

    const payload = u8.slice(offset);

    try {
      remote = connect({ hostname: host, port });
      const writer = remote.writable.getWriter();
      if (payload.byteLength) {
        await writer.write(payload);
        bytesUp += payload.byteLength;
      }
      writer.releaseLock();

      // reply VLESS response header
      server.send(new Uint8Array([chunk[0], 0]));

      // pipe remote -> client
      (async () => {
        try {
          const reader = remote.readable.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength) {
              bytesDown += value.byteLength;
              if (server.readyState === 1) server.send(value);
            }
          }
        } catch (_) {
        } finally {
          try { server.close(); } catch (_) {}
          await flushTraffic();
        }
      })();
    } catch (e) {
      server.close(1011, "connect fail");
      return false;
    }
    return true;
  };

  server.addEventListener("message", async (ev) => {
    try {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : enc.encode(ev.data);
      if (!headerDone) {
        headerDone = true;
        const ok = await processHeader(data);
        if (!ok) return;
        return;
      }
      if (remote) {
        const writer = remote.writable.getWriter();
        await writer.write(data);
        bytesUp += data.byteLength;
        writer.releaseLock();
      }
    } catch (_) {
      try { server.close(); } catch (__) {}
    }
  });

  server.addEventListener("close", async () => {
    try { if (remote) remote.close(); } catch (_) {}
    await flushTraffic();
  });

  // early data
  if (earlyData && earlyData.byteLength) {
    headerDone = true;
    await processHeader(earlyData);
  }

  return new Response(null, { status: 101, webSocket: client });
}

/* ───────────────── subscription ───────────────── */
async function handleSub(url, env) {
  const name = decodeURIComponent(url.pathname.slice(LV.SUB_PATH.length + 1) || "");
  if (!name) return new Response("Not Found", { status: 404 });

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?"
  )
    .bind(name, name)
    .first();

  if (!user || user.is_active !== 1) return new Response("Not Found", { status: 404 });

  const host = url.hostname;
  const path = encodeURIComponent(LV.WS_PATH);
  const remark = encodeURIComponent(`Leviko · ${user.username}`);
  const link = `vless://${user.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=${path}#${remark}`;

  // also non-tls :80 style for some clients
  const link80 = `vless://${user.uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=${path}#${remark}-80`;

  const body = btoa(unescape(encodeURIComponent([link, link80].join("\n"))));
  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo": `upload=0; download=${Math.floor((user.used_gb || 0) * 1073741824)}; total=${Math.floor((user.limit_gb || 0) * 1073741824)}; expire=${user.expiry_days > 0 ? Math.floor((user.created_at + user.expiry_days * 86400000) / 1000) : 0}`,
    },
  });
}

/* ───────────────── API ───────────────── */
async function handleApi(request, url, env) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  // setup password
  if (path === "/setup" && method === "POST") {
    const existing = await Schema.getSetting(env.DB, "panel_pass");
    if (existing) return json({ error: "already set" }, 400);
    const body = await request.json().catch(() => ({}));
    const pass = (body.password || "").trim();
    if (pass.length < 4) return json({ error: "min 4 chars" }, 400);
    const hash = await sha256(pass);
    await Schema.setSetting(env.DB, "panel_pass", hash);
    const token = await sha256(hash + "|leviko");
    return json(
      { ok: true },
      200,
      { "Set-Cookie": sessionCookie(token) }
    );
  }

  // login
  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const pass = (body.password || "").trim();
    const hash = await Schema.getSetting(env.DB, "panel_pass");
    if (!hash) return json({ error: "setup required" }, 400);
    const check = await sha256(pass);
    if (check !== hash) return json({ error: "wrong password" }, 401);
    const token = await sha256(hash + "|leviko");
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  // auth gate
  const sess = await checkSession(request, env.DB);
  if (sess.needSetup) return json({ error: "setup" }, 403);
  if (!sess.ok) return json({ error: "unauthorized" }, 401);

  // stats
  if (path === "/stats" && method === "GET") {
    const total = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    const active = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE is_active = 1").first();
    const traffic = await env.DB.prepare("SELECT COALESCE(SUM(used_gb),0) as s FROM users").first();
    return json({
      users: total?.c || 0,
      active: active?.c || 0,
      traffic: +(traffic?.s || 0).toFixed(3),
      version: LV.VERSION,
    });
  }

  // list users
  if (path === "/users" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id, username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark, last_active FROM users ORDER BY id DESC"
    ).all();
    return json({ users: results || [] });
  }

  // create user
  if (path === "/users" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = (body.username || "").trim().replace(/[^a-zA-Z0-9_\-.]/g, "");
    if (!username) return json({ error: "username required" }, 400);
    const id = body.uuid && /^[0-9a-f-]{36}$/i.test(body.uuid) ? body.uuid : uuid();
    const limit = parseFloat(body.limit_gb) || 0;
    const days = parseInt(body.expiry_days) || 0;
    const remark = (body.remark || "").slice(0, 120);
    try {
      await env.DB.prepare(
        `INSERT INTO users (username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark)
         VALUES (?, ?, ?, 0, ?, ?, 1, ?)`
      )
        .bind(username, id, limit, days, Date.now(), remark)
        .run();
      return json({ ok: true, uuid: id, username });
    } catch (e) {
      return json({ error: e.message.includes("UNIQUE") ? "username exists" : e.message }, 400);
    }
  }

  // update user
  if (path.startsWith("/users/") && method === "PATCH") {
    const id = path.split("/")[2];
    const body = await request.json().catch(() => ({}));
    const fields = [];
    const vals = [];
    if (body.is_active !== undefined) {
      fields.push("is_active = ?");
      vals.push(body.is_active ? 1 : 0);
    }
    if (body.limit_gb !== undefined) {
      fields.push("limit_gb = ?");
      vals.push(parseFloat(body.limit_gb) || 0);
    }
    if (body.expiry_days !== undefined) {
      fields.push("expiry_days = ?");
      vals.push(parseInt(body.expiry_days) || 0);
    }
    if (body.remark !== undefined) {
      fields.push("remark = ?");
      vals.push(String(body.remark).slice(0, 120));
    }
    if (body.reset_traffic) {
      fields.push("used_gb = 0");
    }
    if (!fields.length) return json({ error: "nothing" }, 400);
    vals.push(id);
    await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  }

  // delete user
  if (path.startsWith("/users/") && method === "DELETE") {
    const id = path.split("/")[2];
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  // change password
  if (path === "/password" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const pass = (body.password || "").trim();
    if (pass.length < 4) return json({ error: "min 4" }, 400);
    const hash = await sha256(pass);
    await Schema.setSetting(env.DB, "panel_pass", hash);
    const token = await sha256(hash + "|leviko");
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  return json({ error: "not found" }, 404);
}

/* ───────────────── user status page ───────────────── */
async function handleStatus(url, env) {
  const name = decodeURIComponent(url.pathname.replace(/^\/status\//, "") || "");
  if (!name) return html("Not found", 404);
  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?"
  )
    .bind(name, name)
    .first();
  if (!user) return html("Not found", 404);

  const host = url.hostname;
  const remain =
    user.limit_gb > 0 ? Math.max(0, user.limit_gb - user.used_gb).toFixed(2) : "∞";
  const pct =
    user.limit_gb > 0 ? Math.min(100, ((user.used_gb / user.limit_gb) * 100).toFixed(1)) : 0;
  let daysLeft = "∞";
  if (user.expiry_days > 0) {
    const left = Math.ceil((user.created_at + user.expiry_days * 86400000 - Date.now()) / 86400000);
    daysLeft = left > 0 ? left : 0;
  }

  const subUrl = `${url.protocol}//${host}${LV.SUB_PATH}/${encodeURIComponent(user.username)}`;
  const path = encodeURIComponent(LV.WS_PATH);
  const links = [
    `vless://${user.uuid}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=${path}#Leviko-${user.username}`,
    `vless://${user.uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=${path}#Leviko-${user.username}-80`,
  ];

  return html(statusPage(user, remain, pct, daysLeft, subUrl, links));
}

/* ───────────────── HTML pages ───────────────── */
function baseCss() {
  return `
:root{
  --bg:#06060a;--s1:#0c0c14;--s2:#12121e;--s3:#1a1a2a;
  --line:rgba(255,255,255,.07);--line2:rgba(255,255,255,.12);
  --txt:#f0f0f8;--mut:#8a8aa0;--faint:#55556a;
  --a:#7c5cfc;--a2:#a78bfa;--a-glow:rgba(124,92,252,.35);
  --ok:#34d399;--warn:#fbbf24;--err:#f87171;
  --r:20px;--rs:12px;
  --font:'Segoe UI',system-ui,-apple-system,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px}
body{
  font-family:var(--font);background:var(--bg);color:var(--txt);
  min-height:100vh;line-height:1.55;-webkit-font-smoothing:antialiased;
}
body::before{
  content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:
    radial-gradient(ellipse 70% 50% at 15% 0%,rgba(124,92,252,.14),transparent 55%),
    radial-gradient(ellipse 50% 40% at 90% 80%,rgba(167,139,250,.08),transparent 50%),
    radial-gradient(ellipse 40% 30% at 50% 100%,rgba(52,211,153,.05),transparent 45%);
}
.scene{position:relative;z-index:1;max-width:960px;margin:0 auto;padding:28px 18px 60px}
.glass{
  background:linear-gradient(145deg,rgba(255,255,255,.04),rgba(255,255,255,.01));
  border:1px solid var(--line);border-radius:var(--r);
  backdrop-filter:blur(24px) saturate(1.4);
  -webkit-backdrop-filter:blur(24px) saturate(1.4);
  box-shadow:
    0 8px 32px rgba(0,0,0,.4),
    inset 0 1px 0 rgba(255,255,255,.06);
}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:11px 20px;border:none;border-radius:var(--rs);
  font:700 .9rem var(--font);cursor:pointer;transition:.2s;
}
.btn-a{
  background:linear-gradient(135deg,#8b6fff,#6d4aff);
  color:#fff;box-shadow:0 6px 24px var(--a-glow);
}
.btn-a:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn-g{background:rgba(255,255,255,.05);border:1px solid var(--line2);color:var(--mut)}
.btn-g:hover{border-color:var(--a);color:var(--a2)}
.btn-d{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:var(--err)}
input,select,textarea{
  width:100%;padding:11px 14px;background:var(--s2);border:1px solid var(--line);
  border-radius:var(--rs);color:var(--txt);font:400 .92rem var(--font);outline:none;transition:.2s;
}
input:focus,select:focus,textarea:focus{border-color:var(--a);box-shadow:0 0 0 3px rgba(124,92,252,.15)}
label{display:block;font-size:.78rem;font-weight:600;color:var(--mut);margin-bottom:5px}
`;
}

function setupPage() {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko · Setup</title><style>${baseCss()}
.box{max-width:400px;margin:12vh auto;padding:32px 28px;text-align:center}
.logo{width:64px;height:64px;margin:0 auto 16px;border-radius:18px;
  background:linear-gradient(145deg,#a78bfa,#6d4aff);display:grid;place-items:center;
  font-size:1.6rem;font-weight:900;color:#fff;box-shadow:0 12px 40px var(--a-glow);
  transform:perspective(400px) rotateY(-8deg) rotateX(6deg)}
h1{font-size:1.4rem;font-weight:800;margin-bottom:6px}
p{color:var(--mut);font-size:.9rem;margin-bottom:22px}
.field{text-align:right;margin-bottom:14px}
.err{color:var(--err);font-size:.85rem;margin-top:10px;display:none}
</style></head><body><div class="scene">
<div class="glass box">
  <div class="logo">L</div>
  <h1>Leviko</h1>
  <p>اولین ورود — یک رمز برای پنل انتخاب کن</p>
  <div class="field"><label>رمز عبور</label>
    <input type="password" id="pass" placeholder="حداقل ۴ کاراکتر"></div>
  <div class="field"><label>تکرار رمز</label>
    <input type="password" id="pass2" placeholder="تکرار"></div>
  <div class="err" id="err"></div>
  <button class="btn btn-a" style="width:100%;margin-top:8px" onclick="go()">ذخیره و ورود</button>
</div></div>
<script>
async function go(){
  const p=document.getElementById('pass').value,p2=document.getElementById('pass2').value;
  const e=document.getElementById('err');
  if(p.length<4){e.style.display='block';e.textContent='حداقل ۴ کاراکتر';return}
  if(p!==p2){e.style.display='block';e.textContent='رمزها یکسان نیستند';return}
  const r=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  const j=await r.json();
  if(!r.ok){e.style.display='block';e.textContent=j.error||'error';return}
  location.href='${LV.PANEL_PATH}';
}
</script></body></html>`;
}

function loginPage() {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko · Login</title><style>${baseCss()}
.box{max-width:380px;margin:14vh auto;padding:32px 28px;text-align:center}
.logo{width:64px;height:64px;margin:0 auto 16px;border-radius:18px;
  background:linear-gradient(145deg,#a78bfa,#6d4aff);display:grid;place-items:center;
  font-size:1.6rem;font-weight:900;color:#fff;box-shadow:0 12px 40px var(--a-glow);
  transform:perspective(400px) rotateY(-8deg) rotateX(6deg)}
h1{font-size:1.35rem;font-weight:800;margin-bottom:18px}
.field{text-align:right;margin-bottom:14px}
.err{color:var(--err);font-size:.85rem;margin-top:10px;display:none}
</style></head><body><div class="scene">
<div class="glass box">
  <div class="logo">L</div>
  <h1>Leviko Panel</h1>
  <div class="field"><label>رمز عبور</label>
    <input type="password" id="pass" placeholder="••••••••" onkeydown="if(event.key==='Enter')go()"></div>
  <div class="err" id="err"></div>
  <button class="btn btn-a" style="width:100%" onclick="go()">ورود</button>
</div></div>
<script>
async function go(){
  const p=document.getElementById('pass').value;
  const e=document.getElementById('err');
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  const j=await r.json();
  if(!r.ok){e.style.display='block';e.textContent=j.error||'رمز اشتباه';return}
  location.href='${LV.PANEL_PATH}';
}
</script></body></html>`;
}

function panelPage() {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko Panel</title><style>${baseCss()}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.brand .mark{
  width:44px;height:44px;border-radius:14px;
  background:linear-gradient(145deg,#a78bfa,#6d4aff);
  display:grid;place-items:center;font-weight:900;font-size:1.2rem;color:#fff;
  box-shadow:0 8px 28px var(--a-glow);
  transform:perspective(300px) rotateY(-10deg) rotateX(5deg);
}
.brand h1{font-size:1.2rem;font-weight:800}
.brand span{font-size:.72rem;color:var(--mut);letter-spacing:.06em}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:22px}
.stat{padding:18px 16px;text-align:center}
.stat .n{font-size:1.6rem;font-weight:800;background:linear-gradient(135deg,#a78bfa,#7c5cfc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .l{font-size:.75rem;color:var(--mut);margin-top:2px}
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:right;padding:10px 12px;color:var(--mut);font-weight:600;border-bottom:1px solid var(--line);font-size:.75rem}
td{padding:12px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:.72rem;font-weight:700}
.badge-on{background:rgba(52,211,153,.12);color:var(--ok)}
.badge-off{background:rgba(248,113,113,.12);color:var(--err)}
.acts{display:flex;gap:6px;flex-wrap:wrap}
.acts button{padding:6px 10px;font-size:.75rem;border-radius:8px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:50;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}
.modal{width:100%;max-width:420px;padding:24px}
.modal h3{font-size:1.05rem;font-weight:800;margin-bottom:16px}
.modal .field{margin-bottom:12px}
.modal .row{display:flex;gap:10px;margin-top:16px}
.modal .row .btn{flex:1}
.empty{text-align:center;padding:40px;color:var(--mut)}
@media(max-width:640px){.stats{grid-template-columns:1fr}.brand .mark{transform:none}}
</style></head><body><div class="scene">
<div class="top">
  <div class="brand">
    <div class="mark">L</div>
    <div><h1>Leviko</h1><span>CONTROL PANEL</span></div>
  </div>
  <button class="btn btn-g" onclick="logout()">خروج</button>
</div>

<div class="stats">
  <div class="glass stat"><div class="n" id="sUsers">—</div><div class="l">کل کاربران</div></div>
  <div class="glass stat"><div class="n" id="sActive">—</div><div class="l">فعال</div></div>
  <div class="glass stat"><div class="n" id="sTraffic">—</div><div class="l">مصرف (GB)</div></div>
</div>

<div class="toolbar">
  <button class="btn btn-a" onclick="openCreate()">+ کاربر جدید</button>
  <button class="btn btn-g" onclick="load()">↻ بروزرسانی</button>
</div>

<div class="glass table-wrap" style="padding:8px 0">
<table>
<thead><tr>
  <th>کاربر</th><th>وضعیت</th><th>حجم</th><th>روز</th><th>عملیات</th>
</tr></thead>
<tbody id="tbody"><tr><td colspan="5" class="empty">در حال بارگذاری…</td></tr></tbody>
</table>
</div>
</div>

<div class="modal-bg" id="modal">
  <div class="glass modal">
    <h3 id="modalTitle">کاربر جدید</h3>
    <div class="field"><label>نام کاربری</label><input id="fUser" placeholder="user1"></div>
    <div class="field"><label>سقف حجم (GB) — 0 = نامحدود</label><input id="fLimit" type="number" value="10" min="0" step="0.1"></div>
    <div class="field"><label>روز انقضا — 0 = نامحدود</label><input id="fDays" type="number" value="30" min="0"></div>
    <div class="field"><label>یادداشت</label><input id="fRemark" placeholder="اختیاری"></div>
    <div class="row">
      <button class="btn btn-a" onclick="saveUser()">ذخیره</button>
      <button class="btn btn-g" onclick="closeModal()">لغو</button>
    </div>
  </div>
</div>

<script>
const host=location.host;
async function api(path,opts={}){
  const r=await fetch('/api'+path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
  if(r.status===401){location.href='${LV.PANEL_PATH}';return null}
  return r.json();
}
function logout(){document.cookie='lv_session=; Max-Age=0; Path=/';location.reload()}
async function load(){
  const s=await api('/stats');
  if(!s)return;
  document.getElementById('sUsers').textContent=s.users;
  document.getElementById('sActive').textContent=s.active;
  document.getElementById('sTraffic').textContent=s.traffic;
  const u=await api('/users');
  if(!u)return;
  const tb=document.getElementById('tbody');
  if(!u.users.length){tb.innerHTML='<tr><td colspan="5" class="empty">هنوز کاربری نیست</td></tr>';return}
  tb.innerHTML=u.users.map(x=>{
    const used=(x.used_gb||0).toFixed(2);
    const lim=x.limit_gb>0?x.limit_gb:'∞';
    let days='∞';
    if(x.expiry_days>0){
      const left=Math.ceil((x.created_at+x.expiry_days*86400000-Date.now())/86400000);
      days=left>0?left:0;
    }
    const st=x.is_active?'<span class="badge badge-on">فعال</span>':'<span class="badge badge-off">غیرفعال</span>';
    const sub=\`\${location.protocol}//\${host}${LV.SUB_PATH}/\${encodeURIComponent(x.username)}\`;
    const status=\`\${location.protocol}//\${host}/status/\${encodeURIComponent(x.username)}\`;
    return \`<tr>
      <td><strong>\${x.username}</strong><br><span style="font-size:.7rem;color:var(--faint)">\${x.uuid.slice(0,8)}…</span></td>
      <td>\${st}</td>
      <td>\${used} / \${lim}</td>
      <td>\${days}</td>
      <td class="acts">
        <button class="btn btn-g" onclick="copy('\${sub}')">ساب</button>
        <button class="btn btn-g" onclick="window.open('\${status}')">صفحه</button>
        <button class="btn btn-g" onclick="toggle(\${x.id},\${x.is_active?0:1})">\${x.is_active?'قطع':'فعال'}</button>
        <button class="btn btn-g" onclick="resetT(\${x.id})">ریست</button>
        <button class="btn btn-d" onclick="del(\${x.id})">حذف</button>
      </td>
    </tr>\`;
  }).join('');
}
function openCreate(){
  document.getElementById('modalTitle').textContent='کاربر جدید';
  document.getElementById('fUser').value='';
  document.getElementById('fLimit').value='10';
  document.getElementById('fDays').value='30';
  document.getElementById('fRemark').value='';
  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open')}
async function saveUser(){
  const body={
    username:document.getElementById('fUser').value.trim(),
    limit_gb:parseFloat(document.getElementById('fLimit').value)||0,
    expiry_days:parseInt(document.getElementById('fDays').value)||0,
    remark:document.getElementById('fRemark').value.trim()
  };
  if(!body.username){alert('نام کاربری لازم است');return}
  const r=await api('/users',{method:'POST',body:JSON.stringify(body)});
  if(r&&r.error){alert(r.error);return}
  closeModal();load();
}
async function toggle(id,v){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({is_active:v})});load()}
async function resetT(id){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({reset_traffic:true})});load()}
async function del(id){if(!confirm('حذف شود؟'))return;await api('/users/'+id,{method:'DELETE'});load()}
function copy(t){navigator.clipboard.writeText(t).then(()=>alert('کپی شد')).catch(()=>prompt('کپی:',t))}
load();
</script></body></html>`;
}

function statusPage(user, remain, pct, daysLeft, subUrl, links) {
  const active = user.is_active === 1;
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko · ${user.username}</title><style>${baseCss()}
.box{max-width:440px;margin:6vh auto;padding:28px 24px}
.head{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.logo{width:48px;height:48px;border-radius:14px;background:linear-gradient(145deg,#a78bfa,#6d4aff);
  display:grid;place-items:center;font-weight:900;color:#fff;font-size:1.1rem;
  box-shadow:0 8px 28px var(--a-glow);transform:perspective(300px) rotateY(-8deg) rotateX(5deg)}
.badge{padding:4px 12px;border-radius:99px;font-size:.75rem;font-weight:700}
.on{background:rgba(52,211,153,.15);color:var(--ok)}
.off{background:rgba(248,113,113,.15);color:var(--err)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px}
.cell{padding:14px;text-align:center;border-radius:var(--rs);background:var(--s2);border:1px solid var(--line)}
.cell .v{font-size:1.15rem;font-weight:800}
.cell .k{font-size:.72rem;color:var(--mut);margin-top:2px}
.bar{height:8px;background:var(--s3);border-radius:99px;overflow:hidden;margin-bottom:18px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,#7c5cfc,#a78bfa);border-radius:99px;width:${pct}%}
.links{display:flex;flex-direction:column;gap:8px}
.link{
  display:flex;align-items:center;justify-content:space-between;gap:8px;
  padding:12px 14px;background:var(--s2);border:1px solid var(--line);border-radius:var(--rs);
  font-size:.78rem;word-break:break-all;cursor:pointer;transition:.2s;
}
.link:hover{border-color:var(--a)}
.link button{flex-shrink:0;padding:6px 12px;font-size:.75rem}
.sub{margin-top:14px;text-align:center}
.sub a{color:var(--a2);font-size:.85rem;font-weight:600}
</style></head><body><div class="scene">
<div class="glass box">
  <div class="head">
    <div style="display:flex;align-items:center;gap:12px">
      <div class="logo">L</div>
      <div><strong style="font-size:1.1rem">Leviko</strong><br>
        <span style="font-size:.8rem;color:var(--mut)">${user.username}</span></div>
    </div>
    <span class="badge ${active ? "on" : "off"}">${active ? "Active" : "Off"}</span>
  </div>
  <div class="grid">
    <div class="cell"><div class="v">${(user.used_gb || 0).toFixed(2)}</div><div class="k">مصرف GB</div></div>
    <div class="cell"><div class="v">${user.limit_gb > 0 ? user.limit_gb : "∞"}</div><div class="k">سقف</div></div>
    <div class="cell"><div class="v">${remain}</div><div class="k">باقیمانده</div></div>
    <div class="cell"><div class="v">${daysLeft}</div><div class="k">روز مانده</div></div>
  </div>
  <div class="bar"><i></div>
  <div style="font-size:.8rem;color:var(--mut);margin-bottom:8px">کانفیگ‌ها</div>
  <div class="links" id="links">
    ${links
      .map(
        (l, i) =>
          `<div class="link" onclick="cp(${i})"><span>${l.slice(0, 48)}…</span><button class="btn btn-a" data-i="${i}">کپی</button></div>`
      )
      .join("")}
  </div>
  <div class="sub"><a href="${subUrl}" target="_blank">لینک سابسکریپشن</a></div>
</div></div>
<script>
const L=${JSON.stringify(links)};
function cp(i){
  navigator.clipboard.writeText(L[i]).then(()=>alert('کپی شد')).catch(()=>prompt('کپی:',L[i]));
}
</script></body></html>`;
}

function camouflagePage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Welcome</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0a0f;color:#666;font-family:system-ui}
.box{text-align:center;opacity:.5}a{color:#7c5cfc;text-decoration:none}</style></head>
<body><div class="box"><p>Leviko Edge</p><p style="font-size:.85rem"><a href="${LV.PANEL_PATH}">panel</a></p></div></body></html>`;
}

/* ───────────────── router ───────────────── */
export default {
  async fetch(request, env, ctx) {
    if (!env.DB) {
      return new Response("D1 binding 'DB' is missing. Bind a D1 database as DB.", { status: 500 });
    }

    try {
      await Schema.ensure(env.DB);
    } catch (_) {}

    const url = new URL(request.url);
    const path = url.pathname;

    // WebSocket / VLESS
    if (request.headers.get("Upgrade") === "websocket") {
      return handleVless(request, env);
    }

    // also accept WS on configured path without Upgrade check edge-cases
    if (path === LV.WS_PATH || path.startsWith(LV.WS_PATH + "/")) {
      if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
        return handleVless(request, env);
      }
    }

    // API
    if (path.startsWith("/api/")) {
      return handleApi(request, url, env);
    }

    // Subscription
    if (path.startsWith(LV.SUB_PATH + "/") || path === LV.SUB_PATH) {
      return handleSub(url, env);
    }

    // User status page
    if (path.startsWith("/status/")) {
      return handleStatus(url, env);
    }

    // Panel
    if (path === LV.PANEL_PATH || path === LV.PANEL_PATH + "/") {
      const sess = await checkSession(request, env.DB);
      if (sess.needSetup) return html(setupPage());
      if (!sess.ok) return html(loginPage());
      return html(panelPage());
    }

    // root camouflage
    return html(camouflagePage());
  },
};
