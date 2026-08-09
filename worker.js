/**
 * Leviko Panel v2.0.0
 * Full-featured VLESS gateway on Cloudflare Workers + D1
 * Panel: /8080/dash  ·  Sub: /8080?sub=NAME
 */

import { connect } from "cloudflare:sockets";

const CFG = {
  VERSION: "2.0.0",
  ROOT: "/8080",
  DASH: "/8080/dash",
  WS: "/lv",
};

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ═══════════════ helpers ═══════════════ */
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

async function sha256(t) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(t));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function okName(s) {
  return typeof s === "string" && /^[a-zA-Z0-9_\-.]{1,48}$/.test(s);
}

/* ═══════════════ database ═══════════════ */
const Store = {
  async init(db) {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        uuid TEXT UNIQUE NOT NULL,
        limit_gb REAL NOT NULL DEFAULT 0,
        used_gb REAL NOT NULL DEFAULT 0,
        expiry_days INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        remark TEXT NOT NULL DEFAULT '',
        last_active INTEGER NOT NULL DEFAULT 0
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT ''
      )`),
    ]);
  },
  async get(db, key, fallback = null) {
    const row = await db.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
    return row ? row.value : fallback;
  },
  async set(db, key, value) {
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(key, String(value)).run();
  },
  async log(db, action, detail = "") {
    try {
      await db.prepare("INSERT INTO logs (ts, action, detail) VALUES (?, ?, ?)").bind(Date.now(), action, String(detail).slice(0, 200)).run();
      await db.prepare("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 200)").run();
    } catch (_) {}
  },
};

/* ═══════════════ auth ═══════════════ */
async function getSession(request, db) {
  const userHash = await Store.get(db, "admin_user");
  const passHash = await Store.get(db, "admin_pass");
  if (!userHash || !passHash) return { needSetup: true, ok: false };
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)lv_session=([^;]+)/);
  if (!m) return { needSetup: false, ok: false };
  const expected = await sha256(userHash + ":" + passHash + "|leviko|v2");
  return { needSetup: false, ok: m[1] === expected };
}

function sessionCookie(token) {
  return `lv_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}

async function makeToken(db) {
  const u = await Store.get(db, "admin_user");
  const p = await Store.get(db, "admin_pass");
  return sha256(u + ":" + p + "|leviko|v2");
}

/* ═══════════════ VLESS core ═══════════════ */
async function handleVless(request, env) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
    return new Response("Expected WebSocket", { status: 426 });
  }

  // global kill switch
  try {
    const killed = await Store.get(env.DB, "kill_switch");
    if (killed === "1") return new Response("Service paused", { status: 503 });
  } catch (_) {}

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();

  let remote = null;
  let username = null;
  let headerDone = false;
  let bytesUp = 0;
  let bytesDown = 0;

  let earlyData = null;
  try {
    const ed = new URL(request.url).searchParams.get("ed");
    if (ed) {
      const raw = atob(ed.replace(/-/g, "+").replace(/_/g, "/"));
      earlyData = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    }
  } catch (_) {}

  const flush = async () => {
    if (!username || (bytesUp === 0 && bytesDown === 0)) return;
    try {
      const add = (bytesUp + bytesDown) / 1073741824;
      await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, last_active = ? WHERE username = ?")
        .bind(add, Date.now(), username).run();
    } catch (_) {}
    bytesUp = 0;
    bytesDown = 0;
  };

  const processHeader = async (chunk) => {
    const id = parseUUID(chunk);
    if (!id) { try { server.close(1002, "bad"); } catch (_) {} return false; }

    let user;
    try {
      user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(id).first();
    } catch (_) {
      try { server.close(1011, "db"); } catch (__) {}
      return false;
    }

    if (!user || user.is_active !== 1) { try { server.close(1008, "off"); } catch (_) {} return false; }
    if (user.limit_gb > 0 && user.used_gb >= user.limit_gb) { try { server.close(1008, "quota"); } catch (_) {} return false; }
    if (user.expiry_days > 0 && Date.now() > user.created_at + user.expiry_days * 86400000) {
      try { server.close(1008, "expired"); } catch (_) {}
      return false;
    }

    username = user.username;
    let offset = 17;
    const u8 = new Uint8Array(chunk);
    if (u8.byteLength <= offset) return true;
    const optLen = u8[offset];
    offset += 1 + optLen;
    if (u8.byteLength <= offset + 3) return true;
    offset += 1;
    const port = (u8[offset] << 8) | u8[offset + 1];
    offset += 2;
    const atyp = u8[offset++];
    let host = "";
    try {
      if (atyp === 1) {
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
        try { server.close(1002, "atyp"); } catch (_) {}
        return false;
      }
    } catch (_) {
      try { server.close(1002, "parse"); } catch (__) {}
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
      server.send(new Uint8Array([chunk[0], 0]));

      (async () => {
        try {
          const reader = remote.readable.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value?.byteLength) {
              bytesDown += value.byteLength;
              if (server.readyState === 1) server.send(value);
            }
          }
        } catch (_) {
        } finally {
          try { server.close(); } catch (_) {}
          await flush();
        }
      })();
    } catch (_) {
      try { server.close(1011, "connect"); } catch (__) {}
      return false;
    }
    return true;
  };

  server.addEventListener("message", async (ev) => {
    try {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : enc.encode(String(ev.data));
      if (!headerDone) {
        headerDone = true;
        await processHeader(data);
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
  server.addEventListener("close", async () => { try { remote?.close?.(); } catch (_) {} await flush(); });
  server.addEventListener("error", async () => { try { remote?.close?.(); } catch (_) {} await flush(); });

  if (earlyData?.byteLength) {
    headerDone = true;
    await processHeader(earlyData);
  }
  return new Response(null, { status: 101, webSocket: client });
}

/* ═══════════════ links ═══════════════ */
function buildLinks(host, user, cleanIps = []) {
  const path = encodeURIComponent(CFG.WS);
  const tag = (suffix) => encodeURIComponent(`Leviko-${user.username}${suffix || ""}`);
  const links = [];
  const hosts = [host, ...cleanIps.filter(Boolean)];
  const seen = new Set();
  for (const h of hosts) {
    const addr = h.trim();
    if (!addr || seen.has(addr)) continue;
    seen.add(addr);
    links.push(
      `vless://${user.uuid}@${addr}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=${path}#${tag(addr === host ? "" : "-" + addr)}`
    );
  }
  links.push(
    `vless://${user.uuid}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=${path}#${tag("-80")}`
  );
  return links;
}

async function getCleanIps(db) {
  const raw = (await Store.get(db, "clean_ips", "")) || "";
  return raw.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).slice(0, 30);
}

async function handleSub(url, env) {
  const name = (url.searchParams.get("sub") || "").trim();
  if (!name) return new Response("Missing ?sub=username", { status: 400 });

  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?"
  ).bind(name, name).first();

  if (!user || user.is_active !== 1) return new Response("Not Found", { status: 404 });

  const host = url.hostname;
  const ips = await getCleanIps(env.DB);
  const links = buildLinks(host, user, ips);
  const body = btoa(unescape(encodeURIComponent(links.join("\n"))));
  const expire = user.expiry_days > 0
    ? Math.floor((user.created_at + user.expiry_days * 86400000) / 1000) : 0;

  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo": `upload=0; download=${Math.floor((user.used_gb || 0) * 1073741824)}; total=${Math.floor((user.limit_gb || 0) * 1073741824)}; expire=${expire}`,
    },
  });
}

/* ═══════════════ API ═══════════════ */
async function handleApi(request, url, env) {
  const path = url.pathname.replace(/^\/api/, "") || "/";
  const method = request.method;

  // setup admin (first time)
  if (path === "/setup" && method === "POST") {
    const existing = await Store.get(env.DB, "admin_pass");
    if (existing) return json({ error: "already configured" }, 400);
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "admin").trim();
    const password = String(body.password || "").trim();
    if (!okName(username)) return json({ error: "invalid username" }, 400);
    if (password.length < 4) return json({ error: "password min 4" }, 400);
    await Store.set(env.DB, "admin_user", await sha256(username));
    await Store.set(env.DB, "admin_pass", await sha256(password));
    await Store.set(env.DB, "admin_user_plain", username);
    await Store.log(env.DB, "setup", username);
    const token = await makeToken(env.DB);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  // bootstrap from installer
  if (path === "/bootstrap" && method === "POST") {
    const existing = await Store.get(env.DB, "admin_pass");
    if (existing) return json({ ok: true, already: true });
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || env.ADMIN_USER || "admin").trim();
    const password = String(body.password || env.ADMIN_PASS || "").trim();
    if (password.length < 4) return json({ error: "password required" }, 400);
    await Store.set(env.DB, "admin_user", await sha256(username));
    await Store.set(env.DB, "admin_pass", await sha256(password));
    await Store.set(env.DB, "admin_user_plain", username);
    await Store.log(env.DB, "bootstrap", username);
    return json({ ok: true });
  }

  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    const uh = await Store.get(env.DB, "admin_user");
    const ph = await Store.get(env.DB, "admin_pass");
    if (!uh || !ph) return json({ error: "setup required" }, 400);
    if ((await sha256(username)) !== uh || (await sha256(password)) !== ph) {
      await Store.log(env.DB, "login_fail", username);
      return json({ error: "wrong credentials" }, 401);
    }
    await Store.log(env.DB, "login_ok", username);
    const token = await makeToken(env.DB);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  if (path === "/logout" && method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": "lv_session=; Path=/; Max-Age=0" });
  }

  const sess = await getSession(request, env.DB);
  if (sess.needSetup) return json({ error: "setup" }, 403);
  if (!sess.ok) return json({ error: "unauthorized" }, 401);

  // ── stats
  if (path === "/stats" && method === "GET") {
    const total = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    const active = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE is_active = 1").first();
    const traffic = await env.DB.prepare("SELECT COALESCE(SUM(used_gb),0) as s FROM users").first();
    const kill = await Store.get(env.DB, "kill_switch", "0");
    return json({
      users: total?.c || 0,
      active: active?.c || 0,
      traffic: +(Number(traffic?.s) || 0).toFixed(3),
      version: CFG.VERSION,
      kill: kill === "1",
    });
  }

  // ── users list
  if (path === "/users" && method === "GET") {
    const { results } = await env.DB.prepare(
      `SELECT id, username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark, last_active
       FROM users ORDER BY id DESC`
    ).all();
    return json({ users: results || [] });
  }

  // ── create user
  if (path === "/users" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    if (!okName(username)) return json({ error: "invalid username" }, 400);
    const id = body.uuid && /^[0-9a-f-]{36}$/i.test(body.uuid) ? body.uuid : uuid();
    const limit = Math.max(0, parseFloat(body.limit_gb) || 0);
    const days = Math.max(0, parseInt(body.expiry_days, 10) || 0);
    const remark = String(body.remark || "").slice(0, 120);
    try {
      await env.DB.prepare(
        `INSERT INTO users (username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark)
         VALUES (?, ?, ?, 0, ?, ?, 1, ?)`
      ).bind(username, id, limit, days, Date.now(), remark).run();
      await Store.log(env.DB, "user_create", username);
      return json({ ok: true, uuid: id, username });
    } catch (e) {
      return json({ error: String(e.message || e).includes("UNIQUE") ? "exists" : String(e.message || e) }, 400);
    }
  }

  // ── patch user
  if (path.startsWith("/users/") && method === "PATCH") {
    const id = path.split("/")[2];
    if (!/^\d+$/.test(id)) return json({ error: "bad id" }, 400);
    const body = await request.json().catch(() => ({}));
    const fields = [];
    const vals = [];
    if (body.is_active !== undefined) { fields.push("is_active = ?"); vals.push(body.is_active ? 1 : 0); }
    if (body.limit_gb !== undefined) { fields.push("limit_gb = ?"); vals.push(Math.max(0, parseFloat(body.limit_gb) || 0)); }
    if (body.expiry_days !== undefined) { fields.push("expiry_days = ?"); vals.push(Math.max(0, parseInt(body.expiry_days, 10) || 0)); }
    if (body.remark !== undefined) { fields.push("remark = ?"); vals.push(String(body.remark).slice(0, 120)); }
    if (body.reset_traffic) fields.push("used_gb = 0");
    if (!fields.length) return json({ error: "nothing" }, 400);
    vals.push(id);
    await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).bind(...vals).run();
    await Store.log(env.DB, "user_patch", id);
    return json({ ok: true });
  }

  // ── delete user
  if (path.startsWith("/users/") && method === "DELETE") {
    const id = path.split("/")[2];
    if (!/^\d+$/.test(id)) return json({ error: "bad id" }, 400);
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
    await Store.log(env.DB, "user_delete", id);
    return json({ ok: true });
  }

  // ── settings get/set
  if (path === "/settings" && method === "GET") {
    return json({
      clean_ips: await Store.get(env.DB, "clean_ips", ""),
      panel_title: await Store.get(env.DB, "panel_title", "Leviko"),
      kill_switch: (await Store.get(env.DB, "kill_switch", "0")) === "1",
      admin_user: await Store.get(env.DB, "admin_user_plain", "admin"),
      version: CFG.VERSION,
    });
  }

  if (path === "/settings" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (body.clean_ips !== undefined) await Store.set(env.DB, "clean_ips", String(body.clean_ips).slice(0, 4000));
    if (body.panel_title !== undefined) await Store.set(env.DB, "panel_title", String(body.panel_title).slice(0, 40));
    if (body.kill_switch !== undefined) {
      await Store.set(env.DB, "kill_switch", body.kill_switch ? "1" : "0");
      await Store.log(env.DB, body.kill_switch ? "kill_on" : "kill_off", "");
    }
    return json({ ok: true });
  }

  // ── change admin credentials
  if (path === "/admin" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    if (username && okName(username)) {
      await Store.set(env.DB, "admin_user", await sha256(username));
      await Store.set(env.DB, "admin_user_plain", username);
    }
    if (password.length >= 4) {
      await Store.set(env.DB, "admin_pass", await sha256(password));
    }
    await Store.log(env.DB, "admin_change", username || "");
    const token = await makeToken(env.DB);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
  }

  // ── logs
  if (path === "/logs" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 100").all();
    return json({ logs: results || [] });
  }

  // ── export
  if (path === "/export" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark FROM users").all();
    return json({ version: CFG.VERSION, exported_at: Date.now(), users: results || [] });
  }

  // ── import
  if (path === "/import" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const users = Array.isArray(body.users) ? body.users : [];
    let n = 0;
    for (const u of users.slice(0, 500)) {
      if (!okName(u.username)) continue;
      const id = u.uuid && /^[0-9a-f-]{36}$/i.test(u.uuid) ? u.uuid : uuid();
      try {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO users (username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, remark)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          u.username, id,
          Math.max(0, parseFloat(u.limit_gb) || 0),
          Math.max(0, parseFloat(u.used_gb) || 0),
          Math.max(0, parseInt(u.expiry_days, 10) || 0),
          u.created_at || Date.now(),
          u.is_active === 0 ? 0 : 1,
          String(u.remark || "").slice(0, 120)
        ).run();
        n++;
      } catch (_) {}
    }
    await Store.log(env.DB, "import", String(n));
    return json({ ok: true, imported: n });
  }

  return json({ error: "not found" }, 404);
}

/* ═══════════════ UI CSS ═══════════════ */
function css() {
  return `
:root{--bg:#06060a;--s2:#12121e;--line:rgba(255,255,255,.08);--txt:#f0f0f8;--mut:#8a8aa0;--faint:#55556a;
--a:#7c5cfc;--a2:#a78bfa;--glow:rgba(124,92,252,.35);--ok:#34d399;--err:#f87171;--warn:#fbbf24;
--r:18px;--rs:12px;--font:'Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--txt);min-height:100vh;line-height:1.55}
body::before{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;background:
radial-gradient(ellipse 70% 50% at 12% 0%,rgba(124,92,252,.15),transparent 55%),
radial-gradient(ellipse 50% 40% at 90% 85%,rgba(167,139,250,.08),transparent 50%)}
.scene{position:relative;z-index:1;max-width:1000px;margin:0 auto;padding:24px 16px 60px}
.glass{background:linear-gradient(145deg,rgba(255,255,255,.045),rgba(255,255,255,.012));border:1px solid var(--line);
border-radius:var(--r);backdrop-filter:blur(22px);box-shadow:0 8px 32px rgba(0,0,0,.4),inset 0 1px 0 rgba(255,255,255,.06)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 16px;border:none;border-radius:var(--rs);
font:700 .88rem var(--font);cursor:pointer;transition:.2s}
.btn-a{background:linear-gradient(135deg,#8b6fff,#6d4aff);color:#fff;box-shadow:0 6px 22px var(--glow)}
.btn-a:hover{filter:brightness(1.1)}
.btn-g{background:rgba(255,255,255,.05);border:1px solid var(--line);color:var(--mut)}
.btn-g:hover{border-color:var(--a);color:var(--a2)}
.btn-d{background:rgba(248,113,113,.12);border:1px solid rgba(248,113,113,.3);color:var(--err)}
.btn-w{background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.3);color:var(--warn)}
input,select,textarea{width:100%;padding:11px 14px;background:var(--s2);border:1px solid var(--line);border-radius:var(--rs);
color:var(--txt);font:400 .92rem var(--font);outline:none}
input:focus,textarea:focus{border-color:var(--a);box-shadow:0 0 0 3px rgba(124,92,252,.15)}
label{display:block;font-size:.76rem;font-weight:600;color:var(--mut);margin-bottom:5px}
.tabs{display:flex;gap:6px;margin-bottom:18px;flex-wrap:wrap}
.tab{padding:8px 14px;border-radius:99px;border:1px solid var(--line);background:transparent;color:var(--mut);
font:600 .82rem var(--font);cursor:pointer}
.tab.on{background:rgba(124,92,252,.15);border-color:var(--a);color:var(--a2)}
`;
}

/* ═══════════════ pages ═══════════════ */
function authPage(setup = false) {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko</title><style>${css()}
.box{max-width:400px;margin:10vh auto;padding:32px 28px;text-align:center}
.logo{width:64px;height:64px;margin:0 auto 16px;border-radius:18px;background:linear-gradient(145deg,#a78bfa,#6d4aff);
display:grid;place-items:center;font-size:1.6rem;font-weight:900;color:#fff;box-shadow:0 12px 40px var(--glow);
transform:perspective(400px) rotateY(-8deg) rotateX(6deg)}
h1{font-size:1.35rem;font-weight:800;margin-bottom:6px}p{color:var(--mut);font-size:.9rem;margin-bottom:16px}
.field{text-align:right;margin-bottom:12px}.err{color:var(--err);font-size:.85rem;margin-top:10px;display:none}
</style></head><body><div class="scene"><div class="glass box">
<div class="logo">L</div><h1>Leviko</h1>
<p>${setup ? "ساخت حساب ادمین" : "ورود به پنل"}</p>
<div class="field"><label>نام کاربری</label><input id="user" value="${setup ? "admin" : ""}" placeholder="admin"></div>
<div class="field"><label>رمز عبور</label><input type="password" id="pass" placeholder="••••••••" onkeydown="if(event.key==='Enter')go()"></div>
${setup ? '<div class="field"><label>تکرار رمز</label><input type="password" id="pass2" placeholder="تکرار"></div>' : ""}
<div class="err" id="err"></div>
<button class="btn btn-a" style="width:100%;margin-top:8px" onclick="go()">${setup ? "ذخیره و ورود" : "ورود"}</button>
</div></div>
<script>
async function go(){
  const user=document.getElementById('user').value.trim();
  const pass=document.getElementById('pass').value;
  const e=document.getElementById('err');
  ${setup ? `const p2=document.getElementById('pass2').value;if(pass.length<4){e.style.display='block';e.textContent='حداقل ۴ کاراکتر';return}if(pass!==p2){e.style.display='block';e.textContent='رمزها یکسان نیستند';return}` : ""}
  const r=await fetch('/api/${setup ? "setup" : "login"}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){e.style.display='block';e.textContent=j.error||'خطا';return}
  location.href='${CFG.DASH}';
}
</script></body></html>`;
}

function panelPage() {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko Panel</title><style>${css()}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.brand .mark{width:44px;height:44px;border-radius:14px;background:linear-gradient(145deg,#a78bfa,#6d4aff);
display:grid;place-items:center;font-weight:900;color:#fff;box-shadow:0 8px 28px var(--glow);
transform:perspective(300px) rotateY(-10deg) rotateX(5deg)}
.brand h1{font-size:1.15rem;font-weight:800}.brand span{font-size:.7rem;color:var(--mut)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.stat{padding:14px;text-align:center}
.stat .n{font-size:1.4rem;font-weight:800;background:linear-gradient(135deg,#a78bfa,#7c5cfc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .l{font-size:.72rem;color:var(--mut);margin-top:2px}
.toolbar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th{text-align:right;padding:10px;color:var(--mut);font-weight:600;border-bottom:1px solid var(--line);font-size:.72rem}
td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:3px 9px;border-radius:99px;font-size:.7rem;font-weight:700}
.badge-on{background:rgba(52,211,153,.12);color:var(--ok)}.badge-off{background:rgba(248,113,113,.12);color:var(--err)}
.acts{display:flex;gap:5px;flex-wrap:wrap}.acts button{padding:5px 9px;font-size:.72rem;border-radius:8px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:50;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}.modal{width:100%;max-width:440px;padding:22px;max-height:90vh;overflow-y:auto}
.modal h3{font-size:1.05rem;font-weight:800;margin-bottom:14px}
.modal .field{margin-bottom:11px}.modal .row{display:flex;gap:10px;margin-top:14px}.modal .row .btn{flex:1}
.empty{text-align:center;padding:36px;color:var(--mut)}
.sec{display:none}.sec.on{display:block}
.kill-banner{display:none;padding:10px 14px;margin-bottom:14px;border-radius:12px;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.35);color:var(--warn);font-size:.85rem;font-weight:600}
.kill-banner.on{display:block}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}}
</style></head><body><div class="scene">
<div class="top">
  <div class="brand"><div class="mark">L</div><div><h1 id="title">Leviko</h1><span>v${CFG.VERSION}</span></div></div>
  <button class="btn btn-g" onclick="logout()">خروج</button>
</div>
<div class="kill-banner" id="killBanner">⚠ Kill Switch فعال است — تمام ترافیک پروکسی متوقف شده</div>
<div class="tabs">
  <button class="tab on" data-t="users" onclick="tab('users')">کاربران</button>
  <button class="tab" data-t="settings" onclick="tab('settings')">تنظیمات</button>
  <button class="tab" data-t="logs" onclick="tab('logs')">لاگ</button>
</div>

<div class="sec on" id="sec-users">
  <div class="stats">
    <div class="glass stat"><div class="n" id="sUsers">—</div><div class="l">کل کاربران</div></div>
    <div class="glass stat"><div class="n" id="sActive">—</div><div class="l">فعال</div></div>
    <div class="glass stat"><div class="n" id="sTraffic">—</div><div class="l">مصرف GB</div></div>
    <div class="glass stat"><div class="n" id="sKill">—</div><div class="l">وضعیت</div></div>
  </div>
  <div class="toolbar">
    <button class="btn btn-a" onclick="openCreate()">+ کاربر</button>
    <button class="btn btn-g" onclick="loadUsers()">↻</button>
    <button class="btn btn-g" onclick="doExport()">خروجی JSON</button>
    <button class="btn btn-g" onclick="document.getElementById('imp').click()">ورود JSON</button>
    <input type="file" id="imp" accept="application/json" style="display:none" onchange="doImport(event)">
  </div>
  <div class="glass" style="padding:6px 0;overflow-x:auto">
  <table><thead><tr><th>کاربر</th><th>وضعیت</th><th>حجم</th><th>روز</th><th>عملیات</th></tr></thead>
  <tbody id="tbody"><tr><td colspan="5" class="empty">…</td></tr></tbody></table>
  </div>
</div>

<div class="sec" id="sec-settings">
  <div class="glass" style="padding:20px">
    <div class="field"><label>عنوان پنل</label><input id="setTitle"></div>
    <div class="field"><label>Clean IP / Host (هر خط یکی)</label><textarea id="setIps" rows="5" placeholder="1.2.3.4&#10;cf.example.com"></textarea></div>
    <div class="field" style="display:flex;align-items:center;gap:10px;margin-top:8px">
      <input type="checkbox" id="setKill" style="width:auto">
      <label for="setKill" style="margin:0">Kill Switch — توقف کل ترافیک</label>
    </div>
    <hr style="border:none;border-top:1px solid var(--line);margin:18px 0">
    <h3 style="font-size:.95rem;margin-bottom:12px">تغییر یوزر / پسورد ادمین</h3>
    <div class="field"><label>نام کاربری جدید</label><input id="setUser" placeholder="اختیاری"></div>
    <div class="field"><label>رمز جدید</label><input type="password" id="setPass" placeholder="اختیاری — حداقل ۴"></div>
    <button class="btn btn-a" style="margin-top:10px" onclick="saveSettings()">ذخیره تنظیمات</button>
  </div>
</div>

<div class="sec" id="sec-logs">
  <div class="glass" style="padding:12px;overflow-x:auto">
    <table><thead><tr><th>زمان</th><th>عملیات</th><th>جزئیات</th></tr></thead>
    <tbody id="logBody"><tr><td colspan="3" class="empty">…</td></tr></tbody></table>
  </div>
</div>
</div>

<div class="modal-bg" id="modal">
  <div class="glass modal">
    <h3>کاربر جدید</h3>
    <div class="field"><label>نام کاربری</label><input id="fUser"></div>
    <div class="field"><label>سقف GB (۰=∞)</label><input id="fLimit" type="number" value="10" min="0" step="0.1"></div>
    <div class="field"><label>روز انقضا (۰=∞)</label><input id="fDays" type="number" value="30" min="0"></div>
    <div class="field"><label>یادداشت</label><input id="fRemark"></div>
    <div class="row"><button class="btn btn-a" onclick="saveUser()">ذخیره</button><button class="btn btn-g" onclick="closeModal()">لغو</button></div>
  </div>
</div>
<script>
const root=location.protocol+'//'+location.host;
async function api(path,opts={}){
  const r=await fetch('/api'+path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
  if(r.status===401){location.href='${CFG.DASH}';return null}
  return r.json();
}
function tab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.t===name));
  document.querySelectorAll('.sec').forEach(s=>s.classList.toggle('on',s.id==='sec-'+name));
  if(name==='logs')loadLogs();
  if(name==='settings')loadSettings();
}
async function logout(){await api('/logout',{method:'POST'});location.reload()}
async function loadUsers(){
  const s=await api('/stats');if(!s)return;
  document.getElementById('sUsers').textContent=s.users;
  document.getElementById('sActive').textContent=s.active;
  document.getElementById('sTraffic').textContent=s.traffic;
  document.getElementById('sKill').textContent=s.kill?'PAUSE':'ON';
  document.getElementById('killBanner').classList.toggle('on',!!s.kill);
  const u=await api('/users');if(!u)return;
  const tb=document.getElementById('tbody');
  if(!u.users.length){tb.innerHTML='<tr><td colspan="5" class="empty">کاربری نیست</td></tr>';return}
  tb.innerHTML=u.users.map(x=>{
    const used=(x.used_gb||0).toFixed(2),lim=x.limit_gb>0?x.limit_gb:'∞';
    let days='∞';
    if(x.expiry_days>0){const left=Math.ceil((x.created_at+x.expiry_days*86400000-Date.now())/86400000);days=left>0?left:0}
    const st=x.is_active?'<span class="badge badge-on">فعال</span>':'<span class="badge badge-off">قطع</span>';
    const sub=root+'${CFG.ROOT}?sub='+encodeURIComponent(x.username);
    return \`<tr><td><strong>\${x.username}</strong><br><span style="font-size:.68rem;color:var(--faint)">\${x.uuid.slice(0,8)}…</span></td>
      <td>\${st}</td><td>\${used}/\${lim}</td><td>\${days}</td>
      <td class="acts">
        <button class="btn btn-g" onclick="copy('\${sub}')">ساب</button>
        <button class="btn btn-g" onclick="toggle(\${x.id},\${x.is_active?0:1})">\${x.is_active?'قطع':'فعال'}</button>
        <button class="btn btn-g" onclick="resetT(\${x.id})">ریست</button>
        <button class="btn btn-d" onclick="del(\${x.id})">حذف</button>
      </td></tr>\`;
  }).join('');
}
function openCreate(){['fUser','fRemark'].forEach(i=>document.getElementById(i).value='');document.getElementById('fLimit').value='10';document.getElementById('fDays').value='30';document.getElementById('modal').classList.add('open')}
function closeModal(){document.getElementById('modal').classList.remove('open')}
async function saveUser(){
  const body={username:document.getElementById('fUser').value.trim(),limit_gb:parseFloat(document.getElementById('fLimit').value)||0,expiry_days:parseInt(document.getElementById('fDays').value)||0,remark:document.getElementById('fRemark').value.trim()};
  if(!body.username){alert('نام لازم است');return}
  const r=await api('/users',{method:'POST',body:JSON.stringify(body)});
  if(r?.error){alert(r.error);return}closeModal();loadUsers();
}
async function toggle(id,v){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({is_active:v})});loadUsers()}
async function resetT(id){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({reset_traffic:true})});loadUsers()}
async function del(id){if(!confirm('حذف؟'))return;await api('/users/'+id,{method:'DELETE'});loadUsers()}
function copy(t){navigator.clipboard.writeText(t).then(()=>alert('کپی شد')).catch(()=>prompt('کپی',t))}
async function loadSettings(){
  const s=await api('/settings');if(!s)return;
  document.getElementById('setTitle').value=s.panel_title||'Leviko';
  document.getElementById('setIps').value=s.clean_ips||'';
  document.getElementById('setKill').checked=!!s.kill_switch;
  document.getElementById('setUser').value=s.admin_user||'';
  document.getElementById('title').textContent=s.panel_title||'Leviko';
}
async function saveSettings(){
  await api('/settings',{method:'POST',body:JSON.stringify({
    panel_title:document.getElementById('setTitle').value,
    clean_ips:document.getElementById('setIps').value,
    kill_switch:document.getElementById('setKill').checked
  })});
  const user=document.getElementById('setUser').value.trim();
  const pass=document.getElementById('setPass').value;
  if(user||pass){await api('/admin',{method:'POST',body:JSON.stringify({username:user,password:pass})})}
  alert('ذخیره شد');loadUsers();loadSettings();
}
async function loadLogs(){
  const r=await api('/logs');if(!r)return;
  const tb=document.getElementById('logBody');
  if(!r.logs?.length){tb.innerHTML='<tr><td colspan="3" class="empty">خالی</td></tr>';return}
  tb.innerHTML=r.logs.map(l=>{
    const d=new Date(l.ts).toLocaleString('fa-IR');
    return \`<tr><td style="font-size:.75rem">\${d}</td><td>\${l.action}</td><td style="color:var(--faint)">\${l.detail||''}</td></tr>\`;
  }).join('');
}
async function doExport(){
  const r=await api('/export');if(!r)return;
  const blob=new Blob([JSON.stringify(r,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='leviko-export.json';a.click();
}
async function doImport(ev){
  const f=ev.target.files[0];if(!f)return;
  const text=await f.text();
  let data;try{data=JSON.parse(text)}catch{alert('JSON نامعتبر');return}
  const r=await api('/import',{method:'POST',body:JSON.stringify(data)});
  alert('وارد شد: '+(r?.imported||0));loadUsers();
}
loadUsers();
</script></body></html>`;
}

function camouflage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title></title>
<style>body{margin:0;min-height:100vh;background:#0a0a0f}</style></head><body></body></html>`;
}

/* ═══════════════ router ═══════════════ */
export default {
  async fetch(request, env) {
    if (!env.DB) return new Response("D1 binding 'DB' missing", { status: 500 });
    try { await Store.init(env.DB); } catch (_) {}

    // bootstrap admin from installer env vars
    try {
      if (env.ADMIN_PASS) {
        const exists = await Store.get(env.DB, "admin_pass");
        if (!exists) {
          const user = String(env.ADMIN_USER || "admin").trim() || "admin";
          await Store.set(env.DB, "admin_user", await sha256(user));
          await Store.set(env.DB, "admin_pass", await sha256(String(env.ADMIN_PASS)));
          await Store.set(env.DB, "admin_user_plain", user);
        }
      }
    } catch (_) {}

    const url = new URL(request.url);
    const path = url.pathname;

    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      return handleVless(request, env);
    }
    if (path === CFG.WS || path.startsWith(CFG.WS + "/")) {
      if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
        return handleVless(request, env);
      }
    }

    if (path.startsWith("/api/")) return handleApi(request, url, env);

    if (path === CFG.ROOT || path === CFG.ROOT + "/") {
      if (url.searchParams.has("sub")) return handleSub(url, env);
      return new Response("Leviko · /8080?sub=USERNAME", { headers: { "Content-Type": "text/plain" } });
    }

    if (path === CFG.DASH || path === CFG.DASH + "/") {
      const sess = await getSession(request, env.DB);
      if (sess.needSetup) return html(authPage(true));
      if (!sess.ok) return html(authPage(false));
      return html(panelPage());
    }

    return html(camouflage());
  },
};
