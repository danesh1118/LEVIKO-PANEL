/**
 * Leviko Panel v1.0.0
 * Full panel · VLESS/Trojan · Clean IP · Upstream · Sub info · Telegram shop · D1
 * /8080/dash  ·  /8080?sub=NAME
 */
import { connect } from "cloudflare:sockets";

const V = "3.0.0";
const ROOT = "/8080";
const DASH = "/8080/dash";
const WS = "/lv";
const LOGO = "https://avatars.githubusercontent.com/u/221537174?v=4";

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
async function sha256(t) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(t));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Compact SHA-224 (needed for Trojan password hash) */
function sha224(str) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  ]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  const bytes = enc.encode(str);
  const bitLen = bytes.length * 8;
  const withPad = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  withPad.set(bytes);
  withPad[bytes.length] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 4, bitLen >>> 0, false);
  dv.setUint32(withPad.length - 8, Math.floor(bitLen / 0x100000000), false);
  let h0 = 0xc1059ed8, h1 = 0x367cd507, h2 = 0x3070dd17, h3 = 0xf70e5939;
  let h4 = 0xffc00b31, h5 = 0x68581511, h6 = 0x64f98fa7, h7 = 0xbefa4fa4;
  const w = new Uint32Array(64);
  for (let i = 0; i < withPad.length; i += 64) {
    for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
    for (let j = 16; j < 64; j++) {
      const s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
      const s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let j = 0; j < 64; j++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[j] + w[j]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const out = new Uint8Array(28);
  const o = new DataView(out.buffer);
  o.setUint32(0, h0, false); o.setUint32(4, h1, false); o.setUint32(8, h2, false);
  o.setUint32(12, h3, false); o.setUint32(16, h4, false); o.setUint32(20, h5, false);
  o.setUint32(24, h6, false);
  return [...out].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const json = (d, s = 200, h = {}) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...h } });
const html = (b, s = 200) =>
  new Response(b, { status: s, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
const okName = (s) => typeof s === "string" && /^[a-zA-Z0-9_\-.]{1,48}$/.test(s);

/* ─── DB ─── */
const Store = {
  async init(db) {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`),
      db.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, uuid TEXT UNIQUE NOT NULL,
        limit_gb REAL NOT NULL DEFAULT 0, used_gb REAL NOT NULL DEFAULT 0,
        expiry_days INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1, remark TEXT NOT NULL DEFAULT '',
        last_active INTEGER NOT NULL DEFAULT 0, tg_id TEXT NOT NULL DEFAULT ''
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
        days INTEGER NOT NULL DEFAULT 30, gb REAL NOT NULL DEFAULT 10,
        price INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1,
        btn_name TEXT NOT NULL DEFAULT ''
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id TEXT NOT NULL, plan_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, username TEXT DEFAULT '',
        amount INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'plan', note TEXT NOT NULL DEFAULT ''
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS tg_customers (
        tg_id TEXT PRIMARY KEY, balance INTEGER NOT NULL DEFAULT 0,
        referrer TEXT NOT NULL DEFAULT '', trial_used INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT '', state_data TEXT NOT NULL DEFAULT '',
        discount TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL DEFAULT 0,
        name TEXT NOT NULL DEFAULT ''
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS discounts (
        code TEXT PRIMARY KEY, percent INTEGER NOT NULL DEFAULT 10,
        max_uses INTEGER NOT NULL DEFAULT 0, used_count INTEGER NOT NULL DEFAULT 0,
        is_active INTEGER NOT NULL DEFAULT 1
      )`),
    ]);
    // migrate older DBs missing columns
    for (const sql of [
      "ALTER TABLE users ADD COLUMN tg_id TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE users ADD COLUMN last_active INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE users ADD COLUMN remark TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE orders ADD COLUMN amount INTEGER NOT NULL DEFAULT 0",
      "ALTER TABLE orders ADD COLUMN kind TEXT NOT NULL DEFAULT 'plan'",
      "ALTER TABLE orders ADD COLUMN note TEXT NOT NULL DEFAULT ''",
      "ALTER TABLE plans ADD COLUMN btn_name TEXT NOT NULL DEFAULT ''",
    ]) {
      try { await db.prepare(sql).run(); } catch (_) {}
    }
  },
  async get(db, k, fb = null) {
    const r = await db.prepare("SELECT value FROM settings WHERE key=?").bind(k).first();
    return r ? r.value : fb;
  },
  async set(db, k, v) {
    await db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)").bind(k, String(v)).run();
  },
  async log(db, a, d = "") {
    try {
      await db.prepare("INSERT INTO logs (ts,action,detail) VALUES (?,?,?)").bind(Date.now(), a, String(d).slice(0, 200)).run();
      await db.prepare("DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT 300)").run();
    } catch (_) {}
  },
};

/* ─── Auth ─── */
async function getSession(req, db) {
  const uh = await Store.get(db, "admin_user");
  const ph = await Store.get(db, "admin_pass");
  if (!uh || !ph) return { needSetup: true, ok: false };
  const m = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)lv_session=([^;]+)/);
  if (!m) return { needSetup: false, ok: false };
  const exp = await sha256(uh + ":" + ph + "|leviko|v3");
  return { needSetup: false, ok: m[1] === exp };
}
const cookie = (t) => `lv_session=${t}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
async function token(db) {
  return sha256((await Store.get(db, "admin_user")) + ":" + (await Store.get(db, "admin_pass")) + "|leviko|v3");
}

/* ─── settings helpers ─── */
async function cfg(db) {
  let info_entries = [];
  try { info_entries = JSON.parse(await Store.get(db, "info_entries", "[]") || "[]"); } catch (_) { info_entries = []; }
  if (!Array.isArray(info_entries)) info_entries = [];
  // default info rows if empty and legacy flag on
  const legacyInfo = (await Store.get(db, "info_cfg", "1")) !== "0";
  if (!info_entries.length && legacyInfo) {
    info_entries = ["📊 {remain} ⏳ {expiry}"];
  }
  return {
    protocol: (await Store.get(db, "protocol", "vless")) || "vless",
    ports: (await Store.get(db, "ports", "443")) || "443",
    clean_ips: (await Store.get(db, "clean_ips", "🇩🇪 Germany|www.speedtest.com")) || "🇩🇪 Germany|www.speedtest.com",
    upstream: (await Store.get(db, "upstream", "")) || "",
    sub_prefix: (await Store.get(db, "sub_prefix", "Leviko")) || "Leviko",
    fingerprint: (await Store.get(db, "fingerprint", "chrome")) || "chrome",
    name_template: (await Store.get(db, "name_template", "{IP_NAME}")) || "{IP_NAME}",
    info_entries,
    info_cfg: legacyInfo,
    kill: (await Store.get(db, "kill_switch", "0")) === "1",
    title: (await Store.get(db, "panel_title", "Leviko")) || "Leviko",
    tg_token: (await Store.get(db, "tg_token", "")) || "",
    tg_admin: (await Store.get(db, "tg_admin", "")) || "",
    tg_welcome: (await Store.get(db, "tg_welcome", "به ربات فروش Leviko خوش آمدید 👋")) || "",
    card: (await Store.get(db, "pay_card", "")) || "",
    tg_channel: (await Store.get(db, "tg_channel", "")) || "",
    tg_support: (await Store.get(db, "tg_support", "")) || "",
    trial_gb: parseFloat(await Store.get(db, "trial_gb", "1") || "1") || 1,
    trial_days: parseInt(await Store.get(db, "trial_days", "1") || "1", 10) || 1,
    referral_bonus: parseInt(await Store.get(db, "referral_bonus", "5000") || "5000", 10) || 5000,
    tg_tutorial: (await Store.get(db, "tg_tutorial", "📚 برای اتصال، لینک ساب را در کلاینت وارد کنید.\n\nاندروید: v2rayNG\nآیفون: Streisand / Shadowrocket\nویندوز: v2rayN / Hiddify")) || "",
  };
}

/** Parse clean IP lines: IP or IP#Name or IP Name */
function parseCleanLines(raw) {
  const out = [];
  for (const line of String(raw || "").split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    let ip = t, name = "";
    if (t.includes("#")) {
      const i = t.indexOf("#");
      ip = t.slice(0, i).trim();
      name = t.slice(i + 1).trim();
    } else {
      const m = t.match(/^(\S+)\s+(.+)$/);
      if (m) { ip = m[1]; name = m[2].trim(); }
    }
    if (ip) out.push({ ip, name: name || ip });
  }
  return out.slice(0, 40);
}

function applyTemplate(tpl, vars) {
  return String(tpl || "").replace(/\{([A-Za-z0-9_]+)\}/g, (_, k) => {
    if (vars[k] != null && vars[k] !== "") return String(vars[k]);
    const up = k.toUpperCase();
    if (vars[up] != null && vars[up] !== "") return String(vars[up]);
    const lo = k.toLowerCase();
    if (vars[lo] != null && vars[lo] !== "") return String(vars[lo]);
    return "";
  });
}

/* ─── VLESS + Trojan proxy ─── */
async function checkUser(env, user) {
  if (!user || user.is_active !== 1) return false;
  if (user.limit_gb > 0 && user.used_gb >= user.limit_gb) return false;
  if (user.expiry_days > 0 && Date.now() > user.created_at + user.expiry_days * 86400000) return false;
  return true;
}

async function handleVless(request, env, ctx) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket")
    return new Response("Expected WebSocket", { status: 426 });
  try {
    if ((await Store.get(env.DB, "kill_switch")) === "1") return new Response("Paused", { status: 503 });
  } catch (_) {}

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  let remote = null, username = null, headerDone = false, bytesUp = 0, bytesDown = 0;
  let earlyData = null;
  let lastFlush = Date.now();
  try {
    const ed = new URL(request.url).searchParams.get("ed");
    if (ed) {
      const raw = atob(ed.replace(/-/g, "+").replace(/_/g, "/"));
      earlyData = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    }
  } catch (_) {}
  // Trojan early data can also arrive via sec-websocket-protocol
  try {
    if (!earlyData) {
      const swp = request.headers.get("sec-websocket-protocol") || "";
      if (swp) {
        const raw = atob(swp.replace(/-/g, "+").replace(/_/g, "/"));
        earlyData = Uint8Array.from(raw, (c) => c.charCodeAt(0));
      }
    }
  } catch (_) {}

  const flush = async () => {
    if (!username || !(bytesUp || bytesDown)) return;
    const add = (bytesUp + bytesDown) / 1073741824;
    const uname = username;
    bytesUp = 0;
    bytesDown = 0;
    lastFlush = Date.now();
    try {
      await env.DB.prepare("UPDATE users SET used_gb=used_gb+?, last_active=? WHERE username=?")
        .bind(add, Date.now(), uname).run();
    } catch (_) {}
  };
  const scheduleFlush = () => {
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(flush());
    else flush();
  };
  const maybeFlush = () => {
    // flush every ~0.5 MB or every 20s so traffic is not lost if isolate dies
    if ((bytesUp + bytesDown) > 500000 || Date.now() - lastFlush > 20000) scheduleFlush();
  };

  const pipeRemote = async (host, port, payload, isVless, versionByte) => {
    try {
      remote = connect({ hostname: host, port });
      const w = remote.writable.getWriter();
      if (payload?.byteLength) { await w.write(payload); bytesUp += payload.byteLength; }
      w.releaseLock();
      if (isVless) server.send(new Uint8Array([versionByte, 0]));
      (async () => {
        try {
          const r = remote.readable.getReader();
          while (true) {
            const { done, value } = await r.read();
            if (done) break;
            if (value?.byteLength) {
              bytesDown += value.byteLength;
              if (server.readyState === 1) server.send(value);
              maybeFlush();
            }
          }
        } catch (_) {} finally { try { server.close(); } catch (_) {} scheduleFlush(); }
      })();
      return true;
    } catch (_) {
      try { server.close(1011); } catch (__) {}
      return false;
    }
  };

  const processVless = async (chunk) => {
    const id = parseUUID(chunk);
    if (!id) return false;
    let user;
    try { user = await env.DB.prepare("SELECT * FROM users WHERE uuid=?").bind(id).first(); }
    catch (_) { return false; }
    if (!(await checkUser(env, user))) { try { server.close(1008); } catch (_) {} return false; }
    username = user.username;
    let offset = 17;
    const u8 = new Uint8Array(chunk);
    if (u8.byteLength <= offset) return true;
    offset += 1 + u8[offset];
    if (u8.byteLength <= offset + 3) return true;
    offset += 1;
    const port = (u8[offset] << 8) | u8[offset + 1];
    offset += 2;
    const atyp = u8[offset++];
    let host = "";
    try {
      if (atyp === 1) { host = `${u8[offset]}.${u8[offset+1]}.${u8[offset+2]}.${u8[offset+3]}`; offset += 4; }
      else if (atyp === 2) { const len = u8[offset++]; host = dec.decode(u8.slice(offset, offset + len)); offset += len; }
      else if (atyp === 3) {
        const parts = [];
        for (let i = 0; i < 8; i++) { parts.push(((u8[offset] << 8) | u8[offset+1]).toString(16)); offset += 2; }
        host = parts.join(":");
      } else return false;
    } catch (_) { return false; }
    return pipeRemote(host, port, u8.slice(offset), true, chunk[0]);
  };

  const processTrojan = async (chunk) => {
    const u8 = new Uint8Array(chunk);
    if (u8.byteLength < 58) return false;
    // 56 hex chars of sha224(password) + \r\n
    const hashHex = dec.decode(u8.slice(0, 56));
    if (!/^[0-9a-f]{56}$/i.test(hashHex)) return false;
    if (u8[56] !== 0x0d || u8[57] !== 0x0a) return false;
    // Find matching user by computing sha224 of each uuid is expensive;
    // instead: get all active users and match hash (limit scan)
    let user = null;
    try {
      const { results } = await env.DB.prepare("SELECT * FROM users WHERE is_active=1 LIMIT 500").all();
      for (const u of results || []) {
        if (sha224(u.uuid) === hashHex.toLowerCase()) { user = u; break; }
      }
    } catch (_) { return false; }
    if (!(await checkUser(env, user))) { try { server.close(1008); } catch (_) {} return false; }
    username = user.username;
    let offset = 58;
    if (u8.byteLength <= offset + 3) return true;
    const cmd = u8[offset++]; // 0x01 CONNECT
    if (cmd !== 0x01) { try { server.close(1002); } catch (_) {} return false; }
    const atyp = u8[offset++];
    let host = "";
    try {
      if (atyp === 1) { host = `${u8[offset]}.${u8[offset+1]}.${u8[offset+2]}.${u8[offset+3]}`; offset += 4; }
      else if (atyp === 3) { const len = u8[offset++]; host = dec.decode(u8.slice(offset, offset + len)); offset += len; }
      else if (atyp === 4) {
        const parts = [];
        for (let i = 0; i < 8; i++) { parts.push(((u8[offset] << 8) | u8[offset+1]).toString(16)); offset += 2; }
        host = parts.join(":");
      } else return false;
    } catch (_) { return false; }
    if (u8.byteLength < offset + 4) return true;
    const port = (u8[offset] << 8) | u8[offset + 1];
    offset += 2;
    // trailing \r\n
    if (u8[offset] === 0x0d && u8[offset + 1] === 0x0a) offset += 2;
    return pipeRemote(host, port, u8.slice(offset), false, 0);
  };

  const processHeader = async (chunk) => {
    // Detect: VLESS starts with version byte 0/1 + UUID; Trojan starts with 56 hex chars
    const u8 = new Uint8Array(chunk);
    let ok = false;
    if (u8.byteLength >= 17 && (u8[0] === 0 || u8[0] === 1) && parseUUID(chunk)) {
      ok = await processVless(chunk);
    } else if (u8.byteLength >= 58) {
      ok = await processTrojan(chunk);
    }
    if (!ok) { try { server.close(1002); } catch (_) {} }
    return ok;
  };

  server.addEventListener("message", async (ev) => {
    try {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : enc.encode(String(ev.data));
      if (!headerDone) { headerDone = true; await processHeader(data); return; }
      if (remote) {
        const w = remote.writable.getWriter();
        await w.write(data); bytesUp += data.byteLength; w.releaseLock();
        maybeFlush();
      }
    } catch (_) { try { server.close(); } catch (__) {} }
  });
  server.addEventListener("close", () => { try { remote?.close?.(); } catch (_) {} scheduleFlush(); });
  server.addEventListener("error", () => { try { remote?.close?.(); } catch (_) {} scheduleFlush(); });
  if (earlyData?.byteLength) { headerDone = true; await processHeader(earlyData); }
  return new Response(null, { status: 101, webSocket: client });
}

/* ─── subscription builder ─── */
function userUsageVars(user) {
  const usedNum = Number(user.used_gb) || 0;
  const limNum = Number(user.limit_gb) || 0;
  const usedFmt = (n) => (n < 0.01 && n > 0 ? n.toFixed(4) : n.toFixed(2));
  const used = usedFmt(usedNum);
  const lim = limNum > 0 ? limNum + " Gig" : "∞";
  const remainGb = limNum > 0 ? usedFmt(Math.max(0, limNum - usedNum)) + " Gig" : "∞";
  let days = "∞";
  let expiryStr = "∞";
  let leftDays = -1;
  if (user.expiry_days > 0) {
    leftDays = Math.ceil((user.created_at + user.expiry_days * 86400000 - Date.now()) / 86400000);
    days = String(leftDays > 0 ? leftDays : 0);
    expiryStr = days + " days";
  }
  return {
    usage: used + "/" + lim,
    used: used + " Gig",
    remain: remainGb,
    expiry: expiryStr,
    days,
    USER: user.username,
    leftDays,
  };
}

function infoLineFromTemplate(tpl, user, prefix) {
  const uv = userUsageVars(user);
  const name = encodeURIComponent(applyTemplate(tpl, {
    PREFIX: prefix,
    USER: uv.USER,
    usage: uv.usage,
    used: uv.used,
    remain: uv.remain,
    expiry: uv.expiry,
    days: uv.days,
    USAGE: uv.usage,
    USED: uv.used,
    REMAIN: uv.remain,
    EXPIRY: uv.expiry,
    DAYS: uv.days,
  }));
  return `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=ws&path=%2F#${name}`;
}

function buildUserLinks(host, user, c) {
  const path = encodeURIComponent(WS);
  const ports = (c.ports || "443,80").split(/[,\s]+/).map((p) => parseInt(p, 10)).filter((p) => p > 0 && p < 65536);
  const clean = parseCleanLines(c.clean_ips);
  const protocol = (c.protocol || "vless").toLowerCase();
  const tpl = c.name_template || "{PREFIX} · {USER} · {IP_NAME}";
  const prefix = c.sub_prefix || "Leviko";
  const links = [];

  // custom info entries (display-only)
  const entries = Array.isArray(c.info_entries) ? c.info_entries : [];
  for (const e of entries) {
    if (e && String(e).trim()) links.push(infoLineFromTemplate(String(e).trim(), user, prefix));
  }

  const make = (addr, port, tls, ipName) => {
    const vars = {
      PREFIX: prefix,
      USER: user.username,
      PORT: String(port),
      PROTOCOL: protocol.toUpperCase(),
      HOST: host,
      IP: addr,
      IP_NAME: ipName || (addr === host ? "Core" : addr),
      FLAG: "", COUNTRY: "", CITY: "", ISP: "",
    };
    const name = encodeURIComponent(applyTemplate(tpl, vars).replace(/\s·\s$/g, "").replace(/^\s·\s/g, "").trim() || prefix);
    const fp = c.fingerprint || "chrome";
    if (protocol === "trojan") {
      if (tls) {
        return `trojan://${user.uuid}@${addr}:${port}?security=tls&sni=${host}&fp=${fp}&alpn=h2%2Chttp%2F1.1&type=ws&host=${host}&path=${path}#${name}`;
      }
      return `trojan://${user.uuid}@${addr}:${port}?security=none&type=ws&host=${host}&path=${path}#${name}`;
    }
    if (tls) {
      return `vless://${user.uuid}@${addr}:${port}?encryption=none&security=tls&sni=${host}&fp=${fp}&alpn=h2%2Chttp%2F1.1&type=ws&host=${host}&path=${path}#${name}`;
    }
    return `vless://${user.uuid}@${addr}:${port}?encryption=none&security=none&type=ws&host=${host}&path=${path}#${name}`;
  };

  if (clean.length) {
    for (const row of clean) {
      for (const port of (ports.length ? ports : [443])) {
        links.push(make(row.ip, port, port === 443 || port === 8443, row.name));
      }
    }
  } else {
    const mainPort = ports.includes(443) ? 443 : (ports[0] || 443);
    links.push(make(host, mainPort, mainPort === 443 || mainPort === 8443, "Core"));
    if (ports.includes(80) && mainPort !== 80) links.push(make(host, 80, false, "Core-80"));
  }

  const up = (c.upstream || "").split("\n").map((s) => s.trim()).filter((s) => /^(vless|trojan|vmess|ss):\/\//i.test(s));
  for (const line of up.slice(0, 50)) links.push(line);

  return links;
}

function isBrowserRequest(request) {
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  // known subscription / proxy clients → always return raw sub
  if (/v2ray|clash|sing-box|singbox|hiddify|nekobox|nekoray|shadowrocket|streisand|quantumult|surge|loon|stash|surfboard|okhttp|go-http-client|dart\/|axios|curl|wget|python-requests|librev2ray/.test(ua)) {
    return false;
  }
  // browsers
  if (/mozilla|chrome|safari|firefox|edg|opr|crios|fxios/.test(ua)) return true;
  const accept = (request.headers.get("Accept") || "").toLowerCase();
  if (accept.includes("text/html") && !accept.includes("text/plain")) return true;
  return false;
}

async function handleSub(url, env, request) {
  const name = (url.searchParams.get("sub") || "").trim();
  if (!name) return new Response("Missing ?sub=", { status: 400 });
  const user = await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR uuid=?")
    .bind(name, name).first();
  if (!user) return new Response("Not Found", { status: 404 });
  const c = await cfg(env.DB);

  // Browser → beautiful user status panel (like Marzban sub page)
  if (request && isBrowserRequest(request)) {
    return html(statusPage(user, c, url.origin));
  }

  if (user.is_active !== 1) return new Response("Not Found", { status: 404 });
  const links = buildUserLinks(url.hostname, user, c);
  const body = btoa(unescape(encodeURIComponent(links.join("\n"))));
  const expire = user.expiry_days > 0 ? Math.floor((user.created_at + user.expiry_days * 86400000) / 1000) : 0;
  const download = Math.floor((user.used_gb || 0) * 1073741824);
  const total = Math.floor((user.limit_gb || 0) * 1073741824);
  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo": `upload=0; download=${download}; total=${total}; expire=${expire}`,
      "profile-title": encodeURIComponent((c.sub_prefix || "Leviko") + " · " + user.username),
    },
  });
}

/* ─── Telegram bot (Mirza-style) ─── */
async function tgApi(token, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return r.json().catch(() => ({}));
}

async function ensureCustomer(db, tgId, name = "", referrer = "") {
  let c = await db.prepare("SELECT * FROM tg_customers WHERE tg_id=?").bind(tgId).first();
  if (!c) {
    await db.prepare(
      "INSERT INTO tg_customers (tg_id,balance,referrer,trial_used,state,state_data,discount,created_at,name) VALUES (?,?,?,0,'','','',?,?)"
    ).bind(tgId, 0, referrer || "", Date.now(), name || "").run();
    c = await db.prepare("SELECT * FROM tg_customers WHERE tg_id=?").bind(tgId).first();
  }
  return c;
}

async function setState(db, tgId, state, data = "") {
  await db.prepare("UPDATE tg_customers SET state=?, state_data=? WHERE tg_id=?")
    .bind(state || "", typeof data === "string" ? data : JSON.stringify(data), tgId).run();
}

async function getCustomer(db, tgId) {
  return db.prepare("SELECT * FROM tg_customers WHERE tg_id=?").bind(tgId).first();
}

function mainKeyboard(isAdmin) {
  const rows = [
    [{ text: "🛒 خرید اشتراک", callback_data: "shop", style: "primary" }],
    [{ text: "🎁 اکانت تست", callback_data: "trial", style: "success" }],
    [{ text: "📱 سرویس‌های من", callback_data: "mysub" }, { text: "💰 کیف پول", callback_data: "wallet" }],
    [{ text: "👥 دعوت دوستان", callback_data: "ref" }],
    [{ text: "📚 بخش آموزش", callback_data: "tutorial" }, { text: "🆘 پشتیبانی", callback_data: "support", style: "danger" }],
  ];
  if (isAdmin) rows.push([{ text: "🛠 پنل مدیریت", callback_data: "admin" }]);
  return { inline_keyboard: rows };
}

function backHome() {
  return { inline_keyboard: [[{ text: "🏠 منوی اصلی", callback_data: "home" }]] };
}

function planLabel(p) {
  return (p.btn_name && String(p.btn_name).trim()) || p.title || "پلن";
}

async function calcPlanPrice(db, plan, tgId) {
  let price = Number(plan.price) || 0;
  let discNote = "";
  const cu = await getCustomer(db, tgId);
  if (cu?.discount) {
    const d = await db.prepare("SELECT * FROM discounts WHERE code=? AND is_active=1").bind(cu.discount).first();
    if (d) {
      price = Math.max(0, Math.floor(price * (1 - d.percent / 100)));
      discNote = `\n🎫 تخفیف ${d.percent}٪ با کد <code>${d.code}</code>`;
    }
  }
  return { price, discNote, code: cu?.discount || "" };
}

async function checkChannel(token, channel, userId) {
  if (!channel) return true;
  const ch = channel.startsWith("@") ? channel : "@" + channel.replace(/^https?:\/\/t\.me\//, "");
  try {
    const r = await tgApi(token, "getChatMember", { chat_id: ch, user_id: Number(userId) });
    const st = r?.result?.status || "";
    return ["creator", "administrator", "member", "restricted"].includes(st);
  } catch (_) {
    return true;
  }
}

async function deliverService(env, c, host, tgId, plan, orderId) {
  const uname = ("u" + tgId.slice(-6) + "o" + orderId).replace(/[^a-zA-Z0-9_]/g, "").slice(0, 24);
  const id = uuid();
  const label = planLabel(plan);
  await env.DB.prepare(
    `INSERT INTO users (username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,tg_id)
     VALUES (?,?,?,0,?,?,1,?,?)`
  ).bind(uname, id, plan.gb || 10, plan.days || 30, Date.now(), label + " #" + orderId, tgId).run();
  if (orderId) await env.DB.prepare("UPDATE orders SET status='done', username=? WHERE id=?").bind(uname, orderId).run();
  const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(uname)}`;
  const caption =
    `✅ <b>سرویس با موفقیت ایجاد شد</b>\n\n` +
    `👤 نام کاربری سرویس : <code>${uname}</code>\n` +
    `🌿 نام سرویس: ${label}\n` +
    `⏳ مدت زمان: ${plan.days || 0} روز\n` +
    `🗜 حجم سرویس: ${plan.gb || 0} GB\n\n` +
    `🔗 لینک اتصال:\n\n` +
    `<code>${sub}</code>\n\n` +
    `🧑‍🦯 شما میتوانید شیوه اتصال را با فشردن دکمه زیر و انتخاب سیستم عامل خود دریافت کنید`;
  const kb = {
    inline_keyboard: [
      [{ text: "📚 بخش آموزش", callback_data: "tutorial" }],
      [{ text: "📱 سرویس‌های من", callback_data: "mysub" }, { text: "🏠 منو", callback_data: "home" }],
    ],
  };
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=320x320&margin=8&data=${encodeURIComponent(sub)}`;
  const photoRes = await tgApi(c.tg_token, "sendPhoto", {
    chat_id: tgId,
    photo: qrUrl,
    caption,
    parse_mode: "HTML",
    reply_markup: kb,
  });
  // fallback if photo failed
  if (!photoRes?.ok) {
    await tgApi(c.tg_token, "sendMessage", {
      chat_id: tgId,
      text: caption,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      reply_markup: kb,
    });
  }
  return uname;
}

async function handleTelegram(request, env) {
  const c = await cfg(env.DB);
  if (!c.tg_token) return json({ ok: false, error: "no token" });
  const update = await request.json().catch(() => null);
  if (!update) return json({ ok: true });

  const msg = update.message || update.callback_query?.message;
  const from = update.message?.from || update.callback_query?.from;
  const chatId = String(from?.id || update.message?.chat?.id || "");
  const text = (update.message?.text || "").trim();
  const data = update.callback_query?.data || "";
  const isAdmin = !!(c.tg_admin && chatId === String(c.tg_admin));
  const host = new URL(request.url).hostname;
  const botUsername = (await Store.get(env.DB, "tg_bot_username", "")) || "";

  const send = (txt, extra = {}) =>
    tgApi(c.tg_token, "sendMessage", {
      chat_id: chatId,
      text: txt,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      ...extra,
    });
  // پیام تحویل با عکس (QR) است؛ editMessageText روی عکس خطا می‌دهد → در آن حالت پیام جدید می‌فرستیم
  const isPhotoMsg = !!(msg && (msg.photo || msg.document || msg.video));
  const edit = async (txt, extra = {}) => {
    if (!msg?.message_id || isPhotoMsg) {
      return send(txt, extra);
    }
    const r = await tgApi(c.tg_token, "editMessageText", {
      chat_id: chatId,
      message_id: msg.message_id,
      text: txt,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      ...extra,
    });
    if (!r || r.ok === false) {
      return send(txt, extra);
    }
    return r;
  };

  if (update.callback_query) {
    await tgApi(c.tg_token, "answerCallbackQuery", { callback_query_id: update.callback_query.id });
  }

  // ensure customer + referral from /start CODE
  let refFromStart = "";
  if (text.startsWith("/start")) {
    const parts = text.split(/\s+/);
    if (parts[1] && /^\d+$/.test(parts[1]) && parts[1] !== chatId) refFromStart = parts[1];
  }
  const cust = await ensureCustomer(
    env.DB,
    chatId,
    [from?.first_name, from?.last_name].filter(Boolean).join(" "),
    refFromStart
  );

  // force channel join
  if (c.tg_channel && !isAdmin && (data === "shop" || data === "trial" || data.startsWith("buy_") || data === "wallet")) {
    const ok = await checkChannel(c.tg_token, c.tg_channel, chatId);
    if (!ok) {
      const ch = c.tg_channel.startsWith("@") ? c.tg_channel : "@" + c.tg_channel.replace(/^https?:\/\/t\.me\//, "");
      const link = ch.startsWith("@") ? `https://t.me/${ch.slice(1)}` : c.tg_channel;
      await send(
        `🔒 برای استفاده از ربات ابتدا در کانال عضو شوید:\n${link}`,
        {
          reply_markup: {
            inline_keyboard: [
              [{ text: "📢 عضویت در کانال", url: link }],
              [{ text: "✅ عضو شدم", callback_data: "home" }],
            ],
          },
        }
      );
      return json({ ok: true });
    }
  }

  // ── states (text input) ──
  if (text && !text.startsWith("/") && cust?.state) {
    const st = cust.state;
    if (st === "wait_discount") {
      const code = text.toUpperCase().replace(/\s/g, "");
      const pid = parseInt(cust.state_data || "0", 10);
      const d = await env.DB.prepare("SELECT * FROM discounts WHERE code=? AND is_active=1").bind(code).first();
      if (!d) {
        await send("❌ کد تخفیف معتبر نیست.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: pid ? "buy_" + pid : "shop" }]] },
        });
      } else if (d.max_uses > 0 && d.used_count >= d.max_uses) {
        await send("❌ ظرفیت این کد تمام شده.", {
          reply_markup: { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: pid ? "buy_" + pid : "shop" }]] },
        });
      } else {
        await env.DB.prepare("UPDATE tg_customers SET discount=? WHERE tg_id=?").bind(code, chatId).run();
        await setState(env.DB, chatId, "");
        if (pid) {
          const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(pid).first();
          if (plan) {
            const { price, discNote } = await calcPlanPrice(env.DB, plan, chatId);
            const label = planLabel(plan);
            await send(
              `✅ کد <b>${code}</b> اعمال شد (${d.percent}٪)\n\n` +
                `📦 <b>${label}</b>\n💰 مبلغ جدید: <b>${price.toLocaleString("fa-IR")}</b> تومان${discNote}\n\nروش پرداخت:`,
              {
                reply_markup: {
                  inline_keyboard: [
                    [{ text: "💳 کارت به کارت", callback_data: "paycard_" + pid }],
                    [{ text: "💰 پرداخت از کیف پول", callback_data: "paywallet_" + pid }],
                    [{ text: "🎫 تغییر کد تخفیف", callback_data: "discplan_" + pid }],
                    [{ text: "🔙 بازگشت", callback_data: "shop" }],
                  ],
                },
              }
            );
            return json({ ok: true });
          }
        }
        await send(`✅ کد <b>${code}</b> اعمال شد · ${d.percent}٪ تخفیف`, { reply_markup: backHome() });
      }
      await setState(env.DB, chatId, "");
      return json({ ok: true });
    }
    if (st === "wait_charge") {
      const amount = parseInt(text.replace(/[^\d]/g, ""), 10);
      if (!amount || amount < 10000) {
        await send("مبلغ نامعتبر. حداقل ۱۰٬۰۰۰ تومان:", { reply_markup: backHome() });
        return json({ ok: true });
      }
      await env.DB.prepare(
        "INSERT INTO orders (tg_id, plan_id, status, created_at, amount, kind, note) VALUES (?,?,?,?,?,?,?)"
      ).bind(chatId, 0, "pending", Date.now(), amount, "charge", "wallet").run();
      const order = await env.DB.prepare("SELECT id FROM orders WHERE tg_id=? ORDER BY id DESC LIMIT 1").bind(chatId).first();
      await setState(env.DB, chatId, "wait_receipt", String(order?.id || ""));
      const card = c.card || "کارت هنوز تنظیم نشده — به پشتیبانی پیام دهید";
      await send(
        `💳 <b>افزایش موجودی</b>\nمبلغ: <b>${amount.toLocaleString("fa-IR")}</b> تومان\nسفارش: #${order?.id}\n\n` +
          `به کارت زیر واریز کنید:\n<code>${card}</code>\n\nسپس <b>عکس رسید</b> را همین‌جا ارسال کنید.`,
        { reply_markup: backHome() }
      );
      return json({ ok: true });
    }
    if (st === "wait_support") {
      if (c.tg_admin) {
        await tgApi(c.tg_token, "sendMessage", {
          chat_id: c.tg_admin,
          text: `💬 پشتیبانی از <code>${chatId}</code> (${cust.name || "-"})\n\n${text}`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[{ text: "پاسخ", callback_data: "reply_" + chatId }]],
          },
        });
      }
      await setState(env.DB, chatId, "");
      await send("✅ پیام شما به پشتیبانی ارسال شد.", { reply_markup: backHome() });
      return json({ ok: true });
    }
    if (st === "wait_broadcast" && isAdmin) {
      const { results } = await env.DB.prepare("SELECT tg_id FROM tg_customers LIMIT 500").all();
      let n = 0;
      for (const u of results || []) {
        try {
          await tgApi(c.tg_token, "sendMessage", { chat_id: u.tg_id, text, parse_mode: "HTML" });
          n++;
        } catch (_) {}
      }
      await setState(env.DB, chatId, "");
      await send(`✅ پیام برای ${n} کاربر ارسال شد.`);
      return json({ ok: true });
    }
    if (st.startsWith("reply_") && isAdmin) {
      const target = st.slice(6);
      await tgApi(c.tg_token, "sendMessage", {
        chat_id: target,
        text: `📩 <b>پاسخ پشتیبانی:</b>\n\n${text}`,
        parse_mode: "HTML",
      });
      await setState(env.DB, chatId, "");
      await send("✅ پاسخ ارسال شد.");
      return json({ ok: true });
    }
  }

  // photo receipt
  if (update.message?.photo && cust?.state === "wait_receipt") {
    const orderId = cust.state_data;
    const photos = update.message.photo;
    const fileId = photos[photos.length - 1].file_id;
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(orderId).first();
    let planInfo = order?.note || "";
    if (order?.plan_id) {
      const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(order.plan_id).first();
      if (plan) {
        planInfo =
          `🌿 محصول: ${planLabel(plan)}\n` +
          `📊 حجم: ${plan.gb} GB\n` +
          `⏳ مدت: ${plan.days} روز\n` +
          `💰 مبلغ: ${Number(order.amount || plan.price || 0).toLocaleString("fa-IR")} تومان`;
      }
    } else if (order?.kind === "charge") {
      planInfo = `💰 افزایش موجودی: ${Number(order.amount || 0).toLocaleString("fa-IR")} تومان`;
    }
    if (c.tg_admin) {
      await tgApi(c.tg_token, "sendPhoto", {
        chat_id: c.tg_admin,
        photo: fileId,
        caption:
          `🧾 <b>رسید سفارش #${orderId}</b>\n` +
          `از: <code>${chatId}</code> (${cust.name || "-"})\n` +
          `نوع: ${order?.kind || "plan"}\n\n` +
          `${planInfo}`,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "✅ تایید", callback_data: "approve_" + orderId },
              { text: "❌ رد", callback_data: "reject_" + orderId },
            ],
          ],
        },
      });
    }
    await setState(env.DB, chatId, "");
    await send("✅ رسید دریافت شد. پس از تایید ادمین، سرویس/موجودی فعال می‌شود.", { reply_markup: backHome() });
    return json({ ok: true });
  }

  // ── /start & home ──
  if (text === "/start" || text.startsWith("/start ") || data === "home") {
    // referral bonus once
    if (refFromStart && cust.referrer === refFromStart) {
      const ref = await getCustomer(env.DB, refFromStart);
      if (ref) {
        const already = await Store.get(env.DB, "ref_paid_" + chatId, "");
        if (!already) {
          await env.DB.prepare("UPDATE tg_customers SET balance=balance+? WHERE tg_id=?")
            .bind(c.referral_bonus, refFromStart).run();
          await Store.set(env.DB, "ref_paid_" + chatId, "1");
          await tgApi(c.tg_token, "sendMessage", {
            chat_id: refFromStart,
            text: `🎁 یک نفر با لینک شما عضو شد! +${c.referral_bonus.toLocaleString("fa-IR")} تومان به کیف پولتان اضافه شد.`,
          });
        }
      }
    }
    const bal = (await getCustomer(env.DB, chatId))?.balance || 0;
    const welcome =
      `${c.tg_welcome}\n\n` +
      `👤 شناسه: <code>${chatId}</code>\n` +
      `💰 موجودی: <b>${Number(bal).toLocaleString("fa-IR")}</b> تومان\n\n` +
      `از منوی زیر انتخاب کنید:`;
    if (data === "home" && msg?.message_id) {
      await edit(welcome, { reply_markup: mainKeyboard(isAdmin) });
    } else {
      await send(welcome, { reply_markup: mainKeyboard(isAdmin) });
    }
    await setState(env.DB, chatId, "");
    return json({ ok: true });
  }

  // ── shop ──
  if (data === "shop") {
    const { results: plans } = await env.DB.prepare("SELECT * FROM plans WHERE is_active=1 ORDER BY price").all();
    if (!plans?.length) {
      await edit("فعلاً پلنی تعریف نشده. از پنل وب پلن بسازید.", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const rows = plans.map((p) => [
      {
        text: planLabel(p),
        callback_data: "buy_" + p.id,
        style: "primary",
      },
    ]);
    rows.push([{ text: "🏠 منو", callback_data: "home" }]);
    await edit("🛒 <b>خرید اشتراک</b>\nیک محصول انتخاب کنید:", { reply_markup: { inline_keyboard: rows } });
    return json({ ok: true });
  }

  if (data.startsWith("buy_")) {
    const pid = parseInt(data.slice(4), 10);
    const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=? AND is_active=1").bind(pid).first();
    if (!plan) {
      await edit("پلن نامعتبر", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const { price, discNote } = await calcPlanPrice(env.DB, plan, chatId);
    const label = planLabel(plan);
    await edit(
      `📦 <b>${label}</b>\n📊 ${plan.gb} GB · ⏳ ${plan.days} روز\n💰 مبلغ قابل پرداخت: <b>${price.toLocaleString("fa-IR")}</b> تومان${discNote}\n\nروش پرداخت را انتخاب کنید:`,
      {
        reply_markup: {
          inline_keyboard: [
            [{ text: "💳 کارت به کارت", callback_data: "paycard_" + pid }],
            [{ text: "💰 پرداخت از کیف پول", callback_data: "paywallet_" + pid }],
            [{ text: "🎫 وارد کردن کد تخفیف", callback_data: "discplan_" + pid }],
            [{ text: "🔙 بازگشت", callback_data: "shop" }],
          ],
        },
      }
    );
    return json({ ok: true });
  }

  if (data.startsWith("discplan_")) {
    const pid = parseInt(data.slice(9), 10);
    await setState(env.DB, chatId, "wait_discount", String(pid));
    await edit("🎫 کد تخفیف را وارد کنید:", {
      reply_markup: { inline_keyboard: [[{ text: "🔙 بازگشت", callback_data: "buy_" + pid }]] },
    });
    return json({ ok: true });
  }

  if (data.startsWith("paywallet_")) {
    const pid = parseInt(data.split("_")[1], 10);
    const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(pid).first();
    const cu = await getCustomer(env.DB, chatId);
    if (!plan) {
      await edit("پلن نامعتبر", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const { price } = await calcPlanPrice(env.DB, plan, chatId);
    if ((cu?.balance || 0) < price) {
      await edit(
        `موجودی کافی نیست.\nموجودی: ${(cu?.balance || 0).toLocaleString("fa-IR")} ت\nمبلغ: ${price.toLocaleString("fa-IR")} ت`,
        {
          reply_markup: {
            inline_keyboard: [
              [{ text: "💳 افزایش موجودی", callback_data: "wallet" }],
              [{ text: "🏠 منو", callback_data: "home" }],
            ],
          },
        }
      );
      return json({ ok: true });
    }
    await env.DB.prepare("UPDATE tg_customers SET balance=balance-?, discount='' WHERE tg_id=?")
      .bind(price, chatId).run();
    if (cu?.discount) {
      await env.DB.prepare("UPDATE discounts SET used_count=used_count+1 WHERE code=?").bind(cu.discount).run();
    }
    const note = `${planLabel(plan)} | ${plan.gb}GB | ${plan.days}روز`;
    await env.DB.prepare(
      "INSERT INTO orders (tg_id, plan_id, status, created_at, amount, kind, note) VALUES (?,?,?,?,?,?,?)"
    ).bind(chatId, pid, "done", Date.now(), price, "plan", note).run();
    const order = await env.DB.prepare("SELECT id FROM orders WHERE tg_id=? ORDER BY id DESC LIMIT 1").bind(chatId).first();
    await deliverService(env, c, host, chatId, plan, order?.id);
    await Store.log(env.DB, "tg_wallet_buy", chatId + ":" + pid);
    return json({ ok: true });
  }

  if (data.startsWith("paycard_")) {
    const pid = parseInt(data.split("_")[1], 10);
    const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(pid).first();
    if (!plan) {
      await edit("پلن نامعتبر", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const { price, discNote } = await calcPlanPrice(env.DB, plan, chatId);
    const label = planLabel(plan);
    const note = `${label} | ${plan.gb}GB | ${plan.days}روز | ${price}ت`;
    await env.DB.prepare(
      "INSERT INTO orders (tg_id, plan_id, status, created_at, amount, kind, note) VALUES (?,?,?,?,?,?,?)"
    ).bind(chatId, pid, "pending", Date.now(), price, "plan", note).run();
    const order = await env.DB.prepare("SELECT id FROM orders WHERE tg_id=? ORDER BY id DESC LIMIT 1").bind(chatId).first();
    await setState(env.DB, chatId, "wait_receipt", String(order?.id || ""));
    const card = c.card || "کارت تنظیم نشده";
    await edit(
      `💳 <b>پرداخت کارت به کارت</b>\n` +
        `سفارش: #${order?.id}\nمحصول: <b>${label}</b>\n📊 ${plan.gb} GB · ⏳ ${plan.days} روز\n` +
        `مبلغ: <b>${price.toLocaleString("fa-IR")}</b> تومان${discNote}\n\n` +
        `به این کارت واریز کنید:\n<code>${card}</code>\n\nسپس <b>عکس رسید</b> را ارسال کنید.`,
      { reply_markup: backHome() }
    );
    if (c.tg_admin) {
      await tgApi(c.tg_token, "sendMessage", {
        chat_id: c.tg_admin,
        text:
          `🛒 سفارش جدید #${order?.id}\n` +
          `از: <code>${chatId}</code>\n` +
          `🌿 محصول: ${label}\n` +
          `📊 حجم: ${plan.gb} GB\n` +
          `⏳ مدت: ${plan.days} روز\n` +
          `💰 مبلغ: ${price.toLocaleString("fa-IR")} تومان\nمنتظر رسید...`,
        parse_mode: "HTML",
      });
    }
    return json({ ok: true });
  }

  // ── trial ──
  if (data === "trial") {
    const cu = await getCustomer(env.DB, chatId);
    if (cu?.trial_used) {
      await edit("شما قبلاً اکانت تست دریافت کرده‌اید.", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const uname = ("trial" + chatId.slice(-8)).replace(/[^a-zA-Z0-9_]/g, "").slice(0, 20);
    const id = uuid();
    await env.DB.prepare(
      `INSERT INTO users (username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,tg_id)
       VALUES (?,?,?,0,?,?,1,?,?)`
    ).bind(uname, id, c.trial_gb, c.trial_days, Date.now(), "trial", chatId).run();
    await env.DB.prepare("UPDATE tg_customers SET trial_used=1 WHERE tg_id=?").bind(chatId).run();
    const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(uname)}`;
    await edit(
      `🎁 <b>اکانت تست فعال شد</b>\n📊 ${c.trial_gb} GB · ⏳ ${c.trial_days} روز\n\n🔗 <code>${sub}</code>`,
      { reply_markup: backHome() }
    );
    return json({ ok: true });
  }

  // ── my services ──
  if (data === "mysub") {
    const { results } = await env.DB.prepare("SELECT * FROM users WHERE tg_id=? ORDER BY id DESC LIMIT 20").bind(chatId).all();
    if (!results?.length) {
      await edit("سرویسی ندارید.", {
        reply_markup: {
          inline_keyboard: [
            [{ text: "🛒 خرید", callback_data: "shop" }],
            [{ text: "🏠 منو", callback_data: "home" }],
          ],
        },
      });
      return json({ ok: true });
    }
    let out = "<b>📱 سرویس‌های شما</b>\n\n";
    const rows = [];
    for (const u of results) {
      const used = (u.used_gb || 0).toFixed(2);
      const lim = u.limit_gb > 0 ? u.limit_gb : "∞";
      let days = "∞";
      if (u.expiry_days > 0) {
        const left = Math.ceil((u.created_at + u.expiry_days * 86400000 - Date.now()) / 86400000);
        days = String(left > 0 ? left : 0);
      }
      const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(u.username)}`;
      out += `👤 <code>${u.username}</code>\n📊 ${used}/${lim} GB · ⏳ ${days} روز\n🔗 <code>${sub}</code>\n\n`;
      rows.push([{ text: `📄 ${u.username}`, callback_data: "svc_" + u.id }]);
    }
    rows.push([{ text: "🏠 منو", callback_data: "home" }]);
    await edit(out, { reply_markup: { inline_keyboard: rows } });
    return json({ ok: true });
  }

  if (data.startsWith("svc_")) {
    const uid = parseInt(data.slice(4), 10);
    const u = await env.DB.prepare("SELECT * FROM users WHERE id=? AND tg_id=?").bind(uid, chatId).first();
    if (!u) {
      await edit("یافت نشد", { reply_markup: backHome() });
      return json({ ok: true });
    }
    const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(u.username)}`;
    const status = `https://${host}${ROOT}?u=${encodeURIComponent(u.username)}`;
    await edit(
      `👤 <code>${u.username}</code>\n📊 ${(u.used_gb || 0).toFixed(2)}/${u.limit_gb || "∞"} GB\n\n🔗 ساب:\n<code>${sub}</code>\n\n🌐 وضعیت:\n<code>${status}</code>`,
      {
        reply_markup: {
          inline_keyboard: [
            [{ text: "🔄 تمدید / حجم اضافه", callback_data: "shop" }],
            [{ text: "🔙 سرویس‌ها", callback_data: "mysub" }],
          ],
        },
      }
    );
    return json({ ok: true });
  }

  // ── wallet ──
  if (data === "wallet") {
    const cu = await getCustomer(env.DB, chatId);
    await edit(
      `💰 <b>کیف پول</b>\nموجودی: <b>${Number(cu?.balance || 0).toLocaleString("fa-IR")}</b> تومان\n\nبرای افزایش موجودی مبلغ را به تومان بفرستید (مثلاً 50000)`,
      {
        reply_markup: {
          inline_keyboard: [
            [{ text: "➕ افزایش موجودی", callback_data: "charge" }],
            [{ text: "🏠 منو", callback_data: "home" }],
          ],
        },
      }
    );
    return json({ ok: true });
  }
  if (data === "charge") {
    await setState(env.DB, chatId, "wait_charge");
    await edit("مبلغ افزایش موجودی را به تومان وارد کنید (حداقل ۱۰۰۰۰):", { reply_markup: backHome() });
    return json({ ok: true });
  }

  // ── referral ──
  if (data === "ref") {
    const link = botUsername
      ? `https://t.me/${botUsername}?start=${chatId}`
      : `لینک: /start را با کد ${chatId} برای دوست بفرستید`;
    await edit(
      `👥 <b>دعوت دوستان</b>\nبا هر دعوت موفق <b>${c.referral_bonus.toLocaleString("fa-IR")}</b> تومان پاداش می‌گیرید.\n\n🔗 لینک اختصاصی:\n<code>${link}</code>`,
      { reply_markup: backHome() }
    );
    return json({ ok: true });
  }

  // ── tutorial ──
  if (data === "tutorial") {
    const tut = c.tg_tutorial || "آموزش هنوز تنظیم نشده است.";
    await edit(`📚 <b>بخش آموزش</b>\n\n${tut}`, { reply_markup: backHome() });
    return json({ ok: true });
  }

  // ── support ──
  if (data === "support") {
    const support = c.tg_support || (c.tg_admin ? `شناسه ادمین: ${c.tg_admin}` : "پشتیبانی تنظیم نشده");
    await setState(env.DB, chatId, "wait_support");
    await edit(`🆘 <b>پشتیبانی</b>\n${support}\n\nپیام خود را بنویسید:`, {
      reply_markup: {
        inline_keyboard: [
          [{ text: "📚 بخش آموزش", callback_data: "tutorial" }],
          [{ text: "🏠 منوی اصلی", callback_data: "home" }],
        ],
      },
    });
    return json({ ok: true });
  }

  // ── admin approve / reject ──
  if (isAdmin && data.startsWith("approve_")) {
    const oid = parseInt(data.slice(8), 10);
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(oid).first();
    if (!order || order.status !== "pending") {
      await send("سفارش نامعتبر یا قبلاً پردازش شده");
      return json({ ok: true });
    }
    if (order.kind === "charge") {
      await env.DB.prepare("UPDATE tg_customers SET balance=balance+? WHERE tg_id=?")
        .bind(order.amount || 0, order.tg_id).run();
      await env.DB.prepare("UPDATE orders SET status='done' WHERE id=?").bind(oid).run();
      await tgApi(c.tg_token, "sendMessage", {
        chat_id: order.tg_id,
        text: `✅ افزایش موجودی تایید شد: +${Number(order.amount || 0).toLocaleString("fa-IR")} تومان`,
      });
      await send(`موجودی شارژ شد برای ${order.tg_id}`);
    } else {
      const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(order.plan_id).first();
      if (!plan) {
        await send("پلن یافت نشد");
        return json({ ok: true });
      }
      const cu = await getCustomer(env.DB, order.tg_id);
      if (cu?.discount) {
        await env.DB.prepare("UPDATE discounts SET used_count=used_count+1 WHERE code=?").bind(cu.discount).run();
        await env.DB.prepare("UPDATE tg_customers SET discount='' WHERE tg_id=?").bind(order.tg_id).run();
      }
      await deliverService(env, c, host, order.tg_id, plan, oid);
      await send(`تایید شد · سفارش #${oid}`);
    }
    await Store.log(env.DB, "tg_approve", String(oid));
    return json({ ok: true });
  }

  if (isAdmin && data.startsWith("reject_")) {
    const oid = parseInt(data.slice(7), 10);
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(oid).first();
    await env.DB.prepare("UPDATE orders SET status='rejected' WHERE id=?").bind(oid).run();
    if (order) {
      await tgApi(c.tg_token, "sendMessage", { chat_id: order.tg_id, text: `❌ سفارش #${oid} رد شد.` });
    }
    await send("رد شد");
    return json({ ok: true });
  }

  if (isAdmin && data.startsWith("reply_")) {
    await setState(env.DB, chatId, data);
    await send("پیام پاسخ را بنویسید:");
    return json({ ok: true });
  }

  // ── admin panel ──
  if (isAdmin && data === "admin") {
    const total = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    const pending = await env.DB.prepare("SELECT COUNT(*) as c FROM orders WHERE status='pending'").first();
    const customers = await env.DB.prepare("SELECT COUNT(*) as c FROM tg_customers").first();
    const bal = await env.DB.prepare("SELECT COALESCE(SUM(balance),0) as s FROM tg_customers").first();
    await edit(
      `<b>🛠 پنل مدیریت</b>\n\n` +
        `👥 مشتریان ربات: ${customers?.c || 0}\n` +
        `🔑 کانفیگ‌ها: ${total?.c || 0}\n` +
        `⏳ سفارش باز: ${pending?.c || 0}\n` +
        `💰 مجموع موجودی‌ها: ${Number(bal?.s || 0).toLocaleString("fa-IR")} ت\n\n` +
        `وب: <code>https://${host}${DASH}</code>`,
      {
        reply_markup: {
          inline_keyboard: [
            [{ text: "📋 سفارش‌های باز", callback_data: "adm_orders" }],
            [{ text: "📢 پیام همگانی", callback_data: "adm_broadcast" }],
            [{ text: "🎫 ساخت کد تخفیف", callback_data: "adm_disc" }],
            [{ text: "🏠 منو", callback_data: "home" }],
          ],
        },
      }
    );
    return json({ ok: true });
  }

  if (isAdmin && data === "adm_orders") {
    const { results } = await env.DB.prepare(
      "SELECT * FROM orders WHERE status='pending' ORDER BY id DESC LIMIT 15"
    ).all();
    if (!results?.length) {
      await edit("سفارش بازی نیست.", { reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "admin" }]] } });
      return json({ ok: true });
    }
    const rows = results.map((o) => [
      {
        text: `#${o.id} · ${o.kind} · ${o.amount || 0}ت · ${o.tg_id}`,
        callback_data: "adm_ord_" + o.id,
      },
    ]);
    rows.push([{ text: "🔙", callback_data: "admin" }]);
    await edit("📋 سفارش‌های در انتظار:", { reply_markup: { inline_keyboard: rows } });
    return json({ ok: true });
  }

  if (isAdmin && data.startsWith("adm_ord_")) {
    const oid = parseInt(data.slice(8), 10);
    const o = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(oid).first();
    if (!o) {
      await edit("یافت نشد", { reply_markup: backHome() });
      return json({ ok: true });
    }
    await edit(
      `سفارش #${o.id}\nنوع: ${o.kind}\nمبلغ: ${o.amount}\nکاربر: <code>${o.tg_id}</code>\nوضعیت: ${o.status}`,
      {
        reply_markup: {
          inline_keyboard: [
            [
              { text: "✅ تایید", callback_data: "approve_" + oid },
              { text: "❌ رد", callback_data: "reject_" + oid },
            ],
            [{ text: "🔙", callback_data: "adm_orders" }],
          ],
        },
      }
    );
    return json({ ok: true });
  }

  if (isAdmin && data === "adm_broadcast") {
    await setState(env.DB, chatId, "wait_broadcast");
    await edit("متن پیام همگانی را بفرستید:", { reply_markup: backHome() });
    return json({ ok: true });
  }

  if (isAdmin && data === "adm_disc") {
    const code = "OFF" + Math.random().toString(36).slice(2, 8).toUpperCase();
    await env.DB.prepare(
      "INSERT OR REPLACE INTO discounts (code,percent,max_uses,used_count,is_active) VALUES (?,?,?,?,1)"
    ).bind(code, 20, 50, 0).run();
    await edit(`🎫 کد ساخته شد:\n<code>${code}</code>\n۲۰٪ تخفیف · حداکثر ۵۰ استفاده`, {
      reply_markup: { inline_keyboard: [[{ text: "🔙", callback_data: "admin" }]] },
    });
    return json({ ok: true });
  }

  // fallback
  if (text) {
    await send("از دکمه‌های منو استفاده کنید 👇", { reply_markup: mainKeyboard(isAdmin) });
  }
  return json({ ok: true });
}


/* ─── API ─── */
async function handleApi(request, url, env) {
  const path = url.pathname.replace(/^\/api/, "") || "/";
  const method = request.method;

  if (path === "/setup" && method === "POST") {
    if (await Store.get(env.DB, "admin_pass")) return json({ error: "already configured" }, 400);
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "admin").trim();
    const password = String(body.password || "").trim();
    if (!okName(username) || password.length < 4) return json({ error: "invalid" }, 400);
    await Store.set(env.DB, "admin_user", await sha256(username));
    await Store.set(env.DB, "admin_pass", await sha256(password));
    await Store.set(env.DB, "admin_user_plain", username);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(await token(env.DB)) });
  }
  if (path === "/bootstrap" && method === "POST") {
    if (await Store.get(env.DB, "admin_pass")) return json({ ok: true, already: true });
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || env.ADMIN_USER || "admin").trim();
    const password = String(body.password || env.ADMIN_PASS || "").trim();
    if (password.length < 4) return json({ error: "password required" }, 400);
    await Store.set(env.DB, "admin_user", await sha256(username));
    await Store.set(env.DB, "admin_pass", await sha256(password));
    await Store.set(env.DB, "admin_user_plain", username);
    return json({ ok: true });
  }
  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const uh = await Store.get(env.DB, "admin_user");
    const ph = await Store.get(env.DB, "admin_pass");
    if (!uh || !ph) return json({ error: "setup" }, 400);
    if ((await sha256(String(body.username || ""))) !== uh || (await sha256(String(body.password || ""))) !== ph)
      return json({ error: "wrong" }, 401);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(await token(env.DB)) });
  }
  if (path === "/logout" && method === "POST")
    return json({ ok: true }, 200, { "Set-Cookie": "lv_session=; Path=/; Max-Age=0" });

  // telegram webhook (no session)
  if (path === "/telegram" && method === "POST") return handleTelegram(request, env);

  const sess = await getSession(request, env.DB);
  if (sess.needSetup) return json({ error: "setup" }, 403);
  if (!sess.ok) return json({ error: "unauthorized" }, 401);

  if (path === "/stats" && method === "GET") {
    const total = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    const active = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE is_active=1").first();
    const inactive = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE is_active=0").first();
    const now = Date.now();
    const allU = await env.DB.prepare("SELECT is_active, expiry_days, created_at, used_gb, limit_gb FROM users").all();
    let expired = 0;
    for (const u of (allU.results || [])) {
      if (u.expiry_days > 0 && now > u.created_at + u.expiry_days * 86400000) expired++;
    }
    const traffic = await env.DB.prepare("SELECT COALESCE(SUM(used_gb),0) as s FROM users").first();
    const pending = await env.DB.prepare("SELECT COUNT(*) as c FROM orders WHERE status='pending'").first();
    const c = await cfg(env.DB);
    // CF free tier daily request estimate is not exposed via Workers runtime; show placeholder from setting
    const cfUsed = parseInt(await Store.get(env.DB, "cf_req_used", "0") || "0", 10) || 0;
    const cfLimit = parseInt(await Store.get(env.DB, "cf_req_limit", "100000") || "100000", 10) || 100000;
    return json({
      users: total?.c || 0,
      active: active?.c || 0,
      inactive: inactive?.c || 0,
      expired,
      traffic: +(Number(traffic?.s) || 0).toFixed(3),
      pending: pending?.c || 0,
      cf_used: cfUsed,
      cf_limit: cfLimit,
      cf_left: Math.max(0, cfLimit - cfUsed),
      kill: c.kill, version: V, protocol: c.protocol,
    });
  }

  if (path === "/users" && method === "GET") {
    try {
      const { results } = await env.DB.prepare(
        "SELECT id,username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,last_active,tg_id FROM users ORDER BY id DESC"
      ).all();
      return json({ users: results || [] });
    } catch (e) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT id,username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,last_active FROM users ORDER BY id DESC"
        ).all();
        return json({ users: (results || []).map(u => ({ ...u, tg_id: '' })) });
      } catch (e2) {
        const { results } = await env.DB.prepare(
          "SELECT id,username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active FROM users ORDER BY id DESC"
        ).all();
        return json({ users: (results || []).map(u => ({ ...u, remark: '', last_active: 0, tg_id: '' })) });
      }
    }
  }
  if (path === "/users" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    if (!okName(username)) return json({ error: "invalid username" }, 400);
    const id = body.uuid && /^[0-9a-f-]{36}$/i.test(body.uuid) ? body.uuid : uuid();
    try {
      await env.DB.prepare(
        `INSERT INTO users (username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark)
         VALUES (?,?,?,0,?,?,1,?)`
      ).bind(username, id, Math.max(0, parseFloat(body.limit_gb) || 0), Math.max(0, parseInt(body.expiry_days, 10) || 0), Date.now(), String(body.remark || "").slice(0, 120)).run();
      await Store.log(env.DB, "user_create", username);
      return json({ ok: true, uuid: id, username });
    } catch (e) {
      return json({ error: String(e.message || e).includes("UNIQUE") ? "exists" : String(e.message || e) }, 400);
    }
  }
  if (path.startsWith("/users/") && method === "PATCH") {
    const id = path.split("/")[2];
    if (!/^\d+$/.test(id)) return json({ error: "bad id" }, 400);
    const body = await request.json().catch(() => ({}));
    const f = [], v = [];
    if (body.is_active !== undefined) { f.push("is_active=?"); v.push(body.is_active ? 1 : 0); }
    if (body.limit_gb !== undefined) { f.push("limit_gb=?"); v.push(Math.max(0, parseFloat(body.limit_gb) || 0)); }
    if (body.expiry_days !== undefined) { f.push("expiry_days=?"); v.push(Math.max(0, parseInt(body.expiry_days, 10) || 0)); }
    if (body.remark !== undefined) { f.push("remark=?"); v.push(String(body.remark).slice(0, 120)); }
    if (body.reset_traffic) f.push("used_gb=0");
    if (!f.length) return json({ error: "nothing" }, 400);
    v.push(id);
    await env.DB.prepare(`UPDATE users SET ${f.join(",")} WHERE id=?`).bind(...v).run();
    return json({ ok: true });
  }
  if (path.startsWith("/users/") && method === "DELETE") {
    const id = path.split("/")[2];
    await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
    return json({ ok: true });
  }

  if (path === "/settings" && method === "GET") {
    const c = await cfg(env.DB);
    return json({
      ...c,
      admin_user: await Store.get(env.DB, "admin_user_plain", "admin"),
      version: V,
    });
  }
  if (path === "/settings" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const map = {
      protocol: "protocol", ports: "ports", clean_ips: "clean_ips", upstream: "upstream",
      sub_prefix: "sub_prefix", panel_title: "panel_title", name_template: "name_template", fingerprint: "fingerprint",
      tg_token: "tg_token", tg_admin: "tg_admin", tg_welcome: "tg_welcome", pay_card: "pay_card",
      tg_channel: "tg_channel", tg_support: "tg_support",
      trial_gb: "trial_gb", trial_days: "trial_days", referral_bonus: "referral_bonus",
      tg_tutorial: "tg_tutorial",
    };
    for (const [k, sk] of Object.entries(map)) {
      if (body[k] !== undefined) await Store.set(env.DB, sk, String(body[k]));
    }
    if (body.info_entries !== undefined) {
      const arr = Array.isArray(body.info_entries) ? body.info_entries.map(String).slice(0, 20) : [];
      await Store.set(env.DB, "info_entries", JSON.stringify(arr));
    }
    if (body.info_cfg !== undefined) await Store.set(env.DB, "info_cfg", body.info_cfg ? "1" : "0");
    if (body.kill_switch !== undefined) {
      await Store.set(env.DB, "kill_switch", body.kill_switch ? "1" : "0");
      await Store.log(env.DB, body.kill_switch ? "kill_on" : "kill_off", "");
    }
    return json({ ok: true });
  }
  if (path === "/admin" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    if (username && okName(username)) {
      await Store.set(env.DB, "admin_user", await sha256(username));
      await Store.set(env.DB, "admin_user_plain", username);
    }
    if (password.length >= 4) await Store.set(env.DB, "admin_pass", await sha256(password));
    return json({ ok: true }, 200, { "Set-Cookie": cookie(await token(env.DB)) });
  }

  if (path === "/plans" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM plans ORDER BY id").all();
    return json({ plans: results || [] });
  }
  if (path === "/plans" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const title = String(body.title || "Plan").slice(0, 60);
    const btnName = String(body.btn_name || body.btnName || title).slice(0, 64);
    await env.DB.prepare("INSERT INTO plans (title,days,gb,price,is_active,btn_name) VALUES (?,?,?,?,1,?)")
      .bind(
        title,
        Math.max(1, parseInt(body.days, 10) || 30),
        Math.max(0, parseFloat(body.gb) || 10),
        Math.max(0, parseInt(body.price, 10) || 0),
        btnName
      ).run();
    return json({ ok: true });
  }
  if (path.startsWith("/plans/") && method === "DELETE") {
    await env.DB.prepare("DELETE FROM plans WHERE id=?").bind(path.split("/")[2]).run();
    return json({ ok: true });
  }

  if (path === "/orders" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT 100").all();
    return json({ orders: results || [] });
  }

  if (path === "/tg-webhook" && method === "POST") {
    const c = await cfg(env.DB);
    if (!c.tg_token) return json({ error: "no token" }, 400);
    const hook = `${url.origin}/api/telegram`;
    const r = await tgApi(c.tg_token, "setWebhook", { url: hook, drop_pending_updates: true });
    try {
      const me = await tgApi(c.tg_token, "getMe", {});
      if (me?.result?.username) await Store.set(env.DB, "tg_bot_username", me.result.username);
    } catch (_) {}
    return json(r);
  }

  if (path === "/logs" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 100").all();
    return json({ logs: results || [] });
  }
  if (path === "/export" && method === "GET") {
    const { results } = await env.DB.prepare("SELECT username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark FROM users").all();
    return json({ version: V, users: results || [] });
  }
  if (path === "/import" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    let n = 0;
    for (const u of (body.users || []).slice(0, 500)) {
      if (!okName(u.username)) continue;
      try {
        await env.DB.prepare(
          `INSERT OR IGNORE INTO users (username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark)
           VALUES (?,?,?,?,?,?,?,?)`
        ).bind(u.username, u.uuid || uuid(), u.limit_gb || 0, u.used_gb || 0, u.expiry_days || 0, u.created_at || Date.now(), u.is_active === 0 ? 0 : 1, String(u.remark || "").slice(0, 120)).run();
        n++;
      } catch (_) {}
    }
    return json({ ok: true, imported: n });
  }

  return json({ error: "not found" }, 404);
}

/* ─── UI ─── */
function css() {
  return `
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;800&display=swap');
:root{--bg:#05050a;--card:rgba(18,18,32,.88);--line:rgba(255,255,255,.08);--txt:#f4f2ff;--mut:#9a96b5;--faint:#5c5878;
--p:#8b5cf6;--p2:#a78bfa;--ok:#34d399;--err:#f87171;--warn:#fbbf24;--r:18px;--rs:12px;--font:Vazirmatn,system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--font);background:var(--bg);color:var(--txt);min-height:100vh;line-height:1.55}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background:
radial-gradient(ellipse 60% 40% at 10% 0%,rgba(139,92,246,.2),transparent 55%),
radial-gradient(ellipse 50% 35% at 95% 90%,rgba(52,211,153,.06),transparent 50%),
radial-gradient(ellipse 40% 30% at 50% 50%,rgba(99,102,241,.05),transparent 60%)}
.scene{position:relative;z-index:1;max-width:1040px;margin:0 auto;padding:22px 14px 70px}
.glass{background:linear-gradient(155deg,rgba(255,255,255,.05),rgba(255,255,255,.015));border:1px solid var(--line);
border-radius:var(--r);backdrop-filter:blur(24px) saturate(1.3);box-shadow:0 12px 40px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.06)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 15px;border:none;border-radius:var(--rs);
font:700 .86rem var(--font);cursor:pointer;transition:.2s}
.btn-a{background:linear-gradient(135deg,#a78bfa,#7c3aed);color:#fff;box-shadow:0 6px 22px rgba(139,92,246,.35)}
.btn-a:hover{filter:brightness(1.08);transform:translateY(-1px)}
.btn-g{background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--mut)}
.btn-g:hover{border-color:var(--p);color:var(--p2)}
.btn-d{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.3);color:var(--err)}
.btn-w{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.3);color:var(--warn)}
input,select,textarea{width:100%;padding:11px 13px;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:var(--rs);
color:var(--txt);font:400 .9rem var(--font);outline:none}
input:focus,textarea:focus,select:focus{border-color:var(--p);box-shadow:0 0 0 3px rgba(139,92,246,.18)}
label{display:block;font-size:.74rem;font-weight:600;color:var(--mut);margin-bottom:5px}
.tabs{display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;padding:4px;background:rgba(255,255,255,.03);border-radius:999px;border:1px solid var(--line)}
.tab{padding:8px 14px;border-radius:999px;border:none;background:transparent;color:var(--mut);font:700 .8rem var(--font);cursor:pointer}
.tab.on{background:linear-gradient(135deg,#8b5cf6,#6d28d9);color:#fff;box-shadow:0 4px 14px rgba(139,92,246,.35)}
`;
}

function authPage(setup) {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko</title><style>${css()}
.box{max-width:400px;margin:12vh auto;padding:34px 28px;text-align:center}
.logo{width:68px;height:68px;margin:0 auto 16px;border-radius:20px;overflow:hidden;box-shadow:0 14px 40px rgba(139,92,246,.35);background:#111;
transform:perspective(420px) rotateY(-10deg) rotateX(8deg)}
h1{font-size:1.4rem;font-weight:800;margin-bottom:6px}p{color:var(--mut);margin-bottom:16px}
.field{text-align:right;margin-bottom:12px}.err{color:var(--err);font-size:.85rem;margin-top:10px;display:none}
</style></head><body><div class="scene"><div class="glass box">
<div class="logo"><img src="${LOGO}" alt="logo" width="68" height="68" style="width:100%;height:100%;object-fit:cover;border-radius:20px;display:block"></div><h1>Leviko</h1><p>${setup ? "ساخت حساب ادمین" : "ورود به پنل"}</p>
<div class="field"><label>نام کاربری</label><input id="user" value="${setup ? "admin" : ""}"></div>
<div class="field"><label>رمز عبور</label><input type="password" id="pass" onkeydown="if(event.key==='Enter')go()"></div>
${setup ? '<div class="field"><label>تکرار رمز</label><input type="password" id="pass2"></div>' : ""}
<div class="err" id="err"></div>
<button class="btn btn-a" style="width:100%;margin-top:8px" onclick="go()">${setup ? "ذخیره و ورود" : "ورود"}</button>
</div></div><script>
async function go(){
  const user=document.getElementById('user').value.trim(),pass=document.getElementById('pass').value,e=document.getElementById('err');
  ${setup ? `if(pass.length<4){e.style.display='block';e.textContent='حداقل ۴ کاراکتر';return}if(pass!==document.getElementById('pass2').value){e.style.display='block';e.textContent='رمزها یکسان نیستند';return}` : ""}
  const r=await fetch('/api/${setup ? "setup" : "login"}',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
  const j=await r.json().catch(()=>({}));if(!r.ok){e.style.display='block';e.textContent=j.error||'خطا';return}location.href='${DASH}';
}</script></body></html>`;
}

function panelPage() {
  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leviko Panel</title><style>${css()}
.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.brand{display:flex;align-items:center;gap:12px}
.brand .mark{width:46px;height:46px;border-radius:15px;overflow:hidden;box-shadow:0 10px 28px rgba(139,92,246,.35);background:#111;flex-shrink:0;
transform:perspective(320px) rotateY(-12deg) rotateX(6deg)}
.brand h1{font-size:1.2rem;font-weight:800}.brand span{font-size:.7rem;color:var(--mut);letter-spacing:.08em}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px}
.stat{padding:16px 12px;text-align:center;position:relative;overflow:hidden;border-radius:16px}
.stat .n{font-size:1.45rem;font-weight:800}
.stat .l{font-size:.72rem;margin-top:3px;opacity:.85}
.stat-blue{border-color:rgba(96,165,250,.35)!important;background:linear-gradient(160deg,rgba(59,130,246,.14),rgba(255,255,255,.02))}
.stat-blue .n{color:#60a5fa}.stat-blue .l{color:#93c5fd}
.stat-green{border-color:rgba(52,211,153,.35)!important;background:linear-gradient(160deg,rgba(16,185,129,.14),rgba(255,255,255,.02))}
.stat-green .n{color:#34d399}.stat-green .l{color:#6ee7b7}
.stat-red{border-color:rgba(248,113,113,.35)!important;background:linear-gradient(160deg,rgba(239,68,68,.14),rgba(255,255,255,.02))}
.stat-red .n{color:#f87171}.stat-red .l{color:#fca5a5}
.stat-gray{border-color:rgba(148,163,184,.3)!important;background:linear-gradient(160deg,rgba(100,116,139,.14),rgba(255,255,255,.02))}
.stat-gray .n{color:#94a3b8}.stat-gray .l{color:#cbd5e1}
.stat-orange{border-color:rgba(251,146,60,.35)!important;background:linear-gradient(160deg,rgba(249,115,22,.14),rgba(255,255,255,.02))}
.stat-orange .n{color:#fb923c}.stat-orange .l{color:#fdba74}
.ip-row{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.ip-row input{flex:1}
.ip-list{margin-top:10px}
.ip-item{display:flex;justify-content:space-between;align-items:center;padding:8px 10px;margin-bottom:6px;border-radius:10px;background:rgba(255,255,255,.03);border:1px solid var(--line);font-size:.84rem}
.ip-item code{color:var(--p2)}
.toolbar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th{text-align:right;padding:10px;color:var(--mut);font-weight:600;border-bottom:1px solid var(--line);font-size:.72rem}
td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:3px 9px;border-radius:99px;font-size:.7rem;font-weight:700}
.badge-on{background:rgba(52,211,153,.12);color:var(--ok)}.badge-off{background:rgba(248,113,113,.12);color:var(--err)}
.acts{display:flex;gap:5px;flex-wrap:wrap}.acts button{padding:5px 9px;font-size:.72rem;border-radius:8px}
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:50;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}.modal{width:100%;max-width:460px;padding:22px;max-height:90vh;overflow-y:auto}
.modal h3{font-size:1.05rem;font-weight:800;margin-bottom:14px}.modal .field{margin-bottom:11px}
.modal .row{display:flex;gap:10px;margin-top:14px}.modal .row .btn{flex:1}
.empty{text-align:center;padding:36px;color:var(--mut)}.sec{display:none}.sec.on{display:block}
.kill{display:none;padding:11px 14px;margin-bottom:12px;border-radius:12px;background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.35);color:var(--warn);font-size:.85rem;font-weight:600}
.kill.on{display:block}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.card-in{padding:16px}.card-in h4{font-size:.92rem;font-weight:800;margin-bottom:10px;color:var(--p2)}
.help q,.help p{color:var(--mut);font-size:.88rem;margin-bottom:10px}.help b{color:var(--txt)}
@media(max-width:720px){.stats{grid-template-columns:1fr 1fr}.grid2{grid-template-columns:1fr}.ip-row{flex-direction:column}}
</style></head><body><div class="scene">
<div class="top">
  <div class="brand"><div class="mark"><img src="${LOGO}" alt="logo" width="46" height="46" style="width:100%;height:100%;object-fit:cover;border-radius:15px;display:block"></div><div><h1 id="title">Leviko</h1><span>PANEL · v${V}</span></div></div>
  <button class="btn btn-g" onclick="logout()">خروج</button>
</div>
<div class="kill" id="killBanner">⚠ Kill Switch فعال — ترافیک پروکسی متوقف است</div>
<div class="tabs">
  <button class="tab on" data-t="users" onclick="tab('users')">کاربران</button>
  <button class="tab" data-t="adv" onclick="tab('adv')">پیشرفته</button>
  <button class="tab" data-t="tg" onclick="tab('tg')">تلگرام</button>
  <button class="tab" data-t="sys" onclick="tab('sys')">سیستم</button>
  <button class="tab" data-t="help" onclick="tab('help')">راهنما</button>
</div>

<div class="sec on" id="sec-users">
  <div class="stats">
    <div class="glass stat stat-blue"><div class="n" id="sUsers">—</div><div class="l">کل کاربران</div></div>
    <div class="glass stat stat-green"><div class="n" id="sActive">—</div><div class="l">فعال</div></div>
    <div class="glass stat stat-red"><div class="n" id="sInactive">—</div><div class="l">غیرفعال</div></div>
    <div class="glass stat stat-gray"><div class="n" id="sExpired">—</div><div class="l">منقضی</div></div>
    <div class="glass stat stat-orange"><div class="n" id="sTraffic">—</div><div class="l">مصرف حجم GB</div></div>
    <div class="glass stat stat-orange"><div class="n" id="sCf">—</div><div class="l">درخواست CF (باقی)</div></div>
  </div>
  <div class="toolbar">
    <button class="btn btn-a" onclick="openCreate()">+ کاربر</button>
    <button class="btn btn-g" onclick="loadUsers()">↻</button>
    <button class="btn btn-g" onclick="doExport()">Export</button>
    <button class="btn btn-g" onclick="document.getElementById('imp').click()">Import</button>
    <input type="file" id="imp" accept="application/json" hidden onchange="doImport(event)">
  </div>
  <div class="glass" style="padding:6px 0;overflow-x:auto">
  <table><thead><tr><th>کاربر</th><th>وضعیت</th><th>حجم</th><th>روز</th><th>عملیات</th></tr></thead>
  <tbody id="tbody"></tbody></table></div>
</div>

<div class="sec" id="sec-adv">
  <div class="grid2">
    <div class="glass card-in">
      <h4>🌐 شبکه و DNS — آی‌پی‌های تمیز</h4>
      <div class="ip-row">
        <input id="cipIp" dir="ltr" style="text-align:left" placeholder="1.2.3.4">
        <input id="cipName" dir="ltr" style="text-align:left" placeholder="Name (Optional)">
        <button type="button" class="btn btn-a" style="width:auto;padding:10px 14px" onclick="addCleanIp()">+</button>
      </div>
      <div class="field"><label>لیست (هر خط یا با کاما)</label>
        <textarea id="cleanIps" rows="4" placeholder="1.2.3.4#Tehran" dir="ltr" style="text-align:left"></textarea></div>
      <div class="ip-list" id="cipPreview"></div>
      <p style="font-size:.75rem;color:var(--faint);margin-top:8px">آی‌پی را با کاما یا خط جدید جدا کنید. لینک ساب برای همه ترکیب می‌سازد. با پر شدن لیست، کانفیگ Core حذف می‌شود.</p>
      <div class="field" style="margin-top:12px"><label>امضای امنیتی (Fingerprint)</label>
        <select id="fpSel"><option>chrome</option><option>firefox</option><option>safari</option><option>ios</option><option>android</option><option>edge</option><option>random</option></select></div>
    </div>
    <div class="glass card-in">
      <h4>🔗 آپ‌استریم</h4>
      <div class="field"><label>لینک کانفیگ اضافه (هر خط)</label>
        <textarea id="upstream" rows="7" placeholder="vless://...&#10;trojan://..."></textarea></div>
      <p style="font-size:.75rem;color:var(--faint)">به انتهای ساب اضافه می‌شود.</p>
    </div>
  </div>

  <div class="glass card-in" style="margin-top:12px">
    <h4>✏️ اشتراک — نام‌گذاری کانفیگ</h4>
    <div class="field"><label>قالب نام</label>
      <input id="nameTpl" dir="ltr" style="text-align:left" placeholder="{PREFIX} · {USER} · {IP_NAME}"></div>
    <div id="varChips" style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 12px"></div>
    <div class="grid2">
      <div class="field"><label>پیشوند {PREFIX}</label><input id="subPrefix" placeholder="Leviko"></div>
      <div class="field"><label>پروتکل</label>
        <select id="protocol"><option value="vless">VLESS</option><option value="trojan">Trojan</option></select></div>
      <div class="field"><label>پورت‌ها</label><input id="ports" placeholder="443,80"></div>
    </div>
  </div>

  <div class="glass card-in" style="margin-top:12px">
    <h4>📊 ورودی‌های اطلاعاتی اشتراک</h4>
    <p style="font-size:.78rem;color:var(--mut);margin-bottom:10px">ردیف‌های نمایشی (غیرقابل‌اتصال). از <code>{usage}</code> و <code>{expiry}</code> استفاده کن.</p>
    <div id="infoList"></div>
    <button class="btn btn-g" style="margin-top:8px" type="button" onclick="addInfoRow()">+ افزودن ورودی</button>
  </div>

  <button class="btn btn-a" style="margin-top:14px;width:100%" onclick="saveAdv()">ذخیره تنظیمات پیشرفته</button>
</div>

<div class="sec" id="sec-tg">
  <div class="glass card-in">
    <h4>ربات فروش تلگرام (پیشرفته)</h4>
    <div class="grid2">
      <div class="field"><label>Bot Token</label><input id="tgToken" dir="ltr" style="text-align:left"></div>
      <div class="field"><label>Admin Chat ID</label><input id="tgAdmin" dir="ltr" style="text-align:left"></div>
      <div class="field"><label>کانال اجباری (@channel)</label><input id="tgChannel" dir="ltr" style="text-align:left" placeholder="@mychannel"></div>
      <div class="field"><label>آیدی پشتیبانی</label><input id="tgSupport" dir="ltr" style="text-align:left"></div>
      <div class="field"><label>حجم تست (GB)</label><input id="trialGb" type="number" value="1" step="0.1"></div>
      <div class="field"><label>روز تست</label><input id="trialDays" type="number" value="1"></div>
      <div class="field"><label>پاداش دعوت (تومان)</label><input id="refBonus" type="number" value="5000"></div>
      <div class="field"><label>شماره کارت</label><input id="payCard" dir="ltr" style="text-align:left"></div>
    </div>
    <div class="field"><label>پیام خوش‌آمد</label><input id="tgWelcome"></div>
    <div class="field"><label>متن بخش آموزش 📚 (نمایش در ربات)</label>
      <textarea id="tgTutorial" rows="5" placeholder="آموزش اتصال به کلاینت‌ها..."></textarea></div>
    <div class="toolbar" style="margin-top:8px">
      <button class="btn btn-a" onclick="saveTg()">ذخیره ربات</button>
      <button class="btn btn-g" onclick="setHook()">فعال‌سازی Webhook</button>
    </div>
  </div>
  <div class="glass card-in" style="margin-top:12px">
    <h4>پلن‌های فروش</h4>
    <div class="field"><label>نام نمایشی در ربات (همین متن روی دکمه خرید نشان داده می‌شود)</label>
      <input id="planBtnName" placeholder="مثلاً: یک‌ماهه طلایی"></div>
    <div class="grid2">
      <div class="field"><label>عنوان داخلی</label><input id="planTitle" placeholder="ماهانه"></div>
      <div class="field"><label>قیمت (تومان)</label><input id="planPrice" type="number" value="50000"></div>
      <div class="field"><label>حجم GB</label><input id="planGb" type="number" value="30"></div>
      <div class="field"><label>روز</label><input id="planDays" type="number" value="30"></div>
    </div>
    <button class="btn btn-a" style="margin-top:8px" onclick="addPlan()">+ افزودن پلن</button>
    <div id="planList" style="margin-top:14px"></div>
  </div>
  <div class="glass card-in" style="margin-top:12px">
    <h4>سفارش‌ها</h4>
    <div id="orderList" style="font-size:.85rem;color:var(--mut)">—</div>
  </div>
</div>

<div class="sec" id="sec-sys">
  <div class="glass card-in">
    <div class="field"><label>عنوان پنل</label><input id="panelTitle"></div>
    <div class="field" style="display:flex;align-items:center;gap:10px">
      <input type="checkbox" id="killSwitch" style="width:auto"><label for="killSwitch" style="margin:0">Kill Switch</label>
    </div>
    <hr style="border:none;border-top:1px solid var(--line);margin:16px 0">
    <div class="field"><label>یوزر ادمین جدید</label><input id="setUser"></div>
    <div class="field"><label>پسورد جدید</label><input type="password" id="setPass"></div>
    <button class="btn btn-a" style="margin-top:10px" onclick="saveSys()">ذخیره سیستم</button>
  </div>
  <div class="glass card-in" style="margin-top:12px">
    <h4>لاگ</h4>
    <div id="logBox" style="font-size:.8rem;color:var(--mut);max-height:220px;overflow:auto">—</div>
  </div>
</div>

<div class="sec help" id="sec-help">
  <div class="glass card-in">
    <h4 style="margin-bottom:12px">راهنما و سوالات</h4>
    <p><b>پنل کجاست؟</b><br>مسیر <code>/8080/dash</code></p>
    <p><b>سابسکریپشن؟</b><br><code>/8080?sub=USERNAME</code></p>
    <p><b>Clean IP</b><br>هر خط IP یا IP#نام. نام در {IP_NAME} می‌آید. با پر شدن لیست، کانفیگ Core حذف می‌شود. ورودی‌های اطلاعاتی با {usage}/{expiry} قابل تنظیم‌اند.</p>
    <p><b>کانفیگ نمایش حجم</b><br>یک ردیف غیرقابل‌اتصال است که نامش حجم مصرفی و روز باقی‌مانده را نشان می‌دهد.</p>
    <p><b>آپ‌استریم</b><br>لینک‌های vless/trojan اضافی را خط‌به‌خط بچسبان تا به ساب اضافه شوند.</p>
    <p><b>ربات تلگرام</b><br>توکن ربات + Chat ID ادمین را بگذار، Webhook را فعال کن، پلن بساز. کاربر خرید می‌کند و تو تایید می‌کنی.</p>
    <p><b>Binding</b><br>متغیر D1 باید دقیقاً <code>DB</code> باشد.</p>
    <p><b>پروتکل و پورت</b><br>از تب پیشرفته VLESS یا Trojan و پورت‌های دلخواه را تنظیم کن.</p>
  </div>
</div>
</div>

<div class="modal-bg" id="modal"><div class="glass modal">
  <h3>کاربر جدید</h3>
  <div class="field"><label>نام کاربری</label><input id="fUser"></div>
  <div class="field"><label>سقف GB (۰=∞)</label><input id="fLimit" type="number" value="10" min="0" step="0.1"></div>
  <div class="field"><label>روز (۰=∞)</label><input id="fDays" type="number" value="30" min="0"></div>
  <div class="field"><label>یادداشت</label><input id="fRemark"></div>
  <div class="row"><button class="btn btn-a" onclick="saveUser()">ذخیره</button><button class="btn btn-g" onclick="closeModal()">لغو</button></div>
</div></div>

<script>
const root = location.protocol + '//' + location.host;
const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  try {
    const r = await fetch('/api' + path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      credentials: 'same-origin'
    });
    if (r.status === 401) { location.href = '${DASH}'; return null; }
    const j = await r.json().catch(() => ({}));
    return j;
  } catch (e) {
    console.error('api', path, e);
    return null;
  }
}

function tab(n) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('on', t.getAttribute('data-t') === n));
  document.querySelectorAll('.sec').forEach(s => s.classList.toggle('on', s.id === 'sec-' + n));
  if (n === 'adv' || n === 'sys' || n === 'tg') loadSettings();
  if (n === 'tg') { loadPlans(); loadOrders(); }
  if (n === 'sys') loadLogs();
}

async function logout() {
  await api('/logout', { method: 'POST' });
  location.reload();
}

async function loadUsers() {
  const s = await api('/stats');
  if (s) {
  if ($('sUsers')) $('sUsers').textContent = s.users ?? '—';
  if ($('sActive')) $('sActive').textContent = s.active ?? '—';
  if ($('sInactive')) $('sInactive').textContent = s.inactive ?? '—';
  if ($('sExpired')) $('sExpired').textContent = s.expired ?? '—';
  if ($('sTraffic')) $('sTraffic').textContent = s.traffic ?? '—';
  if ($('sCf')) {
    var left = s.cf_left != null ? s.cf_left : '—';
    var used = s.cf_used != null ? s.cf_used : 0;
    var lim = s.cf_limit != null ? s.cf_limit : 100000;
    // LTR mark so RTL layout doesn't reverse numbers
    $('sCf').textContent = '\u200E' + used + ' / ' + lim;
    $('sCf').parentElement.querySelector('.l').textContent = 'درخواست CF · باقی ' + left;
  }
  if ($('killBanner')) $('killBanner').classList.toggle('on', !!s.kill);
  }

  const u = await api('/users');
  const tb = $('tbody');
  if (!tb) return;
  if (!u || !u.users || !u.users.length) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">کاربری نیست</td></tr>';
    return;
  }
  var list = Array.isArray(u.users) ? u.users : [];
  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">کاربری نیست</td></tr>';
    return;
  }
  tb.innerHTML = list.map(function (x) {
    var usedNum = Number(x.used_gb) || 0;
    var used = usedNum < 0.01 && usedNum > 0 ? usedNum.toFixed(4) : usedNum.toFixed(2);
    var lim = Number(x.limit_gb) > 0 ? x.limit_gb : '∞';
    var days = '∞';
    var isExp = false;
    if (Number(x.expiry_days) > 0) {
      var left = Math.ceil((Number(x.created_at) + Number(x.expiry_days) * 86400000 - Date.now()) / 86400000);
      days = left > 0 ? left : 0;
      isExp = left <= 0;
    }
    var st = isExp
      ? '<span class="badge" style="background:rgba(148,163,184,.15);color:#94a3b8">منقضی</span>'
      : (Number(x.is_active) === 1
        ? '<span class="badge badge-on">فعال</span>'
        : '<span class="badge badge-off">غیرفعال</span>');
    var sub = root + '${ROOT}?sub=' + encodeURIComponent(x.username);
    var stUrl = root + '${ROOT}?u=' + encodeURIComponent(x.username);
    return '<tr><td><strong>' + x.username + '</strong><br><span style="font-size:.68rem;color:var(--faint)">' +
      String(x.uuid).slice(0, 8) + '…</span></td><td>' + st + '</td><td>' + used + '/' + lim +
      '</td><td>' + days + '</td><td class="acts">' +
      '<button type="button" class="btn btn-g" data-sub="' + sub.replace(/"/g, '') + '">ساب</button>' +
      '<button type="button" class="btn btn-g" data-status="' + stUrl.replace(/"/g, '') + '">وضعیت</button>' +
      '<button type="button" class="btn btn-g" data-toggle="' + x.id + '" data-v="' + (x.is_active ? 0 : 1) + '">' +
      (x.is_active ? 'قطع' : 'فعال') + '</button>' +
      '<button type="button" class="btn btn-g" data-reset="' + x.id + '">ریست</button>' +
      '<button type="button" class="btn btn-d" data-del="' + x.id + '">حذف</button></td></tr>';
  }).join('');

  tb.onclick = function (ev) {
    var t = ev.target.closest('button');
    if (!t) return;
    if (t.dataset.sub) copy(t.dataset.sub);
    if (t.dataset.status) window.open(t.dataset.status, '_blank');
    if (t.dataset.toggle) toggle(+t.dataset.toggle, +t.dataset.v);
    if (t.dataset.reset) resetT(+t.dataset.reset);
    if (t.dataset.del) del(+t.dataset.del);
  };
}

function openCreate() {
  if ($('fUser')) $('fUser').value = '';
  if ($('fRemark')) $('fRemark').value = '';
  if ($('fLimit')) $('fLimit').value = 10;
  if ($('fDays')) $('fDays').value = 30;
  if ($('modal')) $('modal').classList.add('open');
}
function closeModal() {
  if ($('modal')) $('modal').classList.remove('open');
}

async function saveUser() {
  var body = {
    username: ($('fUser') && $('fUser').value || '').trim(),
    limit_gb: parseFloat($('fLimit') && $('fLimit').value) || 0,
    expiry_days: parseInt($('fDays') && $('fDays').value, 10) || 0,
    remark: ($('fRemark') && $('fRemark').value || '').trim()
  };
  if (!body.username) { alert('نام لازم است'); return; }
  var r = await api('/users', { method: 'POST', body: JSON.stringify(body) });
  if (r && r.error) { alert(r.error); return; }
  closeModal();
  loadUsers();
}

async function toggle(id, v) {
  await api('/users/' + id, { method: 'PATCH', body: JSON.stringify({ is_active: v }) });
  loadUsers();
}
async function resetT(id) {
  await api('/users/' + id, { method: 'PATCH', body: JSON.stringify({ reset_traffic: true }) });
  loadUsers();
}
async function del(id) {
  if (!confirm('حذف شود؟')) return;
  await api('/users/' + id, { method: 'DELETE' });
  loadUsers();
}
function copy(t) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(t).then(function () { alert('کپی شد'); }).catch(function () { prompt('کپی', t); });
  } else prompt('کپی', t);
}

var NAME_VARS = ['FLAG', 'COUNTRY', 'CITY', 'ISP', 'PROTOCOL', 'USER', 'PORT', 'PREFIX', 'IP', 'IP_NAME', 'HOST'];

function renderChips() {
  var box = $('varChips');
  if (!box) return;
  box.innerHTML = NAME_VARS.map(function (v) {
    return '<button type="button" class="btn btn-g" style="padding:5px 10px;font-size:.72rem;font-family:monospace" data-var="{' + v + '}">' + v + '</button>';
  }).join('');
  box.onclick = function (ev) {
    var b = ev.target.closest('button[data-var]');
    if (b) insertVar(b.getAttribute('data-var'));
  };
}

function insertVar(v) {
  var el = $('nameTpl');
  if (!el) return;
  var start = el.selectionStart || el.value.length;
  var end = el.selectionEnd || start;
  el.value = el.value.slice(0, start) + v + el.value.slice(end);
  el.focus();
  try { el.setSelectionRange(start + v.length, start + v.length); } catch (e) {}
}

function renderInfoRows(list) {
  var box = $('infoList');
  if (!box) return;
  if (!list || !list.length) list = ['📊 {used} / {remain}', '⏳ {expiry}'];
  box.innerHTML = list.map(function (t, i) {
    return '<div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">' +
      '<input data-info="' + i + '" value="' + String(t).replace(/"/g, '&quot;') + '" dir="ltr" style="text-align:left;flex:1">' +
      '<button type="button" class="btn btn-d" style="padding:6px 10px" data-rm="1">×</button></div>';
  }).join('');
  box.onclick = function (ev) {
    if (ev.target.getAttribute('data-rm')) ev.target.parentElement.remove();
  };
}

function addInfoRow() {
  var box = $('infoList');
  if (!box) return;
  var div = document.createElement('div');
  div.style.cssText = 'display:flex;gap:8px;margin-bottom:8px;align-items:center';
  div.innerHTML = '<input value="" dir="ltr" style="text-align:left;flex:1" placeholder="{usage} / {expiry}">' +
    '<button type="button" class="btn btn-d" style="padding:6px 10px" data-rm="1">×</button>';
  box.appendChild(div);
}

function collectInfo() {
  return Array.prototype.map.call(document.querySelectorAll('#infoList input'), function (i) {
    return i.value.trim();
  }).filter(Boolean);
}

function addCleanIp() {
  var ip = ($('cipIp') && $('cipIp').value || '').trim();
  var name = ($('cipName') && $('cipName').value || '').trim();
  if (!ip) { alert('IP را وارد کن'); return; }
  var line = name ? (ip + '#' + name) : ip;
  var ta = $('cleanIps');
  if (!ta) return;
  var cur = ta.value.trim();
  ta.value = cur ? (cur + '\\n' + line) : line;
  $('cipIp').value = '';
  $('cipName').value = '';
  previewCleanIps();
}

function previewCleanIps() {
  var box = $('cipPreview');
  var ta = $('cleanIps');
  if (!box || !ta) return;
  var lines = ta.value.split(/[\\n,]+/).map(function (s) { return s.trim(); }).filter(Boolean);
  box.innerHTML = lines.length
    ? ('<span class="badge badge-on" style="margin-bottom:8px;display:inline-block">' + lines.length + ' کانفیگ</span>')
    : '';
}

async function loadSettings() {
  var s = await api('/settings');
  if (!s) return;
  if ($('cleanIps')) $('cleanIps').value = s.clean_ips || '';
  if ($('fpSel') && s.fingerprint) $('fpSel').value = s.fingerprint;
  previewCleanIps();
  if ($('cleanIps')) $('cleanIps').oninput = previewCleanIps;
  if ($('upstream')) $('upstream').value = s.upstream || '';
  if ($('protocol')) $('protocol').value = s.protocol || 'vless';
  if ($('ports')) $('ports').value = s.ports || '443,80';
  if ($('subPrefix')) $('subPrefix').value = s.sub_prefix || 'Leviko';
  if ($('nameTpl')) $('nameTpl').value = s.name_template || '{PREFIX} · {USER} · {IP_NAME}';
  renderChips();
  renderInfoRows(Array.isArray(s.info_entries) ? s.info_entries : []);
  if ($('panelTitle')) $('panelTitle').value = s.title || s.panel_title || 'Leviko';
  if ($('killSwitch')) $('killSwitch').checked = !!s.kill;
  if ($('setUser')) $('setUser').value = s.admin_user || '';
  if ($('title')) $('title').textContent = ($('panelTitle') && $('panelTitle').value) || 'Leviko';
  if ($('tgToken')) $('tgToken').value = s.tg_token || '';
  if ($('tgAdmin')) $('tgAdmin').value = s.tg_admin || '';
  if ($('tgWelcome')) $('tgWelcome').value = s.tg_welcome || '';
  if ($('payCard')) $('payCard').value = s.card || s.pay_card || '';
  if ($('tgChannel')) $('tgChannel').value = s.tg_channel || '';
  if ($('tgSupport')) $('tgSupport').value = s.tg_support || '';
  if ($('trialGb')) $('trialGb').value = s.trial_gb != null ? s.trial_gb : 1;
  if ($('trialDays')) $('trialDays').value = s.trial_days != null ? s.trial_days : 1;
  if ($('refBonus')) $('refBonus').value = s.referral_bonus != null ? s.referral_bonus : 5000;
  if ($('tgTutorial')) $('tgTutorial').value = s.tg_tutorial || '';
}

async function saveAdv() {
  await api('/settings', {
    method: 'POST',
    body: JSON.stringify({
      clean_ips: $('cleanIps') ? $('cleanIps').value : '',
      upstream: $('upstream') ? $('upstream').value : '',
      protocol: $('protocol') ? $('protocol').value : 'vless',
      ports: $('ports') ? $('ports').value : '443,80',
      sub_prefix: $('subPrefix') ? $('subPrefix').value : 'Leviko',
      name_template: $('nameTpl') ? $('nameTpl').value : '',
      fingerprint: $('fpSel') ? $('fpSel').value : 'chrome',
      info_entries: collectInfo(),
      info_cfg: collectInfo().length > 0
    })
  });
  alert('ذخیره شد');
}

async function saveSys() {
  await api('/settings', {
    method: 'POST',
    body: JSON.stringify({
      panel_title: $('panelTitle') ? $('panelTitle').value : '',
      kill_switch: $('killSwitch') ? $('killSwitch').checked : false
    })
  });
  var user = $('setUser') ? $('setUser').value.trim() : '';
  var pass = $('setPass') ? $('setPass').value : '';
  if (user || pass) {
    await api('/admin', { method: 'POST', body: JSON.stringify({ username: user, password: pass }) });
  }
  alert('ذخیره شد');
  loadUsers();
}

async function saveTg() {
  await api('/settings', {
    method: 'POST',
    body: JSON.stringify({
      tg_token: $('tgToken') ? $('tgToken').value.trim() : '',
      tg_admin: $('tgAdmin') ? $('tgAdmin').value.trim() : '',
      tg_welcome: $('tgWelcome') ? $('tgWelcome').value : '',
      pay_card: $('payCard') ? $('payCard').value.trim() : '',
      tg_channel: $('tgChannel') ? $('tgChannel').value.trim() : '',
      tg_support: $('tgSupport') ? $('tgSupport').value.trim() : '',
      trial_gb: $('trialGb') ? $('trialGb').value : '1',
      trial_days: $('trialDays') ? $('trialDays').value : '1',
      referral_bonus: $('refBonus') ? $('refBonus').value : '5000',
      tg_tutorial: $('tgTutorial') ? $('tgTutorial').value : ''
    })
  });
  alert('ذخیره شد');
}

async function setHook() {
  var r = await api('/tg-webhook', { method: 'POST', body: '{}' });
  alert((r && (r.ok || r.result)) ? 'Webhook فعال شد' : JSON.stringify(r));
}

async function loadPlans() {
  var r = await api('/plans');
  var box = $('planList');
  if (!box) return;
  if (!r || !r.plans || !r.plans.length) {
    box.innerHTML = '<div class="empty">پلنی نیست</div>';
    return;
  }
  box.innerHTML = r.plans.map(function (p) {
    var btn = (p.btn_name && String(p.btn_name).trim()) || p.title;
    return '<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)">' +
      '<span><b>' + btn + '</b><br><span style="font-size:.75rem;color:var(--mut)">' + p.title + ' · ' + p.gb + 'GB · ' + p.days + 'روز · ' + Number(p.price).toLocaleString('fa-IR') + 'ت</span></span>' +
      '<button type="button" class="btn btn-d" style="padding:4px 8px;font-size:.7rem" data-plan-del="' + p.id + '">حذف</button></div>';
  }).join('');
  box.onclick = function (ev) {
    var b = ev.target.closest('[data-plan-del]');
    if (b) delPlan(+b.getAttribute('data-plan-del'));
  };
}

async function addPlan() {
  var title = $('planTitle') ? $('planTitle').value : 'Plan';
  var btnName = $('planBtnName') ? $('planBtnName').value.trim() : '';
  await api('/plans', {
    method: 'POST',
    body: JSON.stringify({
      title: title || 'Plan',
      btn_name: btnName || title || 'Plan',
      price: $('planPrice') ? +$('planPrice').value : 0,
      gb: $('planGb') ? +$('planGb').value : 10,
      days: $('planDays') ? +$('planDays').value : 30
    })
  });
  if ($('planBtnName')) $('planBtnName').value = '';
  loadPlans();
}

async function delPlan(id) {
  await api('/plans/' + id, { method: 'DELETE' });
  loadPlans();
}

async function loadOrders() {
  var r = await api('/orders');
  var box = $('orderList');
  if (!box) return;
  if (!r || !r.orders || !r.orders.length) {
    box.textContent = 'خالی';
    return;
  }
  box.innerHTML = r.orders.slice(0, 20).map(function (o) {
    return '#' + o.id + ' · tg:' + o.tg_id + ' · ' + o.status + ' · ' + (o.username || '-');
  }).join('<br>');
}

async function loadLogs() {
  var r = await api('/logs');
  var box = $('logBox');
  if (!box) return;
  if (!r || !r.logs || !r.logs.length) {
    box.textContent = '—';
    return;
  }
  box.innerHTML = r.logs.map(function (l) {
    return new Date(l.ts).toLocaleString('fa-IR') + ' — ' + l.action + ' ' + (l.detail || '');
  }).join('<br>');
}

async function doExport() {
  var r = await api('/export');
  if (!r) return;
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }));
  a.download = 'leviko.json';
  a.click();
}

async function doImport(ev) {
  var f = ev.target.files[0];
  if (!f) return;
  try {
    var data = JSON.parse(await f.text());
    var r = await api('/import', { method: 'POST', body: JSON.stringify(data) });
    alert('وارد شد: ' + ((r && r.imported) || 0));
    loadUsers();
  } catch (e) {
    alert('فایل نامعتبر');
  }
}

// wire static buttons that use onclick in HTML still work (global functions)
document.addEventListener('DOMContentLoaded', function () {
  loadUsers();
});
// also run immediately (DOM already parsed when script is at end)
loadUsers();
</script></body></html>`;
}

function statusPage(user, c, origin) {
  const uv = userUsageVars(user);
  const used = Number(user.used_gb) || 0;
  const lim = Number(user.limit_gb) || 0;
  const pct = lim > 0 ? Math.min(100, Math.round((used / lim) * 100)) : 0;
  const subUrl = origin + ROOT + "?sub=" + encodeURIComponent(user.username);
  const title = c.title || "Leviko";
  const active = user.is_active === 1 && (uv.leftDays < 0 || uv.leftDays > 0);
  const statusTxt = !user.is_active ? "غیرفعال" : (uv.leftDays === 0 ? "منقضی" : "فعال");
  const statusClr = !user.is_active || uv.leftDays === 0 ? "#f87171" : "#34d399";

  return `<!DOCTYPE html><html lang="fa" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${user.username}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;700;800&display=swap');
:root{--bg:#06060c;--card:rgba(20,20,36,.92);--line:rgba(255,255,255,.08);--txt:#f4f2ff;--mut:#9a96b5;--p:#8b5cf6;--ok:#34d399;--err:#f87171}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Vazirmatn,system-ui,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;line-height:1.6}
body::before{content:'';position:fixed;inset:0;pointer-events:none;background:radial-gradient(ellipse 55% 40% at 15% 0%,rgba(139,92,246,.22),transparent 55%),radial-gradient(ellipse 45% 35% at 90% 100%,rgba(52,211,153,.07),transparent 50%)}
.wrap{position:relative;z-index:1;max-width:520px;margin:0 auto;padding:24px 16px 60px}
.brand{text-align:center;margin-bottom:22px}
.brand .logo{width:64px;height:64px;margin:0 auto 12px;border-radius:18px;overflow:hidden;box-shadow:0 12px 36px rgba(139,92,246,.35);background:#111}
.brand h1{font-size:1.35rem;font-weight:800}.brand p{color:var(--mut);font-size:.88rem}
.card{background:linear-gradient(155deg,rgba(255,255,255,.06),rgba(255,255,255,.015));border:1px solid var(--line);border-radius:18px;padding:18px;margin-bottom:14px;backdrop-filter:blur(20px)}
.card h3{font-size:.95rem;font-weight:800;margin-bottom:12px;color:#c4b5fd}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:.9rem}
.row .l{color:var(--mut)}.row .v{font-weight:700}
.badge{display:inline-block;padding:4px 12px;border-radius:99px;font-size:.75rem;font-weight:700;background:rgba(52,211,153,.12);color:var(--ok)}
.bar{height:10px;background:rgba(255,255,255,.06);border-radius:99px;overflow:hidden;margin:10px 0 4px}
.bar>i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,#a78bfa,#7c3aed);width:${pct}%}
.subbox{display:flex;gap:8px;margin-top:10px}
.subbox input{flex:1;padding:11px 12px;background:rgba(0,0,0,.35);border:1px solid var(--line);border-radius:12px;color:var(--txt);font:400 .78rem monospace;direction:ltr;text-align:left}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:11px 16px;border:none;border-radius:12px;font:700 .86rem Vazirmatn;cursor:pointer;background:linear-gradient(135deg,#a78bfa,#7c3aed);color:#fff;box-shadow:0 6px 20px rgba(139,92,246,.35)}
.btn:active{transform:scale(.97)}
.btn-g{background:rgba(255,255,255,.05);border:1px solid var(--line);color:var(--mut);box-shadow:none}
.clients{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.cli{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 10px;border-radius:14px;background:rgba(255,255,255,.03);border:1px solid var(--line);text-decoration:none;color:var(--txt);transition:.2s}
.cli:hover{border-color:var(--p);background:rgba(139,92,246,.08)}
.cli svg{width:36px;height:36px}
.cli span{font-size:.78rem;font-weight:700;text-align:center}
.cli small{font-size:.65rem;color:var(--mut)}
.steps{counter-reset:s}
.steps li{list-style:none;position:relative;padding:10px 12px 10px 44px;margin-bottom:8px;background:rgba(255,255,255,.03);border-radius:12px;font-size:.84rem;color:var(--mut)}
.steps li::before{counter-increment:s;content:counter(s);position:absolute;right:12px;top:50%;transform:translateY(-50%);width:24px;height:24px;border-radius:8px;background:rgba(139,92,246,.2);color:#c4b5fd;font-weight:800;font-size:.75rem;display:grid;place-items:center}
.qr{text-align:center;margin-top:12px}
.qr img{width:160px;height:160px;border-radius:12px;background:#fff;padding:8px}
.foot{text-align:center;margin-top:20px;color:var(--mut);font-size:.75rem}
</style></head><body><div class="wrap">
<div class="brand">
  <div class="logo"><img src="${LOGO}" alt="logo" width="64" height="64" style="width:100%;height:100%;object-fit:cover;border-radius:18px;display:block"></div>
  <h1>${title}</h1>
  <p>پنل کاربری · ${user.username}</p>
</div>

<div class="card">
  <div class="row"><span class="l">وضعیت</span><span class="badge" style="background:${statusClr}22;color:${statusClr}">${statusTxt}</span></div>
  <div class="row"><span class="l">حجم مصرف‌شده</span><span class="v">${uv.used}</span></div>
  <div class="row"><span class="l">سقف حجم</span><span class="v">${lim > 0 ? lim + " Gig" : "∞"}</span></div>
  <div class="row"><span class="l">باقی‌مانده</span><span class="v">${uv.remain}</span></div>
  ${lim > 0 ? `<div class="bar"><i></i></div><div class="row"><span class="l">پیشرفت</span><span class="v">${pct}%</span></div>` : ""}
  <div class="row" style="margin-top:8px"><span class="l">روز باقی‌مانده</span><span class="v">${uv.expiry}</span></div>
</div>

<div class="card">
  <h3>لینک اشتراک</h3>
  <div class="subbox">
    <input id="sub" readonly value="${subUrl}" onclick="this.select()">
    <button class="btn" onclick="copySub()">کپی</button>
  </div>
  <div class="qr"><img src="https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(subUrl)}" alt="QR" width="160" height="160"></div>
</div>

<div class="card">
  <h3>دانلود کلاینت</h3>
  <div class="clients">
    <a class="cli" href="https://github.com/2dust/v2rayNG/releases" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#3DDC84"/><path d="M7 8h10v2H7V8zm0 3h10v2H7v-2zm0 3h7v2H7v-2z" fill="#fff"/></svg>
      <span>v2rayNG</span><small>اندروید</small>
    </a>
    <a class="cli" href="https://apps.apple.com/app/streisand/id6450534064" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#007AFF"/><path d="M12 6c.8 0 1.5.3 2 .9.5-.4 1.2-.7 2-.7 1.5 0 2.7 1.2 2.7 2.7 0 2.3-2.1 4.2-5.2 7.1L12 17.5l-1.5-1.5C7.4 12.9 5.3 11 5.3 8.9 5.3 7.4 6.5 6.2 8 6.2c.8 0 1.5.3 2 .7.5-.6 1.2-.9 2-.9z" fill="#fff"/></svg>
      <span>Streisand</span><small>آیفون</small>
    </a>
    <a class="cli" href="https://github.com/2dust/v2rayN/releases" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#0078D4"/><path d="M4 7l8-3 8 3v5c0 4.5-3.2 8.2-8 9.5C7.2 20.2 4 16.5 4 12V7z" fill="#fff" opacity=".9"/></svg>
      <span>v2rayN</span><small>ویندوز</small>
    </a>
    <a class="cli" href="https://github.com/hiddify/hiddify-next/releases" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#6366f1"/><circle cx="12" cy="12" r="5" stroke="#fff" stroke-width="2"/><path d="M12 7v5l3 2" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>
      <span>Hiddify</span><small>همه پلتفرم</small>
    </a>
    <a class="cli" href="https://github.com/MatsuriDayo/NekoBoxForAndroid/releases" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#f59e0b"/><path d="M8 9h8v6H8z" fill="#fff"/><circle cx="10" cy="12" r="1" fill="#f59e0b"/><circle cx="14" cy="12" r="1" fill="#f59e0b"/></svg>
      <span>NekoBox</span><small>اندروید</small>
    </a>
    <a class="cli" href="https://apps.apple.com/app/shadowrocket/id932747118" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="6" fill="#1c1c1e"/><path d="M12 5l7 14H5L12 5z" fill="#fff"/></svg>
      <span>Shadowrocket</span><small>آیفون</small>
    </a>
  </div>
</div>

<div class="card">
  <h3>آموزش اتصال</h3>
  <ol class="steps">
    <li>یکی از کلاینت‌های بالا را دانلود و نصب کنید</li>
    <li>لینک اشتراک را کپی کنید</li>
    <li>در کلاینت گزینه <b>Import from clipboard</b> یا «از کلیپ‌بورد» را بزنید</li>
    <li>پروفایل را انتخاب و اتصال را فعال کنید</li>
    <li>در صورت مشکل یوتیوب/اینستا، DNS را روی <code>1.1.1.1</code> یا FakeDNS بگذارید</li>
  </ol>
</div>

<div class="foot">Leviko Panel · کاربر ${user.username}</div>
</div>
<script>
function copySub(){
  var el=document.getElementById('sub');
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(el.value).then(function(){alert('کپی شد');}).catch(function(){el.select();document.execCommand('copy');alert('کپی شد');});
  } else { el.select(); document.execCommand('copy'); alert('کپی شد'); }
}
</script>
</body></html>`;
}

function camouflage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title></title>
<style>body{margin:0;min-height:100vh;background:#07070c}</style></head><body></body></html>`;
}

/* ─── router ─── */
async function bumpCfReq(env, ctx) {
  const run = async () => {
    try {
      const n = parseInt(await Store.get(env.DB, "cf_req_used", "0") || "0", 10) || 0;
      await Store.set(env.DB, "cf_req_used", String(n + 1));
    } catch (_) {}
  };
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(run());
  else await run();
}

export default {
  async fetch(request, env, ctx) {
    if (!env.DB) return new Response("D1 binding 'DB' missing", { status: 500 });
    try { await Store.init(env.DB); } catch (_) {}

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

    // count worker invocations (approx CF requests)
    bumpCfReq(env, ctx);

    const url = new URL(request.url);
    const path = url.pathname;
    const isWs = (request.headers.get("Upgrade") || "").toLowerCase() === "websocket";

    if (isWs) return handleVless(request, env, ctx);
    if ((path === WS || path.startsWith(WS + "/")) && isWs) return handleVless(request, env, ctx);

    if (path.startsWith("/api/")) return handleApi(request, url, env);

    if (path === ROOT || path === ROOT + "/") {
      if (url.searchParams.has("sub")) return handleSub(url, env, request);
      if (url.searchParams.has("u") || url.searchParams.has("status")) {
        const name = (url.searchParams.get("u") || url.searchParams.get("status") || "").trim();
        if (name) {
          const user = await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR uuid=?")
            .bind(name, name).first();
          if (user) {
            const c = await cfg(env.DB);
            return html(statusPage(user, c, url.origin));
          }
          return new Response("User not found", { status: 404 });
        }
      }
      return new Response("Leviko · /8080?sub=USERNAME  ·  /8080?u=USERNAME", { headers: { "Content-Type": "text/plain" } });
    }

    // /8080/status/USERNAME or /status/USERNAME
    const statusMatch = path.match(/^(?:\/8080)?\/status\/([^/]+)\/?$/);
    if (statusMatch) {
      const name = decodeURIComponent(statusMatch[1]);
      const user = await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR uuid=?")
        .bind(name, name).first();
      if (user) {
        const c = await cfg(env.DB);
        return html(statusPage(user, c, url.origin));
      }
      return new Response("User not found", { status: 404 });
    }

    if (path === DASH || path === DASH + "/") {
      const sess = await getSession(request, env.DB);
      if (sess.needSetup) return html(authPage(true));
      if (!sess.ok) return html(authPage(false));
      return html(panelPage());
    }

    return html(camouflage());
  },
};
