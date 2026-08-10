/**
 * Leviko Panel v3.0.0
 * Full panel · VLESS/Trojan · Clean IP · Upstream · Sub info · Telegram shop · D1
 * /8080/dash  ·  /8080?sub=NAME
 */
import { connect } from "cloudflare:sockets";

const V = "3.0.0";
const ROOT = "/8080";
const DASH = "/8080/dash";
const WS = "/lv";

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
        price INTEGER NOT NULL DEFAULT 0, is_active INTEGER NOT NULL DEFAULT 1
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id TEXT NOT NULL, plan_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, username TEXT DEFAULT ''
      )`),
    ]);
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
  return {
    protocol: (await Store.get(db, "protocol", "vless")) || "vless",
    ports: (await Store.get(db, "ports", "443,80")) || "443,80",
    clean_ips: (await Store.get(db, "clean_ips", "")) || "",
    upstream: (await Store.get(db, "upstream", "")) || "",
    sub_prefix: (await Store.get(db, "sub_prefix", "Leviko")) || "Leviko",
    info_cfg: (await Store.get(db, "info_cfg", "1")) !== "0",
    kill: (await Store.get(db, "kill_switch", "0")) === "1",
    title: (await Store.get(db, "panel_title", "Leviko")) || "Leviko",
    tg_token: (await Store.get(db, "tg_token", "")) || "",
    tg_admin: (await Store.get(db, "tg_admin", "")) || "",
    tg_welcome: (await Store.get(db, "tg_welcome", "به ربات فروش Leviko خوش آمدید")) || "",
    card: (await Store.get(db, "pay_card", "")) || "",
  };
}

/* ─── VLESS proxy ─── */
async function handleVless(request, env) {
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket")
    return new Response("Expected WebSocket", { status: 426 });
  try {
    if ((await Store.get(env.DB, "kill_switch")) === "1") return new Response("Paused", { status: 503 });
  } catch (_) {}

  const [client, server] = Object.values(new WebSocketPair());
  server.accept();
  let remote = null, username = null, headerDone = false, bytesUp = 0, bytesDown = 0;
  let earlyData = null;
  try {
    const ed = new URL(request.url).searchParams.get("ed");
    if (ed) {
      const raw = atob(ed.replace(/-/g, "+").replace(/_/g, "/"));
      earlyData = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    }
  } catch (_) {}

  const flush = async () => {
    if (!username || !(bytesUp || bytesDown)) return;
    try {
      await env.DB.prepare("UPDATE users SET used_gb=used_gb+?, last_active=? WHERE username=?")
        .bind((bytesUp + bytesDown) / 1073741824, Date.now(), username).run();
    } catch (_) {}
    bytesUp = bytesDown = 0;
  };

  const processHeader = async (chunk) => {
    const id = parseUUID(chunk);
    if (!id) { try { server.close(1002); } catch (_) {} return false; }
    let user;
    try { user = await env.DB.prepare("SELECT * FROM users WHERE uuid=?").bind(id).first(); }
    catch (_) { try { server.close(1011); } catch (__) {} return false; }
    if (!user || user.is_active !== 1) { try { server.close(1008); } catch (_) {} return false; }
    if (user.limit_gb > 0 && user.used_gb >= user.limit_gb) { try { server.close(1008); } catch (_) {} return false; }
    if (user.expiry_days > 0 && Date.now() > user.created_at + user.expiry_days * 86400000) {
      try { server.close(1008); } catch (_) {} return false;
    }
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
      } else { try { server.close(1002); } catch (_) {} return false; }
    } catch (_) { try { server.close(1002); } catch (__) {} return false; }

    const payload = u8.slice(offset);
    try {
      remote = connect({ hostname: host, port });
      const w = remote.writable.getWriter();
      if (payload.byteLength) { await w.write(payload); bytesUp += payload.byteLength; }
      w.releaseLock();
      server.send(new Uint8Array([chunk[0], 0]));
      (async () => {
        try {
          const r = remote.readable.getReader();
          while (true) {
            const { done, value } = await r.read();
            if (done) break;
            if (value?.byteLength) { bytesDown += value.byteLength; if (server.readyState === 1) server.send(value); }
          }
        } catch (_) {} finally { try { server.close(); } catch (_) {} await flush(); }
      })();
    } catch (_) { try { server.close(1011); } catch (__) {} return false; }
    return true;
  };

  server.addEventListener("message", async (ev) => {
    try {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : enc.encode(String(ev.data));
      if (!headerDone) { headerDone = true; await processHeader(data); return; }
      if (remote) {
        const w = remote.writable.getWriter();
        await w.write(data); bytesUp += data.byteLength; w.releaseLock();
      }
    } catch (_) { try { server.close(); } catch (__) {} }
  });
  server.addEventListener("close", async () => { try { remote?.close?.(); } catch (_) {} await flush(); });
  server.addEventListener("error", async () => { try { remote?.close?.(); } catch (_) {} await flush(); });
  if (earlyData?.byteLength) { headerDone = true; await processHeader(earlyData); }
  return new Response(null, { status: 101, webSocket: client });
}

/* ─── subscription builder ─── */
function tag(prefix, parts) {
  return encodeURIComponent([prefix, ...parts.filter(Boolean)].join(" · "));
}

function infoLine(user, prefix) {
  const used = (user.used_gb || 0).toFixed(2);
  const lim = user.limit_gb > 0 ? user.limit_gb + "GB" : "∞";
  let days = "∞";
  if (user.expiry_days > 0) {
    const left = Math.ceil((user.created_at + user.expiry_days * 86400000 - Date.now()) / 86400000);
    days = (left > 0 ? left : 0) + "d";
  }
  // non-working display-only entry (invalid host) — clients show the name
  const name = tag(prefix, [`📊 ${used}/${lim}`, `⏳ ${days}`, user.username]);
  return `vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none&security=none&type=ws&path=%2F#${name}`;
}

function buildUserLinks(host, user, c) {
  const path = encodeURIComponent(WS);
  const ports = (c.ports || "443,80").split(/[,\s]+/).map((p) => parseInt(p, 10)).filter((p) => p > 0 && p < 65536);
  const ips = (c.clean_ips || "").split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).slice(0, 40);
  const protocol = (c.protocol || "vless").toLowerCase();
  const links = [];

  // info config first
  if (c.info_cfg) links.push(infoLine(user, c.sub_prefix));

  const make = (addr, port, tls) => {
    const name = tag(c.sub_prefix, [user.username, addr === host ? "" : addr, String(port)]);
    if (protocol === "trojan") {
      const sec = tls ? "tls" : "none";
      const sni = tls ? `&sni=${host}&fp=chrome` : "";
      return `trojan://${user.uuid}@${addr}:${port}?security=${sec}${sni}&type=ws&host=${host}&path=${path}#${name}`;
    }
    const sec = tls ? "tls" : "none";
    const sni = tls ? `&sni=${host}&fp=chrome` : "";
    return `vless://${user.uuid}@${addr}:${port}?encryption=none&security=${sec}${sni}&type=ws&host=${host}&path=${path}#${name}`;
  };

  if (ips.length) {
    // only clean IPs when provided
    for (const ip of ips) {
      for (const port of ports.length ? ports : [443]) {
        links.push(make(ip, port, port === 443 || port === 8443));
      }
    }
  } else {
    // default: one working config on worker host
    const mainPort = ports.includes(443) ? 443 : (ports[0] || 443);
    links.push(make(host, mainPort, mainPort === 443 || mainPort === 8443));
    if (ports.includes(80) && mainPort !== 80) links.push(make(host, 80, false));
  }

  // upstream extra configs (raw share links, one per line)
  const up = (c.upstream || "").split("\n").map((s) => s.trim()).filter((s) => /^(vless|trojan|vmess|ss):\/\//i.test(s));
  for (const line of up.slice(0, 50)) links.push(line);

  return links;
}

async function handleSub(url, env) {
  const name = (url.searchParams.get("sub") || "").trim();
  if (!name) return new Response("Missing ?sub=", { status: 400 });
  const user = await env.DB.prepare("SELECT * FROM users WHERE username=? COLLATE NOCASE OR uuid=?")
    .bind(name, name).first();
  if (!user || user.is_active !== 1) return new Response("Not Found", { status: 404 });
  const c = await cfg(env.DB);
  const links = buildUserLinks(url.hostname, user, c);
  const body = btoa(unescape(encodeURIComponent(links.join("\n"))));
  const expire = user.expiry_days > 0 ? Math.floor((user.created_at + user.expiry_days * 86400000) / 1000) : 0;
  return new Response(body, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Profile-Update-Interval": "6",
      "Subscription-Userinfo": `upload=0; download=${Math.floor((user.used_gb || 0) * 1073741824)}; total=${Math.floor((user.limit_gb || 0) * 1073741824)}; expire=${expire}`,
    },
  });
}

/* ─── Telegram bot ─── */
async function tgApi(token, method, body) {
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json().catch(() => ({}));
}

async function handleTelegram(request, env) {
  const c = await cfg(env.DB);
  if (!c.tg_token) return json({ ok: false });
  const update = await request.json().catch(() => null);
  if (!update) return json({ ok: true });

  const msg = update.message || update.callback_query?.message;
  const chatId = String(update.message?.chat?.id || update.callback_query?.from?.id || "");
  const text = (update.message?.text || "").trim();
  const data = update.callback_query?.data || "";
  const isAdmin = c.tg_admin && chatId === String(c.tg_admin);

  const send = (txt, extra = {}) => tgApi(c.tg_token, "sendMessage", { chat_id: chatId, text: txt, parse_mode: "HTML", ...extra });
  const edit = (txt, extra = {}) =>
    tgApi(c.tg_token, "editMessageText", { chat_id: chatId, message_id: msg?.message_id, text: txt, parse_mode: "HTML", ...extra });

  const mainKb = {
    inline_keyboard: [
      [{ text: "🛒 خرید اشتراک", callback_data: "shop" }],
      [{ text: "📱 سرویس‌های من", callback_data: "mysub" }],
      [{ text: "💳 کارت به کارت", callback_data: "card" }, { text: "ℹ️ راهنما", callback_data: "help" }],
    ],
  };
  if (isAdmin) mainKb.inline_keyboard.push([{ text: "🛠 پنل ادمین", callback_data: "admin" }]);

  if (update.callback_query) {
    await tgApi(c.tg_token, "answerCallbackQuery", { callback_query_id: update.callback_query.id });
  }

  // /start
  if (text.startsWith("/start") || data === "home") {
    await send(`${c.tg_welcome}\n\nاز منو یک گزینه انتخاب کن:`, { reply_markup: mainKb });
    return json({ ok: true });
  }

  if (data === "help" || text === "/help") {
    await send(
      `<b>راهنما</b>\n\n` +
        `• خرید اشتراک: پلن را انتخاب و پرداخت را انجام بده\n` +
        `• سرویس‌های من: لینک ساب و وضعیت حجم/زمان\n` +
        `• پشتیبانی: به ادمین پیام بده\n\n` +
        `پنل وب فقط برای مدیر است.`,
      { reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] } }
    );
    return json({ ok: true });
  }

  if (data === "card") {
    await send(c.card ? `<b>کارت:</b>\n<code>${c.card}</code>\n\nبعد از واریز، رسید را برای ادمین بفرست.` : "کارت هنوز تنظیم نشده.", {
      reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] },
    });
    return json({ ok: true });
  }

  if (data === "shop") {
    const { results: plans } = await env.DB.prepare("SELECT * FROM plans WHERE is_active=1 ORDER BY id").all();
    if (!plans?.length) {
      await send("پلنی فعال نیست.", { reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] } });
      return json({ ok: true });
    }
    const rows = plans.map((p) => [{ text: `${p.title} — ${p.price.toLocaleString("fa-IR")} ت · ${p.gb}GB · ${p.days}روز`, callback_data: "buy_" + p.id }]);
    rows.push([{ text: "🏠 منو", callback_data: "home" }]);
    await send("یک پلن انتخاب کن:", { reply_markup: { inline_keyboard: rows } });
    return json({ ok: true });
  }

  if (data.startsWith("buy_")) {
    const pid = parseInt(data.slice(4), 10);
    const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=? AND is_active=1").bind(pid).first();
    if (!plan) { await send("پلن نامعتبر"); return json({ ok: true }); }
    await env.DB.prepare("INSERT INTO orders (tg_id, plan_id, status, created_at) VALUES (?,?,?,?)")
      .bind(chatId, pid, "pending", Date.now()).run();
    const order = await env.DB.prepare("SELECT id FROM orders WHERE tg_id=? ORDER BY id DESC LIMIT 1").bind(chatId).first();
    await send(
      `<b>سفارش #${order?.id}</b>\n` +
        `پلن: ${plan.title}\nحجم: ${plan.gb}GB · مدت: ${plan.days} روز\nمبلغ: ${plan.price.toLocaleString("fa-IR")} تومان\n\n` +
        (c.card ? `کارت: <code>${c.card}</code>\n` : "") +
        `بعد از پرداخت، رسید را ارسال کن. ادمین تایید می‌کند.`,
      { reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] } }
    );
    if (c.tg_admin) {
      await tgApi(c.tg_token, "sendMessage", {
        chat_id: c.tg_admin,
        text: `🛒 سفارش جدید #${order?.id}\nاز: ${chatId}\n${plan.title} · ${plan.price} ت`,
        reply_markup: {
          inline_keyboard: [
            [{ text: "✅ تایید و ساخت", callback_data: "approve_" + order?.id }],
            [{ text: "❌ رد", callback_data: "reject_" + order?.id }],
          ],
        },
      });
    }
    return json({ ok: true });
  }

  if (data === "mysub") {
    const { results } = await env.DB.prepare("SELECT * FROM users WHERE tg_id=? ORDER BY id DESC").bind(chatId).all();
    if (!results?.length) {
      await send("سرویسی نداری.", { reply_markup: { inline_keyboard: [[{ text: "🛒 خرید", callback_data: "shop" }], [{ text: "🏠 منو", callback_data: "home" }]] } });
      return json({ ok: true });
    }
    const host = new URL(request.url).hostname;
    let out = "<b>سرویس‌های تو</b>\n\n";
    for (const u of results) {
      const used = (u.used_gb || 0).toFixed(2);
      const lim = u.limit_gb > 0 ? u.limit_gb : "∞";
      let days = "∞";
      if (u.expiry_days > 0) {
        const left = Math.ceil((u.created_at + u.expiry_days * 86400000 - Date.now()) / 86400000);
        days = left > 0 ? left : 0;
      }
      const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(u.username)}`;
      out += `👤 <code>${u.username}</code>\n📊 ${used}/${lim} GB · ⏳ ${days} روز\n🔗 <code>${sub}</code>\n\n`;
    }
    await send(out, { reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] } });
    return json({ ok: true });
  }

  // admin approve
  if (isAdmin && data.startsWith("approve_")) {
    const oid = parseInt(data.slice(8), 10);
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(oid).first();
    if (!order || order.status !== "pending") { await send("سفارش نامعتبر"); return json({ ok: true }); }
    const plan = await env.DB.prepare("SELECT * FROM plans WHERE id=?").bind(order.plan_id).first();
    const uname = "tg" + order.tg_id.slice(-8) + oid;
    const id = uuid();
    await env.DB.prepare(
      `INSERT INTO users (username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,tg_id)
       VALUES (?,?,?,0,?,?,1,?,?)`
    ).bind(uname, id, plan?.gb || 10, plan?.days || 30, Date.now(), "tg-order-" + oid, order.tg_id).run();
    await env.DB.prepare("UPDATE orders SET status='done', username=? WHERE id=?").bind(uname, oid).run();
    const host = new URL(request.url).hostname;
    const sub = `https://${host}${ROOT}?sub=${encodeURIComponent(uname)}`;
    await tgApi(c.tg_token, "sendMessage", {
      chat_id: order.tg_id,
      text: `✅ سفارش #${oid} تایید شد\nکاربر: <code>${uname}</code>\nساب:\n<code>${sub}</code>`,
      parse_mode: "HTML",
    });
    await send(`تایید شد · ${uname}`);
    await Store.log(env.DB, "tg_approve", String(oid));
    return json({ ok: true });
  }

  if (isAdmin && data.startsWith("reject_")) {
    const oid = parseInt(data.slice(7), 10);
    await env.DB.prepare("UPDATE orders SET status='rejected' WHERE id=?").bind(oid).run();
    const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(oid).first();
    if (order) await tgApi(c.tg_token, "sendMessage", { chat_id: order.tg_id, text: `❌ سفارش #${oid} رد شد.` });
    await send("رد شد");
    return json({ ok: true });
  }

  if (isAdmin && data === "admin") {
    const total = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    const pending = await env.DB.prepare("SELECT COUNT(*) as c FROM orders WHERE status='pending'").first();
    await send(`<b>ادمین</b>\nکاربران: ${total?.c || 0}\nسفارش باز: ${pending?.c || 0}\n\nپنل وب: /8080/dash`, {
      reply_markup: { inline_keyboard: [[{ text: "🏠 منو", callback_data: "home" }]] },
    });
    return json({ ok: true });
  }

  // fallback
  if (text) {
    await send("از منو استفاده کن.", { reply_markup: mainKb });
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
    const traffic = await env.DB.prepare("SELECT COALESCE(SUM(used_gb),0) as s FROM users").first();
    const pending = await env.DB.prepare("SELECT COUNT(*) as c FROM orders WHERE status='pending'").first();
    const c = await cfg(env.DB);
    return json({
      users: total?.c || 0, active: active?.c || 0,
      traffic: +(Number(traffic?.s) || 0).toFixed(3),
      pending: pending?.c || 0, kill: c.kill, version: V, protocol: c.protocol,
    });
  }

  if (path === "/users" && method === "GET") {
    const { results } = await env.DB.prepare(
      "SELECT id,username,uuid,limit_gb,used_gb,expiry_days,created_at,is_active,remark,last_active,tg_id FROM users ORDER BY id DESC"
    ).all();
    return json({ users: results || [] });
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
      sub_prefix: "sub_prefix", panel_title: "panel_title",
      tg_token: "tg_token", tg_admin: "tg_admin", tg_welcome: "tg_welcome", pay_card: "pay_card",
    };
    for (const [k, sk] of Object.entries(map)) {
      if (body[k] !== undefined) await Store.set(env.DB, sk, String(body[k]));
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
    await env.DB.prepare("INSERT INTO plans (title,days,gb,price,is_active) VALUES (?,?,?,?,1)")
      .bind(String(body.title || "Plan").slice(0, 60), Math.max(1, parseInt(body.days, 10) || 30), Math.max(0, parseFloat(body.gb) || 10), Math.max(0, parseInt(body.price, 10) || 0)).run();
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
    const body = await request.json().catch(() => ({}));
    const c = await cfg(env.DB);
    if (!c.tg_token) return json({ error: "no token" }, 400);
    const hook = `${url.origin}/api/telegram`;
    const r = await tgApi(c.tg_token, "setWebhook", { url: hook, drop_pending_updates: true });
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
.logo{width:68px;height:68px;margin:0 auto 16px;border-radius:20px;background:linear-gradient(145deg,#c4b5fd,#7c3aed);
display:grid;place-items:center;font-size:1.7rem;font-weight:900;color:#fff;box-shadow:0 14px 40px rgba(139,92,246,.45);
transform:perspective(420px) rotateY(-10deg) rotateX(8deg)}
h1{font-size:1.4rem;font-weight:800;margin-bottom:6px}p{color:var(--mut);margin-bottom:16px}
.field{text-align:right;margin-bottom:12px}.err{color:var(--err);font-size:.85rem;margin-top:10px;display:none}
</style></head><body><div class="scene"><div class="glass box">
<div class="logo">L</div><h1>Leviko</h1><p>${setup ? "ساخت حساب ادمین" : "ورود به پنل"}</p>
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
.brand .mark{width:46px;height:46px;border-radius:15px;background:linear-gradient(145deg,#c4b5fd,#7c3aed);
display:grid;place-items:center;font-weight:900;color:#fff;box-shadow:0 10px 28px rgba(139,92,246,.4);
transform:perspective(320px) rotateY(-12deg) rotateX(6deg)}
.brand h1{font-size:1.2rem;font-weight:800}.brand span{font-size:.7rem;color:var(--mut);letter-spacing:.08em}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.stat{padding:16px 12px;text-align:center;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;inset:auto -20% -40% auto;width:80px;height:80px;border-radius:50%;background:rgba(139,92,246,.12);filter:blur(20px)}
.stat .n{font-size:1.45rem;font-weight:800;background:linear-gradient(135deg,#c4b5fd,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .l{font-size:.72rem;color:var(--mut);margin-top:3px}
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
@media(max-width:720px){.stats{grid-template-columns:1fr 1fr}.grid2{grid-template-columns:1fr}}
</style></head><body><div class="scene">
<div class="top">
  <div class="brand"><div class="mark">L</div><div><h1 id="title">Leviko</h1><span>PANEL · v${V}</span></div></div>
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
    <div class="glass stat"><div class="n" id="sUsers">—</div><div class="l">کاربران</div></div>
    <div class="glass stat"><div class="n" id="sActive">—</div><div class="l">فعال</div></div>
    <div class="glass stat"><div class="n" id="sTraffic">—</div><div class="l">مصرف GB</div></div>
    <div class="glass stat"><div class="n" id="sPending">—</div><div class="l">سفارش باز</div></div>
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
      <h4>شبکه و DNS</h4>
      <div class="field"><label>Clean IP / Host (هر خط یکی)</label>
        <textarea id="cleanIps" rows="6" placeholder="1.2.3.4&#10;cf.example.com"></textarea></div>
      <p style="font-size:.75rem;color:var(--faint)">با افزودن IP تمیز، کانفیگ پیش‌فرض هاست حذف و فقط IPها در ساب می‌آیند.</p>
    </div>
    <div class="glass card-in">
      <h4>آپ‌استریم</h4>
      <div class="field"><label>لینک‌های کانفیگ اضافه (هر خط یکی)</label>
        <textarea id="upstream" rows="6" placeholder="vless://...&#10;trojan://..."></textarea></div>
      <p style="font-size:.75rem;color:var(--faint)">لینک‌های خارجی به انتهای سابسکریپشن اضافه می‌شوند.</p>
    </div>
  </div>
  <div class="glass card-in" style="margin-top:12px">
    <h4>اشتراک و پروتکل</h4>
    <div class="grid2">
      <div class="field"><label>پروتکل</label>
        <select id="protocol"><option value="vless">VLESS</option><option value="trojan">Trojan</option></select></div>
      <div class="field"><label>پورت‌ها (با ویرگول)</label><input id="ports" placeholder="443,80"></div>
      <div class="field"><label>پیشوند نام کانفیگ</label><input id="subPrefix" placeholder="Leviko"></div>
      <div class="field" style="display:flex;align-items:center;gap:10px;padding-top:22px">
        <input type="checkbox" id="infoCfg" style="width:auto"><label for="infoCfg" style="margin:0">کانفیگ نمایش حجم/زمان</label>
      </div>
    </div>
    <button class="btn btn-a" style="margin-top:12px" onclick="saveAdv()">ذخیره پیشرفته</button>
  </div>
</div>

<div class="sec" id="sec-tg">
  <div class="glass card-in">
    <h4>ربات فروش تلگرام</h4>
    <div class="grid2">
      <div class="field"><label>Bot Token</label><input id="tgToken" dir="ltr" style="text-align:left"></div>
      <div class="field"><label>Admin Chat ID</label><input id="tgAdmin" dir="ltr" style="text-align:left"></div>
    </div>
    <div class="field"><label>پیام خوش‌آمد</label><input id="tgWelcome"></div>
    <div class="field"><label>شماره کارت</label><input id="payCard" dir="ltr" style="text-align:left"></div>
    <div class="toolbar" style="margin-top:8px">
      <button class="btn btn-a" onclick="saveTg()">ذخیره ربات</button>
      <button class="btn btn-g" onclick="setHook()">فعال‌سازی Webhook</button>
    </div>
  </div>
  <div class="glass card-in" style="margin-top:12px">
    <h4>پلن‌های فروش</h4>
    <div class="grid2">
      <div class="field"><label>عنوان</label><input id="planTitle" placeholder="ماهانه"></div>
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
    <p><b>Clean IP</b><br>با پر کردن IP تمیز، کانفیگ پیش‌فرض هاست حذف و فقط IPها ساخته می‌شوند. کانفیگ نمایش حجم همیشه (اگر فعال باشد) اول لیست می‌آید.</p>
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
const root=location.protocol+'//'+location.host;
async function api(path,opts={}){
  const r=await fetch('/api'+path,{...opts,headers:{'Content-Type':'application/json',...(opts.headers||{})}});
  if(r.status===401){location.href='${DASH}';return null}
  return r.json();
}
function tab(n){
  document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.t===n));
  document.querySelectorAll('.sec').forEach(s=>s.classList.toggle('on',s.id==='sec-'+n));
  if(n==='adv'||n==='sys'||n==='tg')loadSettings();
  if(n==='tg'){loadPlans();loadOrders()}
  if(n==='sys')loadLogs();
}
async function logout(){await api('/logout',{method:'POST'});location.reload()}
async function loadUsers(){
  const s=await api('/stats');if(!s)return;
  sUsers.textContent=s.users;sActive.textContent=s.active;sTraffic.textContent=s.traffic;sPending.textContent=s.pending||0;
  killBanner.classList.toggle('on',!!s.kill);
  const u=await api('/users');if(!u)return;
  tbody.innerHTML=u.users.length?u.users.map(x=>{
    const used=(x.used_gb||0).toFixed(2),lim=x.limit_gb>0?x.limit_gb:'∞';
    let days='∞';
    if(x.expiry_days>0){const left=Math.ceil((x.created_at+x.expiry_days*86400000-Date.now())/86400000);days=left>0?left:0}
    const st=x.is_active?'<span class="badge badge-on">فعال</span>':'<span class="badge badge-off">قطع</span>';
    const sub=root+'${ROOT}?sub='+encodeURIComponent(x.username);
    return \`<tr><td><strong>\${x.username}</strong><br><span style="font-size:.68rem;color:var(--faint)">\${x.uuid.slice(0,8)}…</span></td>
      <td>\${st}</td><td>\${used}/\${lim}</td><td>\${days}</td>
      <td class="acts">
        <button class="btn btn-g" onclick="copy('\${sub}')">ساب</button>
        <button class="btn btn-g" onclick="toggle(\${x.id},\${x.is_active?0:1})">\${x.is_active?'قطع':'فعال'}</button>
        <button class="btn btn-g" onclick="resetT(\${x.id})">ریست</button>
        <button class="btn btn-d" onclick="del(\${x.id})">حذف</button></td></tr>\`;
  }).join(''):'<tr><td colspan="5" class="empty">کاربری نیست</td></tr>';
}
function openCreate(){fUser.value=fRemark.value='';fLimit.value=10;fDays.value=30;modal.classList.add('open')}
function closeModal(){modal.classList.remove('open')}
async function saveUser(){
  const body={username:fUser.value.trim(),limit_gb:parseFloat(fLimit.value)||0,expiry_days:parseInt(fDays.value)||0,remark:fRemark.value.trim()};
  if(!body.username){alert('نام لازم');return}
  const r=await api('/users',{method:'POST',body:JSON.stringify(body)});
  if(r?.error){alert(r.error);return}closeModal();loadUsers();
}
async function toggle(id,v){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({is_active:v})});loadUsers()}
async function resetT(id){await api('/users/'+id,{method:'PATCH',body:JSON.stringify({reset_traffic:true})});loadUsers()}
async function del(id){if(!confirm('حذف؟'))return;await api('/users/'+id,{method:'DELETE'});loadUsers()}
function copy(t){navigator.clipboard.writeText(t).then(()=>alert('کپی شد')).catch(()=>prompt('کپی',t))}
async function loadSettings(){
  const s=await api('/settings');if(!s)return;
  cleanIps.value=s.clean_ips||'';upstream.value=s.upstream||'';
  protocol.value=s.protocol||'vless';ports.value=s.ports||'443,80';
  subPrefix.value=s.sub_prefix||'Leviko';infoCfg.checked=s.info_cfg!==false;
  panelTitle.value=s.title||s.panel_title||'Leviko';killSwitch.checked=!!s.kill;
  setUser.value=s.admin_user||'';title.textContent=panelTitle.value;
  tgToken.value=s.tg_token||'';tgAdmin.value=s.tg_admin||'';
  tgWelcome.value=s.tg_welcome||'';payCard.value=s.card||s.pay_card||'';
}
async function saveAdv(){
  await api('/settings',{method:'POST',body:JSON.stringify({
    clean_ips:cleanIps.value,upstream:upstream.value,protocol:protocol.value,
    ports:ports.value,sub_prefix:subPrefix.value,info_cfg:infoCfg.checked
  })});alert('ذخیره شد');
}
async function saveSys(){
  await api('/settings',{method:'POST',body:JSON.stringify({panel_title:panelTitle.value,kill_switch:killSwitch.checked})});
  if(setUser.value.trim()||setPass.value)await api('/admin',{method:'POST',body:JSON.stringify({username:setUser.value.trim(),password:setPass.value})});
  alert('ذخیره شد');loadUsers();
}
async function saveTg(){
  await api('/settings',{method:'POST',body:JSON.stringify({
    tg_token:tgToken.value.trim(),tg_admin:tgAdmin.value.trim(),
    tg_welcome:tgWelcome.value,pay_card:payCard.value.trim()
  })});alert('ذخیره شد');
}
async function setHook(){
  const r=await api('/tg-webhook',{method:'POST',body:'{}'});
  alert(r?.ok||r?.result?'Webhook فعال شد':(r?.description||JSON.stringify(r)));
}
async function loadPlans(){
  const r=await api('/plans');if(!r)return;
  planList.innerHTML=(r.plans||[]).map(p=>\`<div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--line)">
    <span>\${p.title} · \${p.gb}GB · \${p.days}روز · \${Number(p.price).toLocaleString('fa-IR')}ت</span>
    <button class="btn btn-d" style="padding:4px 8px;font-size:.7rem" onclick="delPlan(\${p.id})">حذف</button></div>\`).join('')||'<div class="empty">پلنی نیست</div>';
}
async function addPlan(){
  await api('/plans',{method:'POST',body:JSON.stringify({title:planTitle.value,price:+planPrice.value,gb:+planGb.value,days:+planDays.value})});
  loadPlans();
}
async function delPlan(id){await api('/plans/'+id,{method:'DELETE'});loadPlans()}
async function loadOrders(){
  const r=await api('/orders');if(!r)return;
  orderList.innerHTML=(r.orders||[]).slice(0,20).map(o=>\`#\${o.id} · tg:\${o.tg_id} · \${o.status} · \${o.username||'-'}\`).join('<br>')||'خالی';
}
async function loadLogs(){
  const r=await api('/logs');if(!r)return;
  logBox.innerHTML=(r.logs||[]).map(l=>\`\${new Date(l.ts).toLocaleString('fa-IR')} — \${l.action} \${l.detail||''}\`).join('<br>')||'—';
}
async function doExport(){
  const r=await api('/export');if(!r)return;
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(r,null,2)],{type:'application/json'}));
  a.download='leviko.json';a.click();
}
async function doImport(ev){
  const f=ev.target.files[0];if(!f)return;
  const data=JSON.parse(await f.text());
  const r=await api('/import',{method:'POST',body:JSON.stringify(data)});
  alert('وارد شد: '+(r?.imported||0));loadUsers();
}
loadUsers();
</script></body></html>`;
}

function camouflage() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title></title>
<style>body{margin:0;min-height:100vh;background:#07070c}</style></head><body></body></html>`;
}

/* ─── router ─── */
export default {
  async fetch(request, env) {
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

    const url = new URL(request.url);
    const path = url.pathname;

    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") return handleVless(request, env);
    if ((path === WS || path.startsWith(WS + "/")) && (request.headers.get("Upgrade") || "").toLowerCase() === "websocket")
      return handleVless(request, env);

    if (path.startsWith("/api/")) return handleApi(request, url, env);

    if (path === ROOT || path === ROOT + "/") {
      if (url.searchParams.has("sub")) return handleSub(url, env);
      return new Response("Leviko · /8080?sub=USERNAME", { headers: { "Content-Type": "text/plain" } });
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
