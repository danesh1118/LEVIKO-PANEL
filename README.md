# 🦖 TrexBridge Installer

### Automated Cloudflare Worker Deployment for TrexBridge Panel

One-click web installer that deploys **TrexBridge** (VLESS over WebSocket panel) on your Cloudflare account — no CLI, no manual binding.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🚀 **One-Click Deploy** | Deploy with a single API token |
| 🗄️ **Auto D1 Database** | Creates and binds D1 automatically (`DB`) |
| 🔗 **Auto Worker Deploy** | Uploads `Panel.js` and deploys |
| 🌐 **Bilingual UI** | فارسی / English |
| 🔐 **Optional CORS Proxy** | Self-hostable proxy for browser API calls |

---

## 🚀 Quick Start

1. Open `index.html` in your browser (or host it on GitHub Pages)
2. Click **Create Token on Cloudflare** — permissions are pre-filled
3. Paste the token
4. Set Worker name / D1 name (or keep defaults)
5. Click **Deploy**
6. Open the panel URL → set your password on first visit

**Panel path after install:** `https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/panel`

---

## 📁 Project Structure

```
trexbridge-installer/
├── index.html           # Main installer UI (open in browser)
├── installer-proxy.js   # Optional CORS proxy Worker
└── README.md
```

---

## 🔑 Required API Token Permissions

- **Account** — Read
- **Account Analytics** — Read
- **D1** — Edit
- **Workers Scripts** — Edit

The "Create Token" button in the installer opens Cloudflare with these already selected.

---

## 🔒 About the Proxy

Browsers block direct calls to `api.cloudflare.com` (CORS).  
Options:

1. **Leave proxy empty** — installer tries direct + public CDNs for the script
2. **Self-host proxy** — deploy `installer-proxy.js` as a Worker and paste its URL in Advanced settings

### Self-host proxy

1. Create a Worker in Cloudflare
2. Paste contents of `installer-proxy.js`
3. Deploy and copy the `*.workers.dev` URL
4. Enter that URL in the installer’s Advanced → Proxy field

---

## ⚙️ Defaults

| Option | Default |
|--------|---------|
| Worker Name | `trexbridge` |
| D1 Database | `trexbridge-db` |
| Binding name | `DB` (required by Panel.js) |
| Panel path | `/panel` |

---

## 📦 Hosting the Installer

### GitHub Pages

1. Push this folder to a repo
2. Settings → Pages → Deploy from `main` / root
3. Open `https://YOUR_USER.github.io/YOUR_REPO/`

### Local

Just open `index.html` in a modern browser.

---

## 📝 Source Panel

Panel code is fetched from:

- https://github.com/icubaby/TrexBridgePanel  
- File: `Panel.js`

---

## License

MIT — use freely.
