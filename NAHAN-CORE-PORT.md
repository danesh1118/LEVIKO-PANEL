# LEVIKO main Worker – Nahan-inspired core integration

This patch is applied to the main `worker.js`, not to `index.html` or the installer.

## Integrated patterns
- D1 binding compatibility: accepts the existing `DB` binding and the Nahan-style `IOT_DB` alias. Existing LEVIKO code continues to use `env.DB` internally.
- Per-isolate, concurrency-safe D1 schema initialization/migration. Concurrent first requests share one initialization promise; failed initialization is evicted so a later request can retry.
- Bounded Telegram HTTP calls (12 seconds) with explicit HTTP status handling.
- Request correlation IDs and detailed runtime exception logging to `console.error`, plus a short reference ID in the HTTP 500 response and persisted LEVIKO log entry.
- Existing dashboard, APIs, D1 schema, VLESS/Trojan handling, Telegram shop, and visual assets are retained.

## Important architectural note
Nahan Gateway is a separate gateway implementation with its own routes, D1 schema (`IOT_DB`), authentication, subscriptions, dashboard, and proxy runtime. Replacing LEVIKO's `worker.js` wholesale with Nahan would remove LEVIKO-specific features and data compatibility. This patch ports compatible operational patterns into LEVIKO's existing runtime instead of transplanting Nahan's unrelated product code.

## Deploy
Keep the existing D1 binding named `DB`. If the Worker is already configured with `IOT_DB`, the new code accepts that name too. Deploy the updated `worker.js` using the same build/deploy process as before.
