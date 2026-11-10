# LEVIKO Worker 1101 hardening notes

Only `worker.js` was changed. `index.html` and `installer-proxy.js` are unchanged.

Changes:
- Added a request-boundary catch around WebSocket setup so setup exceptions become a logged HTTP 500 instead of escaping as Error 1101.
- Added a 16 MiB cap to queued client-to-upstream WebSocket data to prevent unbounded buffering when the upstream is slow.
- Kept client frame processing serialized and added explicit queue error logging.
- Made usage-flush background work rejection-safe.
- Added explicit logging for upstream read failures.

No visual/theme/UI settings were removed. They do not execute in the Worker request runtime and are not a plausible cause of Cloudflare Error 1101. Removing them would damage the panel without fixing the Worker exception.

Validation: `node --check worker.js` passes. This is a static syntax check only; it is not a live Cloudflare deployment test. Error 1101 is a runtime JavaScript exception, so the exact root cause still needs the Cloudflare exception stack from the failing Worker invocation.
