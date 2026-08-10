/**
 * Leviko Installer Proxy
 * CORS proxy for Cloudflare API — used only by the web installer.
 * Deploy this as a separate Worker on your own account.
 *
 * Allowed paths only:
 *  - /accounts
 *  - /accounts/{id}
 *  - /accounts/{id}/d1/database*
 *  - /accounts/{id}/workers/scripts*
 *  - /accounts/{id}/workers/services*
 *  - /accounts/{id}/workers/subdomain
 *  - /github  (fetch worker source)
 *  - /health
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Proxy-Target, X-GitHub-Url',
  'Access-Control-Max-Age': '86400',
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });

function isAllowed(path) {
  if (path === '/accounts' || path === '/accounts/') return true;
  if (!path.startsWith('/accounts/')) return false;
  return [
    /^\/accounts\/[^/]+$/,                                    // account details
    /^\/accounts\/[^/]+\/d1\/database/,                        // D1 list/create
    /^\/accounts\/[^/]+\/workers\/scripts/,                    // deploy + settings + subdomain
    /^\/accounts\/[^/]+\/workers\/services/,                   // hosts / real URL
    /^\/accounts\/[^/]+\/workers\/subdomain$/,                 // account workers.dev subdomain
  ].some((re) => re.test(path));
}

export default {
  async fetch(request) {
    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);

    // Health check
    if (url.pathname === '/health') {
      return json({ ok: true, service: 'leviko-installer-proxy', version: '1.0.0' });
    }

    // Fetch worker source from GitHub / jsDelivr
    if (url.pathname === '/github') {
      const target = request.headers.get('X-GitHub-Url') || '';
      const allowed =
        target.startsWith('https://raw.githubusercontent.com/') ||
        target.startsWith('https://cdn.jsdelivr.net/') ||
        target.startsWith('https://api.github.com/');
      if (!allowed) return json({ error: 'url blocked' }, 403);

      const res = await fetch(target, {
        headers: { 'User-Agent': 'Leviko-Installer-Proxy' },
      });
      const body = await res.text();
      return new Response(body, {
        status: res.status,
        headers: {
          'Content-Type': res.headers.get('Content-Type') || 'application/javascript',
          ...CORS,
        },
      });
    }

    // Cloudflare API proxy
    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'missing Authorization' }, 401);

    const target = request.headers.get('X-Proxy-Target');
    if (!target || !isAllowed(target)) {
      return json({ error: 'path denied', path: target || null }, 403);
    }

    const opts = {
      method: request.method,
      headers: { Authorization: auth },
    };

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const ct = request.headers.get('Content-Type') || '';
      if (ct.includes('multipart/form-data')) {
        opts.body = await request.formData();
      } else {
        opts.body = await request.text();
        opts.headers['Content-Type'] = 'application/json';
      }
    }

    const cfRes = await fetch('https://api.cloudflare.com/client/v4' + target, opts);
    const text = await cfRes.text();

    return new Response(text, {
      status: cfRes.status,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        ...CORS,
      },
    });
  },
};
