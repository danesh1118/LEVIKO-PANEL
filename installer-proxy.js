// TrexBridge Installer Proxy Worker
// Relays Cloudflare API calls for the web installer.
// Restricted to installer-required API paths only.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Proxy-Target, X-GitHub-Url',
  'Access-Control-Max-Age': '86400',
};

const jsonResp = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });

function isAllowedPath(path) {
  if (path === '/accounts' || path === '/accounts/') return true;
  if (!path.startsWith('/accounts/')) return false;
  const patterns = [
    /^\/accounts\/[^/]+\/d1\/database/,
    /^\/accounts\/[^/]+\/workers\/scripts\//,
    /^\/accounts\/[^/]+\/workers\/scripts\/[^/]+\/deployments$/,
    /^\/accounts\/[^/]+\/workers\/workers(\/|$)/,
    /^\/accounts\/[^/]+\/workers\/services\//,
    /^\/accounts\/[^/]+\/workers\/subdomain$/,
    /^\/accounts\/[^/]+$/,
  ];
  return patterns.some((p) => p.test(path));
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return jsonResp({ ok: true, ts: Date.now() });
    }

    if (url.pathname === '/github') {
      const target = request.headers.get('X-GitHub-Url');
      if (!target) return jsonResp({ error: 'Missing X-GitHub-Url header' }, 400);
      if (
        !target.startsWith('https://raw.githubusercontent.com/') &&
        !target.startsWith('https://cdn.jsdelivr.net/') &&
        !target.startsWith('https://api.github.com/')
      ) {
        return jsonResp({ error: 'URL not allowed' }, 403);
      }
      try {
        const resp = await fetch(target);
        return new Response(await resp.text(), {
          status: resp.status,
          headers: { 'Content-Type': 'application/javascript', ...CORS },
        });
      } catch (e) {
        return jsonResp({ error: e.message }, 502);
      }
    }

    const apiToken = request.headers.get('Authorization');
    if (!apiToken) return jsonResp({ error: 'Missing Authorization header' }, 401);

    const target = request.headers.get('X-Proxy-Target');
    if (!target) return jsonResp({ error: 'Missing X-Proxy-Target header' }, 400);

    if (!isAllowedPath(target)) {
      return jsonResp({ error: 'Path not allowed by proxy' }, 403);
    }

    try {
      const cfUrl = `https://api.cloudflare.com/client/v4${target}`;
      const opts = {
        method: request.method,
        headers: { Authorization: apiToken },
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

      const resp = await fetch(cfUrl, opts);
      const respText = await resp.text();
      return new Response(respText, {
        status: resp.status,
        headers: { 'Content-Type': 'application/json', ...CORS },
      });
    } catch (e) {
      return jsonResp({ error: e.message }, 502);
    }
  },
};
