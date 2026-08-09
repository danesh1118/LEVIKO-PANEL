/**
 * Leviko Installer Proxy
 * Optional CORS relay for Cloudflare API — path-restricted only
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
    headers: { 'Content-Type': 'application/json', ...CORS },
  });

function allowed(path) {
  if (path === '/accounts' || path === '/accounts/') return true;
  if (!path.startsWith('/accounts/')) return false;
  return [
    /^\/accounts\/[^/]+\/d1\/database/,
    /^\/accounts\/[^/]+\/workers\/scripts\//,
    /^\/accounts\/[^/]+\/workers\/scripts\/[^/]+\/deployments$/,
    /^\/accounts\/[^/]+\/workers\/services\//,
    /^\/accounts\/[^/]+\/workers\/subdomain$/,
    /^\/accounts\/[^/]+$/,
  ].some((p) => p.test(path));
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);

    if (url.pathname === '/health') {
      return json({ ok: true, service: 'leviko-installer-proxy' });
    }

    if (url.pathname === '/github') {
      const target = request.headers.get('X-GitHub-Url');
      if (!target) return json({ error: 'Missing X-GitHub-Url' }, 400);
      if (
        !target.startsWith('https://raw.githubusercontent.com/') &&
        !target.startsWith('https://cdn.jsdelivr.net/') &&
        !target.startsWith('https://api.github.com/')
      ) {
        return json({ error: 'URL not allowed' }, 403);
      }
      const resp = await fetch(target);
      return new Response(await resp.text(), {
        status: resp.status,
        headers: { 'Content-Type': 'application/javascript', ...CORS },
      });
    }

    const auth = request.headers.get('Authorization');
    if (!auth) return json({ error: 'Missing Authorization' }, 401);

    const target = request.headers.get('X-Proxy-Target');
    if (!target) return json({ error: 'Missing X-Proxy-Target' }, 400);
    if (!allowed(target)) return json({ error: 'Path not allowed' }, 403);

    const cfUrl = `https://api.cloudflare.com/client/v4${target}`;
    const opts = { method: request.method, headers: { Authorization: auth } };

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
    return new Response(await resp.text(), {
      status: resp.status,
      headers: { 'Content-Type': 'application/json', ...CORS },
    });
  },
};
