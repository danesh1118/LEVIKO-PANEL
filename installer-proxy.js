const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Proxy-Target, X-GitHub-Url',
  'Access-Control-Max-Age': '86400',
};

const j = (d, s = 200) =>
  new Response(JSON.stringify(d), {
    status: s,
    headers: { 'Content-Type': 'application/json', ...CORS }
  });

function ok(p) {
  if (p === '/accounts' || p === '/accounts/') return true;
  if (!p.startsWith('/accounts/')) return false;

  return [
    /^\/accounts\/[^/]+\/d1\/database/,
    /^\/accounts\/[^/]+\/workers\/scripts\//,

    // Worker deployments
    /^\/accounts\/[^/]+\/workers\/scripts\/[^/]+\/deployments/,

    // Cloudflare workers.dev service subdomain API
    /^\/accounts\/[^/]+\/workers\/services\/[^/]+\/environments\/production\/subdomain$/,

    // Account workers.dev subdomain
    /^\/accounts\/[^/]+\/workers\/subdomain$/,

    /^\/accounts\/[^/]+$/,
  ].some((r) => r.test(p));
}

export default {
  async fetch(req) {
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const u = new URL(req.url);

    if (u.pathname === '/health') {
      return j({ ok: true, service: 'leviko-proxy' });
    }

    if (u.pathname === '/github') {
      const t = req.headers.get('X-GitHub-Url');

      if (!t) return j({ error: 'no url' }, 400);

      if (
        !t.startsWith('https://raw.githubusercontent.com/') &&
        !t.startsWith('https://cdn.jsdelivr.net/') &&
        !t.startsWith('https://api.github.com/')
      ) {
        return j({ error: 'blocked' }, 403);
      }

      const r = await fetch(t);

      return new Response(await r.text(), {
        status: r.status,
        headers: {
          'Content-Type': 'application/javascript',
          ...CORS
        }
      });
    }

    const auth = req.headers.get('Authorization');
    if (!auth) return j({ error: 'no auth' }, 401);

    const target = req.headers.get('X-Proxy-Target');

    if (!target || !ok(target)) {
      return j({
        error: 'path denied',
        target: target || null
      }, 403);
    }

    const opts = {
      method: req.method,
      headers: {
        Authorization: auth
      }
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const ct = req.headers.get('Content-Type') || '';

      if (ct.includes('multipart/form-data')) {
        opts.body = await req.formData();
      } else {
        opts.body = await req.text();
        opts.headers['Content-Type'] = ct || 'application/json';
      }
    }

    const r = await fetch(
      'https://api.cloudflare.com/client/v4' + target,
      opts
    );

    return new Response(await r.text(), {
      status: r.status,
      headers: {
        'Content-Type': 'application/json',
        ...CORS
      }
    });
  }
};
