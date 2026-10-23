const encoder = new TextEncoder();

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Complaint form from Tanishtha</title>
  <style>
    * { box-sizing: border-box; }
    html, body { width: 100%; height: 100%; margin: 0; }
    body { font: 16px Arial, sans-serif; }
    main { width: 100%; max-width: 1100px; height: 100vh; height: 100dvh; margin: 0 auto; padding: env(safe-area-inset-top) 12px env(safe-area-inset-bottom); }
    #complaint-form { display: flex; flex-direction: column; align-items: flex-start; gap: 8px; width: 100%; height: 100%; }
    #message { flex: none; width: 100%; height: 40vh; height: 40dvh; min-height: 180px; max-height: 420px; resize: vertical; font: inherit; }
    #status { margin: 0; }
  </style>
</head>
<body>
  <main>
    <form id="complaint-form">
      <p>Complaint form from Tanishtha</p>
      <textarea id="message" maxlength="10000" placeholder="Write your complaint here..." aria-label="Write your complaint" required></textarea>
    <button type="submit">Send to Taiyr</button>
    <p id="status" role="status" aria-live="polite"></p>
    </form>
  </main>
  <script>
    document.querySelector('#complaint-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = event.currentTarget.querySelector('button');
      const message = document.querySelector('#message');
      const status = document.querySelector('#status');
      button.disabled = true;
      status.textContent = 'Sending…';
      try {
        const response = await fetch('/complaints/send', {
          method: 'POST',
          headers: {'content-type': 'application/json'},
          credentials: 'same-origin',
          body: JSON.stringify({message: message.value})
        });
        if (response.status === 401) {
          location.reload();
          return;
        }
        if (!response.ok) throw new Error();
        message.value = '';
        status.textContent = 'Sent. Thank you for writing.';
      } catch {
        status.textContent = 'Sorry, it could not be sent. Please try again.';
      } finally {
        button.disabled = false;
      }
    });
  </script>
</body>
</html>`;

const loginHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Passkey</title>
  <style>
    * { box-sizing: border-box; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #fff; color: #111; font: 16px Arial, sans-serif; }
    main { width: min(350px, calc(100vw - 40px)); }
    label { display: block; margin-bottom: 4px; font-size: 16px; font-weight: 400; line-height: 1.2; }
    input { width: 100%; height: 36px; border: 2px solid #202426; border-radius: 0; padding: 5px 8px; background: white; color: #111; font: inherit; }
    #password { -webkit-text-security: disc; }
    input:focus { outline: 2px solid #555; outline-offset: 2px; }
    #status { margin: 8px 0 0; font-size: 14px; }
  </style>
</head>
<body>
  <main>
    <form id="login-form">
      <label for="password">passkey</label>
      <input id="password" name="passkey" type="text" inputmode="numeric" autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="passkey" autocomplete="off" required autofocus>
      <button type="submit">Enter</button>
      <p id="status" role="status" aria-live="polite"></p>
    </form>
  </main>
  <script>
    document.querySelector('#login-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const password = document.querySelector('#password');
      const button = event.currentTarget.querySelector('button');
      const status = document.querySelector('#status');
      password.disabled = true;
      button.disabled = true;
      status.textContent = 'Checking…';
      try {
        const response = await fetch('/complaints/auth', {
          method: 'POST',
          headers: {'content-type': 'application/json'},
          credentials: 'same-origin',
          body: JSON.stringify({password: password.value})
        });
        if (response.ok) {
          location.reload();
        } else if (response.status === 401) {
          status.textContent = 'That password did not work. Please try again.';
        } else if (response.status === 503) {
          status.textContent = 'Unable to verify the passkey right now. Please try again later.';
        } else {
          status.textContent = 'Unable to verify the passkey right now. Please try again later.';
        }
      } catch {
        status.textContent = 'Could not connect. Please try again.';
      } finally {
        password.disabled = false;
        button.disabled = false;
      }
    });
  </script>
</body>
</html>`;

function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  return b64(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}
function response(body, status=200, headers={}) {
  return new Response(body, {status, headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", ...headers}});
}
async function authorized(request, env) {
  const token = request.headers.get('Cookie')?.match(/(?:^|; )complaints_session=([^;]+)/)?.[1];
  if (!token) return false;
  const [expires, sig] = token.split('.');
  if (!expires || !sig || Number(expires) < Date.now()) return false;
  return (await hmac(env.SESSION_SECRET, expires)) === sig;
}
export default {
 async fetch(request, env) {
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/complaints')) return fetch(request);
  if (request.method === 'GET' && (url.pathname === '/complaints' || url.pathname === '/complaints/')) {
    if (!(await authorized(request, env))) return response(loginHtml, 200, {'Content-Type':'text/html; charset=utf-8'});
    return response(html, 200, {'Content-Type':'text/html; charset=utf-8'});
  }
  if (url.pathname === '/complaints/auth' && request.method === 'GET') return (await authorized(request, env)) ? response(null, 204) : response('Unauthorized', 401);
  if (url.pathname === '/complaints/auth' && request.method === 'POST') {
    if (!env.COMPLAINT_PASSWORD || !env.SESSION_SECRET) return response('Server not configured', 503);
    let body; try { body = await request.json(); } catch { return response('Bad request', 400); }
    if (typeof body.password !== 'string' || body.password.length > 256 || body.password !== env.COMPLAINT_PASSWORD) return response('Unauthorized', 401);
    const expires = String(Date.now() + 60 * 60 * 1000), sig = await hmac(env.SESSION_SECRET, expires);
    return response(null, 204, {'Set-Cookie':`complaints_session=${expires}.${sig}; HttpOnly; Secure; SameSite=Strict; Path=/complaints; Max-Age=3600`});
  }
  if (url.pathname === '/complaints/send' && request.method === 'POST') {
    if (!(await authorized(request, env))) return response('Unauthorized', 401);
    let body; try { body = await request.json(); } catch { return response('Bad request', 400); }
    if (typeof body.message !== 'string' || !body.message.trim() || body.message.length > 10000) return response('Invalid message', 400);
    if (!env.RESEND_API_KEY || !env.COMPLAINT_TO) return response('Email service not configured', 503);
    const result = await fetch('https://api.resend.com/emails', {method:'POST',headers:{Authorization:`Bearer ${env.RESEND_API_KEY}`,'Content-Type':'application/json'},body:JSON.stringify({from:'Tanishtha <complaints@taiyr.com>',to:[env.COMPLAINT_TO],subject:'A complaint from Tanishtha',text:body.message.trim()})});
    if (!result.ok) return response('Could not send email', 502);
    return response('Sent', 200, {'Content-Type':'text/plain; charset=utf-8'});
  }
  return response('Not found', 404);
 }
};
