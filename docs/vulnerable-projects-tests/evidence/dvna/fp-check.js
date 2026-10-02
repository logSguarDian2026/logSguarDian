// fp-check.js — Paso 5: a handful of typical, entirely benign DVNA requests
// (login page, home, a normal search) sent with a real browser User-Agent,
// to check whether logsguardian blocks legitimate traffic. Run against the
// PROTECTED instance (mode: block, default config). Does not use the
// toggle file — this is meant to hit the middleware exactly as a real user
// would.

const BASE_URL = process.env.TARGET_URL || 'http://localhost:9191';
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

const CHECKS = [
  { name: 'GET / (home, unauthenticated)', method: 'GET', path: '/' },
  { name: 'GET /login (login page)', method: 'GET', path: '/login' },
  { name: 'POST /login (valid credentials, alice)', method: 'POST', path: '/login', body: { username: 'alice', password: 'alice12345' } },
  { name: 'GET /app/usersearch (search page, no query)', method: 'GET', path: '/app/usersearch' },
  { name: 'GET /app/products (product listing page)', method: 'GET', path: '/app/products' },
];

async function run() {
  const results = [];
  let cookie = '';
  for (const check of CHECKS) {
    const opts = {
      method: check.method,
      headers: { 'User-Agent': UA, Cookie: cookie },
      redirect: 'manual',
    };
    if (check.body) {
      opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      opts.body = new URLSearchParams(check.body).toString();
    }
    const res = await fetch(`${BASE_URL}${check.path}`, opts);
    const setCookie = res.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    let predictedClass = null;
    if (res.status === 403) {
      try {
        predictedClass = JSON.parse(await res.text()).class || null;
      } catch (e) {}
    }
    results.push({ name: check.name, status: res.status, predictedClass });
    console.log(`${check.name}: ${res.status}${predictedClass ? ` (predicted: ${predictedClass})` : ''}`);
  }
  const falsePositives = results.filter((r) => r.status === 403);
  console.log(`\n${falsePositives.length}/${results.length} benign requests blocked.`);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
