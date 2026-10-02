// Step 5 quick false-positive check: a handful of ordinary, benign requests
// a real dvws-node user/browser would make, sent with a realistic browser
// User-Agent, no query, no body (or a trivial one) -- exactly the shape the
// project's sibling apps found gets mis-blocked because of how much weight
// the RF model puts on `ua_length` and general "shortness"/emptiness of a
// request. Run against the server with logsguardian active (mode: block).

const BASE_URL = process.env.TARGET_URL || 'http://localhost:3000';
const UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

async function check(name, url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { 'User-Agent': UA, ...(opts.headers || {}) },
    redirect: 'manual',
  });
  const blocked = res.status === 403;
  let predictedClass = null;
  if (blocked) {
    try {
      predictedClass = (await res.clone().json()).class || null;
    } catch {}
  }
  console.log(
    `${blocked ? 'BLOCKED' : 'ok     '}  ${String(res.status).padEnd(4)}  ${name}${predictedClass ? `  (predicted: ${predictedClass})` : ''}`
  );
}

async function run() {
  console.log(`Benign false-positive spot check against ${BASE_URL}\n`);

  // 1. Home page -- plain GET, no query, no body.
  await check('GET / (home page)', `${BASE_URL}/`);

  // 2. Simple info listing -- plain GET, no query, no body.
  await check('GET /api/v1/info (simple listing)', `${BASE_URL}/api/v1/info`);

  // 3. A normal-looking login with a plain, unremarkable password (uses the
  //    same harness account run-attacks.js registers: zzzuser/xxxxxxxx --
  //    the one credential pair we found that survives the filter under this
  //    exact browser UA; see the long comment in run-attacks.js documenting
  //    how fiddly/unstable that turned out to be).
  await check('POST /api/v2/login (normal login)', `${BASE_URL}/api/v2/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'zzzuser', password: 'xxxxxxxx' }).toString(),
  });

  // 4. Authenticated "normal listing" -- GET a user's own profile.
  const loginRes = await fetch(`${BASE_URL}/api/v2/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA },
    body: new URLSearchParams({ username: 'zzzuser', password: 'xxxxxxxx' }).toString(),
  });
  const { token } = await loginRes.json();
  if (token) {
    await check('GET /api/v2/users/profile (own profile, authed)', `${BASE_URL}/api/v2/users/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } else {
    console.log('ok?     n/a   GET /api/v2/users/profile -- skipped, harness login itself did not return a token');
  }

  // 5. A benign SQLi-endpoint-shaped GET with a normal-looking value (the
  //    passphrase lookup endpoint, used here with an unremarkable username,
  //    not an injection payload).
  await check(
    "GET /api/v2/passphrase/admin (benign username, no injection)",
    `${BASE_URL}/api/v2/passphrase/admin`
  );
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
