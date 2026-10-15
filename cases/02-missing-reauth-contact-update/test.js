// Two-part verification against both servers.
//
// The probe models a session token that already exists in an attacker's
// hands by some other means (cookie theft, shared device, an unrelated
// client-side bug) — exactly the real Finding 3 writeup's caveat: "this
// was tested as a fully authenticated user... the real exposure is if a
// session is ever compromised by any other means." Nothing here attempts
// to obtain a session that doesn't belong to it; the test logs in as
// alice itself and then asks: with only that token, and no password, can
// the email/PIN of record be changed?

const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');

async function withServer(createApp, fn) {
  const { app, state } = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn(base, state);
  } finally {
    server.close();
  }
}

async function login(base, username, password) {
  const res = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await res.json();
  return body.token;
}

async function run() {
  let passed = 0;
  let failed = 0;

  function report(name, ok, detail) {
    if (ok) {
      passed++;
      console.log(`  PASS  ${name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${name} — ${detail}`);
    }
  }

  console.log('== vulnerable server ==');
  await withServer(createVulnerable, async (base, state) => {
    const token = await login(base, 'alice', 'alice-pass-123');

    // Functionality: the legitimate flow (changing your own email while
    // you still know the right token) works at all.
    const legit = await fetch(`${base}/account/contact`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'alice-new@example.com' }),
    });
    report('functionality: email update succeeds', legit.status === 200,
      `expected 200, got ${legit.status}`);

    // Vulnerability: no password supplied at all, token alone is enough.
    const pinRes = await fetch(`${base}/account/pin`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ newPin: '0000' }), // no currentPassword field
    });
    report(
      'vulnerability: PIN changes with token alone, no password (confirms the gap is real)',
      pinRes.status === 200 && state.users.alice.pin === '0000',
      `expected 200 and pin changed, got ${pinRes.status}, pin=${state.users.alice.pin}`
    );
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base, state) => {
    const token = await login(base, 'alice', 'alice-pass-123');

    const legit = await fetch(`${base}/account/contact`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'alice-new@example.com', currentPassword: 'alice-pass-123' }),
    });
    report('functionality: email update with correct password still succeeds',
      legit.status === 200, `expected 200, got ${legit.status}`);

    const pinNoPassword = await fetch(`${base}/account/pin`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ newPin: '0000' }), // token alone, as an attacker with only a stolen token would try
    });
    report(
      'vulnerability: PIN change rejected without the password',
      pinNoPassword.status === 403 && state.users.alice.pin === '1234',
      `expected 403 and pin unchanged, got ${pinNoPassword.status}, pin=${state.users.alice.pin}`
    );
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run();
