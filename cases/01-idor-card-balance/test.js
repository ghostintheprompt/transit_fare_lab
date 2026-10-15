// Two-part verification, run against both the vulnerable and fixed app:
//   1. Functionality test — the fix doesn't break the legitimate case
//      (a user reading their own card still works).
//   2. Vulnerability test — a non-destructive probe proving the boundary:
//      can a logged-in user read a card they don't own?
//
// No credential or token is ever obtained by guessing or bypassing login;
// every request is sent with a real session this test itself logged in.
// The only thing under test is server-side authorization on an ID the
// caller already has in hand, modeling the real flagged OMNY gap.

const assert = require('node:assert');
const { createApp: createVulnerable } = require('./vulnerable/server');
const { createApp: createFixed } = require('./fixed/server');

async function withServer(createApp, fn) {
  const { app } = createApp();
  const server = app.listen(0);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  try {
    await fn(base);
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

async function getCard(base, token, cardId) {
  return fetch(`${base}/account/wallet/cards/${cardId}`, {
    headers: { authorization: `Bearer ${token}` },
  });
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
  await withServer(createVulnerable, async (base) => {
    const aliceToken = await login(base, 'alice', 'alice-pass-123');

    const own = await getCard(base, aliceToken, '441335047698');
    report('functionality: alice reads her own card', own.status === 200,
      `expected 200, got ${own.status}`);

    const others = await getCard(base, aliceToken, '532219004412');
    const body = await others.json().catch(() => ({}));
    report(
      'vulnerability: alice CAN read bob\'s card (confirms the gap is real)',
      others.status === 200 && typeof body.balance === 'number',
      `expected 200 with a balance, got ${others.status} ${JSON.stringify(body)}`
    );
  });

  console.log('== fixed server ==');
  await withServer(createFixed, async (base) => {
    const aliceToken = await login(base, 'alice', 'alice-pass-123');

    const own = await getCard(base, aliceToken, '441335047698');
    report('functionality: alice still reads her own card', own.status === 200,
      `expected 200, got ${own.status}`);

    const others = await getCard(base, aliceToken, '532219004412');
    report(
      'vulnerability: alice can no longer read bob\'s card',
      others.status === 403,
      `expected 403, got ${others.status}`
    );
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run();
