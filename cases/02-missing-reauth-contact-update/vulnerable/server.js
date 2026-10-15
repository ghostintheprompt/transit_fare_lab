// VULNERABLE: an authenticated session (bearer token) alone is enough to
// change the email on file or the account PIN. No password or fresh MFA
// challenge is ever requested for either action.
//
// This models Finding 3 of the real OMNY engagement (confirmed live
// against omny.info — see mta_disclosure_email.md / CYBER_BENCH_omny_disclosure.md):
// the risk isn't the legitimate self-service case tested there, it's what
// a *stolen session token* (cookie theft, shared device, an unrelated
// client-side bug) can do with nothing further required. That's exactly
// what this probe checks: possession of a valid session token, with no
// password supplied at all, is sufficient to redirect the account's email
// of record and change its PIN.

const express = require('express');
const { freshState, login, requireAuth, findUserById } = require('../seed');

function createApp() {
  const state = freshState();
  const app = express();
  app.use(express.json());

  app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    const token = login(state, username, password);
    if (!token) return res.status(401).json({ error: 'invalid credentials' });
    res.json({ token });
  });

  app.post('/account/contact', requireAuth(state), (req, res) => {
    const user = findUserById(state, req.userId);
    const { email } = req.body || {};
    // BUG: no currentPassword field required or checked.
    user.email = email;
    res.json({ email: user.email });
  });

  app.post('/account/pin', requireAuth(state), (req, res) => {
    const user = findUserById(state, req.userId);
    const { newPin } = req.body || {};
    // BUG: same gap — the session alone authorizes this.
    user.pin = newPin;
    res.json({ ok: true });
  });

  return { app, state };
}

module.exports = { createApp };
