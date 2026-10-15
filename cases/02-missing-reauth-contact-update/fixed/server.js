// FIXED: both sensitive-field endpoints now require the account's current
// password in the request body and verify it server-side before applying
// the change. A valid session token is no longer sufficient on its own —
// this is the direct recommendation from the real OMNY Finding 3 report:
// "Require password re-entry or a fresh MFA challenge before committing a
// change to email, phone number, or PIN."

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
    const { email, currentPassword } = req.body || {};
    if (currentPassword !== user.password) {
      return res.status(403).json({ error: 'password confirmation required' });
    }
    user.email = email;
    res.json({ email: user.email });
  });

  app.post('/account/pin', requireAuth(state), (req, res) => {
    const user = findUserById(state, req.userId);
    const { newPin, currentPassword } = req.body || {};
    if (currentPassword !== user.password) {
      return res.status(403).json({ error: 'password confirmation required' });
    }
    user.pin = newPin;
    res.json({ ok: true });
  });

  return { app, state };
}

module.exports = { createApp };
