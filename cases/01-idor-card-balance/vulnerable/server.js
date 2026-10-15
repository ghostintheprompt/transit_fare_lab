// VULNERABLE: GET /account/wallet/cards/:id returns whatever card matches
// the ID in the URL, with no check that the requesting session actually
// owns that card. Authentication is required (you must be logged in as
// *someone*), but authorization on the specific resource is missing.
//
// This models, as a reproducible lab instead of an untested guess, the gap
// flagged-but-not-tested in Finding 4 of the real OMNY engagement
// (mta_disclosure_email.md / CYBER_BENCH_omny_disclosure.md): a numeric
// card ID in the URL, Luhn-valid so not trivially guessable, but with no
// visibility into whether the backend actually scopes the query to the
// caller. Here, the backend is ours, so we can just check.

const express = require('express');
const { freshState, login, requireAuth } = require('../seed');

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

  app.get('/account/wallet/cards/:id', requireAuth(state), (req, res) => {
    const card = state.cards[req.params.id];
    if (!card) return res.status(404).json({ error: 'not found' });
    // BUG: no check that card.ownerId === req.userId
    res.json({ id: req.params.id, balance: card.balance, last4: card.last4 });
  });

  return { app, state };
}

module.exports = { createApp };
