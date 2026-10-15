// FIXED: identical to ../vulnerable/server.js except for the one line that
// matters: the card-lookup handler checks that the requesting session's
// userId actually owns the card ID in the URL before returning anything.
// A request for a card you don't own now gets 403, not the card's balance.

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
    if (card.ownerId !== req.userId) {
      return res.status(403).json({ error: 'forbidden' });
    }
    res.json({ id: req.params.id, balance: card.balance, last4: card.last4 });
  });

  return { app, state };
}

module.exports = { createApp };
