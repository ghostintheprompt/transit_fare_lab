// Shared fixture data + session helper for both the vulnerable and fixed
// servers in this case, so the only thing that differs between them is the
// one authorization check under test.

const crypto = require('crypto');

function freshState() {
  const users = {
    alice: { username: 'alice', password: 'alice-pass-123', id: 'user_alice' },
    bob: { username: 'bob', password: 'bob-pass-456', id: 'user_bob' },
  };

  // Card IDs deliberately shaped like the real OMNY finding: a long numeric
  // string, not a small sequential integer. Luhn-valid, same as the real
  // card ID captured during the OMNY engagement, to model the same
  // "hard to guess, but is the server actually checking ownership?" gap.
  const cards = {
    '441335047698': { ownerId: 'user_alice', balance: 42.5, last4: '7698' },
    '532219004412': { ownerId: 'user_bob', balance: 11.0, last4: '4412' },
  };

  const sessions = {}; // token -> userId

  return { users, cards, sessions };
}

function login(state, username, password) {
  const user = state.users[username];
  if (!user || user.password !== password) return null;
  const token = crypto.randomBytes(16).toString('hex');
  state.sessions[token] = user.id;
  return token;
}

function requireAuth(state) {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const userId = token && state.sessions[token];
    if (!userId) return res.status(401).json({ error: 'unauthenticated' });
    req.userId = userId;
    next();
  };
}

module.exports = { freshState, login, requireAuth };
