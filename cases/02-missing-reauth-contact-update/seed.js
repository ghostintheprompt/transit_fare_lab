const crypto = require('crypto');

function freshState() {
  const users = {
    alice: {
      id: 'user_alice',
      username: 'alice',
      password: 'alice-pass-123',
      email: 'alice@example.com',
      pin: '1234',
    },
  };
  const sessions = {}; // token -> userId

  return { users, sessions };
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

function findUserById(state, userId) {
  return Object.values(state.users).find((u) => u.id === userId);
}

module.exports = { freshState, login, requireAuth, findUserById };
