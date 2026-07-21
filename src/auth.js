const bcrypt = require('bcrypt');

// Fixed: Using bcrypt for secure password hashing
// bcrypt is a secure password hashing function with built-in salt generation
// and configurable computational cost
async function hashPassword(password) {
  const saltRounds = 10; // Cost factor for bcrypt
  return await bcrypt.hash(password, saltRounds);
}

// Vulnerability 17: Insecure JWT implementation
function generateJWT(user) {
  // No signature verification, easily forgeable
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify(user)).toString('base64');
  return `${header}.${payload}.`;
}

// Vulnerability 18: Insecure session management
const sessions = {};

function createSession(userId) {
  const sessionId = Math.random().toString(36).substring(2, 15);
  sessions[sessionId] = {
    userId,
    createdAt: new Date(),
    // No expiration time set
  };
  return sessionId;
}

// Vulnerability 19: No rate limiting
async function authenticateUser(username, password) {
  // No rate limiting, vulnerable to brute force attacks
  // Simulated user lookup - in production, this would be a stored hash
  // For demonstration, using a pre-hashed password (hash of 'admin123')
  const storedHash = '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

  if (username === 'admin' && await bcrypt.compare(password, storedHash)) {
    return { id: 1, username: 'admin', role: 'admin' };
  }
  return null;
}

module.exports = {
  hashPassword,
  generateJWT,
  createSession,
  authenticateUser
};
