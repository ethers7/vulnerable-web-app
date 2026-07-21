const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const serialize = require('node-serialize');
const { execFile } = require('child_process');
const crypto = require('crypto');
const mongoose = require('mongoose');
const minimist = require('minimist');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

// Vulnerability 1: Insecure parsing of user input
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// CSRF Protection - Fixed
app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Vulnerability 2: Hardcoded credentials
const dbUser = 'admin';
const dbPassword = 'super_secret_password123';
const dbConnection = `mongodb://localhost:27017/vulnerable_db`;

// Vulnerability 3: Insecure direct object references - Path Traversal Fixed
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;

  // Validate user ID to prevent path traversal
  if (!userId || typeof userId !== 'string') {
    return res.status(400).send('Invalid user ID');
  }

  // Only allow alphanumeric user IDs (no path separators)
  if (!/^[a-zA-Z0-9_-]+$/.test(userId)) {
    return res.status(400).send('Invalid user ID format');
  }

  // Define base directory and resolve path
  const baseDir = path.resolve(__dirname, './data/users');
  const filePath = path.resolve(baseDir, `${userId}.json`);

  // Ensure the resolved path is within the allowed directory
  if (!filePath.startsWith(baseDir + path.sep)) {
    return res.status(403).send('Access denied');
  }

  // No authorization check, anyone can access any user's data
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('User not found');
    }
    res.send(data);
  });
});

// Vulnerability 4: Command injection - Fixed
app.get('/ping', (req, res) => {
  const host = req.query.host;

  // Validate host input to prevent command injection
  if (!host || typeof host !== 'string') {
    return res.status(400).send('Invalid host parameter');
  }

  // Strict length check to prevent abuse
  if (host.length > 253) {
    return res.status(400).send('Host parameter too long');
  }

  // Allowlist validation: only allow valid hostnames and IP addresses
  // Hostname pattern: alphanumeric, hyphens, dots, max 253 chars total
  const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  // IPv4 pattern: validate each octet is 0-255
  const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

  let isValid = false;
  if (hostnamePattern.test(host)) {
    isValid = true;
  } else if (ipv4Pattern.test(host)) {
    // Validate each octet is in range 0-255
    const octets = host.split('.').map(Number);
    isValid = octets.every(octet => octet >= 0 && octet <= 255);
  }

  if (!isValid) {
    return res.status(400).send('Invalid host format');
  }

  // Use execFile instead of exec to avoid shell injection
  // execFile does not spawn a shell, preventing command injection
  execFile('ping', ['-c', '4', host], (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send('Ping failed');
    }
    res.send(stdout);
  });
});

// Vulnerability 5: Insecure deserialization - Fixed
app.post('/deserialize', (req, res) => {
  const userInput = req.body.data;
  // Replaced insecure node-serialize with safe JSON.parse()
  try {
    const deserializedData = JSON.parse(userInput);
    res.send('Data processed');
  } catch (error) {
    res.status(400).send('Invalid JSON data');
  }
});

// Vulnerability 6: Weak cryptography
app.post('/encrypt', (req, res) => {
  const { text } = req.body;
  // Using weak MD5 hash
  const hash = crypto.createHash('md5').update(text).digest('hex');
  res.send({ hash });
});

// Helper function to escape HTML special characters
function escapeHtml(unsafe) {
  if (!unsafe) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Vulnerability 7: SQL Injection (simulated) - XSS Fixed
app.get('/search', (req, res) => {
  const query = req.query.q;
  // Simulating SQL injection vulnerability
  const sqlQuery = `SELECT * FROM products WHERE name LIKE '%${query}%'`;
  // Escape HTML to prevent XSS when displaying user input
  const safeSqlQuery = escapeHtml(sqlQuery);
  res.send(`Query executed: ${safeSqlQuery}`);
});

// Vulnerability 8: Path traversal - Fixed
app.get('/download', (req, res) => {
  const file = req.query.file;

  // Validate input
  if (!file || typeof file !== 'string') {
    return res.status(400).send('Invalid file parameter');
  }

  // Define allowed base directory
  const baseDir = path.resolve(__dirname);

  // Canonicalize the requested file path
  const filePath = path.resolve(baseDir, file);

  // Ensure the resolved path is within the allowed directory
  if (!filePath.startsWith(baseDir + path.sep) && filePath !== baseDir) {
    return res.status(403).send('Access denied');
  }

  // Check if file exists before sending
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }

  res.sendFile(filePath);
});

// Vulnerability 9: Cross-site scripting (XSS) - Fixed
app.get('/profile', (req, res) => {
  const username = req.query.username;
  // XSS vulnerability fixed by escaping HTML entities
  const safeUsername = escapeHtml(username);
  res.send(`
    <html>
      <body>
        <h1>Welcome, ${safeUsername}!</h1>
      </body>
    </html>
  `);
});

// Vulnerability 10: Insecure parsing of command line arguments
const args = minimist(process.argv.slice(2));
const debug = args.debug || false;

if (debug) {
  // Exposing sensitive information in debug mode
  console.log('Database credentials:', { dbUser, dbPassword });
}

app.listen(port, () => {
  console.log(`Vulnerable app listening at http://localhost:${port}`);
});
