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
  // Use path.relative to verify no directory traversal occurred
  const relativePath = path.relative(baseDir, filePath);
  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    return res.status(403).send('Access denied');
  }

  // Additional check: ensure resolved path starts with base directory
  if (!filePath.startsWith(baseDir + path.sep) && filePath !== baseDir) {
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

// HTML Sanitization function following OWASP guidelines
// This function encodes HTML special characters to prevent XSS attacks
// Implements context-aware output encoding as recommended by OWASP
function sanitizeHtml(unsafe) {
  if (!unsafe) return '';
  if (typeof unsafe !== 'string') {
    unsafe = String(unsafe);
  }
  // Encode HTML special characters following OWASP recommendations
  // This prevents XSS by ensuring user input is treated as data, not code
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

// Maintain backward compatibility
function escapeHtml(unsafe) {
  return sanitizeHtml(unsafe);
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

// Vulnerability 8: Path traversal - Fixed (CWE-22)
app.get('/download', (req, res) => {
  const file = req.query.file;

  // Validate input
  if (!file || typeof file !== 'string') {
    return res.status(400).send('Invalid file parameter');
  }

  // Strict input validation: reject paths with dangerous characters and patterns
  // Prevent null bytes, path traversal sequences, and absolute paths
  if (file.includes('\0') ||
      file.includes('..') ||
      file.startsWith('/') ||
      file.startsWith('\\') ||
      file.includes(':')) {
    return res.status(400).send('Invalid file parameter');
  }

  // Define allowed base directory - use path.resolve for canonical path
  const baseDir = path.resolve(__dirname);

  // Resolve the requested file path against the base directory
  // This canonicalizes the path and resolves any symbolic links
  const resolvedPath = path.resolve(baseDir, file);

  // Critical security check: Ensure the resolved path is within the allowed directory
  // This prevents directory traversal attacks (CWE-22)
  // Note: We must check against baseDir + path.sep to prevent prefix matching issues
  // Example: /app/files should not match /app/files_private
  if (!resolvedPath.startsWith(baseDir + path.sep) && resolvedPath !== baseDir) {
    return res.status(403).send('Access denied');
  }

  // Additional validation: compute relative path and verify it doesn't escape
  const relativePath = path.relative(baseDir, resolvedPath);
  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    return res.status(403).send('Access denied');
  }

  // Verify file exists and is a regular file (not a directory or special file)
  try {
    const stats = fs.statSync(resolvedPath);
    if (!stats.isFile()) {
      return res.status(403).send('Access denied');
    }
  } catch (err) {
    return res.status(404).send('File not found');
  }

  // Safe to send the file - the path has been validated to be within baseDir
  res.sendFile(resolvedPath);
});

// Vulnerability 9: Cross-site scripting (XSS) - Fixed
app.get('/profile', (req, res) => {
  const username = req.query.username;
  // XSS Prevention: Sanitize user input before inserting into HTML context
  // Using HTML entity encoding to prevent script injection (CWE-79)
  // This follows OWASP guidelines for output encoding
  const safeUsername = sanitizeHtml(username);
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
