const fs = require('fs');
const crypto = require('crypto');

// Vulnerability 11: Insecure random number generation
function generateToken() {
  // Using Math.random() for security-sensitive operations
  return Math.random().toString(36).substring(2, 15);
}

// Vulnerability 12: Unsafe regex leading to ReDoS
function validateEmail(email) {
  // Vulnerable to ReDoS (Regular Expression Denial of Service)
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  return emailRegex.test(email);
}

// Vulnerability 13: Insecure file operations
function writeLog(logData) {
  // Synchronous file operations can lead to DoS
  fs.writeFileSync('./logs/app.log', logData, { flag: 'a' });
}

// Vulnerability 14: Hardcoded encryption key
function encryptData(data) {
  const key = 'hardcoded-encryption-key-12345';
  const iv = Buffer.from('0123456789abcdef');
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(data);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString('hex');
}

// Vulnerability 15: Prototype pollution - Fixed
function merge(target, source) {
  // Validate that source is an object
  if (!source || typeof source !== 'object') {
    return target;
  }

  for (let key in source) {
    // Prevent prototype pollution by checking for dangerous keys
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    // Only process own properties using safe hasOwnProperty check
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }

    // Safe property access after validation
    const sourceValue = source[key];

    if (typeof sourceValue === 'object' && sourceValue !== null) {
      // Ensure target property exists and is an object
      const targetValue = Object.prototype.hasOwnProperty.call(target, key) ? target[key] : undefined;
      if (!targetValue || typeof targetValue !== 'object') {
        target[key] = {};
      }
      merge(target[key], sourceValue);
    } else {
      target[key] = sourceValue;
    }
  }
  return target;
}

module.exports = {
  generateToken,
  validateEmail,
  writeLog,
  encryptData,
  merge
};
