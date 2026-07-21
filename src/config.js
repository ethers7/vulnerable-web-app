// Configuration file with exposed secrets
// WARNING: This file contains deliberately exposed secrets for educational purposes

// AWS credentials
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const AWS_ACCOUNT_ID = '123456789012';

// Database connection strings
const MONGODB_URI = 'mongodb+srv://admin:SuperSecretPassword123@cluster0.mongodb.net/vulnerable-db?retryWrites=true&w=majority';
const POSTGRES_CONNECTION = 'postgresql://dbuser:dbpass123@database.server.com:5432/mydb';

// API keys
const STRIPE_API_KEY = 'sk_test_51HCOHtGswqtO1FPdONKgAAAjkwoefijasefijasefijasef';
const TWILIO_AUTH_TOKEN = '9c5e36884dfasefasefasefasefasefasef3a';
// GITHUB_PERSONAL_ACCESS_TOKEN should be configured via environment variable
// Set the GITHUB_PERSONAL_ACCESS_TOKEN environment variable in your deployment environment
const GITHUB_PERSONAL_ACCESS_TOKEN = process.env.GITHUB_PERSONAL_ACCESS_TOKEN;
// SLACK_BOT_TOKEN should be configured via environment variable
// Set the SLACK_BOT_TOKEN environment variable in your deployment environment
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
// MAILCHIMP_API_KEY should be configured via environment variable
// Set the MAILCHIMP_API_KEY environment variable in your deployment environment
const MAILCHIMP_API_KEY = process.env.MAILCHIMP_API_KEY;


// OAuth credentials
const GOOGLE_OAUTH_CLIENT_SECRET = 'GOCSPX-1234567890abcdefghijklmnopqrstuvwxyz';
// FACEBOOK_APP_SECRET should be configured via environment variable
// Set the FACEBOOK_APP_SECRET environment variable in your deployment environment
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;

// JWT signing keys
const JWT_SECRET = 'jwt_super_secret_key_for_signing_tokens_do_not_share';
// PRIVATE_KEY should be configured via environment variable or loaded from a secure file
// Set the PRIVATE_KEY environment variable with your RSA private key in your deployment environment
// Alternatively, use PRIVATE_KEY_PATH to specify a path to a file containing the private key
// Example: PRIVATE_KEY_PATH=/path/to/secure/private-key.pem
const PRIVATE_KEY = process.env.PRIVATE_KEY || (process.env.PRIVATE_KEY_PATH ? require('fs').readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8') : null);

// Encryption keys
const ENCRYPTION_KEY = '12345678901234567890123456789012'; // 32-byte AES key

module.exports = {
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  AWS_ACCOUNT_ID,
  MONGODB_URI,
  POSTGRES_CONNECTION,
  STRIPE_API_KEY,
  TWILIO_AUTH_TOKEN,
  GITHUB_PERSONAL_ACCESS_TOKEN,
  SLACK_BOT_TOKEN,
  MAILCHIMP_API_KEY,
  GOOGLE_OAUTH_CLIENT_SECRET,
  FACEBOOK_APP_SECRET,
  JWT_SECRET,
  PRIVATE_KEY,
  ENCRYPTION_KEY
};
