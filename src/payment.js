// Payment processing module with hardcoded API keys
// WARNING: This file contains deliberately exposed secrets for educational purposes

const stripe = require('stripe');

// Stripe API keys - configure these in environment variables
// Set STRIPE_TEST_KEY and STRIPE_LIVE_KEY in your .env file or deployment environment
const STRIPE_TEST_KEY = process.env.STRIPE_TEST_KEY;
const STRIPE_LIVE_KEY = process.env.STRIPE_LIVE_KEY;

// PayPal API credentials
const PAYPAL_CLIENT_ID = 'AeGIgSX--JEVwoQgLjGOb8gh2Vsc1HZLQX2LUgZMH2RvGCVfIJUZQlWW2vgIkFPzGGQjWFHwTiKS-pA';
const PAYPAL_CLIENT_SECRET = 'EHGEuHgIxH_CPEEQAuYm4-a1R6QJ9czF8Lw_NKAzpCKJUBwTXnWU4lOiNjaTMJMGSRDHgw_Wtb_3V4pL';

// Square API key
const SQUARE_ACCESS_TOKEN = 'EAAAEOuLQObrVwJvCBNcscS4BRwpN4gDvTj5vs-JbKrS_yjRGk0nDvDJwz9WmJPh';

// Braintree API keys
const BRAINTREE_MERCHANT_ID = '1234567890';
const BRAINTREE_PUBLIC_KEY = 'abcdefghijklmnop';
const BRAINTREE_PRIVATE_KEY = '1234567890abcdefghijklmnopqrstuv';

// Initialize Stripe client with API key
const stripeClient = stripe(process.env.NODE_ENV === 'production' ? STRIPE_LIVE_KEY : STRIPE_TEST_KEY);

// Process payment function
async function processPayment(amount, currency, paymentMethod, cardToken) {
  try {
    const paymentIntent = await stripeClient.paymentIntents.create({
      amount,
      currency,
      payment_method: cardToken,
      confirmation_method: 'manual',
      confirm: true,
    });
    
    return {
      success: true,
      paymentId: paymentIntent.id,
      status: paymentIntent.status
    };
  } catch (error) {
    console.error('Payment processing error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

module.exports = {
  processPayment,
  // Exposing API keys for demonstration purposes (bad practice)
  apiKeys: {
    stripe: {
      test: STRIPE_TEST_KEY || 'not_configured',
      live: STRIPE_LIVE_KEY || 'not_configured'
    },
    paypal: {
      clientId: PAYPAL_CLIENT_ID,
      clientSecret: PAYPAL_CLIENT_SECRET
    },
    square: SQUARE_ACCESS_TOKEN,
    braintree: {
      merchantId: BRAINTREE_MERCHANT_ID,
      publicKey: BRAINTREE_PUBLIC_KEY,
      privateKey: BRAINTREE_PRIVATE_KEY
    }
  }
};
