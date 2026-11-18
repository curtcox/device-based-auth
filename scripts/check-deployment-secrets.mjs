// Fails the deploy before anything changes when a required secret is missing or malformed.
const required = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'ISSUER_KEYS', 'TOKEN_SIGNING_KEY', 'CLERK_SECRET_KEY', 'CLERK_PUBLISHABLE_KEY', 'CLERK_WEBHOOK_SECRET', 'OPERATOR_ACCOUNT'];
const missing = required.filter(name => !process.env[name]);
const problems = missing.map(name => `${name} is not set`);
try {
  const keys = JSON.parse(process.env.ISSUER_KEYS || '[]');
  if (!Array.isArray(keys) || !keys.some(k => !k.retired && k.jwk?.crv === 'P-256' && k.jwk?.d)) problems.push('ISSUER_KEYS needs an active P-256 private JWK');
  if (keys.some(k => k.kid?.startsWith('local-'))) problems.push('ISSUER_KEYS contains the local development key');
} catch { problems.push('ISSUER_KEYS is not JSON'); }
if ((process.env.TOKEN_SIGNING_KEY || '').length < 32) problems.push('TOKEN_SIGNING_KEY must be at least 32 characters');
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }
console.log('deployment secrets present');
