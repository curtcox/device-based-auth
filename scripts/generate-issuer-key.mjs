// Prints a new issuer key entry for the ISSUER_KEYS secret. Usage:
//   node scripts/generate-issuer-key.mjs dba-2026-11 > new-key.json   (keep it out of the repo)
// Rotation: put the new entry FIRST in ISSUER_KEYS and keep the old one (it stays in the JWKS so
// existing credentials verify) until every credential signed by it has expired.
const kid = process.argv[2] || `dba-${new Date().toISOString().slice(0, 7)}`;
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey);
console.log(JSON.stringify({ kid, jwk: { kty, crv, x, y, d } }));
