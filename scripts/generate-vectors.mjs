// Writes spec/vectors/*.json. Evaluation cases are hand-written in scripts/vectors/;
// credential vectors are signed once with a published TEST-ONLY key and then frozen.
import { writeFileSync, existsSync } from 'node:fs';
import { cases } from './vectors/evaluation-cases.mjs';
import { generateKeyPair, exportPublicJwk, jwkThumbprint, issuerSigner, jwksFor, signCredential, createProof, b64u, signStatusList, setBit } from '../packages/verify/src/index.js';

writeFileSync('spec/vectors/evaluation.json', JSON.stringify({ description: 'Grant evaluation conformance vectors. context.now is in seconds; reasons are listed per grant.', cases }, null, 2) + '\n');

const credentialsPath = 'spec/vectors/credentials.json';
if (existsSync(credentialsPath) && !process.argv.includes('--resign')) {
  console.log(`${credentialsPath} exists; pass --resign to regenerate signatures`);
} else {
  const ISSUER = 'https://devicebasedauth.org'; const NOW = 1795017600;
  const issuerPair = await generateKeyPair(true);
  const issuerKey = { kid: 'test-vectors-1', jwk: await crypto.subtle.exportKey('jwk', issuerPair.privateKey) };
  const signer = await issuerSigner(issuerKey);
  const devicePair = await generateKeyPair(true);
  const deviceJwk = await exportPublicJwk(devicePair.publicKey);
  const jkt = await jwkThumbprint(deviceJwk);
  const uri = `${ISSUER}/status/v1/lists/0`;
  const base = { iss: ISSUER, sub: 'dev_VECTORS0001', acct: 'acct_vectors', aud: ['hashbin.org'], cid: 'crd_VECTORS0001', jti: 'crd_VECTORS0001.1', iat: NOW, nbf: NOW, exp: NOW + 86400, cnf: { jkt }, device: { name: 'Vector laptop', kind: 'cli', key_protection: 'software' }, grants: [{ actions: ['hashbin:content:write'] }], status: { status_list: { idx: 3, uri } }, ver: 1 };
  const good = await signCredential(base, signer);
  const [h, , s] = good.split('.');
  const tampered = `${h}.${b64u(JSON.stringify({ ...base, grants: [{ actions: ['hashbin:*'] }] }))}.${s}`;
  const url = 'https://hashbin.org/api/content';
  const proof = await createProof({ privateKey: devicePair.privateKey, publicJwk: deviceJwk, method: 'POST', url, credential: good, now: NOW + 10, jti: 'vector-proof-0001' });
  const statusList = await signStatusList({ uri, bytes: setBit(setBit(new Uint8Array(1), 7), 3), issuer: ISSUER, now: NOW }, signer);
  const vectors = {
    description: 'Credential and proof conformance vectors. The issuer and device private keys are TEST-ONLY and published so other implementations can reproduce signatures.',
    issuer: ISSUER, jwks: jwksFor([issuerKey]), test_only_issuer_private_jwk: issuerKey.jwk, test_only_device_private_jwk: await crypto.subtle.exportKey('jwk', devicePair.privateKey), device_jkt: jkt,
    status_list: { uri, jwt: statusList, revoked_indexes: [3, 7] },
    credentials: [
      { name: 'valid credential', jws: good, audience: 'hashbin.org', now: NOW + 10, expected: { valid: true } },
      { name: 'wrong audience', jws: good, audience: 'cronly.org', now: NOW + 10, expected: { valid: false, code: 'wrong_audience' } },
      { name: 'expired beyond skew', jws: good, audience: 'hashbin.org', now: NOW + 86400 + 61, expected: { valid: false, code: 'expired' } },
      { name: 'within clock skew after exp', jws: good, audience: 'hashbin.org', now: NOW + 86400 + 59, expected: { valid: true } },
      { name: 'not yet valid', jws: good, audience: 'hashbin.org', now: NOW - 61, expected: { valid: false, code: 'not_yet_valid' } },
      { name: 'tampered payload', jws: tampered, audience: 'hashbin.org', now: NOW + 10, expected: { valid: false, code: 'invalid_signature' } },
      { name: 'garbage', jws: 'not-a-jws', audience: 'hashbin.org', now: NOW, expected: { valid: false, code: 'invalid_format' } }
    ],
    proofs: [
      { name: 'valid proof', proof, method: 'POST', url, credential: good, jkt, now: NOW + 10, expected: { valid: true } },
      { name: 'query string ignored in htu', proof, method: 'POST', url: `${url}?a=1`, credential: good, jkt, now: NOW + 10, expected: { valid: true } },
      { name: 'wrong method', proof, method: 'PUT', url, credential: good, jkt, now: NOW + 10, expected: { valid: false, code: 'invalid_proof' } },
      { name: 'wrong url', proof, method: 'POST', url: 'https://hashbin.org/api/other', credential: good, jkt, now: NOW + 10, expected: { valid: false, code: 'invalid_proof' } },
      { name: 'other credential', proof, method: 'POST', url, credential: tampered, jkt, now: NOW + 10, expected: { valid: false, code: 'invalid_proof' } },
      { name: 'other key', proof, method: 'POST', url, credential: good, jkt: 'AAAA', now: NOW + 10, expected: { valid: false, code: 'key_mismatch' } },
      { name: 'too old', proof, method: 'POST', url, credential: good, jkt, now: NOW + 10 + 121, expected: { valid: false, code: 'stale_proof' } }
    ]
  };
  writeFileSync(credentialsPath, JSON.stringify(vectors, null, 2) + '\n');
}
console.log(`wrote ${cases.length} evaluation cases`);
