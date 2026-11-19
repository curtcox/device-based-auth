import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { evaluateGrants, verifyCredential, verifyConfirmation, decodeJws, verifyProof, verifyJws, decodeStatusList, getBit } from '../packages/verify/src/index.js';

const evaluation = JSON.parse(readFileSync(new URL('./vectors/evaluation.json', import.meta.url)));
const credentials = JSON.parse(readFileSync(new URL('./vectors/credentials.json', import.meta.url)));

describe('evaluation vectors', () => {
  for (const c of evaluation.cases) it(c.name, () => {
    const result = evaluateGrants(c.grants, c.context);
    expect({ allow: result.allow, grant_index: result.grant_index, reasons: result.reasons }).toEqual(c.expected);
  });
});

describe('credential vectors', () => {
  for (const c of credentials.credentials) it(c.name, async () => {
    const outcome = await verifyCredential(c.jws, { jwks: credentials.jwks, issuer: credentials.issuer, audience: c.audience, now: c.now }).then(() => ({ valid: true }), e => ({ valid: false, code: e.code }));
    expect(outcome).toEqual(c.expected);
  });
  for (const c of credentials.proofs) it(`proof: ${c.name}`, async () => {
    const outcome = await verifyProof(c.proof, c).then(() => ({ valid: true }), e => ({ valid: false, code: e.code }));
    expect(outcome).toEqual(c.expected);
  });
  const credential = decodeJws(credentials.credentials.find(c => c.name === 'valid credential').jws).payload;
  for (const c of credentials.confirmations) it(`confirmation: ${c.name}`, async () => {
    const outcome = await verifyConfirmation(c.jws, { jwks: credentials.jwks, issuer: credentials.issuer, credential, audience: c.audience }).then(() => ({ valid: true }), e => ({ valid: false, code: e.code }));
    expect(outcome).toEqual(c.expected);
  });
  it('status list', async () => {
    const decoded = await verifyJws(credentials.status_list.jwt, credentials.jwks.keys[0]);
    const bytes = await decodeStatusList(decoded.payload.status_list);
    expect([0, 1, 2, 3, 4, 5, 6, 7, 8].filter(i => getBit(bytes, i))).toEqual(credentials.status_list.revoked_indexes);
  });
});
