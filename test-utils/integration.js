/**
 * Helpers shared by the end-to-end Worker tests (src/integration-*.test.js): funding an account,
 * a verifier that fetches the issuer's keys and status lists from the in-memory Worker, and a
 * DPoP-signed request a site would receive.
 */
import { call, worker, ORIGIN } from './env.js';
import { createVerifier, createProof } from '../packages/verify/src/index.js';

/** Deposits `dollars` into `account` through the local-mode deposit route. */
export const fund = (env, account, dollars = 1) => call(env, 'POST', '/api/v1/dev/deposit', { auth: account, body: { amount_microdollars: dollars * 1_000_000 } });

/** A site's verifier for `audience`, fetching from this env's Worker instead of the network. */
export const verifierFor = (env, audience = 'hashbin.org', options = {}) => createVerifier({ issuer: ORIGIN, audience, fetch: (url, init) => worker.fetch(new Request(url, init), env), ...options });

/** A request carrying `credential` and a fresh DPoP proof from `device`. */
export const requestWith = async (device, credential, method = 'POST', url = 'https://hashbin.org/api/content') => new Request(url, { method, headers: { Authorization: `DBA ${credential}`, DPoP: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method, url, credential }) } });
