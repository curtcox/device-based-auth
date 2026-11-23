import { assert } from '../utils/errors.js';
import { parseCidr } from '../../packages/verify/src/ip.js';
import { ADDRESS_LIST_ID } from '../../packages/verify/src/net.js';
import { signJws, decodeJws } from '../../packages/verify/src/jose.js';
import { ADDRESS_LIST_TYP, grantAddressLists } from '../../packages/verify/src/address-lists.js';
import { activeSigner, issuerName } from './issuer.js';

/**
 * Named address lists (STATUS B10 N3, todo/network_constraints.md §4): account-owned sets of CIDR
 * ranges a grant names in net.client.addresses.lists. Each is published as a signed
 * `dba-addresses+jwt` beside the status lists, so any verifier can enforce it offline.
 */
export const ADDRESS_LIST_LIMITS = Object.freeze({ cidrs: 10_000, perAccount: 50, nameLength: 100, chunk: 1000 });
/** A published copy is valid this long; it is re-signed well before (REPUBLISH_AFTER_MS). */
export const ADDRESS_LIST_LIFETIME_S = 86400;
export const REPUBLISH_AFTER_MS = 20 * 3600000;
/** Changes are published at most this often per list (debounced on the account's alarm). */
export const PUBLISH_INTERVAL_MS = 60000;
const DAY_MS = 86400000;

/** Where a list is published: status.devicebasedauth.org/v1/addresses/{id}. */
export function addressListUri(env, id) { return `${env.STATUS_ORIGIN || 'https://status.devicebasedauth.org'}/v1/addresses/${id}`; }

/** The R2 key of a published list. */
export function addressListKey(id) { return `v1/addresses/${id}`; }

/**
 * One CIDR, trimmed and lower-cased (verifiers parse any spelling). Host bits must be clear, so a
 * typo like 203.0.113.7/24 is refused rather than quietly meaning the whole /24.
 */
function cleanCidr(cidr, i) {
  const parsed = parseCidr(typeof cidr === 'string' ? cidr.trim() : cidr);
  assert(parsed, 'invalid_address_list', `cidrs[${i}] must be an IPv4 or IPv6 range like 203.0.113.0/24 (a single address needs /32 or /128)`);
  const host = BigInt(parsed.bits - parsed.prefix);
  assert(((parsed.value >> host) << host) === parsed.value, 'invalid_address_list', `cidrs[${i}] (${cidr}) has bits set after the /${parsed.prefix}; did you mean the range's first address?`);
  return cidr.trim().toLowerCase();
}

/**
 * Check a create or replace body: { name?, cidrs }. CIDRs are de-duplicated and sorted, so the
 * published list (and its size) does not depend on the order they were sent in.
 * @returns {{ name?: string, cidrs: string[] }}
 */
export function cleanAddressListInput(body, { create }) {
  assert(body && typeof body === 'object' && !Array.isArray(body), 'invalid_address_list', 'Send { name, cidrs }');
  for (const key of Object.keys(body)) assert(['name', 'cidrs'].includes(key), 'invalid_address_list', `Unknown field ${key}`);
  const out = {};
  if (body.name !== undefined || create) {
    assert(typeof body.name === 'string' && body.name.trim().length >= 1 && body.name.length <= ADDRESS_LIST_LIMITS.nameLength && ![...body.name].some(c => c.charCodeAt(0) < 32), 'invalid_address_list', `name must be 1–${ADDRESS_LIST_LIMITS.nameLength} characters`);
    out.name = body.name.trim();
  }
  assert(Array.isArray(body.cidrs) && body.cidrs.length <= ADDRESS_LIST_LIMITS.cidrs, 'invalid_address_list', `cidrs must be a list of up to ${ADDRESS_LIST_LIMITS.cidrs.toLocaleString('en-US')} ranges (it may be empty)`);
  out.cidrs = [...new Set(body.cidrs.map(cleanCidr))].sort();
  return out;
}

/** How many priced units a list of this size is: one per started 1,000 ranges (at least one). */
export function addressListUnits(count) { return Math.max(1, Math.ceil(count / ADDRESS_LIST_LIMITS.chunk)); }

/** Whole days a change extends the list's prepaid published life to (now + retention). */
export function extensionDays(paidUntil, newUntil) { return Math.max(0, Math.ceil((newUntil - paidUntil) / DAY_MS)); }

/**
 * Sign the list as it stands and put it on R2. A deleted list is published as a tombstone that
 * matches nothing, so verifiers holding the old copy drop it at their next fetch.
 */
export async function publishAddressList(env, { id, ver, cidrs, deleted }, now) {
  const signer = await activeSigner(env);
  const iat = Math.floor(now / 1000);
  const payload = { iss: issuerName(env), sub: addressListUri(env, id), id, ver, iat, exp: iat + ADDRESS_LIST_LIFETIME_S, ...(deleted ? { deleted: true, cidrs: [] } : { cidrs }) };
  const jwt = await signJws({ typ: ADDRESS_LIST_TYP, kid: signer.kid }, payload, signer.key);
  await env.STATUS_BUCKET.put(addressListKey(id), jwt, { httpMetadata: { contentType: 'application/jwt', cacheControl: 'public, max-age=60' } });
  return jwt;
}

/**
 * The published copy of a list as devicebasedauth.org itself reads it (issuance, online
 * decisions): straight from R2, which only this Worker writes, so its signature is not checked.
 * Returns { cidrs, ver } for a live list, or null when it is missing, deleted or expired.
 */
export async function readAddressList(env, id, now = Date.now()) {
  if (typeof id !== 'string' || !ADDRESS_LIST_ID.test(id)) return null;
  const object = await env.STATUS_BUCKET.get(addressListKey(id));
  if (!object) return null;
  let payload;
  try { ({ payload } = decodeJws((await object.text()).trim(), 4 * 1024 * 1024)); } catch { return null; }
  if (payload.deleted || !Array.isArray(payload.cidrs) || !(payload.exp * 1000 > now)) return null;
  return { cidrs: payload.cidrs, ver: payload.ver };
}

// Per environment (a Worker has one; tests make many): id -> { list, until }. A list is read from
// R2 at most once a minute per isolate, as verifiers read it through the CDN.
const onlineCaches = new WeakMap();
const ONLINE_CACHE_MS = 60000;

/**
 * The address_lists context for online decisions (spec/evaluation.md §3.10), read from R2:
 * { id: { cidrs, ver } } for each live list a grant names at its canonical URI; others are left
 * out, so they count as unavailable and match nothing.
 */
export async function resolveAddressLists(env, grants, now = Date.now()) {
  let cache = onlineCaches.get(env);
  if (!cache) { cache = new Map(); onlineCaches.set(env, cache); }
  const out = {};
  for (const { id, uri } of grantAddressLists(grants).slice(0, 8)) {
    if (uri !== addressListUri(env, id)) continue;
    let hit = cache.get(id);
    if (!hit || hit.until <= now) {
      hit = { list: await readAddressList(env, id, now), until: now + ONLINE_CACHE_MS };
      if (cache.size >= 1000) cache.delete(cache.keys().next().value);
      cache.set(id, hit);
    }
    if (hit.list) out[id] = hit.list;
  }
  return out;
}

/**
 * Issuance: every list a grant names must be at its canonical URI (whether it exists, in the
 * issuing account, is checked where the account's rows are: checkListsForIssue).
 */
export function checkGrantAddressListUris(env, grants) {
  for (const [i, grant] of grants.entries()) {
    for (const l of grant?.net?.client?.addresses?.lists || []) {
      assert(l.uri === addressListUri(env, l.id), 'invalid_grants', `grants[${i}]: address list ${l.id} must be named with its URI ${addressListUri(env, l.id)}`);
    }
  }
}
