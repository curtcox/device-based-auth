/**
 * Enrollment: the options that say what a new device may do, the signed request that asks for
 * its credential, the proof used to rotate to a new key, and polling until the owner decides.
 */
import { signJws, validateGrants } from '@devicebasedauth/verify';
import { UsageError } from './errors.js';
import { KEY_PROTECTION } from './device-key.js';

export const ENROLL_TYP = 'dba-enroll+jwt';
export const ROTATE_TYP = 'dba-rotate+jwt';
export const DEVICE_KINDS = ['browser', 'phone', 'desktop', 'server', 'cli', 'agent', 'iot', 'other'];

/** Audiences from repeated and/or comma-separated --aud values. */
export function audiencesFromOption(values = []) {
  const audiences = [...new Set(values.flatMap(v => v.split(',')).map(v => v.trim()).filter(Boolean))];
  if (!audiences.length) throw new UsageError('Give the site(s) this device is for with --aud, e.g. --aud hashbin.org');
  return audiences;
}

/**
 * Grants from --grant (one JSON grant, or a JSON list of grants, per use) and --action (all
 * --action values together form one plain grant). Checked locally so a typo fails here, with
 * the evaluator's own message, rather than after the owner has opened the approval page.
 */
export function grantsFromOptions({ grant = [], action = [] }) {
  const grants = [];
  for (const text of grant) {
    let value;
    try { value = JSON.parse(text); } catch { throw new UsageError(`--grant is not valid JSON: ${text}`); }
    grants.push(...(Array.isArray(value) ? value : [value]));
  }
  if (action.length) grants.push({ actions: action });
  if (!grants.length) throw new UsageError('Say what the device may do with --action (e.g. --action hashbin:content:write) or --grant \'<grant JSON>\'');
  const problems = validateGrants(grants);
  if (problems.length) throw new UsageError(`Invalid grants: ${problems.join('; ')}`);
  return grants;
}


/** An enrollment token from --token or $DBA_ENROLLMENT_TOKEN (the variable keeps it out of shell history). */
export function enrollmentTokenOption({ flag, env = {} } = {}) {
  const token = (flag ?? env.DBA_ENROLLMENT_TOKEN ?? '').trim();
  if (!token) return null;
  if (!token.startsWith('dbae_')) throw new UsageError('An enrollment token starts with dbae_');
  return token;
}

/** The payload of an enrollment request (spec: POST /api/v1/enrollments). */
export function enrollmentPayload({ aud, grants, name, kind = 'cli', lifetime, keyProtection = KEY_PROTECTION, attestation, now = Math.floor(Date.now() / 1000) }) {
  if (!DEVICE_KINDS.includes(kind)) throw new UsageError(`--kind must be one of ${DEVICE_KINDS.join(', ')}`);
  // aud and grants may be left out when enrolling with an enrollment token (the token's template applies).
  const payload = { iat: now, ...(aud ? { aud } : {}), ...(grants ? { grants } : {}), device: { name: name || 'dba CLI', kind, key_protection: keyProtection } };
  if (lifetime !== undefined) payload.lifetime_seconds = lifetime;
  if (attestation) payload.attestation = attestation;
  return payload;
}

/** Sign an enrollment request with the device's new key; the server checks it against header.jwk. */
export function signEnrollmentRequest(key, payload) {
  return signJws({ typ: ENROLL_TYP, jwk: key.publicJwk }, payload, key.privateKey);
}

/** Proof that the caller holds the NEW key during rotation (signed by it, naming the credential). */
export function rotationProof(newKey, cid, now = Math.floor(Date.now() / 1000)) {
  return signJws({ typ: ROTATE_TYP, jwk: newKey.publicJwk }, { cid, iat: now }, newKey.privateKey);
}

/**
 * Poll an enrollment until it is decided, at the interval the server asks for. Network errors
 * are retried until the deadline (a laptop may change networks during a 15-minute wait); error
 * responses are not. Returns the last poll body, or { status: 'timeout' }.
 */
export async function pollEnrollment(client, start, { waitSeconds = 900, sleep = ms => new Promise(r => setTimeout(r, ms)), clock = () => Date.now() } = {}) {
  const deadline = clock() + waitSeconds * 1000;
  let interval = start.interval || 3;
  while (clock() < deadline) {
    await sleep(Math.min(interval * 1000, Math.max(0, deadline - clock())));
    try {
      const result = await client.request('GET', start.poll_url);
      if (result.status !== 'pending') return result;
      interval = result.interval || interval;
    } catch (error) {
      if (error.code !== 'network_error') throw error;
    }
  }
  return { status: 'timeout' };
}
