/**
 * WebAuthn for security-key and passkey gates (STATUS B7, done/additional_gates.md §4.3): register
 * a credential (keeping only its public key), then check assertions over a challenge bound to one
 * gate request and decision. ES256 (P-256) only, which every FIDO2 security key and platform
 * passkey supports. Attestation statements are not checked: a gate trusts whoever holds the key
 * it registered, not who made it.
 */
import { decodeCbor, decodeCborPrefix } from './cbor.js';
import { b64u, unb64u } from '../../packages/verify/src/jose.js';

const encoder = new TextEncoder();
const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof bytes === 'string' ? encoder.encode(bytes) : bytes));
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/** A WebAuthn failure (always a 400 to the client). */
export class WebAuthnError extends Error { constructor(message) { super(message); this.code = 'invalid_webauthn'; } }
const fail = message => { throw new WebAuthnError(message); };

/** The relying party id for an app origin (its host name). */
export const rpIdFor = origin => new URL(origin).hostname;

function clientData(json, { type, challenge, origin }) {
  let data;
  try { data = JSON.parse(new TextDecoder().decode(unb64u(json))); } catch { fail('clientDataJSON is not JSON'); }
  if (data.type !== type) fail(`clientDataJSON.type must be ${type}`);
  if (data.challenge !== challenge) fail('clientDataJSON.challenge does not match');
  if (data.origin !== origin) fail(`clientDataJSON.origin must be ${origin}`);
  if (data.crossOrigin === true) fail('cross-origin ceremonies are not accepted');
  return data;
}

/** Parse authenticator data (WebAuthn §6.1). */
function authData(bytes) {
  if (bytes.length < 37) fail('authenticatorData is too short');
  const flags = bytes[32];
  const out = { rpIdHash: bytes.subarray(0, 32), up: !!(flags & 0x01), uv: !!(flags & 0x04), at: !!(flags & 0x40), signCount: new DataView(bytes.buffer, bytes.byteOffset + 33, 4).getUint32(0) };
  if (out.at) {
    if (bytes.length < 55) fail('attested credential data is too short');
    const idLength = bytes[53] * 256 + bytes[54];
    if (idLength < 16 || idLength > 1023 || bytes.length < 55 + idLength) fail('credential id has a bad length');
    out.credentialId = bytes.slice(55, 55 + idLength);
    let key;
    try { key = decodeCborPrefix(bytes.subarray(55 + idLength)).value; } catch { fail('credential public key is not CBOR'); }
    out.publicKey = key;
  }
  return out;
}

/** A COSE EC2 P-256 ES256 key as a JWK (anything else is refused). */
function coseToJwk(key) {
  if (!(key instanceof Map) || key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1) fail('only ES256 (P-256) keys are supported');
  const x = key.get(-2); const y = key.get(-3);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) fail('malformed P-256 key');
  return { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) };
}

/** ASN.1 DER ECDSA signature → raw r‖s (64 bytes) for WebCrypto. */
export function derToRaw(der) {
  const bad = () => fail('signature is not a DER ECDSA signature');
  if (der[0] !== 0x30 || der[1] !== der.length - 2) bad();
  let at = 2; const parts = [];
  for (let i = 0; i < 2; i++) {
    if (der[at] !== 0x02) bad();
    const length = der[at + 1]; let value = der.subarray(at + 2, at + 2 + length);
    if (value.length !== length || length === 0) bad();
    while (value.length > 32 && value[0] === 0) value = value.subarray(1);
    if (value.length > 32) bad();
    const padded = new Uint8Array(32); padded.set(value, 32 - value.length); parts.push(padded);
    at += 2 + length;
  }
  if (at !== der.length) bad();
  const raw = new Uint8Array(64); raw.set(parts[0]); raw.set(parts[1], 32); return raw;
}

/** Registration options for navigator.credentials.create (JSON-safe; ids base64url). */
export function creationOptions({ challenge, rpId, userId, label, exclude = [] }) {
  return {
    challenge, rp: { id: rpId, name: 'devicebasedauth.org' }, user: { id: userId, name: label, displayName: label },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], timeout: 300000, attestation: 'none',
    authenticatorSelection: { userVerification: 'preferred', residentKey: 'discouraged' },
    excludeCredentials: exclude.map(id => ({ type: 'public-key', id }))
  };
}

/**
 * Check a registration (navigator.credentials.create) response: { clientDataJSON,
 * attestationObject } (base64url). Returns { credential_id, public_jwk, sign_count, uv }.
 */
export async function verifyRegistration(response, { challenge, origin, rpId, requireUV = false }) {
  clientData(response?.clientDataJSON, { type: 'webauthn.create', challenge, origin });
  let attestation;
  try { attestation = decodeCbor(unb64u(response.attestationObject)); } catch { fail('attestationObject is not CBOR'); }
  if (!(attestation instanceof Map) || !(attestation.get('authData') instanceof Uint8Array)) fail('attestationObject has no authData');
  const data = authData(attestation.get('authData'));
  if (!equal(data.rpIdHash, await sha256(rpId))) fail(`the credential is not for ${rpId}`);
  if (!data.up) fail('the user was not present');
  if (requireUV && !data.uv) fail('the authenticator did not verify the user');
  if (!data.at) fail('no credential in the registration');
  const jwk = coseToJwk(data.publicKey);
  await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']).catch(() => fail('the public key is not on P-256'));
  return { credential_id: b64u(data.credentialId), public_jwk: jwk, sign_count: data.signCount, uv: data.uv };
}

/**
 * The challenge for answering one entry of one gate request: binding it to the request, entry and
 * decision means an assertion made to allow cannot be replayed to deny, or for another request.
 */
export async function answerChallenge({ requestId, entry, decision, salt }) {
  return b64u(await sha256(`dba-gate-answer\n${requestId}\n${entry}\n${decision}\n${salt}`));
}

/**
 * Check an assertion (navigator.credentials.get) response: { credential_id, clientDataJSON,
 * authenticatorData, signature } against a registered gate. Returns the new sign count.
 */
export async function verifyAssertion(response, { challenge, origin, rpId, credential, requireUV = false }) {
  if (response?.credential_id !== credential.credential_id) fail('not the registered security key');
  const clientJson = response.clientDataJSON;
  clientData(clientJson, { type: 'webauthn.get', challenge, origin });
  let bytes;
  try { bytes = unb64u(response.authenticatorData); } catch { fail('authenticatorData is not base64url'); }
  const data = authData(bytes);
  if (!equal(data.rpIdHash, await sha256(rpId))) fail(`the assertion is not for ${rpId}`);
  if (!data.up) fail('the user was not present');
  if (requireUV && !data.uv) fail('the authenticator did not verify the user');
  const key = await crypto.subtle.importKey('jwk', credential.public_jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const signed = new Uint8Array([...bytes, ...await sha256(unb64u(clientJson))]);
  let signature;
  try { signature = derToRaw(unb64u(response.signature)); } catch (error) { if (error instanceof WebAuthnError) throw error; fail('signature is not base64url'); }
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, signed)) fail('the signature does not verify');
  // A counter that does not grow (when the key keeps one) suggests a cloned key (WebAuthn §6.1.1).
  if ((data.signCount !== 0 || credential.sign_count !== 0) && data.signCount <= credential.sign_count) fail('the security key\'s signature counter went backwards; it may have been cloned');
  return { sign_count: data.signCount, uv: data.uv };
}
