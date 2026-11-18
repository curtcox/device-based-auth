import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { price } from '../utils/pricing.js';
import { decodeJws, publicJwk } from '../../packages/verify/src/jose.js';
import { issuerSigner } from '../../packages/verify/src/issuer.js';
import { trustedIssuerKeys } from '../services/issuer.js';
import { caCertificate, deviceCertificate, deviceUris, pem } from '../services/x509.js';

export const CERT_SECONDS = Object.freeze({ min: 300, max: 86400, default: 3600 });
const caCache = new Map();

/** The CA certificate for each trusted issuer key (active key first), cached per isolate. */
async function caCertificates(env) {
  const keys = trustedIssuerKeys(env);
  const ordered = [...keys.filter(k => !k.retired), ...keys.filter(k => k.retired)];
  return Promise.all(ordered.map(async ({ kid, jwk, retired }) => {
    const id = `${kid}:${jwk.x}`;
    if (!caCache.has(id)) {
      const signer = await issuerSigner({ kid, jwk });
      caCache.set(id, { kid, retired: !!retired, signer, der: await caCertificate({ kid, publicJwk: signer.publicJwk, privateKey: signer.key }) });
    }
    return caCache.get(id);
  }));
}

/** GET /.well-known/dba-ca.pem: every issuer CA certificate, for mTLS trust stores (API Shield). */
export async function caBundle(env) {
  const cas = await caCertificates(env);
  return new Response(cas.map(ca => pem(ca.der)).join(''), { headers: { 'Content-Type': 'application/x-pem-file', 'Cache-Control': 'public, max-age=3600' } });
}

/**
 * POST /api/v1/certificate (device credential + DPoP): an X.509 client certificate for the
 * presenting device's own key, valid lifetime_seconds (300–86400, default 3600) and never past
 * the credential. Charged at the token price, like an access token.
 */
export async function deviceCertificateFor(request, env, auth) {
  const body = await readJson(request, 4096);
  const lifetime = body.lifetime_seconds ?? CERT_SECONDS.default;
  assert(Number.isSafeInteger(lifetime) && lifetime >= CERT_SECONDS.min && lifetime <= CERT_SECONDS.max, 'invalid_lifetime', `lifetime_seconds must be ${CERT_SECONDS.min}–${CERT_SECONDS.max}`);
  const { payload } = auth.device;
  // The DPoP proof that authenticated this request carries the device's public key (its
  // thumbprint was checked against the credential's cnf.jkt).
  const devicePublicJwk = publicJwk(decodeJws(request.headers.get('DPoP')).header.jwk);
  const now = Date.now();
  const notAfter = Math.min(now + lifetime * 1000, payload.exp * 1000);
  assert(notAfter > now + 60000, 'credential_expiring', 'The credential expires too soon; renew it first', 409);
  await rpc(env.ACCOUNTS, payload.acct, 'charge', { kind: 'token', amount: price('token'), aggregate: true, now });
  const [active] = await caCertificates(env);
  const issued = await deviceCertificate({ devicePublicJwk, payload, notBefore: now - 60000, notAfter, issuer: { kid: active.kid, publicJwk: active.signer.publicJwk, privateKey: active.signer.key } });
  return {
    certificate: pem(issued.der), ca: pem(active.der), serial: issued.serial,
    not_before: new Date(now - 60000).toISOString(), not_after: new Date(notAfter).toISOString(),
    subject: payload.sub, uris: deviceUris(payload), cost_microdollars: price('token')
  };
}
