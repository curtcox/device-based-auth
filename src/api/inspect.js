import { assert, readJson } from '../utils/errors.js';
import { rpc } from '../utils/rpc.js';
import { decodeJws } from '../../packages/verify/src/jose.js';
import { verifyCredential, VerificationError } from '../../packages/verify/src/credential.js';
import { describeGrant, evaluateGrants } from '../../packages/verify/src/grants.js';
import { jwks, issuerName } from '../services/issuer.js';

/**
 * Decode and check a credential (free, no storage). Optionally evaluates an action, like the
 * policy playground. Revocation is read from the status-list shard (authoritative copy).
 */
export async function inspect(request, env) {
  const body = await readJson(request, 65536);
  let decoded;
  try { decoded = decodeJws(body.credential); } catch { assert(false, 'invalid_format', 'credential is not a compact JWS'); }
  const result = { header: decoded.header, payload: decoded.payload, signature_valid: false, valid: false, problems: [] };
  try {
    await verifyCredential(body.credential, { jwks: jwks(env), issuer: issuerName(env), typ: 'any', audience: body.audience, now: body.now });
    result.signature_valid = true; result.valid = true;
  } catch (error) {
    if (!(error instanceof VerificationError)) throw error;
    result.signature_valid = !['invalid_signature', 'unknown_kid', 'invalid_format', 'wrong_type'].includes(error.code);
    result.problems.push({ code: error.code, message: error.message });
  }
  const status = decoded.payload.status?.status_list;
  const shard = status?.uri?.match(/\/v1\/lists\/(\d+)$/)?.[1];
  if (result.signature_valid && shard !== undefined && Number.isSafeInteger(status.idx)) {
    result.revoked = (await rpc(env.STATUS, `shard-${shard}`, 'get', { idx: status.idx })).revoked;
    if (result.revoked) { result.valid = false; result.problems.push({ code: 'revoked', message: 'Credential has been revoked' }); }
  }
  if (Array.isArray(decoded.payload.grants)) result.descriptions = decoded.payload.grants.map(describeGrant);
  if (body.check?.action) {
    const now = body.check.now ?? Math.floor(Date.now() / 1000);
    const evaluation = evaluateGrants(decoded.payload.grants, { now, action: body.check.action, resource: body.check.resource, location: body.check.location, online: !!body.check.online, attestation: decoded.payload.device?.attestation });
    result.evaluation = { allow: evaluation.allow && result.valid, grant_index: evaluation.grant_index, reasons: evaluation.reasons, online_required: evaluation.online_required };
  }
  return result;
}
