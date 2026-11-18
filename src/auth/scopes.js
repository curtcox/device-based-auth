import { DBA_SCOPES } from '../services/first-party.js';
import { evaluateGrants } from '../../packages/verify/src/grants.js';

export const PUBLIC = 'public';
export const SESSION = 'session';
/** A route any valid device credential (for any audience) may call: renew, token exchange. */
export const DEVICE = 'device';
/** Any authenticated caller (session, API key or device). */
export const AUTHENTICATED = 'authenticated';
export const USER_SCOPES = Object.freeze(Object.keys(DBA_SCOPES));

/** Parse and deduplicate known scopes; null when any is unknown. */
export function parseScopes(input) {
  if (!Array.isArray(input) || input.length === 0 || input.some(scope => !USER_SCOPES.includes(scope))) return null;
  return [...new Set(input)];
}

/** Does a device credential's grants allow "dba:<action>" right now? */
function deviceAllows(auth, action) {
  if (!auth.device?.dba) return false;
  const result = evaluateGrants(auth.device.payload.grants, { now: Math.floor(Date.now() / 1000), action, location: auth.device.location, online: true });
  return result.allow;
}

/** Check route access; undeclared access always denies. */
export function canAccess(auth, access) {
  if (access === PUBLIC) return true;
  if (!auth) return false;
  if (Array.isArray(access)) return access.some(scope => canAccess(auth, scope));
  if (access === DEVICE) return !!auth.device;
  if (access === AUTHENTICATED) return true;
  if (access === SESSION) return auth.session === true || deviceAllows(auth, 'dba:session');
  if (!USER_SCOPES.includes(access)) return false;
  return auth.session === true || !!auth.scopes?.includes(access) || deviceAllows(auth, `dba:${access}`) || deviceAllows(auth, 'dba:session');
}
