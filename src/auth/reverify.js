import { ApiError } from '../utils/errors.js';

/** How recent a sign-in must be for account-control operations (master plan §10, STATUS S8). */
export const REVERIFY_MINUTES = 10;

/**
 * Minutes since the session's most recent factor verification, from a Clerk session token's
 * `fva` claim ([first factor age, second factor age], -1 when that factor was never used).
 * null when the claim is missing.
 */
export function factorAgeMinutes(claims) {
  if (!Array.isArray(claims?.fva)) return null;
  const ages = claims.fva.filter(n => Number.isFinite(n) && n >= 0);
  return ages.length ? Math.min(...ages) : null;
}

/** Does a grant list contain an action on devicebasedauth.org itself (dba:*)? */
export function hasDbaAction(grants) {
  return Array.isArray(grants) && grants.some(g => Array.isArray(g?.actions) && g.actions.some(a => typeof a === 'string' && (a === '*' || a.startsWith('dba:'))));
}

/** Would requireRecentSignIn let this caller through? (it throws when not) */
export function recentlySignedIn(auth) {
  if (!auth || auth.kind === 'local' || auth.kind === 'key') return true;
  return auth.kind === 'clerk' && auth.factor_age_minutes !== null && auth.factor_age_minutes !== undefined && auth.factor_age_minutes <= REVERIFY_MINUTES;
}

/**
 * Issue to a device that was revoked, which reinstates it (master plan §10: removing a revocation
 * needs a recent sign-in). Callers pass `reinstate: true` only for a person who signed in
 * recently; when the device turns out to be revoked without that, the account DO refuses with
 * device_revoked and this turns it into the reverification prompt for a person who could pass it.
 */
export async function reinstatingIssue(auth, issue, { person = true } = {}) {
  try {
    return await issue(person && recentlySignedIn(auth));
  } catch (error) {
    if (person && error?.code === 'device_revoked') requireRecentSignIn(auth, 'issue a credential to a device that was revoked');
    throw error;
  }
}

/**
 * Account takeover means control of every device, so some operations need a sign-in from the
 * last REVERIFY_MINUTES: issuing dba:* credentials, creating API keys and enrollment tokens with
 * dba:* grants, and raising budget limits. A Clerk session must carry a recent `fva`; local
 * development sessions pass; API keys pass (creating one needed this check); a dashboard device
 * (dba:session) cannot re-verify and is refused. `what` finishes "To …, sign in again".
 * The 403 body includes Clerk's reverification hint so Clerk's client helpers can react.
 */
export function requireRecentSignIn(auth, what) {
  if (recentlySignedIn(auth)) return;
  const message = auth.kind === 'device'
    ? `To ${what}, sign in to the dashboard with your password or passkey; a signed-in device cannot do this`
    : `To ${what}, sign in again: this needs a sign-in from the last ${REVERIFY_MINUTES} minutes`;
  throw new ApiError(403, 'reverification_required', message, {
    max_age_minutes: REVERIFY_MINUTES,
    clerk_error: { type: 'forbidden', reason: 'reverification-error', metadata: { reverification: { level: 'first_factor', afterMinutes: REVERIFY_MINUTES } } }
  });
}
