/**
 * What each priced operation is, for the landing and pricing pages. The numbers themselves always
 * come from GET /api/public/config (src/utils/pricing.js is the only place prices live).
 */
export const OPERATIONS = Object.freeze({
  issue: { label: 'Issue a credential', detail: 'Includes its prepaid revocation and 13 months of records. Paid by the issuing account.' },
  renew: { label: 'Renew a credential', detail: 'Same key, same grants, a fresh expiry. Paid by the issuing account.' },
  decision: { label: 'Online authorization decision', detail: 'Instant revocation, usage limits and step-up. Paid by the site (audience) that asks.' },
  read: { label: 'API read', detail: 'A list or get made with an API key or a non-dashboard device. Dashboard reads are free.' },
  token: { label: 'Access-token exchange', detail: 'Trade a credential for a 10-minute bearer token for scripts.' },
  login: { label: 'Sign in with devicebasedauth.org', detail: 'One OpenID Connect sign-in. Paid by the site.' },
  audience: { label: 'Register or change an audience', detail: 'Publish your site and its action catalog.' },
  notice: { label: 'Security email', detail: 'One email to the account owner: takeover-sensitive events at once, other issuances in an hourly digest. Charged when queued; the owner can turn them down or off.' }
});

/** Free things, for the same tables. */
export const FREE = Object.freeze([
  ['Offline verification', 'Servers verify credentials themselves with @devicebasedauth/verify.'],
  ['Revocation', 'Prepaid when the credential is issued, so it works even at a zero balance.'],
  ['JWKS, status lists, SDK and docs', 'Static files served from the CDN.'],
  ['Developer tools and dashboard reads', 'Inspector, playground, grant builder and request signer.']
]);
