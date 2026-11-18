import { PUBLIC, SESSION, DEVICE, AUTHENTICATED } from '../auth/scopes.js';

const money = { type: 'integer', minimum: 0, description: 'Integer micro-dollars (1 USD = 1,000,000).' };
const jws = { type: 'string', description: 'Compact JWS (ES256).' };
const grant = { $ref: '#/components/schemas/Grant' };
const SUMMARIES = {
  health: 'Service health and deployed commit.', jwks: 'Issuer public keys (JWKS).', 'oidc-configuration': 'OpenID Connect discovery document.',
  'status-list': 'A signed status list (IETF Token Status List). Bit idx = 1 means revoked.', 'public-config': 'Public configuration and prices.',
  quote: 'Price of an operation (op = issue, renew, decision, read, token, login, audience).', inspect: 'Decode and check a credential; optionally evaluate an action. Free.',
  'enroll-start': 'Start an enrollment with a request JWS (typ dba-enroll+jwt) signed by the new device key. Returns the approval URL and a poll URL. Free; nothing is stored.',
  'enroll-describe': 'Describe a pending enrollment ticket for the approval page. Free.', 'enroll-poll': 'Poll an enrollment until it is approved, denied or expired.',
  'enroll-approve': 'Approve an enrollment (optionally narrowing grants) and issue the credential. Charges the issue price.', 'enroll-deny': 'Deny an enrollment.',
  whoami: 'Who is calling: account, credential kind and (for devices) the grants in plain English.', account: 'Balance, this month\'s spend and today\'s aggregated charges.',
  transactions: 'Ledger, newest first.', audit: 'Audit trail, newest first.', 'credentials-list': 'List credentials (filters: status, audience, device).',
  'credentials-create': 'Issue a credential for a public key you hold (API keys, sessions, or devices delegating narrower grants). Charges the issue price.',
  'credentials-get': 'One credential: payload fields, grants in plain English, current JWS and history.', 'revoke-credential': 'Revoke a credential (free, immediate online; status lists within a minute).',
  'credentials-decisions': 'Online authorization decisions for a credential (kept 90 days).', renew: 'Renew the presented credential (same key), or rotate to a new key with new_key_proof. Device credential + DPoP.',
  'devices-list': 'Devices with their credentials.', 'devices-get': 'One device.', 'revoke-device': 'Revoke every credential of a device.', 'revoke-all': 'Revoke everything (optionally one audience). Body {"confirm":"revoke-all"}.',
  'revoke-self': 'A device revokes the credential it presents.', token: 'Exchange the presented device credential for a ≤10-minute bearer access token for one audience. Charges the token price.',
  authorize: 'Online authorization decision for an audience you own: revocation, usage limits, step-up, decision log. Charges the decision price.',
  'step-ups': 'Pending step-up approval requests.', 'step-up-decide': 'Approve or deny a step-up request.', audiences: 'Audiences (relying parties): list, read, register (domain check, charges the audience price) and change.',
  keys: 'Account API keys (dbak_…). The secret is shown once.', checkout: 'Start a Stripe Checkout for prepaid credit. ?dry_run=1 shows the card fee.', 'dev-deposit': 'Local development only: add credit.',
  'oidc-authorize-page': 'OpenID Connect authorization endpoint (redirects to the consent page).', 'oidc-authorize': 'Consent page submission.', 'oidc-token': 'OpenID Connect token endpoint (authorization_code + PKCE S256).',
  'oidc-userinfo': 'OpenID Connect userinfo.', mcp: 'Model Context Protocol (Streamable HTTP, JSON-RPC).', 'clerk-webhook': 'Clerk webhook (signed).', 'stripe-webhook': 'Stripe webhook (signed).'
};
const BODIES = {
  'enroll-start': { type: 'object', required: ['request'], properties: { request: { ...jws, description: 'JWS, header {typ:"dba-enroll+jwt", alg:"ES256", jwk}, payload {iat, aud[], grants[], device{name,kind,key_protection}, lifetime_seconds?, return_origin?}.' } } },
  'enroll-describe': { type: 'object', required: ['request'], properties: { request: { type: 'string', description: 'The enr_… ticket from the approval URL fragment.' } } },
  'enroll-approve': { type: 'object', required: ['request'], properties: { request: { type: 'string' }, device_name: { type: 'string' }, aud: { type: 'array', items: { type: 'string' } }, grants: { type: 'array', items: grant }, lifetime_seconds: { type: 'integer' } } },
  'enroll-deny': { type: 'object', required: ['request'], properties: { request: { type: 'string' } } },
  'credentials-create': { type: 'object', required: ['public_jwk', 'aud', 'grants'], properties: { public_jwk: { type: 'object', description: 'P-256 public JWK.' }, aud: { type: 'array', items: { type: 'string' } }, grants: { type: 'array', items: grant }, device: { type: 'object', properties: { name: { type: 'string' }, kind: { type: 'string' }, key_protection: { type: 'string' } } }, lifetime_seconds: { type: 'integer', minimum: 300, maximum: 34560000 } } },
  renew: { type: 'object', properties: { new_key_proof: { ...jws, description: 'Optional, for rotation: JWS typ dba-rotate+jwt over {cid, iat}, signed by the new key, its jwk in the header.' } } },
  token: { type: 'object', required: ['audience'], properties: { audience: { type: 'string' } } },
  authorize: { type: 'object', required: ['credential', 'audience', 'action'], properties: { credential: jws, proof: { ...jws, description: 'The DPoP proof the device sent you (required for device credentials).' }, request: { type: 'object', properties: { method: { type: 'string' }, url: { type: 'string' } } }, audience: { type: 'string' }, action: { type: 'string' }, resource: { type: 'string' }, context: { type: 'object', properties: { network: { type: 'object', properties: { country: { type: 'string' }, region: { type: 'string' }, lat: { type: 'number' }, lon: { type: 'number' }, ip: { type: 'string' } } } } } } },
  inspect: { type: 'object', required: ['credential'], properties: { credential: jws, audience: { type: 'string' }, check: { type: 'object', properties: { action: { type: 'string' }, resource: { type: 'string' }, now: { type: 'integer' }, location: { type: 'object' }, online: { type: 'boolean' } } } } },
  'revoke-all': { type: 'object', required: ['confirm'], properties: { confirm: { const: 'revoke-all' }, audience: { type: 'string' }, reason: { type: 'string' } } },
  keys: { type: 'object', required: ['scopes'], properties: { name: { type: 'string' }, scopes: { type: 'array', items: { type: 'string' } } } },
  checkout: { type: 'object', required: ['credit_cents'], properties: { credit_cents: { type: 'integer', minimum: 500, maximum: 100000 } } }
};
const SECURITY = {
  [PUBLIC]: [], [SESSION]: [{ Session: [] }, { DeviceCredential: [] }], [DEVICE]: [{ DeviceCredential: [] }],
  [AUTHENTICATED]: [{ Session: [] }, { ApiKey: [] }, { DeviceCredential: [] }]
};

/** OpenAPI 3.1 generated from the only dispatch table (frontend/openapi.json is checked for drift). */
export function openapi(routes) {
  const paths = {};
  for (const route of routes) {
    if (route.path.startsWith('/webhooks/')) continue;
    const path = route.path.replace(/:([a-z_]+)/g, '{$1}');
    const operation = {
      operationId: `${route.method.toLowerCase()}${route.path.replace(/[^a-z0-9]+/gi, '_')}`.replace(/_$/, ''), summary: SUMMARIES[route.handler] || route.handler,
      'x-access': route.access, security: SECURITY[route.access] ?? [{ ApiKey: [] }, { Session: [] }, { DeviceCredential: [] }],
      parameters: [...route.path.matchAll(/:([a-z_]+)/g)].map(([, name]) => ({ name, in: 'path', required: true, schema: { type: 'string' } })),
      responses: {
        200: { description: 'Success. Every JSON response includes cost_microdollars.', content: { 'application/json': { schema: { type: 'object', properties: { cost_microdollars: money } } } } },
        400: { description: 'Invalid request', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        401: { description: 'Missing or invalid credential' }, 402: { description: 'Insufficient balance' }, 403: { description: 'Not allowed' }, 404: { description: 'Not found' }, 409: { description: 'Conflict (already decided, superseded)' }, 429: { description: 'Rate limited' }, 503: { description: 'Cost-safety brake or dependency unavailable' }
      }
    };
    if (route.access !== PUBLIC && !SECURITY[route.access]) operation.description = `Requires scope \`${route.access}\` (API key), a signed-in session, or a device credential with \`dba:${route.access}\`.`;
    if (['POST', 'PATCH', 'DELETE'].includes(route.method) && route.path.startsWith('/api/')) operation.parameters.push({ name: 'Idempotency-Key', in: 'header', schema: { type: 'string', maxLength: 128 } });
    if (BODIES[route.handler] && route.method !== 'GET' && route.method !== 'DELETE') operation.requestBody = { required: true, content: { 'application/json': { schema: BODIES[route.handler] } } };
    if (route.handler === 'quote') operation.parameters.push({ name: 'op', in: 'query', required: true, schema: { type: 'string' } });
    if (route.handler === 'credentials-list') for (const name of ['status', 'audience', 'device', 'cursor']) operation.parameters.push({ name, in: 'query', schema: { type: 'string' } });
    if (route.handler === 'enroll-poll') operation.parameters.push({ name: 'poll_token', in: 'query', required: true, schema: { type: 'string' } });
    (paths[path] ||= {})[route.method.toLowerCase()] = operation;
  }
  return {
    openapi: '3.1.0',
    info: { title: 'devicebasedauth.org API', version: '1.0.0', description: 'Revocable, device-bound credentials. Prepaid, no subscription; prices in integer micro-dollars. Credential format: https://github.com/curtcox/device-based-auth/blob/main/spec/credential.md' },
    servers: [{ url: 'https://devicebasedauth.org' }], paths,
    components: {
      securitySchemes: {
        ApiKey: { type: 'apiKey', in: 'header', name: 'Authorization', description: '"ApiKey dbak_…" — scoped account key.' },
        Session: { type: 'http', scheme: 'bearer', bearerFormat: 'Clerk session JWT (the dashboard).' },
        DeviceCredential: { type: 'apiKey', in: 'header', name: 'Authorization', description: '"DBA <credential>" plus a "DPoP: <proof>" header signed by the device key (RFC 9449).' }
      },
      schemas: {
        Error: { type: 'object', required: ['error', 'code'], properties: { error: { type: 'string' }, code: { type: 'string' } } },
        Grant: { type: 'object', required: ['actions'], additionalProperties: false, description: 'See spec/evaluation.md.', properties: {
          actions: { type: 'array', items: { type: 'string', pattern: '^[a-z0-9-]{1,32}(:[a-z0-9_.-]{1,64})*:([a-z0-9_.-]{1,64}|\\*)$' } }, resources: { type: 'array', items: { type: 'string' } },
          when: { type: 'object', properties: { tz: { type: 'string' }, windows: { type: 'array', items: { type: 'object', properties: { days: { type: 'array', items: { enum: ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] } }, from: { type: 'string' }, to: { type: 'string' } } } }, not_before: { type: 'integer' }, not_after: { type: 'integer' } } },
          where: { type: 'object', properties: { source: { enum: ['network', 'device', 'both'] }, countries: { type: 'array', items: { type: 'string' } }, regions: { type: 'array', items: { type: 'string' } }, areas: { type: 'array', items: { type: 'object', properties: { lat: { type: 'number' }, lon: { type: 'number' }, radius_m: { type: 'number' } } } }, networks: { type: 'array', items: { type: 'string' } } } },
          limits: { type: 'object', properties: { uses: { type: 'object', properties: { count: { type: 'integer' }, per: { enum: ['minute', 'hour', 'day', 'month', 'total'] } } }, spend_usd_per_month: { type: 'number' } } },
          require: { type: 'object', properties: { online: { type: 'boolean' }, step_up: { type: 'boolean' } } }
        } }
      }
    }
  };
}
