import { PUBLIC, SESSION, DEVICE, AUTHENTICATED } from '../auth/scopes.js';

const money = { type: 'integer', minimum: 0, description: 'Integer micro-dollars (1 USD = 1,000,000).' };
const jws = { type: 'string', description: 'Compact JWS (ES256).' };
const grant = { $ref: '#/components/schemas/Grant' };
const SUMMARIES = {
  health: 'Service health and deployed commit.', jwks: 'Issuer public keys (JWKS).', 'oidc-configuration': 'OpenID Connect discovery document; also OAuth authorization-server metadata (RFC 8414) for MCP clients.', 'oauth-resource': 'OAuth protected-resource metadata (RFC 9728) for the MCP server at /mcp.', 'oauth-register': 'Register an MCP client (RFC 7591; public clients with PKCE). Stateless and free: the client_id is signed, nothing is stored.', 'oauth-client': 'Describe a registered MCP client (name, redirect URIs) for the consent page.',
  'status-list': 'A signed status list (IETF Token Status List). Bit idx = 1 means revoked.', 'public-config': 'Public configuration and prices.',
  quote: 'Price of an operation (op = issue, renew, decision, read, token, login, audience).', inspect: 'Decode and check a credential; optionally evaluate an action. Free.',
  'enroll-start': 'Start an enrollment with a request JWS (typ dba-enroll+jwt) signed by the new device key. Returns the approval URL and a poll URL. Free; nothing is stored.',
  'enroll-describe': 'Describe a pending enrollment ticket for the approval page. Free.',
  'attestation-challenge': 'A challenge for key attestation, valid 10 minutes. Android: generate the key with setAttestationChallenge(challenge as ASCII bytes), then add attestation {format:"android-key", challenge, x5c[]} to the enrollment request. iOS: attestKey with clientDataHash SHA-256("<challenge>.<JWK thumbprint of the enrolled key>") and add {format:"apple-appattest", challenge, app_id, key_id, object}. TPM 2.0 (Windows): TPM2_Certify the TPM-resident P-256 key with the AIK and qualifyingData SHA-256("<challenge>.<JWK thumbprint>"), and add {format:"tpm", challenge, alg, x5c[], sig, cert_info, pub_area}. TPM 2.0 without a Microsoft AIK certificate (Linux): see POST /api/v1/enrollments/tpm-activation. Free; stateless.',
  'tpm-activation': 'TPM 2.0 attestation by EK credential activation, step 1, for TPMs whose attestation key (AK) has no Microsoft certificate. Send {challenge, ek_certificate (the TPM\'s RSA-2048 EK certificate, DER base64; NV index 0x01c00002), ek_chain[] (optional CA certificates up to the manufacturer\'s), ak_pub_area (the restricted signing AK, TPM2B_PUBLIC or TPMT_PUBLIC), pub_area (the TPM-resident P-256 device key), cert_info (TPMS_ATTEST from TPM2_Certify of the device key by the AK), sig (TPMT_SIGNATURE)}. Answers a secret wrapped for that TPM (id_object, encrypted_secret, and credential_blob in tpm2_activatecredential\'s file format) and an activation token valid 10 minutes. Unwrap with TPM2_ActivateCredential and add attestation {format:"tpm-ek", challenge, activation, secret (base64)} to the enrollment request. Free; stateless.', 'enroll-poll': 'Poll an enrollment until it is approved, denied or expired.',
  'enroll-approve': 'Approve an enrollment (optionally narrowing grants) and issue the credential. Charges the issue price.', 'enroll-deny': 'Deny an enrollment.',
  whoami: 'Who is calling: account, credential kind and (for devices) the grants in plain English.', account: 'Balance, this month\'s spend and today\'s aggregated charges.',
  transactions: 'Ledger, newest first.', audit: 'Audit trail, newest first.', 'credentials-list': 'List credentials (filters: status, audience, device).',
  'credentials-create': 'Issue a credential for a public key you hold (API keys, sessions, or devices delegating narrower grants). Charges the issue price.',
  'credentials-get': 'One credential: payload fields, grants in plain English, current JWS and history.', 'revoke-credential': 'Revoke a credential (free, immediate online; status lists within a minute).',
  'credentials-decisions': 'Online authorization decisions for a credential (kept 90 days).', renew: 'Renew the presented credential (same key), or rotate to a new key with new_key_proof. Device credential + DPoP. Also accepts a credential signed by a withdrawn issuer key if it is exactly the one stored; that renewal is free and answers recovered: true.',
  'devices-list': 'Devices with their credentials.', 'devices-get': 'One device.', 'revoke-device': 'Revoke every credential of a device.', 'revoke-all': 'Revoke everything (optionally one audience). Body {"confirm":"revoke-all"}.',
  'revoke-self': 'A device revokes the credential it presents.', token: 'Exchange the presented device credential for a ≤10-minute bearer access token for one audience. Charges the token price.',
  authorize: 'Online authorization decision for an audience you own: revocation, usage limits, step-up, decision log. Charges the decision price.',
  'step-ups': 'Pending step-up approval requests (gate requests the owner gate can answer).', 'step-up-decide': 'Approve or deny a step-up request (an answer from the owner gate).',
  gates: 'The account\'s gates: devices (and later services) that approve requests (require.gates). GET lists them with the built-in owner gate; POST adds one: { kind: "dba-device", label, device_id }, { kind: "totp", label } (answers with setup.secret and setup.otpauth_uri, shown once) or { kind: "webauthn", label, user_verification? } (answers with setup.public_key, options for navigator.credentials.create) or { kind: "webhook", label, url, public_jwk } (your approval service: DBA posts it a dba-gate+jwt per request, spec/events.md §6), { kind: "duo", label, api_host, integration_key, secret_key, username } (Duo Push through your Duo Auth API application) or { kind: "okta-verify", label, org_url, api_token, user_id, factor_id } (Okta Verify push); vendor secrets are sealed and never returned; POST …/activate finishes a TOTP gate ({ code }) or a security key ({ registration: { clientDataJSON, attestationObject } }); DELETE removes one. Changes need a recent sign-in.',
  'dashboard-session': 'The dashboard\'s own sign-in gate: GET says whether this session is open, confirmed or locked (and how many recovery codes are left); POST …/confirm opens or reads its gate request (it may carry this page\'s own answer: { entry?, gate, totp | webauthn }); POST …/recover { code } passes it with a one-time recovery code. A locked session gets 403 sign_in_gate_required everywhere except these, whoami and revocation.',
  'recovery-codes': 'Make 10 new one-time recovery codes for the dashboard sign-in gate (shown once, stored hashed; the old ones stop working). Needs a recent sign-in.',
  confirm: 'Confirm a credential that carries confirm: { gates, every_s } (spec/credential.md §9), from its own device: opens (or reads) a gate request for its confirm gates; once they pass, answers { status: "confirmed", confirmation } — a dba-confirmation+jwt to send as the DBA-Confirmation header, valid every_s seconds. Ask again every retry_after seconds while it waits. Charges the confirmation price when one is issued.',
  unconfirm: 'Stop trusting a device now: ends the credential\'s current confirmation for online checks (/authorize) at once. Offline verifiers accept its last confirmation until that expires; revoke the credential to stop those too.',
  'sign-in-gates': 'Sign-in gates: { default, audiences: { <site>: entries }, dashboard } where entries are gate entries as in require.gates (not the owner gate). A Sign in with devicebasedauth.org then waits on the consent page until they pass (POST /oauth/authorize answers { pending, gate_request } meanwhile, with the request number to match) and the ID token carries amr, acr (urn:devicebasedauth.org:acr:gated or …:gated-timeout) and dba_gates. PUT needs a recent sign-in.',
  'gate-links': 'The approval page\'s view of one gate request, named by a signed link (/gate.html#<link>, sent to the owner\'s browsers and returned as gate_request.approve_url): GET shows the request and the factors that may answer it; POST …/answer { entry?, gate, decision, totp: { code } | webauthn: { credential_id, clientDataJSON, authenticatorData, signature } } answers with a TOTP code or a security key, no sign-in needed; POST …/callback takes a webhook gate\'s late answer (a JWS, typ dba-gate-answer+jwt, signed with the key the gate registered). The security-key challenge is base64url(SHA-256("dba-gate-answer\\n<request id>\\n<entry>\\n<decision>\\n<salt>")).',
  'gate-requests': 'Gate requests: list the ones waiting or approved (the owner sees all; a device holding dba:approvals:answer sees those its gates can answer), read one, or answer one: POST …/answer { gate, decision: "allow" | "deny", entry? }. The first answer settles an entry; a device never approves its own request.', audiences: 'Audiences (relying parties): list, read, register (domain check, charges the audience price) and change. revocation_webhook (https on the audience domain, or null) receives signed credentials.revoked events (spec/events.md); it is only shown to the owner. A catalog entry may carry a gate policy, gates: { require, kinds, fail_open } (spec/evaluation.md §3.8): grants for that action must have gates (of those kinds), and fail_open: false refuses allows by timeout; it applies at once, also to credentials issued before it. sign_in_gates: { require, kinds, fail_open } is the same policy for signing in to the site.',
  'push-subscriptions': 'Browsers that get security notices (Web Push) when credentials, API keys or enrollment tokens are issued; at most 5, free, dashboard only. POST takes a PushSubscription made with push_public_key from /api/public/config and sends it a first notice; DELETE tells every subscribed browser.',
  'account-settings': 'Budget guards: max_issues_per_day (default 500) and max_renewals_per_credential_per_month (default null, no cap). PATCH changes the members given; dashboard only.',
  'enroll-redeem': 'Enroll with an enrollment token instead of a per-device approval: body {request (the dba-enroll+jwt; aud and grants may be left out or narrow the token\'s), enrollment_token}. Charges the issue price to the token\'s account.',
  'enrollment-tokens': 'Enrollment tokens (dbae_…): a pre-approved template (aud, grants, lifetime_seconds) for up to max_uses devices (1–10000) until expires_in_days (default 7, ≤ 90). The secret is shown once. Not available to delegating devices.',
  certificate: 'An X.509 client certificate (PEM) for the presenting device key, for mTLS (e.g. Cloudflare API Shield): CN = device id, subjectAltName URIs for device, credential and account, clientAuth only. lifetime_seconds 300–86400 (default 3600), never past the credential; mTLS cannot see revocation. Charges the token price.',
  'ca-bundle': 'The CA certificates (PEM) that sign device client certificates, one per issuer key. Add them to your mTLS trust store.',
  'audience-webhook-test': 'Send a signed webhook.test event (typ dba-event+jwt, spec/events.md) to the audience\'s revocation_webhook now and report the answer. Charges the read price.',
  'audience-usage': 'Online decisions, sign-ins and spend per month for an audience you own (this month and up to 11 before it).',
  keys: 'Account API keys (dbak_…). The secret is shown once.', checkout: 'Start a Stripe Checkout for prepaid credit. ?dry_run=1 shows the card fee.', 'dev-deposit': 'Local development only: add credit.',
  'oidc-authorize-page': 'OpenID Connect authorization endpoint (redirects to the consent page).', 'oidc-authorize': 'Consent page submission.', 'oidc-token': 'OpenID Connect token endpoint (authorization_code + PKCE S256).',
  'oidc-userinfo': 'OpenID Connect userinfo.', mcp: 'Model Context Protocol (Streamable HTTP, JSON-RPC).', 'clerk-webhook': 'Clerk webhook (signed).', 'stripe-webhook': 'Stripe webhook (signed).'
};
const BODIES = {
  'enroll-start': { type: 'object', required: ['request'], properties: { request: { ...jws, description: 'JWS, header {typ:"dba-enroll+jwt", alg:"ES256", jwk}, payload {iat, aud[], grants[], device{name,kind,key_protection}, lifetime_seconds?, return_origin?, attestation?{format:"android-key", challenge, x5c[] (base64 DER, leaf first)} or {format:"apple-appattest", challenge, app_id:"TEAMID.bundle.id", key_id (base64), object (base64 attestation object; clientDataHash = SHA-256("<challenge>.<JWK thumbprint>"))}}.' } } },
  'enroll-describe': { type: 'object', required: ['request'], properties: { request: { type: 'string', description: 'The enr_… ticket from the approval URL fragment.' } } },
  'enroll-approve': { type: 'object', required: ['request'], properties: { request: { type: 'string' }, device_name: { type: 'string' }, aud: { type: 'array', items: { type: 'string' } }, grants: { type: 'array', items: grant }, lifetime_seconds: { type: 'integer' } } },
  'enroll-redeem': { type: 'object', required: ['request', 'enrollment_token'], properties: { request: jws, enrollment_token: { type: 'string', description: 'dbae_… token from POST /api/v1/enrollment-tokens.' } } },
  'enrollment-tokens': { type: 'object', required: ['aud', 'grants'], properties: { name: { type: 'string' }, aud: { type: 'array', items: { type: 'string' } }, grants: { type: 'array', items: grant }, lifetime_seconds: { type: 'integer' }, max_uses: { type: 'integer', minimum: 1, maximum: 10000 }, expires_in_days: { type: 'number', exclusiveMinimum: 0, maximum: 90 } } },
  'enroll-deny': { type: 'object', required: ['request'], properties: { request: { type: 'string' } } },
  'credentials-create': { type: 'object', required: ['public_jwk', 'aud', 'grants'], properties: { public_jwk: { type: 'object', description: 'P-256 public JWK.' }, aud: { type: 'array', items: { type: 'string' } }, grants: { type: 'array', items: grant }, device: { type: 'object', properties: { name: { type: 'string' }, kind: { type: 'string' }, key_protection: { type: 'string' } } }, lifetime_seconds: { type: 'integer', minimum: 300, maximum: 34560000 } } },
  renew: { type: 'object', properties: { new_key_proof: { ...jws, description: 'Optional, for rotation: JWS typ dba-rotate+jwt over {cid, iat}, signed by the new key, its jwk in the header.' } } },
  certificate: { type: 'object', properties: { lifetime_seconds: { type: 'integer', minimum: 300, maximum: 86400 } } },
  token: { type: 'object', required: ['audience'], properties: { audience: { type: 'string' } } },
  authorize: { type: 'object', required: ['credential', 'audience', 'action'], properties: { credential: jws, proof: { ...jws, description: 'The DPoP proof the device sent you (required for device credentials).' }, request: { type: 'object', properties: { method: { type: 'string' }, url: { type: 'string' } } }, audience: { type: 'string' }, action: { type: 'string' }, resource: { type: 'string' }, context: { type: 'object', properties: { network: { type: 'object', properties: { country: { type: 'string' }, region: { type: 'string' }, lat: { type: 'number' }, lon: { type: 'number' }, ip: { type: 'string' } } } } } } },
  inspect: { type: 'object', required: ['credential'], properties: { credential: jws, audience: { type: 'string' }, check: { type: 'object', properties: { action: { type: 'string' }, resource: { type: 'string' }, now: { type: 'integer' }, location: { type: 'object' }, online: { type: 'boolean' } } } } },
  'revoke-all': { type: 'object', required: ['confirm'], properties: { confirm: { const: 'revoke-all' }, audience: { type: 'string' }, reason: { type: 'string' } } },
  'account-settings': { type: 'object', properties: { max_issues_per_day: { type: 'integer', minimum: 1, maximum: 100000 }, max_renewals_per_credential_per_month: { type: ['integer', 'null'], minimum: 1, maximum: 100000 } } },
  'push-subscriptions': { type: 'object', required: ['subscription'], properties: { name: { type: 'string', maxLength: 64 }, subscription: { type: 'object', required: ['endpoint', 'keys'], description: 'PushSubscription.toJSON() from the browser.', properties: { endpoint: { type: 'string', format: 'uri' }, keys: { type: 'object', required: ['p256dh', 'auth'], properties: { p256dh: { type: 'string' }, auth: { type: 'string' } } } } } } },
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
    if (route.idempotent) operation.parameters.push({ name: 'Idempotency-Key', in: 'header', schema: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[\\x21-\\x7e]+$' }, description: 'Retrying with the same key returns what the first request made, charged once. The same key with a different request is refused (422 idempotency_key_reused). Keys are per account.' });
    if (BODIES[route.handler] && route.method !== 'GET' && route.method !== 'DELETE') operation.requestBody = { required: true, content: { 'application/json': { schema: BODIES[route.handler] } } };
    if (route.billable) {
      operation.parameters.push({ name: 'dry_run', in: 'query', schema: { enum: ['1'] }, description: `1: only quote the price (op ${route.billable}) and, for callers with account:read, the balance and whether it suffices. Nothing else happens.` });
      operation['x-billable'] = route.billable;
      operation.responses[200].headers = { 'X-DBA-Cost-Microdollars': { schema: money }, 'X-DBA-Balance-Microdollars': { schema: money, description: 'Remaining balance; only for callers with account:read.' } };
    }
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
