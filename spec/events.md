# Webhook events, version 1

Status: draft (STATUS B1; implemented in `src/services/webhooks.js`, verified by `verifyEvent` and
`createVerifier().handleEvent` in `packages/verify`).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

An audience may register a **revocation webhook**. devicebasedauth.org then POSTs a signed event to
it whenever a credential naming that audience in `aud` is revoked, so an offline verifier can stop
accepting the credential at once instead of when its cached status list expires.

Webhooks are an acceleration, not a replacement. Delivery is best effort (§5); the status lists
remain authoritative and verifiers MUST keep checking them.

## 2. Registering

`PATCH /api/v1/audiences/{name}` with `{"revocation_webhook": "https://…"}` (or `null` to remove it),
by the audience's owner. The URL MUST use `https`, MUST be on the audience's own domain or one of its
subdomains, and MUST use the default port: the domain was already proven when the audience was
registered, so the service never sends requests to hosts the owner does not control. Changing an
audience costs the audience price. The URL is shown only to the owner.

`POST /api/v1/audiences/{name}/webhook-test` sends a `webhook.test` event at once and reports the
endpoint's HTTP status (metered at the read price).

## 3. Request

```
POST <revocation_webhook>
Content-Type: application/jwt
User-Agent: devicebasedauth.org-webhooks/1

<compact JWS>
```

The body is a compact JWS signed with the issuer key, exactly like a credential:

| Header member | Value |
|---------------|-------|
| `typ` | `dba-event+jwt` |
| `alg` | `ES256` |
| `kid` | Issuer key id, in `https://devicebasedauth.org/.well-known/jwks.json` |

| Payload member | Meaning |
|----------------|---------|
| `iss` | `https://devicebasedauth.org` |
| `aud` | The one audience this event is for (a string, not a list) |
| `iat` | When the event was signed (seconds) |
| `jti` | Event id. A retried delivery of the same batch has a new `jti`. |
| `type` | `credentials.revoked` or `webhook.test` |
| `credentials` | `credentials.revoked` only: 1–100 entries `{ cid, jti, exp, revoked_at, status: { idx, uri } }` |

`status` is the credential's `status.status_list` claim; `jti` and `exp` are those of the version
current when it was revoked. Every version of a credential shares its status entry (until key
rotation, which moves it), so a verifier SHOULD treat `status` as the revoked thing.

Example payload:

```json
{
  "iss": "https://devicebasedauth.org", "aud": "hashbin.org", "iat": 1795000000,
  "jti": "evt_8Q2M9X4K1BZ0R3P5T7V9", "type": "credentials.revoked",
  "credentials": [{ "cid": "crd_7Q2M9X4K1BZ0R3P5", "jti": "crd_7Q2M9X4K1BZ0R3P5.3", "exp": 1795600000,
    "revoked_at": 1794999990, "status": { "idx": 4211, "uri": "https://status.devicebasedauth.org/v1/lists/0" } }]
}
```

## 4. Receiving

A receiver MUST:

1. Verify the signature against the issuer JWKS (refetching it once on an unknown `kid`), `typ`,
   `alg`, `iss`, and that `aud` is its own audience name.
2. Refuse events whose `iat` is more than 600 s old or more than 60 s in the future.
3. Answer `2xx` once the event is applied. Any other answer, a redirect, or no answer within 5 s
   counts as a failure.

It SHOULD keep each revoked `status` entry until that credential's `exp`, and deny credentials whose
`status.status_list` matches. Applying the same revocation twice is harmless; receivers MAY skip
event ids they have seen.

With `@devicebasedauth/verify`:

```js
const dba = createVerifier({ audience: 'hashbin.org' });
// in the webhook route:
const result = await dba.handleEvent(await request.text());
return new Response(null, { status: result.ok ? 204 : result.status });
// later requests through the same verifier see the revocation at once
```

## 5. Delivery

- One event per audience per batch of up to 100 revoked credentials; a bulk revocation produces
  several events.
- The revocation itself never waits on an endpoint: status bits are published first, and events are
  sent by the account's next alarm, normally within a second.
- A failed delivery is retried after 1 minute, 10 minutes and 1 hour. After the fourth failure the
  event is dropped; the credential stays revoked in the status list.
- Delivery is paid for in advance by the issue price (docs/business/pricing.md); audiences pay
  nothing to receive events.
- Key rotation (`renew` with `new_key_proof`) retires the old status entry without an event; the
  credential itself stays valid under its new key.
