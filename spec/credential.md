# Device credential format, version 1

Status: draft (STATUS D2 recommends this format; implemented in `packages/verify`).
Conformance vectors: [`vectors/credentials.json`](vectors/credentials.json) (signatures),
[`vectors/evaluation.json`](vectors/evaluation.json) (grant evaluation; see
[evaluation.md](evaluation.md)).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

A **device credential** is a compact JWS (RFC 7515) signed by devicebasedauth.org with ES256
(ECDSA P-256, SHA-256, raw `r‖s` signature). Its payload is plain JSON that lists what one device
may do. The credential is bound to a key pair the device generated itself: every use is
accompanied by a **DPoP proof** (RFC 9449) signed with the device's private key. The issuer never
sees that private key.

Credentials are not secret, but they are useless without the private key. Anyone can read one by
base64url-decoding its middle segment.

## 2. Header

| Member | Value |
|--------|-------|
| `typ` | `dba-device+jwt` (credential) or `dba-access+jwt` (short-lived access token, §6) |
| `alg` | `ES256` — the only algorithm. Verifiers MUST reject anything else. |
| `kid` | Issuer key id; look it up in `https://devicebasedauth.org/.well-known/jwks.json`. |

## 3. Payload

| Claim | Required | Meaning |
|-------|----------|---------|
| `iss` | yes | `https://devicebasedauth.org` |
| `sub` | yes | Device id, `dev_` + 8–64 alphanumerics. Stable for a device key within an account. |
| `acct` | yes | The issuing devicebasedauth.org account. Relying parties map it to a local account (account linking). |
| `aud` | yes | Array of audience names (site domains) the credential is valid for. |
| `cid` | yes | Credential id, `crd_…`. Stable across renewals; revoking it revokes every version. |
| `jti` | yes | Unique id of this version, `<cid>.<version>`. |
| `iat`, `nbf`, `exp` | yes | NumericDate seconds. `exp > nbf`. Verifiers allow 60 s clock skew. |
| `cnf.jkt` | yes (device) | RFC 7638 SHA-256 thumbprint of the device public key. Absent on access tokens. |
| `device` | no | `{ name, kind, key_protection }` for display. `kind` ∈ `browser`, `phone`, `desktop`, `server`, `cli`, `agent`, `iot`, `other`. `key_protection` ∈ `webcrypto-nonextractable`, `secure-enclave`, `android-keystore`, `tpm`, `os-keychain`, `software`. Self-reported unless attested. |
| `grants` | yes | 1–32 grants; see [evaluation.md](evaluation.md). |
| `status.status_list` | yes | `{ idx, uri }` — the credential's bit in an IETF OAuth Token Status List. |
| `ver` | yes | Grant vocabulary version, `1`. |

Unknown top-level claims MUST be ignored. Unknown **grant** members MUST make that grant deny.

### Example

```json
{
  "iss": "https://devicebasedauth.org",
  "sub": "dev_7Q2M9X4K1B",
  "acct": "user_2abc",
  "aud": ["hashbin.org"],
  "cid": "crd_K3J8P1W6ZQ",
  "jti": "crd_K3J8P1W6ZQ.1",
  "iat": 1795017600, "nbf": 1795017600, "exp": 1797609600,
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "device": { "name": "Laptop — Firefox", "kind": "browser", "key_protection": "webcrypto-nonextractable" },
  "grants": [{
    "actions": ["hashbin:content:write"],
    "when": { "tz": "America/Chicago", "windows": [{ "days": ["mon","tue","wed","thu","fri"], "from": "08:00", "to": "18:00" }] },
    "where": { "source": "network", "countries": ["US"] },
    "limits": { "spend_usd_per_month": 5 }
  }],
  "status": { "status_list": { "idx": 48213, "uri": "https://status.devicebasedauth.org/v1/lists/7" } },
  "ver": 1
}
```

## 4. Presenting a credential

```
Authorization: DBA <credential>
DPoP: <proof>
```

The proof is a JWS with header `{ "typ": "dpop+jwt", "alg": "ES256", "jwk": <device public JWK> }`
and payload:

| Claim | Meaning |
|-------|---------|
| `jti` | Random, 8–128 characters, single use. |
| `htm` | HTTP method, upper case. |
| `htu` | Request URL without query or fragment: `scheme://host[:port]/path`. |
| `iat` | Seconds. Accepted from 120 s before to 60 s after the verifier's clock. |
| `ath` | base64url SHA-256 of the credential string. |
| `nonce` | Only when the verifier issued one. |
| `loc` | Optional device-reported location `{ lat, lon, acc_m, t }` (§5 of evaluation.md). |

## 5. Verification

A verifier MUST, in order:

1. Decode the JWS; require `typ`, `alg: ES256`, a known `kid`; verify the signature.
2. Require `iss`, structurally valid claims, its own audience in `aud`, and `nbf − 60 ≤ now < exp + 60`.
3. Verify the DPoP proof: signature by `header.jwk`; `jkt(header.jwk) == cnf.jkt`; `htm`, `htu`,
   `iat` window, `ath`; and `jti` not seen before (keep a replay cache for at least 3 minutes).
4. Check revocation: bit `idx` of the status list at `uri` must be 0. Status lists are themselves
   JWTs (`typ: statuslist+jwt`) signed by the issuer with `sub` equal to `uri`; cache them for at
   most their `ttl` (the service publishes 60 s; verifiers SHOULD cache ≤ 5 minutes).
5. Evaluate the grants for the requested action ([evaluation.md](evaluation.md)).

If the JWKS or status list cannot be fetched, verifiers MUST fail closed (deny).

## 6. Access tokens

`POST /api/v1/token` exchanges a credential + proof for a bearer token with `typ: dba-access+jwt`,
lifetime ≤ 10 minutes, one audience, the same grants, the same `status`, and no `cnf`. It is
presented as `Authorization: Bearer <token>` and verified the same way minus step 3. Audiences MAY
refuse access tokens.

## 7. Status lists

Status lists follow the IETF OAuth Token Status List draft: 1 bit per credential, byte
`floor(idx / 8)`, bit `idx mod 8` (least significant first), zlib-compressed and base64url-encoded
in the `status_list.lst` claim with `bits: 1`. Revocations are published within 60 seconds.

## 8. Online authorization

Constraints that need state (`limits.uses`, `require.step_up`, `require.online`) cannot be checked
offline. Verifiers send those requests to `POST /api/v1/authorize` (metered, billed to the
audience's account), which also sees revocations instantly.
