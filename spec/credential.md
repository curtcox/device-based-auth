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
| `device` | no | `{ name, kind, key_protection }` for display. `kind` ∈ `browser`, `phone`, `desktop`, `server`, `cli`, `agent`, `iot`, `other`. `key_protection` ∈ `webcrypto-nonextractable`, `secure-enclave`, `android-keystore`, `tpm`, `os-keychain`, `software`. Self-reported unless `device.attestation` is present (§3a). |
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

## 3a. Device key attestation

`device.attestation` is present only when the issuer verified platform evidence, at enrollment,
that the device key was generated inside secure hardware. Devices cannot set it: the issuer drops
any `attestation` a device or API caller puts in `device`. Verifiers may rely on it as far as they
trust the issuer; it says nothing about the device after `verified_at`, and it is removed when a
credential rotates to a new key.

| Member | Meaning |
|--------|---------|
| `format` | `android-key` (Android Key Attestation), `apple-appattest` (Apple App Attest) or `tpm` (TPM 2.0). |
| `security_level` | `tee`, `strongbox`, `secure_enclave` or `tpm`: where the key lives. Software keys are never attested. |
| `tpm_manufacturer` | `tpm` only: the TPM vendor id from the attestation key's certificate (e.g. `NTC`, `IFX`, `INTC`, `AMD`). |
| `app_id` | `apple-appattest` only: the app (`TEAMID.bundle.id`) that Apple attested and that reported the key. |
| `environment` | `apple-appattest` only: `production` (App Store, TestFlight, enterprise) or `development`. |
| `verified_boot` | `verified`, `self_signed`, `unverified`, `failed` or `unknown` (Android root of trust), when reported. |
| `device_locked` | Whether the bootloader was locked, when reported. |
| `attestation_version` | The Keymaster/KeyMint attestation version. |
| `verified_at` | NumericDate the issuer checked the evidence. |

With an attestation, `key_protection` is set by the issuer (`android-keystore`, `secure-enclave` or `tpm`).

**Android.** The device asks `POST /api/v1/enrollments/attestation-challenge` for a challenge (a
43-character string, valid 10 minutes), generates its P-256 signing key in the Android Keystore
with `setAttestationChallenge(<the challenge's ASCII bytes>)`, and adds
`attestation: { format: "android-key", challenge, x5c }` to its enrollment request, `x5c` being the
key's certificate chain (base64 DER, leaf first). The issuer accepts it only when:

1. the chain has 2–8 certificates, each signed by the next, the last by itself, and its public key
   is a pinned Google hardware attestation root;
2. no certificate is expired (the leaf's `notBefore` is set by the device clock and not checked)
   or on Google's attestation revocation list (if the list cannot be fetched, enrollment fails
   with `503 attestation_unavailable` rather than continuing unattested);
3. the KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17) is in the leaf **only** — otherwise
   an attested signing key could sign a forged leaf;
4. the leaf's public key is the enrolled key, and the hardware-enforced list says it was generated
   on the device (`origin` GENERATED), as an EC P-256 key with purpose SIGN, at TEE or StrongBox
   level for both attestation and KeyMint;
5. the challenge in the extension equals the request's `challenge`, which the issuer made and has
   not expired.

**Apple.** App Attest cannot attest an arbitrary key: Apple attests a key of its own and says
which app, on a genuine Apple device, holds it. So the app generates its P-256 signing key in the
Secure Enclave (`kSecAttrTokenIDSecureEnclave`), gets a challenge as above, calls
`DCAppAttestService.generateKey()` and then `attestKey(keyId, clientDataHash:)` with
`clientDataHash = SHA-256("<challenge>.<JWK thumbprint (RFC 7638) of the Secure Enclave key>")`,
and adds `attestation: { format: "apple-appattest", challenge, app_id, key_id, object }` to its
enrollment request (`key_id` and `object` base64; `app_id` is `TEAMID.bundle.id`). The issuer
follows Apple's "Validating apps that connect to your server" and accepts it only when:

1. `object` is CBOR with `fmt` `apple-appattest` and an `x5c` of the credential certificate and
   its intermediate; the certificate is signed by the intermediate, the intermediate by the pinned
   Apple App Attestation Root CA, and neither is outside its validity period;
2. the certificate's extension 1.2.840.113635.100.8.2 holds
   `SHA-256(authData ‖ SHA-256("<challenge>.<thumbprint>"))`, with the enrolled key's thumbprint
   and a challenge the issuer made and has not expired;
3. `key_id` is the SHA-256 of the certificate's public key and is also `authData`'s credential id;
4. `authData`'s RP id hash is `SHA-256(app_id)`, its counter is 0, and its AAGUID names the
   production or development environment.

The app's receipt (for Apple's fraud-metric service) is not used. What this proves is that a
genuine copy of `app_id` reported the key, so it is only as good as that app: the
`secure_enclave` level counts for `require.attestation` only in grants that also name the app
(`require.app_ids`, evaluation.md §3.6).

**TPM 2.0.** The device creates its P-256 signing key inside the TPM (on Windows, the Platform
Crypto Provider) and has the TPM's attestation identity key (AIK) certify it with `TPM2_Certify`,
passing `qualifyingData = SHA-256("<challenge>.<JWK thumbprint of the key>")` (on Windows, the
`NCryptCreateClaim` nonce with the "Windows AIK" as authority). It adds
`attestation: { format: "tpm", challenge, alg, x5c, sig, cert_info, pub_area }`: `alg` is the
COSE algorithm of the AIK's signature (`-257` RS256 or `-65535` RS1), `x5c` the AIK certificate
then its CA certificates (base64 DER, root left out), and `sig`, `cert_info` (the `TPMS_ATTEST`)
and `pub_area` (the key's `TPMT_PUBLIC`) base64. The issuer follows the WebAuthn `tpm`
attestation format (§8.3) and accepts it only when:

1. the chain has 1–5 certificates, each signed by the next and the last by the pinned Microsoft
   TPM Root Certificate Authority 2014, none outside its validity period, and the last not on the
   root's CRL (signed by the root and current to within 7 days past its `nextUpdate`; if it
   cannot be fetched, enrollment fails with `503 attestation_unavailable`); Microsoft issues AIK
   certificates only to TPMs whose endorsement certificate it has checked;
2. the AIK certificate has extended key usage 2.23.133.8.3, is not a CA, and names the TPM
   manufacturer in its subject alternative name;
3. the AIK certificate's key signed `cert_info` (RS1 is accepted: the AIK is a restricted key, so
   the TPM signs only structures it built itself, with at most 64 caller-chosen bytes);
4. `cert_info` is a TPM-generated `TPM_ST_ATTEST_CERTIFY` whose `extraData` is the qualifying data
   above, for a challenge the issuer made and has not expired, and whose certified name is the
   name of `pub_area` (SHA-256, SHA-384 or SHA-512);
5. `pub_area` is an ECC NIST P-256 key equal to the enrolled key, with `fixedTPM`, `fixedParent`,
   `sensitiveDataOrigin` and `sign` set: generated in this TPM and unable to leave it.

AIK certificates themselves carry no revocation pointer. A TPM whose AIK has no certificate from
Microsoft (most Linux machines) cannot attest yet: that needs endorsement-key credential
activation against the manufacturers' roots.

Any failure refuses the enrollment with `400 invalid_attestation`; a device that wants a credential
without attestation omits the member.

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

**Withdrawn issuer keys.** When an issuer key is compromised the service removes it from the JWKS,
so every credential it signed fails step 1 (`unknown_kid`) once verifier caches refresh; verifiers
that see an unknown `kid` SHOULD refetch the JWKS before denying, and need nothing else. Devices
replace such a credential with `POST /api/v1/credentials/{cid}/renew`, which accepts it only if the
account's registry holds that exact credential (byte for byte) and it is unrevoked and unexpired;
the renewal is signed by the current key, keeps `cid` and the status index, and is free. Any other
DBA API answers such a credential with 401 `reissue_required`.

## 6. Access tokens

`POST /api/v1/token` exchanges a credential + proof for a bearer token with `typ: dba-access+jwt`,
lifetime ≤ 10 minutes, one audience, the same grants, the same `status`, and no `cnf`. It is
presented as `Authorization: Bearer <token>` and verified the same way minus step 3. Audiences MAY
refuse access tokens.

## 6a. X.509 client certificates

For relying parties that authenticate with mutual TLS (for example Cloudflare API Shield), a device
can exchange its credential for an X.509 v3 certificate over its own key:
`POST /api/v1/certificate` with `{ "lifetime_seconds": 300–86400 }` (default 3600), authenticated
by the credential and a DPoP proof. The certificate never outlives the credential.

| Field | Value |
|-------|-------|
| Signature | `ecdsa-with-SHA256` by the CA certificate of the active issuer key |
| Issuer | `O=devicebasedauth.org, CN=devicebasedauth.org device CA <kid>`; the CA certificates are published at `/.well-known/dba-ca.pem` (one per issuer key, path length 0) |
| Subject | `O=devicebasedauth.org, CN=<device id>` (the credential's `sub`) |
| Subject public key | The device's P-256 key (`cnf.jkt` of the credential) |
| Validity | `notBefore` 60 s in the past; `notAfter` at most 24 h later, never past `exp` |
| subjectAltName | URIs `urn:devicebasedauth:device:<sub>`, `urn:devicebasedauth:credential:<cid>`, `urn:devicebasedauth:account:<acct>` |
| Extensions | basicConstraints `CA:FALSE` (critical), keyUsage `digitalSignature` (critical), extendedKeyUsage `clientAuth`, subject and authority key identifiers (first 20 bytes of SHA-256 over the public point) |

A certificate carries **no grants** and mTLS cannot see revocation: it only proves that the client
holds a device key that devicebasedauth.org vouched for within the last day. Relying parties look up
the credential named in the subjectAltName (or require the credential as well) to decide actions,
and keep certificate lifetimes short.

## 7. Status lists

Status lists follow the IETF OAuth Token Status List draft: 1 bit per credential, byte
`floor(idx / 8)`, bit `idx mod 8` (least significant first), zlib-compressed and base64url-encoded
in the `status_list.lst` claim with `bits: 1`. Revocations are published within 60 seconds.

A credential's `idx` is an integer from 0 to 2³¹−1; any other value makes the credential
`invalid_claims`. Verifiers compute the byte and bit with integer arithmetic, never with 32-bit
bitwise operators, and read bits past the end of a list as 0.

## 8. Online authorization

Constraints that need state (`limits.uses`, `require.step_up`, `require.online`) cannot be checked
offline. Verifiers send those requests to `POST /api/v1/authorize` (metered, billed to the
audience's account), which also sees revocations instantly.
