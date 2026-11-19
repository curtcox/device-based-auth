# Grant evaluation, vocabulary version 1

Implemented by `evaluateGrants` in `packages/verify/src/grants.js`. Every implementation MUST
pass [`vectors/evaluation.json`](vectors/evaluation.json): for each case, evaluating `grants`
in `context` yields `expected.allow`, `expected.grant_index`, and per-grant `expected.reasons`.

## 1. Inputs

- `grants` — the credential's grant list.
- `action` — the action being attempted, e.g. `hashbin:content:write`.
- `resource` — optional, audience-defined string.
- `now` — the **verifier's** clock, in seconds. Device clocks are never trusted for time windows.
- `location.network` — what the verifier observed: `{ country, region, lat, lon, ip }`
  (on Cloudflare: `request.cf.country`, `` `${cf.country}-${cf.regionCode}` ``, `cf.latitude`,
  `cf.longitude`, `CF-Connecting-IP`).
- `location.device` — the `loc` claim from the verified DPoP proof: `{ lat, lon, acc_m, t }`.
- `online` — true only when devicebasedauth.org itself is evaluating (it can enforce counters).
- `attestation` — the presented credential's `device.attestation`, if any (credential.md §3a).
- `confirmation` — `{ iat, exp, by_timeout }` of the confirmation presented with the credential
  and verified by the verifier (credential.md §9); online, devicebasedauth.org's own record.
- `policy` — the audience's action catalog entry for `action`, if any (§3.8).
- `gate_kinds` — `{ <gate id>: <kind> }` for the issuing account's gates. Only
  devicebasedauth.org knows them, so only online evaluations have it.

## 2. Decision

The request is allowed when **at least one grant passes**. A grant passes when every check below
passes. Otherwise it is denied. Nothing is allowed by default.

Each failing check adds a reason code to that grant's reason list (all applicable reasons,
in the order of this document).

## 3. Grant members

A grant may contain only `actions`, `resources`, `when`, `where`, `limits`, `require`. Any other
member — at any nesting level listed here — makes the grant fail with
`unknown_constraint:<path>` and no other reasons. A grant that is otherwise invalid fails with
`invalid_grant`.

### 3.1 `actions` (required) → `action_not_granted`

1–64 patterns. A pattern is `namespace(:segment)*:last`, where `last` may be `*`. An exact pattern
matches only itself. `ns:a:*` matches any action starting with `ns:a:`. Namespaces are 1–32 of
`[a-z0-9-]`, segments 1–64 of `[a-z0-9_.-]`.

### 3.2 `resources` (default `["*"]`) → `resource_not_granted`

`*` matches anything, including no resource. `prefix*` matches resources starting with `prefix`.
Anything else is an exact match. An absent resource matches only `*`.

### 3.3 `when`

- `not_before` → `before_not_before` when `now < not_before`.
- `not_after` → `after_not_after` when `now ≥ not_after`.
- `windows` with `tz` (IANA zone) → `outside_time_window` unless `now`, converted to local
  weekday and minute in `tz`, is inside at least one window. A window is
  `{ days?, from, to }` (`days` ⊆ `sun…sat`, default all; `HH:MM`, `to` may be `24:00`).
  If `from < to`: inside when today ∈ days and `from ≤ time < to`.
  If `from > to` (overnight): inside when (today ∈ days and `time ≥ from`) or
  (yesterday ∈ days and `time < to`) — an overnight window belongs to the day it starts.

### 3.4 `where`

`source` is `network`, `device` or `both`; for `both`, the checks run independently against each
source and both must pass. For each source:

- Location absent → `location_unavailable:<source>`.
- Device location with `|now − t| > 300` → `location_stale:device`.
- **Places** (`countries`, `regions`, `areas`) form a union: the location must match at least one
  entry, otherwise `outside_location:<source>`.
  - Network: `countries` match `country`; `regions` (ISO 3166-2, `US-MO`) match `region`; `areas`
    match when the great-circle distance from `(lat, lon)` to the centre is ≤ `radius_m`.
  - Device: only `areas` are allowed, and match when `distance + acc_m ≤ radius_m` (accuracy is
    held against the device; a missing or negative `acc_m` never matches).
- `networks` (network source only): the observed IP must be inside one CIDR range, otherwise
  `network_not_allowed`. Networks are checked in addition to places.

Location is evidence, not proof: network location can be moved with a VPN; device location is as
honest as the device. See the master plan §3.5.

### 3.5 `limits`

- `uses: { count, per }` (`per` ∈ `minute`, `hour`, `day`, `month` (30 days), `total`) — enforced
  only online by devicebasedauth.org with a counter per credential and grant. Fixed windows aligned
  to the Unix epoch. An access token's uses count on the credential grant it was cut from (its own
  grant indexes differ), and a delegated grant that copied its parent's limit spends the parent
  grant's counter, so neither a token nor any number of delegates adds uses.
- `spend_usd_per_month` — not checked by the evaluator. It is returned as a **caveat** for the
  audience to enforce on its own spending (e.g. hashbin's monthly spend limit).

### 3.6 `require`

- `online: true` — the grant may only be used through online authorization.
- `step_up: true` — online, and the account owner must approve each use (never from the device that asked).
- `attestation: "hardware" | "strongbox"` — the credential's `device.attestation` (credential.md
  §3a) must show the key in a TEE, StrongBox, Secure Enclave or TPM (`hardware`), or in StrongBox
  only (`strongbox`); otherwise `attestation_required`. The evaluator reads it from
  `context.attestation`, which verifiers set to the presented credential's `device.attestation`
  (never from the request). An `apple-appattest` attestation is Apple vouching for the **app**
  that reported the key, not for the key, and any developer can ship an app that reports a key it
  can export; so it satisfies `attestation` only when its `environment` is `production` and
  `app_ids` (below) lists its `app_id`.
- `app_ids: ["TEAMID.bundle.id", "android:<package>:<sha256>", …]` — 1–16 app ids, at most 200
  characters each: Apple app ids (10-character team id, a dot, a bundle id of dot-separated
  letters, digits and hyphens) or Android apps (`android:`, a package name of two or more
  dot-separated parts each starting with a letter and then letters, digits or `_`, `:`, and the
  SHA-256 of the app's signing certificate as 64 lowercase hex digits). `context.attestation` must
  be an object whose `app_id` is in the list; otherwise `attested_app_required`. An `android:` id
  matches only an `android-key` attestation, and only one that also reports
  `verified_boot: "verified"` and `device_locked: true` (Android's OS names the app, so a device
  whose OS is not verified could name any app); any other id matches only a non-Android
  attestation.
- `verified_boot: true` — `context.attestation` must report `verified_boot: "verified"` and
  `device_locked: true`; otherwise `verified_boot_required`. `false` requires nothing.

Both are checked offline: the attestation is part of the signed credential.

- `gates: [entry, …]` — online, and each use waits until every entry is satisfied (1–3 entries).
  An entry is `{ any, timeout_s?, on_timeout? }`:
  - `any`: 1–5 different gates of the issuing account, each `"owner"` (any browser signed in to
    the account, or a dashboard device: today's step-up) or a gate id `gate_` + 8–64 letters and
    digits. One allow from any of them satisfies the entry.
  - `timeout_s`: integer 10–86 400, default 300.
  - `on_timeout`: `"deny"` (default) or `"allow"`. With `"allow"` the use goes ahead if nobody
    answers within `timeout_s`, whether the approver ignored the request or could not be reached:
    a veto window, not a check.

  Any other entry member, or a value out of range, makes the grant `invalid_grant`. Gates are
  decided by devicebasedauth.org's gate engine, not by the evaluator: the evaluator only makes the
  grant online-only, and `/authorize` answers `gate_pending` until the gates settle
  (credential.md §8). The device that asks can never approve its own request.
- `step_up: true` is exactly `gates: [{ "any": ["owner"], "timeout_s": 600, "on_timeout": "deny" }]`.
  A grant may not have both (`invalid_grant`).
- `gates_reuse_s` — integer 0–3600 (default 0), only with `gates` or `step_up`: one approval covers
  repeated uses of the same credential, action, resource and audience for this long. 0 means
  each approval is spent by one use.
- `confirmation: true` — the credential carries `confirm` (credential.md §9) and this grant counts
  only while the device holds a current confirmation. Checked offline and online, in this order:
  - no `context.confirmation` object with integer `iat` and `exp`, or `now + 60 < iat` →
    `confirmation_required`;
  - `now − 60 ≥ exp` → `confirmation_expired`;
  - `by_timeout` is anything but `false` and the action's policy has `fail_open: false` (§3.8) →
    `confirmation_by_timeout_refused`.

  `false` requires nothing.

### 3.7 Online-only constraints

If a grant would otherwise pass but has `limits.uses`, `require.online: true`,
`require.step_up: true` or `require.gates`, or the action's policy requires gates (§3.8), and the
evaluation is not online, it fails with `online_required` (and the overall result reports
`online_required: true` when that is the only reason any grant failed).

### 3.8 Audience policy

An audience's action catalog entry may carry a gates policy, which applies to every credential
used for that action, old or new:

```json
{ "action": "cronly:jobs:delete", "description": "Delete a job",
  "gates": { "require": true, "kinds": ["webauthn", "dba-device"], "fail_open": false } }
```

Verifiers pass the entry for the requested action as `context.policy`. Only its `gates` object is
read, and only these members:

- `require: true` — a grant counts only if one of its gate entries (with `step_up` as the owner
  entry) consists of gates whose kinds are all listed in `kinds` (any kind when `kinds` is not a
  list; `owner` is of kind `owner`; a gate whose kind is not in `context.gate_kinds` is of no
  kind). Otherwise, online, the grant fails with `gate_required`. Gate kinds are known only to
  devicebasedauth.org, so offline the grant is online-only (§3.7), with or without gates.
- `fail_open: false` — an allow by timeout counts as a deny for this action: confirmations with
  `by_timeout` other than `false` fail with `confirmation_by_timeout_refused` (§3.6), and the gate
  engine answers `by_timeout_refused` for gate entries that would pass by timeout.

Account owners can add gates but never remove an audience's requirement.

### 3.9 Reason order

Reasons are reported in the order of this document; `confirmation_*` come after
`verified_boot_required`, then `gate_required`, then `online_required`.
