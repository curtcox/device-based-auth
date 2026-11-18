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
    held against the device; a missing `acc_m` never matches).
- `networks` (network source only): the observed IP must be inside one CIDR range, otherwise
  `network_not_allowed`. Networks are checked in addition to places.

Location is evidence, not proof: network location can be moved with a VPN; device location is as
honest as the device. See the master plan §3.5.

### 3.5 `limits`

- `uses: { count, per }` (`per` ∈ `minute`, `hour`, `day`, `month` (30 days), `total`) — enforced
  only online by devicebasedauth.org with a counter per credential and grant. Fixed windows aligned
  to the Unix epoch.
- `spend_usd_per_month` — not checked by the evaluator. It is returned as a **caveat** for the
  audience to enforce on its own spending (e.g. hashbin's monthly spend limit).

### 3.6 `require`

- `online: true` — the grant may only be used through online authorization.
- `step_up: true` — online, and the account owner must approve each use.
- `attestation: "hardware" | "strongbox"` — the credential's `device.attestation` (credential.md
  §3a) must show the key in a TEE or StrongBox (`hardware`), or in StrongBox only (`strongbox`);
  otherwise `attestation_required`. The evaluator reads it from `context.attestation`, which
  verifiers set to the presented credential's `device.attestation` (never from the request).
- `verified_boot: true` — `context.attestation` must report `verified_boot: "verified"` and
  `device_locked: true`; otherwise `verified_boot_required`. `false` requires nothing.

Both are checked offline: the attestation is part of the signed credential.

### 3.7 Online-only constraints

If a grant would otherwise pass but has `limits.uses`, `require.online: true` or
`require.step_up: true`, and the evaluation is not online, it fails with `online_required` (and
the overall result reports `online_required: true` when that is the only reason any grant failed).
