# Grant evaluation, vocabulary versions 1 and 2

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
- `location.network.rtt_ms`, `address_lists`, `dns`, `address_webhook`, `route`, `route_error` —
  what the verifier resolved for the `net` constraint before evaluating (§3.10).

## 2. Decision

The request is allowed when **at least one grant passes**. A grant passes when every check below
passes. Otherwise it is denied. Nothing is allowed by default.

Each failing check adds a reason code to that grant's reason list (all applicable reasons,
in the order of this document).

## 3. Grant members

A grant may contain only `actions`, `resources`, `when`, `where`, `net`, `limits`, `require`
(`net` only in vocabulary 2, spec/credential.md). Any other
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

Reasons are reported in the order of this document, except that the `net` reasons of §3.10 come
right after those of `where` (§3.4) and before `limits`; `confirmation_*` come after
`verified_boot_required`, then `gate_required`, then `online_required`.

### 3.10 `net` (vocabulary 2)

Rules about the *connection* a request arrives on rather than the place it comes from: from
which addresses, through which relays, and how far away in round-trip time. Design:
[todo/network_constraints.md](../todo/network_constraints.md). Network rules are evidence about
the connection, not proof of identity; the device key still proves who is talking.

```json
"net": {
  "client": {
    "addresses": { "of": "peer", "cidrs": ["203.0.113.0/24"],
                   "lists": [{ "id": "adl_OFFICE0001", "uri": "https://status.devicebasedauth.org/v1/addresses/adl_OFFICE0001" }],
                   "dns": { "names": ["vpn-egress.example.com"], "dnssec": true }, "webhook": "gate_ADDRHOOK1" },
    "route": { "relays": ["dev_RELAYHQ001"], "min_hops": 1, "max_hops": 2, "require_attested": true },
    "latency": { "max_rtt_ms": 40, "samples": 1, "reuse_s": 60 }
  },
  "server": { "addresses": { "cidrs": ["198.51.100.0/24"] }, "latency": { "max_rtt_ms": 80 } }
}
```

`net` needs `client` or `server`; each needs at least one of `addresses`, `route`, `latency`, and
every one present must pass. **Verifiers evaluate only `client`.** `server` binds the device's own
SDK or CLI (which checks the relying party before sending), is validated like the rest, and is
ignored by verifiers: a relying party never treats a device's report about the server as a
reason to allow.

**Shape** (anything else is `invalid_grant`; unknown members at any level are
`unknown_constraint:net.…`):

- `addresses`: `of` (`"peer"`, the default, or `"origin"`, which needs a `route` in the same
  direction and is not allowed in `server`) and at least one source: `cidrs` (1–64 CIDR ranges),
  `lists` (1–8 `{ id, uri }`, `id` = `adl_` + 8–64 letters and digits, `uri` an `https://` URL of
  at most 512 characters), `dns` (`names`: 1–16 lower-case host names of two or more labels whose
  last label is not all digits, at most 253 characters; `dnssec`: boolean), `webhook` (a gate id,
  `client` only). Lists have no duplicates.
- `route`: `relays` (1–16 device ids `dev_` + 8–64 letters and digits), `min_hops` and
  `max_hops` (integers 1–4, defaults 1 and 4, `min_hops ≤ max_hops`), `require_attested`
  (boolean).
- `latency`: `max_rtt_ms` (integer 1–5000, required), `samples` (1–5), `reuse_s` (0–300).
  `samples` and `reuse_s` tell the verifier how to measure (the minimum of `samples` timed
  challenges; a passing measurement reused for `reuse_s` for the same key and peer address); the
  evaluator compares only the result.

**Context.** The verifier resolves everything that needs I/O first, so evaluation stays pure:

| Field | Meaning |
|-------|---------|
| `location.network.ip` | The peer address, from the platform (`CF-Connecting-IP`, the socket), never a header the client sets |
| `location.network.rtt_ms` | The measured round trip in milliseconds (a number ≥ 0), or absent |
| `address_lists` | `{ <list id>: { cidrs, ver } }` for lists the verifier holds a current copy of; any other value, or no entry, means unavailable |
| `dns` | `{ <name>: { addrs, dnssec } }` for names that resolved; any other value, or no entry, means unresolved |
| `address_webhook` | Online only: `{ <gate id>: true }` when the webhook allowed this address |
| `route` | `{ relays: [<relay device id>, …] in hop order, origin: <address hop 0 recorded>, attested: [<boolean per hop>] }` after the verifier checked the hops |
| `route_error` | A reason (`[a-z0-9_]{1,64}`) the verifier could not accept the hops, e.g. `egress_mismatch` |

**Checks on `client`, in this order:**

1. `addresses`. The address is the peer address, or `route.origin` for `of: "origin"`. Missing →
   `address_unavailable`. Otherwise the sources form a **union**: the address is allowed when it is
   inside one of `cidrs`; or inside one of the `cidrs` of an available list; or the same address
   (compared as numbers, so `2001:DB8::1` equals `2001:db8:0::1`; families never match) as one of
   the `addrs` of a resolved name, whose `dnssec` is `true` when `dns.dnssec` is `true`.
   If none allows it and there is a `webhook`:
   offline, the grant becomes online-only (§3.7) instead of failing here; online, the webhook's
   answer `true` allows. Otherwise `address_not_allowed`, followed by one informational reason
   per source that could not be consulted: `address_list_unavailable:<id>` for each unavailable
   list, then for each name `dns_unresolved:<name>` or (resolved but not validated where `dnssec`
   is required) `dns_unvalidated:<name>`.
2. `route`. A string `route_error` → `route_invalid:<route_error>` (`route_invalid:malformed` if
   it is not `[a-z0-9_]{1,64}`). Otherwise no `route` object with a `relays` list →
   `route_required`. Otherwise, each that applies: hop count outside `min_hops`…`max_hops` →
   `route_invalid:hop_count`; `require_attested` and `attested` is not one `true` per hop →
   `route_invalid:relay_not_attested`; a relay not in `relays` → `route_relay_not_allowed`.
3. `latency`. `rtt_ms` missing, not a number or negative → `rtt_required` (the verifier must
   challenge the device and try again); greater than `max_rtt_ms` → `rtt_exceeded`.

`where.networks` is unchanged and evaluated with `where`. Old (vocabulary 1) verifiers deny any
grant with `net` as `unknown_constraint:net`, so `net` fails closed everywhere.

**What each rule is worth.** Address rules are as strong as the address the verifier sees: anyone
who controls an allowed address, or a VPN exit inside an allowed range, passes. DNS names are as
strong as the resolver (`dnssec: true` makes an unvalidated answer deny). A route proves the
request passed the relays, not that the relays are honest; relays are revocable DBA devices.
Latency bounds distance, not possession: it stops a credential relayed from far away, not a
stolen key used nearby, and it is only ever an upper bound, because a device can always answer
later but never sooner.
