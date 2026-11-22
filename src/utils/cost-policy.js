// Provider list prices as used by cronly (checked 2026-11-15/16) and hashbin's price-floor sheet
// (2026-10-24). Operation counts come from reading this repository's code; re-audit them when
// handlers change (docs/business/pricing.md).
export const RATES = Object.freeze({
  workerRequest: 0.30, workerCpuMs: 0.02, doRequest: 0.15, rowWritten: 1, rowRead: 0.001,
  storageKBMonth: 0.2, r2ClassA: 4.5, r2ClassB: 0.36,
  // Amazon SES outbound email, $0.10 per 1,000 messages (AWS list price; D9).
  emailMessage: 100
});

export const COST_POLICY = Object.freeze({
  ...RATES, stripeRate: 0.029, stripeFixedCents: 30, revenueKept: 0.92, minimumMargin: 1.5,
  newAccountDepositCapCents: 2000, projectionBrakeCents: 2500
});

/**
 * A device's request to devicebasedauth.org's own API can first be answered 401 use_dpop_nonce
 * (its account's object started less than a minute ago and asks for its nonce, STATUS D15), so
 * each operation a device can ask for with a DPoP proof counts that challenge too: one more Worker
 * request, its authentication (1 DO request, with the rate limit) and ~2 ms to check the proof.
 * `dba curl` and `dba headers` ask POST /api/v1/dpop-nonce first instead, which costs the same.
 */
const withNonceChallenge = o => ({ ...o, workerRequests: o.workerRequests + 1, doRequests: o.doRequests + 1, cpuMs: o.cpuMs + 2 });

/**
 * Worst-case resources per billable operation. Each entry lists the Worker requests,
 * Durable Object requests, rows written (including later pruning deletes), CPU ms,
 * KB-months of storage it prepays, and R2 writes.
 */
export const OPERATIONS = Object.freeze({
  // Enrollment approval: rate limit, registry, funds check, status allocation, store, enrollment
  // get/put and its expiry alarm (8 DO requests); 13 months of device/credential/audit/ledger
  // records; plus a prepaid revocation (worker request, account + shard DO requests, 5 rows,
  // one status-list publish to R2), plus prepaid revocation webhooks (B1): a registry lookup per
  // round, four delivery rounds to up to 8 audiences (signing ~2 ms each), three alarm wake-ups,
  // and four outbox rewrites when every round fails (8 DO requests, 4 rows, 65 ms). Redeeming an
  // enrollment token (B2) adds the token check and its use counter (1 DO request, 1 row).
  // After 13 months compaction deletes what it wrote (credential, device, ledger, receipt and the
  // issued and revoked audit rows: 6 rows), in an alarm wake-up that also rewrites its schedule
  // (1 DO request, 1 row, 1 ms); worst case, one credential falls due per compaction run.
  // Security notices (master plan §10): one encrypted Web Push to each of up to 5 subscribed
  // browsers (ECDH, HKDF, AES-GCM; the VAPID signature is reused for hours), ~2 ms each, sent by
  // the account's DO after it answers; whether to send rides on the balance row (no extra write).
  // Completing a paid sign-up (B9) reads the account's sign-up instead of the enrollment get/put;
  // the sign-up's own writes (the profile and the deposit) are a deposit's, which are free.
  // Recovering onto a new device with a recovery code is an issue given free (an empty balance must
  // not lock the owner out); each costs one code, ten per sheet, and a sheet needs a recent sign-in.
  // Recovering by gate is a gate request (charged as one, D13) plus such an issue, at most three an
  // hour per account.
  issue: withNonceChallenge({ workerRequests: 3, doRequests: 20, rowWrites: 26, cpuMs: 91, storageKBMonths: 6 * 13, r2ClassA: 1 }),
  // Credential status (auth, with the rate limit), credential status (renew), funds check, renew; later
  // compaction deletes its ledger, receipt and audit rows.
  renew: withNonceChallenge({ workerRequests: 1, doRequests: 5, rowWrites: 8, cpuMs: 10, storageKBMonths: 1 * 13, r2ClassA: 0 }),
  // Charges summed into the day's aggregate (decision, read, token, login) each count one more row:
  // the first of a kind on an account each day flushes yesterday's aggregate as a ledger row,
  // which is kept for good (a few bytes; the monthly summary row is shared by all charges).
  // API key check (with the rate limit), registry, charge on the audience's balance row, issuer check
  // with decision row + its pruning delete (decision rows are kept 90 days), plus, worst case,
  // two more rows: a usage counter row and its pruning delete (one decision per usage window),
  // or a new step-up request and its later delete (an approval's use deletes the request it
  // answers). A new step-up request also pushes a notice to up to 5 browsers (10 ms).
  decision: { workerRequests: 1, doRequests: 4, rowWrites: 6, cpuMs: 15, storageKBMonths: 0.5 * 3, r2ClassA: 0 },
  // Authentication (which also checks the rate limit), charge (aggregated on the balance row), and
  // the read itself: at most two calls (a credential's decisions; an audience's usage).
  read: withNonceChallenge({ workerRequests: 1, doRequests: 4, rowWrites: 2, cpuMs: 3, storageKBMonths: 0, r2ClassA: 0 }),
  // Credential status (auth, with the rate limit), registry, charge. An X.509 certificate (B3) costs the
  // same: no registry read, one DER build and signature well inside the CPU allowance.
  token: withNonceChallenge({ workerRequests: 1, doRequests: 4, rowWrites: 2, cpuMs: 5, storageKBMonths: 0, r2ClassA: 0 }),
  // Consent (session check with the rate limit, registry, code put, code alarm) + token (take
  // code, registry, charge). Rows: code put, code taken, code deleted, balance, daily aggregate.
  login: withNonceChallenge({ workerRequests: 2, doRequests: 7, rowWrites: 5, cpuMs: 10, storageKBMonths: 0, r2ClassA: 0 }),
  // One gate contacted by a gate request (STATUS B7, D13), billed to the account whose gates they
  // are. Creating it rides on the decision that asks (no extra request), but adds the charge
  // (balance row and the day's aggregate row) and the request row. Its answer is a request of its
  // own (Worker, authentication with the rate limit, the account's answer: 2 DO requests) that
  // updates the row and writes an audit row (kept 13 months, then deleted by compaction); the
  // decision that uses the approval deletes the row, or the alarm prunes it (1 DO request).
  // Worst case instead of an answer: it settles by timeout, which writes the row and an audit row
  // (+ its later delete) the same way. A TOTP or security-key answer also rewrites the gate row
  // (the last step used, the key's signature counter): 1 row, ~3 ms (HMAC, AES-GCM, ECDSA).
  // Notices: Web Push to up to 5 browsers (10 ms), and the announcement of an allow by timeout
  // (10 ms more). Re-verifying a dashboard device (B9) is one such gate request: asking is a free
  // dashboard request, its answer deletes the row and records the re-verification on the
  // credential's row (instead of the decision's delete) with one audit row.
  gate: withNonceChallenge({ workerRequests: 1, doRequests: 3, rowWrites: 9, cpuMs: 25, storageKBMonths: 0.5 * 13, r2ClassA: 0 }),
  // A webhook gate contacted: as a gate, plus the signed POST to the service after the decision
  // (signing ~2 ms; the subrequest itself is not billed) and the transaction that records its
  // outcome ("failed", or the synchronous answer: 1 row). A late answer arrives as a callback
  // request (the answer's Worker and DO requests, already counted).
  gate_webhook: withNonceChallenge({ workerRequests: 1, doRequests: 3, rowWrites: 10, cpuMs: 28, storageKBMonths: 0.5 * 13, r2ClassA: 0 }),
  // A Duo or Okta Verify gate contacted: as a gate, plus starting the push (a signed subrequest,
  // 2 ms) and the transaction recording it (1 row), then up to 24 status polls, each an alarm
  // wake-up of the account (1 DO request, ~2 ms incl. unsealing the vendor secret); poll times are
  // kept in memory, so a poll writes nothing until the answer arrives (already counted).
  gate_vendor: withNonceChallenge({ workerRequests: 1, doRequests: 3 + 24, rowWrites: 10, cpuMs: 28 + 48, storageKBMonths: 0.5 * 13, r2ClassA: 0 }),
  // Issuing a confirmation (its gates are charged as gate requests): the device's request
  // (credential status with the rate limit, the account's confirm), the credential row's
  // confirmed_until, the charge on the balance row and the day's aggregate, an audit row (and its
  // deletion after 13 months), and signing the confirmation JWS.
  confirm: withNonceChallenge({ workerRequests: 1, doRequests: 2, rowWrites: 5, cpuMs: 5, storageKBMonths: 0.5 * 13, r2ClassA: 0 }),
  // One security email (STATUS S8, D9), charged to the account when it is queued, so it is
  // prepaid before anything is sent. Queueing rides on the request that caused it (an issuance,
  // an API key...): the charge (balance row, ledger and receipt rows, both deleted by compaction
  // after 13 months: 5 rows) and the queue row with its alarm (2 rows). Sending: up to 3 alarm
  // wake-ups (one per attempt; SES is retried only when it answered that it did not take the
  // message, so at most one message is billed), each signing the request (SigV4, ~3 ms) and
  // rewriting or deleting the queue row (3 rows) and setting the next alarm (2 rows), then an
  // audit row and its later deletion (2 rows) and, for the hourly digest, its last-sent row
  // (1 row; building it reads up to 40 rows of the audit trail and devices). Verifying an address and
  // recovering by email (B9) each send one such email; the link in it, used once, costs a read's
  // worth more (src/cost-counts.test.js), and a recovery email the balance cannot pay goes free (at
  // most three an hour per account).
  notice: { workerRequests: 0, doRequests: 3, rowWrites: 15, cpuMs: 10, storageKBMonths: 0.5 * 13, r2ClassA: 0, emails: 1 },
  // Authentication (with the rate limit), registry read, charge, registry write; 4 KB of catalog kept 13 months; compaction later deletes
  // the charge's ledger and receipt rows and the audit row.
  audience: withNonceChallenge({ workerRequests: 1, doRequests: 4, rowWrites: 8, cpuMs: 5, storageKBMonths: 4 * 13, r2ClassA: 0 })
});

/** Worst-case marginal cost of one operation in micro-dollars (not rounded). */
export function worstCaseCost(op) {
  const o = OPERATIONS[op];
  if (!o) throw new Error(`unknown operation ${op}`);
  const r = RATES;
  return o.workerRequests * r.workerRequest + o.doRequests * r.doRequest + o.rowWrites * r.rowWritten + o.cpuMs * r.workerCpuMs + o.storageKBMonths * r.storageKBMonth + o.r2ClassA * r.r2ClassA + (o.emails || 0) * r.emailMessage;
}

/** Gross up the credit to itemize card payment costs (hashbin/cronly). */
export function grossUp(creditCents) {
  if (!Number.isSafeInteger(creditCents) || creditCents < 0) throw new Error('Invalid credit');
  return Math.ceil((creditCents + COST_POLICY.stripeFixedCents) / (1 - COST_POLICY.stripeRate));
}
