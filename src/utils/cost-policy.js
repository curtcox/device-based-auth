// Provider list prices as used by cronly (checked 2026-11-15/16) and hashbin's price-floor sheet
// (2026-10-24). Operation counts come from reading this repository's code; re-audit them when
// handlers change (docs/business/pricing.md).
export const RATES = Object.freeze({
  workerRequest: 0.30, workerCpuMs: 0.02, doRequest: 0.15, rowWritten: 1, rowRead: 0.001,
  storageKBMonth: 0.2, r2ClassA: 4.5, r2ClassB: 0.36
});

export const COST_POLICY = Object.freeze({
  ...RATES, stripeRate: 0.029, stripeFixedCents: 30, revenueKept: 0.92, minimumMargin: 1.5,
  newAccountDepositCapCents: 2000, projectionBrakeCents: 2500
});

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
  issue: { workerRequests: 3, doRequests: 19, rowWrites: 19, cpuMs: 80, storageKBMonths: 6 * 13, r2ClassA: 1 },
  // Rate limit, credential status (auth), credential status (renew), funds check, renew.
  renew: { workerRequests: 1, doRequests: 5, rowWrites: 5, cpuMs: 10, storageKBMonths: 1 * 13, r2ClassA: 0 },
  // Rate limit, charge on the audience's balance row, registry (normally cached), issuer check
  // with usage counter + decision row + its pruning delete; decision rows are kept 90 days.
  decision: { workerRequests: 1, doRequests: 4, rowWrites: 4, cpuMs: 5, storageKBMonths: 0.5 * 3, r2ClassA: 0 },
  // Rate limit, charge (aggregated on the balance row), the read itself.
  read: { workerRequests: 1, doRequests: 3, rowWrites: 1, cpuMs: 3, storageKBMonths: 0, r2ClassA: 0 },
  // Rate limit, credential status (auth), registry, charge.
  token: { workerRequests: 1, doRequests: 4, rowWrites: 1, cpuMs: 5, storageKBMonths: 0, r2ClassA: 0 },
  // Consent (rate limit, registry, code put, code alarm) + token (take code, registry, charge).
  login: { workerRequests: 2, doRequests: 7, rowWrites: 4, cpuMs: 10, storageKBMonths: 0, r2ClassA: 0 },
  // Rate limit, charge, registry write; 4 KB of catalog kept 13 months.
  audience: { workerRequests: 1, doRequests: 3, rowWrites: 5, cpuMs: 5, storageKBMonths: 4 * 13, r2ClassA: 0 }
});

/** Worst-case marginal cost of one operation in micro-dollars (not rounded). */
export function worstCaseCost(op) {
  const o = OPERATIONS[op];
  if (!o) throw new Error(`unknown operation ${op}`);
  const r = RATES;
  return o.workerRequests * r.workerRequest + o.doRequests * r.doRequest + o.rowWrites * r.rowWritten + o.cpuMs * r.workerCpuMs + o.storageKBMonths * r.storageKBMonth + o.r2ClassA * r.r2ClassA;
}

/** Gross up the credit to itemize card payment costs (hashbin/cronly). */
export function grossUp(creditCents) {
  if (!Number.isSafeInteger(creditCents) || creditCents < 0) throw new Error('Invalid credit');
  return Math.ceil((creditCents + COST_POLICY.stripeFixedCents) / (1 - COST_POLICY.stripeRate));
}
