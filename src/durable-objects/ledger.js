import { assert } from '../utils/errors.js';

/** Validate money at the boundary; balances are never floating point. */
export function money(value) {
  assert(Number.isSafeInteger(value) && value >= 0, 'invalid_money', 'Expected nonnegative integer micro-dollars');
  return value;
}

const day = now => new Date(now).toISOString().slice(0, 10);
const month = now => new Date(now).toISOString().slice(0, 7);
const ledgerKey = (at, id) => `ledger:${new Date(at).toISOString()}:${id}`;

/** Read the balance row, rolling day and month summaries forward. Writes happen in save(). */
export async function readBalance(tx, now = Date.now()) {
  const state = (await tx.get('balance')) || { balance_microdollars: 0 };
  const rolled = { ...state };
  if (rolled.day && rolled.day.period !== day(now)) {
    // Flush yesterday's aggregated small charges (reads, decisions, tokens) as one ledger row.
    for (const [kind, agg] of Object.entries(rolled.day.aggregates || {})) {
      if (agg.amount > 0) await tx.put(ledgerKey(Date.parse(`${rolled.day.period}T23:59:59.999Z`), `agg-${kind}-${rolled.day.period}`), { id: `agg-${kind}-${rolled.day.period}`, kind, amount_microdollars: -agg.amount, count: agg.count, aggregate: true, period: rolled.day.period, created_at: Date.parse(`${rolled.day.period}T23:59:59.999Z`) });
    }
    rolled.day = null;
  }
  if (rolled.month && rolled.month.period !== month(now)) { await tx.put(`month:${rolled.month.period}`, rolled.month); rolled.month = null; }
  rolled.day ||= { period: day(now), aggregates: {} };
  rolled.month ||= { period: month(now), spent_microdollars: 0, by_kind: {}, counts: {} };
  return rolled;
}

/**
 * Charge a fixed price inside a storage transaction. Never lets the balance go negative.
 * aggregate=true records the charge in today's summary instead of its own ledger row
 * (used for high-volume small charges: reads, decisions, tokens).
 * Returns { charged, balance_microdollars, duplicate }.
 */
export async function charge(tx, { id, kind, amount, aggregate = false, detail }, now = Date.now()) {
  money(amount);
  if (id && !aggregate) {
    const prior = await tx.get(`receipt:${id}`);
    if (prior) return { ...prior, duplicate: true };
  }
  const state = await readBalance(tx, now);
  assert(state.balance_microdollars >= amount, 'insufficient_balance', 'Insufficient balance', 402, { needed_microdollars: amount - state.balance_microdollars, price_microdollars: amount });
  state.balance_microdollars -= amount;
  state.month.spent_microdollars += amount;
  state.month.by_kind[kind] = (state.month.by_kind[kind] || 0) + amount;
  state.month.counts[kind] = (state.month.counts[kind] || 0) + 1;
  // Per-audience counts for the audience console: online decisions and sign-ins are billed to the
  // audience's owner, who wants to see them by site. Kept in the month row already being written,
  // so it costs no extra storage operation.
  if (typeof detail?.audience === 'string') {
    const usage = (state.month.by_audience ||= {})[detail.audience] ||= { counts: {}, spent_microdollars: 0 };
    usage.counts[kind] = (usage.counts[kind] || 0) + 1;
    usage.spent_microdollars += amount;
  }
  if (aggregate) {
    const agg = state.day.aggregates[kind] ||= { count: 0, amount: 0 };
    agg.count += 1; agg.amount += amount;
  } else {
    await tx.put(ledgerKey(now, id), { id, kind, amount_microdollars: -amount, created_at: now, ...(detail ? { detail } : {}) });
    await tx.put(`receipt:${id}`, { id, charged: amount, created_at: now });
  }
  await tx.put('balance', state);
  return { charged: amount, balance_microdollars: state.balance_microdollars };
}

/** Credit a verified payment exactly once. */
export async function deposit(tx, { id, amount, kind = 'deposit' }, now = Date.now()) {
  money(amount);
  if (await tx.get(`deposit:${id}`)) return { duplicate: true };
  const state = await readBalance(tx, now);
  state.balance_microdollars = money(state.balance_microdollars + amount);
  await tx.put(ledgerKey(now, id), { id, kind, amount_microdollars: amount, created_at: now });
  await tx.put(`deposit:${id}`, { amount, created_at: now });
  await tx.put('balance', state);
  return { balance_microdollars: state.balance_microdollars };
}
