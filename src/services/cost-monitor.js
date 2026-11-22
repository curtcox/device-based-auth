import { COST_POLICY as C } from '../utils/cost-policy.js';
import { rpc } from '../utils/rpc.js';
import { assert } from '../utils/errors.js';

// Ported from cronly/hashbin: total CPU (never percentiles); reject missing or truncated data.
export const USAGE_QUERY = `query Costs($account: string!, $start: Time!, $end: Time!, $scripts: [string!], $namespaces: [string!]) {
 viewer { accounts(filter: {accountTag: $account}) {
  workers: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: $start, datetime_lt: $end, scriptName_in: $scripts}) { sum { requests cpuTimeUs } }
  invocations: durableObjectsInvocationsAdaptiveGroups(limit: 10, filter: {datetime_geq: $start, datetime_lt: $end, namespaceId_in: $namespaces}) { sum { requests } }
  periodic: durableObjectsPeriodicGroups(limit: 10, filter: {datetime_geq: $start, datetime_lt: $end, namespaceId_in: $namespaces}) { sum { rowsRead rowsWritten } }
 } }
}`;

/** Cost in micro-dollars from one day of analytics; throws when data is missing. */
export function measuredCost(account) {
  const sum = (rows, field) => {
    assert(Array.isArray(rows) && rows.length < 10, 'analytics_incomplete', 'Analytics dataset missing or truncated', 503);
    return rows.reduce((total, row) => { const v = row.sum?.[field]; assert(Number.isFinite(v) && v >= 0, 'analytics_incomplete', 'Billing metric unavailable', 503); return total + v; }, 0);
  };
  return Math.ceil(sum(account.workers, 'requests') * C.workerRequest + sum(account.workers, 'cpuTimeUs') / 1000 * C.workerCpuMs + sum(account.invocations, 'requests') * C.doRequest + sum(account.periodic, 'rowsRead') * C.rowRead + sum(account.periodic, 'rowsWritten') * C.rowWritten);
}

/**
 * Daily: measure yesterday's infrastructure cost. Every paid operation is prepaid with margin, so
 * the risk is the free paths; brake them when a month of this cost would pass the limit.
 */
export async function runCostMonitor(env, now = Date.now()) {
  if (env.ENVIRONMENT === 'local') return { local: true };
  let report;
  try {
    assert(env.CLOUDFLARE_ANALYTICS_TOKEN && env.CLOUDFLARE_ACCOUNT_ID && env.COST_SAFETY_DO_NAMESPACES, 'analytics_unconfigured', 'Analytics token, account and namespace IDs are required', 503);
    const midnight = Date.parse(new Date(now).toISOString().slice(0, 10));
    const response = await (env.ANALYTICS_FETCH || fetch)('https://api.cloudflare.com/client/v4/graphql', { method: 'POST', headers: { Authorization: `Bearer ${env.CLOUDFLARE_ANALYTICS_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: USAGE_QUERY, variables: { account: env.CLOUDFLARE_ACCOUNT_ID, start: new Date(midnight - 86400000).toISOString(), end: new Date(midnight).toISOString(), scripts: [env.WORKER_NAME || 'dba-worker-prod'], namespaces: env.COST_SAFETY_DO_NAMESPACES.split(',') } }), signal: AbortSignal.timeout(15000) });
    const data = await response.json();
    assert(response.ok && !data.errors?.length && data.data?.viewer?.accounts?.[0], 'analytics_unavailable', 'Cloudflare analytics unavailable', 503);
    const observed = measuredCost(data.data.viewer.accounts[0]);
    const limit = Number(env.COST_SAFETY_BRAKE_CENTS || C.projectionBrakeCents) * 10000;
    report = { checked_at: now, observed_microdollars: observed, projected_month_microdollars: observed * 30, limit_microdollars: limit, brake: observed * 30 > limit };
  } catch (error) { report = { checked_at: now, brake: true, reason: error.message || 'Analytics unavailable' }; }
  await rpc(env.SAFETY, 'global', 'record', { report });
  if (report.brake && env.ALERT_WEBHOOK_URL) await fetch(env.ALERT_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: 'devicebasedauth.org cost-safety brake is active; free endpoints are paused.' }), signal: AbortSignal.timeout(10000) }).catch(() => null);
  return report;
}

/**
 * Whether the hourly cron should run the monitor: always in the daily hour, and in any other hour
 * when the last report is missing, stale or failed. Without the retry, a deploy made after 02:00
 * UTC or one failed analytics query would keep the free endpoints braked for a day.
 */
export async function costMonitorDue(env, daily) {
  if (daily) return true;
  if (env.ENVIRONMENT === 'local' || !env.SAFETY) return false;
  const status = await rpc(env.SAFETY, 'global', 'status');
  return !!(status.stale || status.reason);
}

let cached = { until: 0, brake: false };
/** Cached (60 s per isolate) brake status. */
export async function brakeActive(env, now = Date.now()) {
  if (env.ENVIRONMENT === 'local' || !env.SAFETY) return false;
  if (env.COST_SAFETY_HARD_STOP === 'true') return true;
  if (cached.until > now) return cached.brake;
  const status = await rpc(env.SAFETY, 'global', 'status');
  cached = { until: now + 60000, brake: !!status.brake };
  return cached.brake;
}
