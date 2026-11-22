import { describe, it, expect } from 'vitest';
import { testEnv } from '../../test-utils/env.js';
import { rpc } from '../utils/rpc.js';
import worker from '../index.js';

const HOUR = 3600000;
const usage = { workers: [{ sum: { requests: 10, cpuTimeUs: 1000 } }], invocations: [{ sum: { requests: 5 } }], periodic: [{ sum: { rowsRead: 1, rowsWritten: 1 } }] };

/** A production environment whose analytics answer from `answer` and count the queries. */
async function productionEnv(answer = () => Response.json({ data: { viewer: { accounts: [usage] } } })) {
  const queries = [];
  const env = await testEnv({ ENVIRONMENT: 'production', CLOUDFLARE_ANALYTICS_TOKEN: 'token', CLOUDFLARE_ACCOUNT_ID: 'account', COST_SAFETY_DO_NAMESPACES: 'a,b', ANALYTICS_FETCH: async (...args) => { queries.push(args); return answer(); } });
  return { env, queries };
}

/** Fire the hourly cron at `time` and wait for everything it started. */
async function cron(env, time) {
  const work = [];
  await worker.scheduled({ scheduledTime: time }, env, { waitUntil: p => work.push(p) });
  await Promise.all(work);
}

const status = env => rpc(env.SAFETY, 'global', 'status');
const at = hour => Date.parse(`2026-11-22T${String(hour).padStart(2, '0')}:07:00Z`);

describe('cost monitor schedule', () => {
  it('runs outside the daily hour when there is no report yet, and releases the brake', async () => {
    const { env, queries } = await productionEnv();
    expect((await status(env)).brake).toBe(true);
    await cron(env, at(6));
    expect(queries).toHaveLength(1);
    expect(await status(env)).toMatchObject({ brake: false, stale: false });
  });

  it('waits for the daily hour once a good report exists', async () => {
    const { env, queries } = await productionEnv();
    await cron(env, at(6));
    await cron(env, at(7));
    expect(queries).toHaveLength(1);
    await cron(env, at(2) + 24 * HOUR);
    expect(queries).toHaveLength(2);
  });

  it('retries every hour after a failed query', async () => {
    let fail = true;
    const { env, queries } = await productionEnv(() => fail ? new Response('{}', { status: 500 }) : Response.json({ data: { viewer: { accounts: [usage] } } }));
    await cron(env, at(2));
    expect(await status(env)).toMatchObject({ brake: true, reason: 'Cloudflare analytics unavailable' });
    fail = false;
    await cron(env, at(3));
    expect(queries).toHaveLength(2);
    const after = await status(env);
    expect(after.brake).toBe(false);
    expect(after.reason).toBeUndefined();
  });

  it('does not re-measure hourly when the brake is on because of projected cost', async () => {
    const { env, queries } = await productionEnv();
    env.COST_SAFETY_BRAKE_CENTS = '0';
    await cron(env, at(2));
    expect((await status(env)).brake).toBe(true);
    await cron(env, at(3));
    expect(queries).toHaveLength(1);
  });
});
