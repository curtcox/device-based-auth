import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv } from '../test-utils/env.js';

// Short-lived rows (OIDC authorization codes, step-up requests) are deleted by the account's alarm
// soon after they expire; nothing pays to keep them.
let env; const realNow = Date.now; let t;
beforeEach(async () => { t = realNow(); Date.now = () => t; env = await testEnv(); });
afterEach(() => { Date.now = realNow; });

async function fireAlarm(account) {
  const at = account.storage.alarm;
  expect(at).not.toBeNull();
  t = Math.max(t, at); account.storage.alarm = null; await account.alarm();
}

describe('alarm pruning', () => {
  it('deletes an authorization code that was never exchanged, on an account with nothing else to do', async () => {
    const account = env.ACCOUNTS.get('alice');
    await account.op_put_code({ id: 'code_1', code: { client_id: 'x', expires_at: t + 60000 } }, t);
    for (let i = 0; i < 3 && account.storage.rows.has('code:code_1'); i++) await fireAlarm(account);
    expect(account.storage.rows.has('code:code_1')).toBe(false);
    expect(account.storage.alarm).toBeNull();
  });

  it('deletes an exchanged code too', async () => {
    const account = env.ACCOUNTS.get('alice');
    await account.op_put_code({ id: 'code_2', code: { client_id: 'x', expires_at: t + 60000 } }, t);
    await account.op_take_code({ id: 'code_2' }, t + 1000);
    await fireAlarm(account);
    expect(account.storage.rows.has('code:code_2')).toBe(false);
  });
});
