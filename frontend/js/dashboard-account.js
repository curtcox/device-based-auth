/**
 * Dashboard pages for the account itself: balance and deposits, budget limits, security notices
 * (Web Push) and the transaction and audit trail.
 */
import { api } from './api.js';
import { signedInLabel, currentDevice } from './auth.js';
import { h, replace, usd, money, num, date, badge, notice, table, dl, field } from './html.js';
import { state, view, enc, flash, errorBox, confirmButton, busy, refreshStrip, render } from './dashboard.js';

// ---------------------------------------------------------------------------------------------
// Account

/** Budget guards (GET/PATCH /api/v1/account/settings). */
function settingsForm(settings) {
  const cap = settings.max_renewals_per_credential_per_month;
  const form = h('form', { class: 'stack', id: 'settings-form' },
    h('div', { class: 'row' },
      h('label', {}, 'Credentials issued per day (UTC)', h('input', { name: 'issues', type: 'number', min: 1, max: 100000, step: 1, required: true, value: String(settings.max_issues_per_day) })),
      h('label', {}, 'Renewals per credential per month', h('span', { class: 'hint' }, ' — empty for no cap'), h('input', { name: 'renewals', type: 'number', min: 1, max: 100000, step: 1, value: cap === null ? '' : String(cap) }))),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Save limits')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const renewals = field(form, 'renewals');
      try {
        await api('/api/v1/account/settings', { method: 'PATCH', body: { max_issues_per_day: Number(field(form, 'issues')), max_renewals_per_credential_per_month: renewals === '' ? null : Number(renewals) } });
        replace(out, notice('success', 'Saved.'));
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [h('p', { class: 'muted' }, 'Limits on what this account can spend if a session, API key or device misbehaves. Issuing beyond the daily limit and renewing beyond the monthly cap are refused (HTTP 429) without charge. Changes are recorded in the audit trail.'), form, out];
}

// ---------------------------------------------------------------------------------------------
// Security notices (Web Push, master plan §10)

const PUSH_ID = 'dba.push.subscription';
const pushStore = () => { try { return window.localStorage; } catch { return null; } };
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

function browserName() {
  const ua = navigator.userAgent;
  const name = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /iPhone|iPad/.test(ua) ? 'iOS' : /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${name} on ${os}` : name;
}

/** Subscribe this browser and register it with the account. */
async function enablePush(name) {
  if (await Notification.requestPermission() !== 'granted') throw new Error('Notifications are blocked for this site in the browser settings.');
  const registration = await navigator.serviceWorker.register('/sw.js');
  await navigator.serviceWorker.ready;
  const subscription = await registration.pushManager.getSubscription() || await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64u(state.config.push_public_key) });
  const added = await api('/api/v1/push-subscriptions', { method: 'POST', body: { subscription: subscription.toJSON(), name } });
  pushStore()?.setItem(PUSH_ID, added.id);
  return added;
}

async function disablePush(item) {
  await api(`/api/v1/push-subscriptions/${enc(item.id)}`, { method: 'DELETE' });
  if (pushStore()?.getItem(PUSH_ID) === item.id) {
    pushStore()?.removeItem(PUSH_ID);
    try { await (await (await navigator.serviceWorker.getRegistration('/'))?.pushManager.getSubscription())?.unsubscribe(); } catch { /* already gone */ }
  }
}

function pushSection(subscriptions) {
  const intro = h('p', { class: 'muted' }, 'Get a notification in this browser when a credential, API key or enrollment token is issued on your account, so a stolen sign-in cannot add devices unnoticed. Credentials that can act on your account, API keys and enrollment tokens are announced at once; other issuances at most once an hour, with a count. Free, up to 5 browsers.');
  if (!state.config.push_public_key) return [intro, h('p', { class: 'muted' }, 'Security notices are not configured on this server.')];
  const mine = pushStore()?.getItem(PUSH_ID);
  const out = h('div', { id: 'push-result' });
  const rows = (subscriptions?.items || []).map(s => [
    [h('strong', {}, s.name), s.id === mine ? [' ', badge('active', 'this browser')] : null], h('span', { class: 'mono small' }, s.push_service), date(s.created_at),
    confirmButton('Turn off', `Stop security notices to “${s.name}”? Every subscribed browser is told.`, async () => {
      await disablePush(s); flash('success', `Security notices to ${s.name} are off.`); await render();
    })
  ]);
  const form = h('form', { class: 'stack', id: 'push-form' },
    h('label', {}, 'Name for this browser', h('input', { name: 'name', value: browserName(), maxlength: 64, required: true })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Notify this browser')));
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        const added = await enablePush(field(form, 'name'));
        replace(view, await accountView());
        flash(added.delivered ? 'success' : 'warn', added.delivered ? `Security notices are on for ${added.name}; a first notice is on its way.` : `${added.name} was added, but the first notice could not be delivered (${added.delivery_error || `HTTP ${added.delivery_status}`}).`);
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [
    intro,
    rows.length ? table(['Browser', 'Push service', 'Added', ''], rows) : h('p', { class: 'muted' }, 'No browser gets security notices yet.'),
    pushSupported() ? form : h('p', { class: 'muted' }, 'This browser cannot receive push notifications.'),
    out
  ];
}

/** Page #account: balance, deposits, budget limits, security notices and dashboard device. */
export async function accountView() {
  const [a, settings, subscriptions] = await Promise.all([api('/api/v1/account'), api('/api/v1/account/settings').catch(() => null), api('/api/v1/push-subscriptions').catch(() => null)]); state.accountInfo = a;
  const kinds = Object.keys(a.month?.by_kind || {});
  const aggregates = Object.entries(a.today?.aggregates || {});
  const deposit = state.config.local ? localDeposit() : cardDeposit();
  const device = currentDevice();
  return [
    h('h1', {}, 'Account'),
    dl([
      ['Account id', h('span', { class: 'mono', id: 'account-id' }, a.account)],
      ['Balance', h('strong', { id: 'account-balance' }, money(a.balance_microdollars))],
      ['Created', date(a.created_at)],
      ['Signed in as', signedInLabel()]
    ]),
    h('h2', {}, `Spend this month (${a.month?.period || ''})`),
    kinds.length
      ? table(['Kind', 'Count', 'Amount'], [...kinds.map(k => [k, num(a.month.counts?.[k]), money(a.month.by_kind[k])]), [h('strong', {}, 'Total'), '', h('strong', {}, money(a.month.spent_microdollars))]])
      : h('p', { class: 'muted' }, 'Nothing spent this month.'),
    h('h3', {}, `Today's small charges (${a.today?.period || ''})`),
    h('p', { class: 'muted small' }, 'Reads, decisions, token exchanges and sign-ins are summed per day and written to the ledger as one row each.'),
    aggregates.length ? table(['Kind', 'Count', 'Amount'], aggregates.map(([k, v]) => [k, num(v.count), money(v.amount)])) : h('p', { class: 'muted' }, 'None today.'),
    h('h2', {}, 'Add credit'), deposit,
    settings ? [h('h2', {}, 'Limits'), settingsForm(settings)] : null,
    subscriptions ? [h('h2', {}, 'Security notices'), pushSection(subscriptions)] : null,
    h('h2', {}, 'Sign in with this browser'),
    device
      ? h('p', {}, 'This browser is signed in with its own device credential ', h('a', { href: `#credential/${enc(device.payload.cid)}` }, device.payload.cid), '. Every request is signed with a key that never leaves this browser. Signing out revokes it.')
      : h('p', {}, 'Make this browser a device: it gets a non-extractable key and a credential for devicebasedauth.org with ', h('code', {}, 'dba:session'), `. After that, the dashboard signs each request with that key instead of your sign-in session, and revoking the credential signs this browser out everywhere. Costs ${money(state.config.prices.issue)}.`)
  ];
}

function localDeposit() {
  const form = h('form', { class: 'row', id: 'deposit-form' },
    h('label', {}, 'Development credit (USD)', h('input', { name: 'dollars', type: 'number', min: '0.000001', max: '100', step: 'any', value: '5', required: true })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit' }, 'Add development credit')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        const amount = Math.round(Number(field(form, 'dollars')) * 1_000_000);
        const result = await api('/api/v1/dev/deposit', { method: 'POST', body: { amount_microdollars: amount } });
        flash('success', `Added ${money(amount)}. Balance ${usd(result.balance_microdollars)}.`);
        await refreshStrip(); await render();
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [notice('info', 'Local development mode: credit is free and not real money.'), form, out];
}

function cardDeposit() {
  const minimum = state.config.minimum_deposit_cents / 100;
  const form = h('form', { class: 'row', id: 'deposit-form' },
    h('label', {}, 'Credit to add (USD)', h('input', { name: 'dollars', type: 'number', min: String(minimum), max: '1000', step: '0.01', value: String(minimum), required: true })),
    h('div', { class: 'shrink' }, h('button', { type: 'submit', class: 'secondary' }, 'Review deposit')));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const credit = Math.round(Number(field(form, 'dollars')) * 100);
      try {
        const quote = await api('/api/v1/payments/checkout?dry_run=1', { method: 'POST', body: { credit_cents: credit } });
        const key = crypto.randomUUID();
        const pay = h('button', { type: 'button' }, `Pay ${usd(quote.total_cents * 10000)} with a card`);
        pay.addEventListener('click', async () => {
          pay.disabled = true;
          try { const session = await api('/api/v1/payments/checkout', { method: 'POST', body: { credit_cents: credit }, idempotencyKey: key }); location.assign(session.url); }
          catch (error) { replace(out, errorBox(error)); }
        });
        replace(out, h('div', { class: 'panel' }, dl([
          ['Credit', usd(quote.credit_cents * 10000)],
          ['Card payment cost', [usd(quote.card_cost_cents * 10000), h('span', { class: 'muted small' }, ' (itemized, non-refundable)')]],
          ['Total charged', h('strong', {}, usd(quote.total_cents * 10000))]
        ]), pay, h('p', { class: 'muted small' }, 'Payment is handled by Stripe. Credit appears once Stripe confirms the payment.')));
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [h('p', { class: 'muted' }, `Prepaid, no subscription. Minimum ${usd(state.config.minimum_deposit_cents * 10000)}; new accounts may add at most $20 per payment in their first week. Unused credit never expires while your account exists.`), form, out];
}

// ---------------------------------------------------------------------------------------------
// Transactions and audit trail

/** Page #transactions (or #transactions/audit): the ledger or the audit trail. */
export async function transactions(arg) {
  const tab = arg === 'audit' ? 'audit' : 'ledger';
  const path = tab === 'audit' ? '/api/v1/audit' : '/api/v1/transactions';
  const headers = tab === 'audit' ? ['When', 'Event', 'Details'] : ['When', 'Kind', 'Amount', 'Detail'];
  const rows = items => items.map(t => tab === 'audit'
    ? (({ id: _id, type, at, ...rest }) => [date(at), h('span', { class: 'mono' }, type), h('span', { class: 'mono small' }, Object.entries(rest).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · '))])(t)
    : [date(t.created_at), t.kind, h('span', { class: t.amount_microdollars >= 0 ? 'badge badge-ok' : '' }, `${t.amount_microdollars >= 0 ? '+' : '−'}${money(Math.abs(t.amount_microdollars))}`),
      t.aggregate ? `${num(t.count)} × for ${t.period}` : t.detail ? Object.entries(t.detail).map(([k, v]) => `${k}: ${v}`).join(' · ') : t.id]);
  const first = await api(path);
  const t = table(headers, rows(first.items));
  const wrap = h('div', {}, first.items.length ? t : h('p', { class: 'muted' }, 'Nothing yet.'));
  let cursor = first.next_cursor;
  if (cursor) {
    const more = h('button', { type: 'button', class: 'secondary' }, 'Load older');
    more.addEventListener('click', async () => {
      const next = await api(`${path}?cursor=${enc(cursor)}`);
      const tbody = t.querySelector('tbody');
      for (const cells of rows(next.items)) tbody.append(h('tr', {}, cells.map((cell, i) => h('td', { 'data-label': headers[i] }, cell))));
      cursor = next.next_cursor; if (!cursor) more.remove();
    });
    wrap.append(more);
  }
  return [
    h('h1', {}, 'Transactions'),
    h('div', { class: 'tabs' },
      h('a', { href: '#transactions', class: `button small ${tab === 'ledger' ? '' : 'secondary'}` }, 'Ledger'),
      h('a', { href: '#transactions/audit', class: `button small ${tab === 'audit' ? '' : 'secondary'}` }, 'Audit trail')),
    h('p', { class: 'muted' }, tab === 'audit' ? 'Every issue, renewal, revocation, key change and approval, newest first.' : 'Deposits and charges in micro-dollars, newest first.'),
    wrap
  ];
}
