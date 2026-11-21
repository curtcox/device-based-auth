/**
 * Create an account with this browser and a card (STATUS B9, todo/clerk_free_accounts.md §3.2):
 * the SDK makes a non-extractable key in the dashboard's device slot, the person pays the first
 * deposit on Stripe Checkout, and the signed payment creates the account bound to that key. The
 * page then offers a way back in while the payment still counts as a recent sign-in (ten minutes).
 */
import { DBA } from '/sdk/dba.js';
import { api } from './api.js';
import { h, $, replace, notice, usd } from './html.js';

const root = $('#signup-root');
const dba = new DBA({ origin: location.origin, name: 'dashboard' });
const DEPOSITS = [500, 1000, 2000];

const browserName = () => { const ua = navigator.userAgent; return `Dashboard — ${/Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser'}`; };

/** The form: deposit, device name, terms, then Checkout. */
async function form() {
  const config = await api('/api/public/config', { auth: false });
  const quote = h('p', { class: 'muted small', id: 'signup-quote' });
  const amount = h('select', { name: 'credit' }, DEPOSITS.map(c => h('option', { value: c }, usd(c * 10000))));
  const showQuote = async () => { try { const q = await api('/api/v1/signup?dry_run=1', { method: 'POST', auth: false, body: { credit_cents: Number(amount.value) } }); replace(quote, `You pay ${usd(q.total_cents * 10000)}: ${usd(q.credit_cents * 10000)} of credit plus ${usd(q.card_cost_cents * 10000)} card cost.`); } catch { replace(quote); } };
  amount.addEventListener('change', showQuote);
  const terms = h('input', { type: 'checkbox', name: 'terms', required: true });
  const out = h('div', {});
  const el = h('form', { class: 'stack', id: 'signup-form' },
    h('label', {}, 'First deposit', amount), quote,
    h('label', {}, 'Name for this browser', h('input', { name: 'name', value: browserName(), maxlength: 80, required: true })),
    h('label', { class: 'check' }, terms, ' I accept the ', h('a', { href: '/terms.html', target: '_blank' }, 'terms'), ' and the ', h('a', { href: '/privacy.html', target: '_blank' }, 'privacy policy'), '.'),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Continue to payment')),
    h('p', { class: 'muted small' }, `Credit never expires. Each credential costs ${usd(config.prices.issue)}; see `, h('a', { href: '/pricing.html' }, 'pricing'), '. Already have an account? ', h('a', { href: '/app.html' }, 'Sign in'), '. Lost your devices? ', h('a', { href: '/recover.html' }, 'Recover your account'), '.'),
    out);
  el.addEventListener('submit', async event => {
    event.preventDefault();
    el.querySelector('button[type=submit]').disabled = true;
    try {
      const started = await dba.signUp({ creditCents: Number(amount.value), acceptTerms: terms.checked, device: { name: el.elements.name.value.trim() }, replace: true });
      if (started.local_payment) await paying(); else location.assign(started.url);
    } catch (error) { replace(out, notice('error', error.message)); el.querySelector('button[type=submit]').disabled = false; }
  });
  replace(root, el);
  showQuote();
}

/** Back from Checkout (or a local server): wait for the payment, then the credential. */
async function paying() {
  const status = h('p', { id: 'signup-status' }, 'Waiting for your payment to arrive…');
  const local = dba.pending.local_payment
    ? h('button', { type: 'button', id: 'local-pay', onclick: async () => { await api('/api/v1/dev/signup-paid', { method: 'POST', auth: false, body: { ticket: dba.pending.ticket } }); } }, 'Pay (local development: no card)')
    : null;
  const again = h('button', { type: 'button', class: 'secondary', onclick: async () => { await dba.forget(); form(); } }, 'Start over');
  replace(root, status, local, h('p', { class: 'muted small' }, 'Cancelled the payment, or nothing happens? ', again));
  try {
    await dba.finish({ timeoutMs: 30 * 60000 });
    ready();
  } catch (error) { replace(status, notice('error', `${error.message}. `)); }
}

/** Signed up: offer a way back in while the payment counts as a recent sign-in. */
function ready() {
  const account = dba.payload.acct;
  const codes = h('div', { id: 'signup-codes' });
  const make = h('button', { type: 'button', id: 'make-codes', onclick: async () => {
    make.disabled = true;
    try {
      const sheet = await (await dba.fetch('/api/v1/settings/recovery-codes', { method: 'POST' })).json();
      const text = `devicebasedauth.org recovery sheet\nAccount: ${sheet.account}\n\n${sheet.codes.join('\n')}\n\nEach code works once, at ${location.origin}/recover.html\n`;
      const download = h('a', { href: `data:text/plain;charset=utf-8,${encodeURIComponent(text)}`, download: 'devicebasedauth-recovery.txt' }, 'Download the sheet');
      replace(codes, notice('warn', h('strong', {}, 'Keep these somewhere safe, away from this browser. '), 'They are shown once.'), h('pre', { class: 'secret', id: 'recovery-sheet' }, text), download);
    } catch (error) { replace(codes, notice('error', error.message)); make.disabled = false; }
  } }, 'Make recovery codes');
  const accept = h('button', { type: 'button', class: 'link', onclick: async () => { await dba.fetch('/api/v1/account/recovery', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ acknowledge_no_recovery: true }) }); replace(codes, notice('warn', 'Noted: if you lose this browser, you lose this account and its balance.')); } }, 'accept having no way back');
  replace(root,
    notice('success', h('strong', {}, 'Your account is ready. '), 'Its id is ', h('span', { class: 'mono', id: 'signup-account' }, account), '.'),
    h('h2', {}, 'Set up a way back in'),
    h('p', {}, 'If you lose this browser, these get you back in. For the next ten minutes you can set them up without confirming it is you.'),
    h('div', { class: 'actions' }, make, h('a', { class: 'button secondary', href: '/app.html#gates' }, 'Add a passkey'), h('a', { class: 'button secondary', href: '/app.html#account' }, 'Verify an email address')),
    codes,
    h('p', { class: 'muted small' }, 'Or ', accept, '.'),
    h('div', { class: 'actions' }, h('a', { class: 'button', href: '/app.html', id: 'open-dashboard' }, 'Open the dashboard')));
}

async function start() {
  try {
    await dba.ready();
    if (dba.pending?.kind === 'signup') return paying();
    if (dba.credential && dba.expiresIn() > 0) {
      return replace(root, notice('info', 'This browser is already signed in to an account. '), h('div', { class: 'actions' }, h('a', { class: 'button', href: '/app.html' }, 'Open the dashboard')));
    }
    await form();
  } catch (error) { replace(root, notice('error', error.message)); }
}

start();
