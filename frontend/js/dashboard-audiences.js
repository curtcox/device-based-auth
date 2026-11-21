/**
 * The dashboard's Audiences page: sites the account owns, their usage, revocation webhook and gate
 * policies.
 */
import { api } from './api.js';
import { h, replace, usd, num, badge, notice, table, field, splitList } from './html.js';
import { GATE_KINDS as POLICY_GATE_KINDS } from '/lib/verify/index.js';
import { state, enc, flash, errorBox, busy, refreshStrip, render } from './dashboard.js';

async function myAudiences(all) {
  // GET /api/v1/audiences?mine=1 needs the caller's account; fall back to reading each audience.
  try { return (await api('/api/v1/audiences?mine=1')).items; } catch { /* fall back */ }
  state.accountInfo ||= await api('/api/v1/account');
  const details = await Promise.all(all.filter(a => !a.first_party).map(a => api(`/api/v1/audiences/${enc(a.name)}`, { auth: false }).catch(() => null)));
  return details.filter(a => a && a.owner === state.accountInfo.account);
}

/** Online decisions, sign-ins and their cost per month (GET /api/v1/audiences/:name/usage). */
function audienceUsage(usage) {
  if (!usage) return h('p', { class: 'muted small' }, 'Usage could not be loaded.');
  const months = usage.items.filter((m, i) => i === 0 || m.decisions || m.logins);
  return [
    h('h4', {}, 'Verification and spend'),
    table(['Month', 'Online decisions', 'Sign-ins', 'Spend'], months.map(m => [m.period, num(m.decisions), num(m.logins), usd(m.spent_microdollars)]), { class: 'audience-usage' }),
    h('p', { class: 'muted small' }, `Online decisions cost ${usd(state.config.prices.decision)} each and sign-ins ${usd(state.config.prices.login)}, paid by you as the site's owner. Offline verification is free and never reported here.`)
  ];
}

/** Revocation webhook (spec/events.md): set or clear the URL, and send a signed test event. */
function audienceWebhook(audience) {
  const out = h('div', {});
  const form = h('form', { class: 'stack webhook-form' },
    h('label', {}, 'Revocation webhook', h('span', { class: 'hint' }, ` — optional; https on ${audience.name.replace(/:\d+$/, '')} or a subdomain. Signed events tell you about revoked credentials at once.`),
      h('input', { name: 'revocation_webhook', type: 'url', value: audience.revocation_webhook || '', placeholder: `https://${audience.name}/webhooks/devicebasedauth`, autocomplete: 'off' })),
    h('div', { class: 'actions' },
      h('button', { type: 'submit' }, `Save for ${usd(state.config.prices.audience)}`),
      audience.revocation_webhook ? h('button', { type: 'button', class: 'secondary', dataset: { action: 'test' } }, `Send test event (${usd(state.config.prices.read)})`) : null),
    out);
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      try {
        const saved = await api(`/api/v1/audiences/${enc(audience.name)}`, { method: 'PATCH', body: { revocation_webhook: field(form, 'revocation_webhook') || null } });
        flash('success', saved.revocation_webhook ? `Revocation webhook for ${saved.name} saved.` : `Revocation webhook for ${saved.name} removed.`); await refreshStrip(); await render();
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  form.querySelector('[data-action="test"]')?.addEventListener('click', () => busy(form, async () => {
    try {
      const result = await api(`/api/v1/audiences/${enc(audience.name)}/webhook-test`, { method: 'POST' });
      replace(out, result.delivered
        ? notice('success', `Delivered: your endpoint answered HTTP ${result.status}.`)
        : notice('error', `Not delivered: ${result.status ? `your endpoint answered HTTP ${result.status}` : result.error || 'no answer'}. Answer 2xx within 5 seconds, without redirecting.`));
      await refreshStrip();
    } catch (error) { replace(out, errorBox(error)); }
  }));
  return form;
}

/** A catalog gate policy in words (spec/evaluation.md §3.8). */
function describeGatePolicy(policy) {
  if (!policy?.require && policy?.fail_open !== false) return '—';
  return [policy.require ? `gates required${policy.kinds ? ` (${policy.kinds.join(', ')})` : ''}` : null, policy.fail_open === false ? 'no allow by timeout' : null].filter(Boolean).join('; ');
}

/**
 * Gate policies for an audience the owner registered: per catalog action, and for signing in.
 * Each row: require gates, optionally of some kinds, and refuse approvals that passed by timeout.
 * They apply at once, also to credentials issued before (STATUS B7 G3).
 */
function audienceGatePolicies(audience) {
  const out = h('div', {});
  const kindsText = policy => (policy?.kinds || []).join(', ');
  const row = (key, label, policy) => h('tr', { dataset: { key } },
    h('td', {}, key ? h('code', {}, key) : label),
    h('td', {}, h('input', { type: 'checkbox', class: 'policy-require', checked: !!policy?.require, 'aria-label': `Require gates for ${label}` })),
    h('td', {}, h('input', { class: 'policy-kinds', value: kindsText(policy), placeholder: 'any kind', spellcheck: 'false', 'aria-label': `Gate kinds for ${label}` })),
    h('td', {}, h('input', { type: 'checkbox', class: 'policy-strict', checked: policy?.fail_open === false, 'aria-label': `Refuse allow by timeout for ${label}` })));
  const rows = [...(audience.catalog || []).map(c => row(c.action, c.action, c.gates)), row('', 'Signing in (OpenID Connect)', audience.sign_in_gates)];
  const form = h('details', { class: 'gate-policies' }, h('summary', {}, 'Gate policies'),
    h('p', { class: 'hint' }, 'Require that grants for an action name gates (an approval from the owner, a phone, a security key…), optionally of certain kinds, and refuse approvals that passed only because nobody answered. Kinds: ', POLICY_GATE_KINDS.join(', '), '. Policies apply at once, also to credentials already issued; offline verifiers that load your catalog deny those actions with online_required.'),
    h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Action'), h('th', {}, 'Require gates'), h('th', {}, 'Of kinds'), h('th', {}, 'No allow by timeout'))), h('tbody', {}, rows)),
    h('div', { class: 'actions' }, h('button', { type: 'button', class: 'save-policies' }, `Save for ${usd(state.config.prices.audience)}`)), out);
  const read = tr => {
    const require = tr.querySelector('.policy-require').checked;
    const kinds = splitList(tr.querySelector('.policy-kinds').value);
    const strict = tr.querySelector('.policy-strict').checked;
    const policy = { ...(require ? { require: true } : {}), ...(require && kinds.length ? { kinds } : {}), ...(strict ? { fail_open: false } : {}) };
    return Object.keys(policy).length ? policy : null;
  };
  form.querySelector('.save-policies').addEventListener('click', () => busy(form, async () => {
    const policies = new Map([...form.querySelectorAll('tbody tr')].map(tr => [tr.dataset.key, read(tr)]));
    const catalog = (audience.catalog || []).map(c => ({ action: c.action, description: c.description, ...(policies.get(c.action) ? { gates: policies.get(c.action) } : {}) }));
    try {
      await api(`/api/v1/audiences/${enc(audience.name)}`, { method: 'PATCH', body: { catalog, sign_in_gates: policies.get('') } });
      flash('success', `Gate policies for ${audience.name} saved.`); await refreshStrip(); await render();
    } catch (error) { replace(out, errorBox(error)); }
  }));
  return form;
}

/** Page #audiences: register sites and manage the ones this account owns. */
export async function audiences() {
  const all = (await api('/api/v1/audiences', { auth: false })).items;
  const mine = await myAudiences(all);
  state.accountInfo ||= await api('/api/v1/account');
  const usage = await Promise.all(mine.map(a => api(`/api/v1/audiences/${enc(a.name)}/usage`).catch(() => null)));
  const form = h('form', { class: 'stack', id: 'audience-form' },
    h('div', { class: 'row' },
      h('label', {}, 'Domain name', h('input', { name: 'name', required: true, placeholder: 'example.com', autocomplete: 'off' })),
      h('label', {}, 'Action namespace', h('input', { name: 'namespace', required: true, placeholder: 'example', pattern: '[a-z0-9\\-]{1,32}' }))),
    h('label', {}, 'Description', h('input', { name: 'description', maxlength: 300, placeholder: 'What your site does, shown on approval pages' })),
    h('label', {}, 'Action catalog', h('span', { class: 'hint' }, ' — one per line: the action, a space, then what it allows'),
      h('textarea', { name: 'catalog', rows: 5, required: true, spellcheck: 'false', placeholder: 'example:session Sign in to example.com\nexample:notes:read Read notes\nexample:notes:write Write notes' })),
    h('label', {}, 'OpenID Connect redirect URIs', h('span', { class: 'hint' }, ' — optional, one per line, https only'),
      h('textarea', { name: 'redirect_uris', rows: 2, spellcheck: 'false', placeholder: 'https://example.com/auth/dba/callback' })),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, `Register for ${usd(state.config.prices.audience)}`)));
  const out = h('div', {});
  form.addEventListener('submit', event => {
    event.preventDefault();
    busy(form, async () => {
      const catalog = field(form, 'catalog').split('\n').map(line => line.trim()).filter(Boolean).map(line => { const [action, ...rest] = line.split(/\s+/); return { action, description: rest.join(' ') }; });
      try {
        const registered = await api('/api/v1/audiences', { method: 'POST', body: { name: field(form, 'name'), namespace: field(form, 'namespace'), description: field(form, 'description'), catalog, redirect_uris: splitList(field(form, 'redirect_uris')) } });
        flash('success', `Registered ${registered.name}.`); await refreshStrip(); await render();
      } catch (error) { replace(out, errorBox(error)); }
    });
  });
  return [
    h('h1', {}, 'Audiences'),
    h('p', { class: 'muted' }, 'An audience is a site or API that accepts devicebasedauth.org credentials. It owns an action namespace and publishes a catalog of actions that grants can name; its OpenID Connect client id is its domain name.'),
    h('h2', {}, 'Yours'),
    mine.length ? mine.map((a, i) => h('div', { class: 'panel', dataset: { audience: a.name } }, h('h3', {}, a.name, ' ', h('span', { class: 'muted small' }, `${a.namespace}:*`)), h('p', {}, a.description || ''),
      table(['Action', 'Allows', 'Gates'], (a.catalog || []).map(c => [h('code', {}, c.action), c.description, describeGatePolicy(c.gates)])),
      a.sign_in_gates ? h('p', { class: 'small' }, 'Signing in: ', describeGatePolicy(a.sign_in_gates)) : null,
      a.redirect_uris?.length ? h('p', { class: 'small' }, 'Redirect URIs: ', a.redirect_uris.join(', ')) : null,
      audienceUsage(usage[i]), audienceWebhook(a), audienceGatePolicies(a))) : h('p', { class: 'muted' }, 'You have not registered an audience.'),
    h('h2', {}, 'Register an audience'),
    notice('info', h('p', {}, h('strong', {}, 'Prove you control the domain. '), 'Before registering, publish this JSON at ', h('code', {}, 'https://<your domain>/.well-known/devicebasedauth.json'), ':'),
      h('pre', { class: 'code' }, JSON.stringify({ account: state.accountInfo.account })),
      state.config.local ? h('p', { class: 'small' }, 'Local mode skips the check for localhost and *.localhost names.') : null),
    form, out,
    h('h2', {}, 'All audiences'),
    table(['Name', 'Namespace', 'Description'], all.map(a => [[h('strong', {}, a.name), a.first_party ? [' ', badge('active', 'first party')] : null], h('code', {}, `${a.namespace}:*`), a.description || '']))
  ];
}
