/** Pricing page: live price table and a monthly cost calculator from /api/public/config. */
import { getConfig } from './auth.js';
import { h, $, replace, usd, money, num, table, notice } from './html.js';
import { OPERATIONS, FREE } from './prices.js';

/** Card total in cents for a credit (mirrors grossUp in src/utils/cost-policy.js). */
export function cardTotalCents(creditCents) { return Math.ceil((creditCents + 30) / (1 - 0.029)); }

/** Monthly line items for the calculator. */
export function estimate(prices, input) {
  const renewalsPerDevice = input.lifetime > 0 ? 30 / (input.lifetime * 2 / 3) : 0;
  const lines = [
    ['issue', 'New enrollments', input.issues],
    ['renew', `Renewals (${renewalsPerDevice.toFixed(2)} per device)`, Math.round(input.devices * renewalsPerDevice)],
    ['decision', 'Online decisions', input.decisions],
    ['token', 'Access-token exchanges', input.tokens],
    ['read', 'API-key reads', input.reads],
    ['login', 'Sign-ins', input.logins]
  ].map(([op, label, count]) => ({ op, label, count, unit: prices[op], subtotal: count * prices[op] }));
  return { lines, total: lines.reduce((sum, line) => sum + line.subtotal, 0) };
}

async function main() {
  let config;
  try { config = await getConfig(); } catch (error) { replace($('#price-table'), notice('error', `Prices could not be loaded: ${error.message}`)); return; }
  const minimumCents = config.minimum_deposit_cents;
  $('#min-deposit').textContent = usd(minimumCents * 10000);
  $('#fee-credit').textContent = usd(minimumCents * 10000);
  $('#fee-total').textContent = usd(cardTotalCents(minimumCents) * 10000);
  replace($('#price-table'), table(['Operation', 'Price', 'Worst-case cost', 'Floor'], config.price_table.map(row => [
    [h('strong', {}, OPERATIONS[row.op]?.label || row.op), h('div', { class: 'small muted' }, OPERATIONS[row.op]?.detail || '')],
    h('span', { dataset: { op: row.op } }, money(row.price_microdollars)),
    money(row.worst_case_cost_microdollars),
    money(row.floor_microdollars)
  ]), { id: 'prices' }));
  replace($('#free-table'), table(['What', 'Why it is free'], FREE.map(([what, why]) => [h('strong', {}, what), why])));
  const form = $('#calculator-form');
  const calculate = () => {
    const read = name => Math.max(0, Number(form.elements[name].value) || 0);
    const { lines, total } = estimate(config.prices, { devices: read('devices'), lifetime: read('lifetime'), issues: read('issues'), decisions: read('decisions'), tokens: read('tokens'), reads: read('reads'), logins: read('logins') });
    const deposit = minimumCents * 10000;
    replace($('#calculator-result'),
      h('h3', {}, 'Estimated month'),
      table(['Item', 'Count', 'Each', 'Subtotal'], lines.filter(l => l.count > 0).map(l => [l.label, num(l.count), usd(l.unit), usd(l.subtotal)])),
      h('p', {}, h('strong', {}, 'Total: ', h('span', { id: 'calculator-total' }, money(total)))),
      h('p', { class: 'muted small' }, total > 0 ? `A ${usd(deposit)} deposit covers about ${num(Math.floor(deposit / total))} month${Math.floor(deposit / total) === 1 ? '' : 's'} like this.` : 'Nothing billable: offline verification is free.'));
  };
  form.addEventListener('input', calculate);
  calculate();
}
main();
