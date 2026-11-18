import { getConfig } from './auth.js';
import { h, replace, usd, num } from './html.js';
import { OPERATIONS } from './prices.js';

/** Fill the landing page's price list from the live configuration. */
async function main() {
  const target = document.getElementById('live-prices');
  try {
    const config = await getConfig();
    replace(target, Object.entries(config.prices).map(([op, micro]) => h('li', { dataset: { op } },
      h('strong', {}, OPERATIONS[op]?.label || op), ': ', h('span', { class: 'price' }, usd(micro)), h('span', { class: 'muted small' }, ` (${num(micro)} µ$)`))),
    h('li', {}, h('strong', {}, 'Offline verification'), ': ', h('span', { class: 'price' }, 'free')));
    const minimum = document.getElementById('minimum-deposit');
    if (minimum) minimum.textContent = usd(config.minimum_deposit_cents * 10000);
  } catch (error) {
    replace(target, h('li', { class: 'muted' }, `Prices could not be loaded: ${error.message}`));
  }
}
main();
