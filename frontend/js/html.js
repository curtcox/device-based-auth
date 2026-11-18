/**
 * Small DOM helpers shared by every page. Credentials, grants, device names and audience
 * descriptions are untrusted input: build DOM nodes with h() (which only ever sets text and
 * attributes), and use escapeHtml() for the rare string that must go through innerHTML.
 */

/**
 * Escape a value for use inside HTML text or a quoted attribute.
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

/** Shorthand for document.querySelector. */
export const $ = (selector, root = document) => root.querySelector(selector);

/**
 * Build an element. Attributes named on* become event listeners; `class`, `text`, `html`
 * (trusted static markup only), `dataset` and boolean attributes are handled; everything else is
 * set with setAttribute. Children may be nodes, strings (inserted as text), arrays, or null.
 * @param {string} tag
 * @param {object} [attrs]
 * @param {...any} children
 * @returns {HTMLElement}
 */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === 'class') el.className = value;
    else if (key === 'text') el.textContent = value;
    else if (key === 'dataset') Object.assign(el.dataset, value);
    else if (key === 'value' && 'value' in el) el.value = value;
    else if (value === true) el.setAttribute(key, '');
    else el.setAttribute(key, String(value));
  }
  append(el, children);
  return el;
}

/** Append children (nodes, strings, arrays, null) to an element. */
export function append(el, children) {
  for (const child of [children].flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

/** Replace an element's children. */
export function replace(el, ...children) { el.replaceChildren(); return append(el, children); }

const DOLLARS = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 6 });
const NUMBER = new Intl.NumberFormat('en-US');

/**
 * Integer micro-dollars as dollars with enough decimals ("$0.000075").
 * @param {number} micro
 */
export function usd(micro) { return DOLLARS.format((Number(micro) || 0) / 1_000_000); }

/** Micro-dollars as "$0.000075 (75 µ$)". */
export function money(micro) { return `${usd(micro)} (${NUMBER.format(Number(micro) || 0)} µ$)`; }

/** A plain number with thousands separators. */
export function num(value) { return NUMBER.format(Number(value) || 0); }

/** A date from milliseconds (or seconds when `seconds` is true), in the viewer's locale. */
export function date(value, seconds = false) {
  if (value === null || value === undefined || value === '') return '—';
  const d = new Date(seconds ? value * 1000 : value);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

/** "in 29 days" / "3 hours ago" for an instant in seconds. */
export function relative(seconds) {
  const diff = seconds - Math.floor(Date.now() / 1000);
  const abs = Math.abs(diff);
  const [value, unit] = abs < 90 ? [abs, 'second'] : abs < 5400 ? [Math.round(abs / 60), 'minute'] : abs < 129600 ? [Math.round(abs / 3600), 'hour'] : [Math.round(abs / 86400), 'day'];
  const text = `${value} ${unit}${value === 1 ? '' : 's'}`;
  return diff >= 0 ? `in ${text}` : `${text} ago`;
}

/** Seconds as "30 days" / "2 hours" / "5 minutes". */
export function duration(seconds) {
  const s = Number(seconds) || 0;
  if (s % 86400 === 0) return `${s / 86400} day${s === 86400 ? '' : 's'}`;
  if (s % 3600 === 0) return `${s / 3600} hour${s === 3600 ? '' : 's'}`;
  if (s % 60 === 0) return `${s / 60} minute${s === 60 ? '' : 's'}`;
  return `${s} seconds`;
}

/** Pretty JSON. */
export function pretty(value) { return JSON.stringify(value, null, 2); }

/** A <pre> block of pretty JSON (text only, never parsed as HTML). */
export function jsonBlock(value, attrs = {}) { return h('pre', { class: 'code', ...attrs }, typeof value === 'string' ? value : pretty(value)); }

/** Copy text to the clipboard, falling back to a selection for older browsers. */
export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const area = h('textarea', { class: 'visually-hidden', 'aria-hidden': 'true' }); area.value = text; document.body.append(area);
    area.select(); let ok = false; try { ok = document.execCommand('copy'); } catch { ok = false; }
    area.remove(); return ok;
  }
}

/**
 * A button that copies text produced by getText() and briefly says so.
 * @param {string} label
 * @param {() => string} getText
 */
export function copyButton(label, getText, attrs = {}) {
  const button = h('button', { type: 'button', class: 'secondary small', ...attrs }, label);
  button.addEventListener('click', async () => {
    const ok = await copyText(getText());
    button.textContent = ok ? 'Copied' : 'Copy failed'; setTimeout(() => { button.textContent = label; }, 1500);
  });
  return button;
}

/** A coloured state badge (active, expired, revoked, pending, approved, denied, allow, deny). */
export function badge(state, label = state) { return h('span', { class: `badge badge-${String(state).replace(/[^a-z_-]/gi, '')}` }, label); }

/** A notice box; kind is "info", "error", "success" or "warn". */
export function notice(kind, ...children) { return h('div', { class: `notice ${kind}`, role: kind === 'error' ? 'alert' : 'status' }, ...children); }

/** A responsive table: headers (strings) and rows (arrays of cell content). */
export function table(headers, rows, attrs = {}) {
  return h('div', { class: 'table-wrap' }, h('table', attrs,
    h('thead', {}, h('tr', {}, headers.map(text => h('th', { scope: 'col' }, text)))),
    h('tbody', {}, rows.map(cells => h('tr', {}, cells.map((cell, i) => h('td', { 'data-label': headers[i] }, cell)))))));
}

/** A definition list from [term, value] pairs (values may be nodes). */
export function dl(pairs, attrs = {}) {
  return h('dl', { class: 'facts', ...attrs }, pairs.filter(Boolean).map(([term, value]) => [h('dt', {}, term), h('dd', {}, value ?? '—')]));
}

/** Read a form control's trimmed value by name. */
export function field(form, name) { const el = form.elements.namedItem(name); return el ? String(el.value ?? '').trim() : ''; }

/** Split "a, b\nc" into ["a", "b", "c"]. */
export function splitList(text) { return String(text || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean); }

const KEY_PROTECTION = {
  'webcrypto-nonextractable': 'a browser key that cannot be exported',
  'secure-enclave': 'Apple Secure Enclave',
  'android-keystore': 'Android Keystore',
  tpm: 'a TPM',
  'os-keychain': 'the operating system keychain',
  software: 'a key file (software)'
};
const LEVELS = { tee: 'trusted execution environment', strongbox: 'StrongBox secure element' };
const BOOT = { verified: 'verified boot', self_signed: 'custom OS (self-signed boot)', unverified: 'unverified boot', failed: 'boot verification failed', unknown: 'boot state unknown' };

/**
 * Where a device's key lives, in words: verified by platform attestation (STATUS B5) when the
 * credential carries device.attestation, otherwise as the device reported it.
 */
export function describeKey(device) {
  const a = device?.attestation;
  if (a?.format === 'android-key') {
    const details = [LEVELS[a.security_level] || a.security_level, a.verified_boot && (BOOT[a.verified_boot] || a.verified_boot), a.device_locked === false ? 'bootloader unlocked' : a.device_locked ? 'bootloader locked' : null].filter(Boolean);
    return `Android Keystore, attested by Google (${details.join(', ')})`;
  }
  if (a?.format === 'apple-appattest') {
    return `Secure Enclave, reported by the app ${a.app_id} as attested by Apple (${a.environment === 'production' ? 'App Store or TestFlight build' : 'development build'})`;
  }
  const kp = device?.key_protection;
  return `${KEY_PROTECTION[kp] || kp || 'unknown'} (self-reported)`;
}
