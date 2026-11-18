/**
 * Request signer: a throwaway non-extractable key and a DPoP proof (createProof) for one request.
 * Shows the headers, the decoded proof and a curl command. Nothing leaves the browser.
 */
import { h, $, replace, notice, copyButton, dl, jsonBlock } from '../html.js';
import { generateKeyPair, exportPublicJwk, jwkThumbprint, createProof, inspectCredential, decodeJws } from '/lib/verify/index.js';
import { numberOrUndefined } from './common.js';

const form = $('#signer-form');
const out = $('#signer-result');
let key = null;

async function generate() {
  const pair = await generateKeyPair(false);
  const publicJwk = await exportPublicJwk(pair.publicKey);
  key = { privateKey: pair.privateKey, publicJwk, jkt: await jwkThumbprint(publicJwk) };
  replace($('#key-info'),
    dl([['Algorithm', 'ES256 (ECDSA P-256), non-extractable'], ['Thumbprint (jkt)', h('span', { class: 'mono', id: 'jkt' }, key.jkt)]]),
    h('p', { class: 'small muted' }, 'Public key (this is what enrollment sends; the private half cannot be exported, even by this page):'),
    jsonBlock(publicJwk, { id: 'public-jwk' }),
    h('div', { class: 'actions' }, copyButton('Copy public JWK', () => JSON.stringify(publicJwk))));
  replace(out);
}

const quote = text => `'${text.replaceAll("'", "'\\''")}'`;

async function sign(event) {
  event?.preventDefault();
  if (!key) await generate();
  const method = form.elements.method.value;
  const url = form.elements.url.value.trim();
  try { new URL(url); } catch { replace(out, notice('error', 'Enter an absolute URL.')); return; }
  const credential = form.elements.credential.value.trim().replace(/^(DBA|Bearer)\s+/i, '') || undefined;
  const warnings = [];
  if (credential) {
    try {
      const { payload } = inspectCredential(credential);
      if (payload.cnf?.jkt && payload.cnf.jkt !== key.jkt) warnings.push(`This credential is bound to key ${payload.cnf.jkt}, not this throwaway key (${key.jkt}). A verifier will refuse the pair with key_mismatch.`);
    } catch { warnings.push('The credential is not a compact JWS; it is included as given.'); }
  }
  const lat = numberOrUndefined(form.elements.lat.value); const lon = numberOrUndefined(form.elements.lon.value);
  const now = Math.floor(Date.now() / 1000);
  const location = lat !== undefined && lon !== undefined ? { lat, lon, ...(numberOrUndefined(form.elements.acc.value) !== undefined ? { acc_m: numberOrUndefined(form.elements.acc.value) } : {}), t: now } : undefined;
  const proof = await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method, url, credential, nonce: form.elements.nonce.value.trim() || undefined, location, now });
  const headers = [...(credential ? [`Authorization: DBA ${credential}`] : []), `DPoP: ${proof}`];
  const curl = ['curl', ...(method === 'GET' ? [] : ['-X', method]), ...headers.flatMap(line => ['-H', quote(line)]), quote(url)].join(' ');
  const decoded = decodeJws(proof);
  replace(out,
    warnings.map(w => notice('warn', w)),
    h('div', { class: 'panel' },
      h('h2', {}, 'Headers'),
      h('pre', { class: 'code wrap', id: 'headers' }, headers.join('\n')),
      h('div', { class: 'actions' }, copyButton('Copy headers', () => headers.join('\n')), copyButton('Copy curl command', () => curl)),
      h('h3', {}, 'curl'),
      h('pre', { class: 'code wrap', id: 'curl' }, curl),
      h('p', { class: 'small muted' }, 'A proof is single-use (its jti goes into the verifier\'s replay cache) and is accepted for about a minute. Sign again for each request.'),
      h('h3', {}, 'Proof header'), jsonBlock(decoded.header),
      h('h3', {}, 'Proof payload'), jsonBlock(decoded.payload, { id: 'proof-payload' }),
      h('p', { class: 'small muted' }, 'htm and htu bind the proof to this method and URL (without query or fragment); ath binds it to the credential; iat makes it fresh.')));
}

$('#generate').addEventListener('click', generate);
form.addEventListener('submit', sign);
generate();
