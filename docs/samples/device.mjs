// A device in JavaScript (Node 22+, Deno, Bun, Workers or a browser): make a key, ask for a
// credential, wait for the account owner to approve it, then sign requests with it.
// verify-request.mjs and the sample harness use it to get a real credential to verify.
import { generateKeyPair, exportPublicJwk, signJws, createProof } from '@devicebasedauth/verify';

/**
 * Enroll a new device and wait for approval.
 * Returns { privateKey, publicJwk, credential }. The private key is non-extractable: it can sign,
 * but nothing (including this code) can read it, so it lives only as long as this process.
 */
export async function enrollDevice({ origin, aud, grants, name = 'JavaScript sample', onApprovalUrl = url => console.log(`Approve this device: ${url}`), waitSeconds = 900 }) {
  const { privateKey, publicKey } = await generateKeyPair(false);
  const publicJwk = await exportPublicJwk(publicKey);

  // The request is signed by the new key, which proves the device holds it.
  const request = await signJws(
    { typ: 'dba-enroll+jwt', jwk: publicJwk },
    { iat: Math.floor(Date.now() / 1000), aud, grants, device: { name, kind: 'server', key_protection: 'webcrypto-nonextractable' } },
    privateKey
  );
  const start = await json(await fetch(`${origin}/api/v1/enrollments`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ request }) }));
  await onApprovalUrl(start.approval_url);

  // Poll until the owner decides.
  const deadline = Date.now() + waitSeconds * 1000;
  let interval = start.interval;
  while (Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, interval * 1000));
    const poll = await json(await fetch(start.poll_url));
    if (poll.status === 'approved') return { privateKey, publicJwk, credential: poll.credential };
    if (poll.status !== 'pending') throw new Error(`Enrollment ${poll.status}`);
    interval = poll.interval;
  }
  throw new Error('Gave up waiting for approval');
}

/** A Request carrying the credential and a fresh, single-use DPoP proof for exactly this method and URL. */
export async function signedRequest(device, method, url, init = {}) {
  const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method, url, credential: device.credential });
  return new Request(url, { ...init, method, headers: { ...init.headers, Authorization: `DBA ${device.credential}`, DPoP: proof } });
}

async function json(response) {
  const body = await response.json();
  if (!response.ok) throw new Error(`${body.error} (${body.code})`);
  return body;
}
