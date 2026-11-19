// A webhook gate (STATUS B7): your own approval service. devicebasedauth.org POSTs it a signed
// gate request (typ dba-gate+jwt, signed with the issuer key from the JWKS) whenever a grant that
// names the gate is used; it answers at once with {"decision": "allow" | "deny"}, or with 202 and
// later POSTs a JWS signed with its own key (typ dba-gate-answer+jwt) to the request's callback.
// Spec: spec/events.md §6. Node 22+, no dependencies beyond the verify library.
import { createServer } from 'node:http';
import { decodeJws, verifyJws, generateKeyPair, exportPublicJwk, signJws } from '@devicebasedauth/verify';

/**
 * Start the service. `decide(request)` returns 'allow', 'deny', or 'later' (answer afterwards
 * with the returned `answerLater`). Register `url` and `publicJwk` as the gate:
 *   POST /api/v1/gates { kind: "webhook", label, url, public_jwk }
 */
export async function startApprovalService({ origin = 'https://devicebasedauth.org', port = 0, host = '127.0.0.1', decide }) {
  // The key this service signs late answers with. Keep it (and register its public half) for good
  // in a real service; this sample makes a fresh one each run.
  const { privateKey, publicKey } = await generateKeyPair(true);
  const publicJwk = await exportPublicJwk(publicKey);
  let jwks = null;
  const pending = [];

  async function verify(jws) {
    const { header, payload } = decodeJws(jws);
    if (header.typ !== 'dba-gate+jwt') throw new Error(`unexpected typ ${header.typ}`);
    jwks ??= await (await fetch(`${origin}/.well-known/jwks.json`)).json();
    const key = jwks.keys.find(k => k.kid === header.kid);
    if (!key || !await verifyJws(jws, key)) throw new Error('signature does not verify');
    if (payload.iss !== origin) throw new Error(`unexpected issuer ${payload.iss}`);
    if (payload.aud !== url) throw new Error('this request is for another service');
    if (payload.exp * 1000 < Date.now()) throw new Error('this request is past its deadline');
    return payload;
  }

  const server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    let request;
    try { request = await verify(Buffer.concat(chunks).toString().trim()); }
    catch (error) { res.writeHead(400, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: error.message })); return; }
    const decision = await decide(request);
    if (decision === 'later') {
      pending.push(request);
      res.writeHead(202).end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ decision }));
  });
  await new Promise(resolve => server.listen(port, host, resolve));
  const url = `http://localhost:${server.address().port}/dba-gate`;

  /** Answer a request that got 202, by POSTing a signed answer to its callback. */
  async function answerLater(request, decision) {
    const jws = await signJws({ typ: 'dba-gate-answer+jwt' }, { gate: request.gate, request: request.request, entry: request.entry, decision, iat: Math.floor(Date.now() / 1000) }, privateKey);
    const response = await fetch(request.callback, { method: 'POST', headers: { 'Content-Type': 'application/jwt' }, body: jws });
    return response.json();
  }

  return { url, publicJwk, pending, answerLater, close: () => server.close() };
}
