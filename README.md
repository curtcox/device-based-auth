# devicebasedauth.org

Revocable, device-bound authentication and authorization as a simple pay-as-you-go web service.

Enroll a device — a browser, phone, laptop, server, script or AI agent. It generates and keeps its
own private key; devicebasedauth.org issues it a signed, human-readable credential listing exactly
what it may do, on which site, at which times and in which places. Servers verify credentials
offline for free, or online (metered) for instant revocation, usage limits and owner approval.
Owners see every credential they issued and can revoke any of them at any time.

Sibling of [hashbin.org](https://github.com/curtcox/hashbin.org) and
[cronly.org](https://github.com/curtcox/cronly): Cloudflare Workers, Durable Objects and R2, Clerk,
Stripe, a prepaid balance and no subscription.

**Status:** implemented and tested locally; not yet deployed. See [STATUS.md](STATUS.md).

## What's here

| Part | Where |
|------|-------|
| Credential format and evaluation rules, with conformance vectors | [spec/](spec/) |
| The service (Cloudflare Worker + Durable Objects) | [src/](src/) |
| `@devicebasedauth/verify` — zero-dependency verifier and site helpers | [packages/verify/](packages/verify/) |
| Browser SDK (`/sdk/v1.1.0/dba.js`, SRI-pinnable) | [packages/browser-sdk/](packages/browser-sdk/) |
| `dba` command-line tool | [packages/cli/](packages/cli/) |
| Website: dashboard, approval page, developer tools, docs, pricing | [frontend/](frontend/) |
| Samples run in CI (shell, Node, Worker, Python, Go) | [docs/samples/](docs/samples/) |
| Pricing model and runbooks | [docs/business/](docs/business/), [docs/ops/](docs/ops/) |
| cronly integration patches | [integrations/cronly/](integrations/cronly/) |
| Design | [todo/master_plan.md](todo/master_plan.md) |

## Try it locally

```bash
npm install
```

```bash
npm run dev:local
```

Open http://localhost:8787/app.html, sign in with any local name, add development credit, then
enroll a device from another terminal:

```bash
DBA_ORIGIN=http://localhost:8787 node packages/cli/dba.js enroll --aud hashbin.org --action hashbin:content:write
```

Open the printed approval link, approve, and the CLI saves its credential. `node packages/cli/dba.js status`
shows what it may do; `dba headers POST https://hashbin.org/api/content` prints the headers a server
would verify.

## Verify on a server

```js
import { createVerifier } from '@devicebasedauth/verify';
const dba = createVerifier({ audience: 'example.com' });
const result = await dba.verifyRequest(request, { action: 'example:write' });
if (!result.allow) return new Response(result.code, { status: result.status });
```

## Tests

```bash
npm test
```

```bash
npm run test:samples
```

```bash
npm run test:e2e
```

Contributors and agents: start with [AGENTS.md](AGENTS.md).
