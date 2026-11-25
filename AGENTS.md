# Working in this repository

Guide for coding agents and new contributors. `CLAUDE.md` points here, so keep this file
current instead of copying it.

devicebasedauth.org ("DBA") issues revocable, device-bound credentials: signed, readable lists of
what a device may do, for which site, when and where. It runs on Cloudflare Workers, Durable
Objects and R2, with Clerk for sign-in and Stripe for deposits into a prepaid micro-dollar
balance.

It is a sibling of [hashbin.org](https://github.com/curtcox/hashbin.org) and
[cronly](https://github.com/curtcox/cronly). When in doubt about a convention, do what those repos
do, and port their code (auth, scopes, payments, ledger, local mode, cost policy) rather than
rewriting it.

## Start here

| Question | Answer lives in |
|----------|-----------------|
| What is done, what blocks launch, what's next? | [`STATUS.md`](STATUS.md) (the only source of truth for status) |
| Design | [`todo/master_plan.md`](todo/master_plan.md) |
| Prices, costs and why | [`docs/business/pricing.md`](docs/business/pricing.md) |

## Repository map

```
src/                 Worker: index.js (API_ROUTES, the only dispatch table), api/ (route handlers),
                     auth/ (Clerk, scopes, tokens, re-verification), durable-objects/ (AccountDO
                     with its operations by area in account/, StatusListDO, RegistryDO, EnrollmentDO,
                     SafetyDO; gates.js and gate-requests.js), services/ (issuance, issuer keys,
                     first-party audiences, attestation, email, push, address lists, OpenAPI, cost
                     monitor), utils/ (pricing.js = prices, cost-policy.js = rates and op counts)
packages/verify/     @devicebasedauth/verify: JOSE, grants, net constraints, DPoP, status lists,
                     address lists, verifier, site helpers, ReplayCacheDO
packages/verify-python/ packages/verify-go/   Ports of the verifier; pass the same vectors
packages/browser-sdk/ Browser SDK source (bundled to frontend/sdk/dba.js by scripts/build-sdk.mjs)
packages/cli/        dba CLI: lib.js re-exports the testable modules beside it; commands/ does the I/O
spec/                Credential format, evaluation rules, events, conformance vectors
frontend/            Static site (no build step). frontend/lib/verify/, frontend/sdk/dba.js,
                     frontend/openapi.json and frontend/llms-full.txt are generated
docs/samples/        CI-executed samples (scripts/run-samples.mjs)
docs/business/ docs/ops/   Pricing model; deployment and incident runbooks
docs/security/       Security review log (STATUS L12)
integrations/        Patches/notes for sibling sites (cronly)
scripts/             Generators, the file-size check, deploy helpers, verify-production
test-utils/          In-memory Durable Object storage, R2, test env and device helpers
todo/ done/          Plans in progress and finished plans
```

## Commands

Node 22+. `npm install` (an `.npmrc` sets `legacy-peer-deps`).

| Command | Use it for |
|---------|-----------|
| `npm test` | Unit, integration and conformance tests (Vitest). Run before every commit. |
| `npm run lint` | ESLint; must be clean. |
| `npm run check:file-sizes` | Per-type file size limits and the ratchet (also run by the pre-push hook, the tests and CI). |
| `npm run dev:local` | Full local stack at http://localhost:8787. `Authorization: LocalDev <name>`; `POST /api/v1/dev/deposit` adds credit. |
| `npm run test:samples` | Runs docs/samples against a fresh local server on port 8788 (needs python3 with cryptography+requests, and go). |
| `npm run test:e2e` | Playwright browser tests (starts the local server). |
| `npm run docs:generate` | Regenerate openapi.json, the browser copy of verify, and the SDK bundle. Tests fail on drift. |
| `node scripts/build-sdk.mjs --release` | Cut an immutable `frontend/sdk/vX.Y.Z/` release (bump `VERSION` in `packages/browser-sdk/dba.js` first). |
| `npm run vectors:generate` | Rewrite evaluation vectors (signature vectors only with `--resign`). |

Pushing to `main` deploys production (the GitHub variable `DBA_DEPLOY_ENABLED` is `true`; see
[`docs/ops/deployment.md`](docs/ops/deployment.md)). Production has real customers and money: keep
`main` green.

## Conventions

- **JavaScript:** ES modules, async/await, JSDoc on exported functions. Files kebab-case,
  classes PascalCase. Comments explain *why*.
- **Tests sit beside the code** as `name.test.js` (Vitest). Durable Objects are tested by
  constructing the class with an in-memory storage stub.
- **Every API route declares its access** in `API_ROUTES` (`src/index.js`): `PUBLIC`, `SESSION`,
  `DEVICE`, `AUTHENTICATED`, or scopes; billable routes also declare `billable` (which gives them
  `?dry_run=1`). A test fails for any undeclared route.
- **Money is integer micro-dollars (µ$).** Rates only in `src/utils/cost-policy.js`, prices only in
  `src/utils/pricing.js`. Reserve the maximum price before doing billable work. A new or changed
  operation updates its counts in `OPERATIONS` and `src/cost-counts.test.js`.
- **Every price must pass the price-floor test** (`price × 0.92 ≥ 1.5 × worst-case cost`).
- **Device private keys never reach the server**, its logs, or its storage.
- **The credential evaluator has one implementation** (`packages/verify`) used by the Worker,
  the dev tools and the SDK, and it must pass every vector in `spec/vectors/`.
- **Docs samples are executed in CI**; never paste an untested sample into a docs page.
- **Frontend:** no framework, no bundler. Escape anything dynamic before `innerHTML`; the
  credential inspector renders untrusted input.
- **File sizes** have per-type limits (source code 32 KiB, HTML/CSS 64 KiB, prose 48 KiB, data
  64 KiB, raster images 256 KiB; the generated `frontend/openapi.json` 256 KiB and
  `frontend/llms-full.txt` 160 KiB, `spec/vectors/*.json` 256 KiB, the SDK bundle 64 KiB; the full
  list is `RULES` in `scripts/check-file-sizes.mjs`). When a file outgrows its limit, split it.
  `scripts/file-size-baseline.json` is empty; it only grandfathers files when a new or tighter
  rule arrives (`--write-baseline`), and those may not grow. After shrinking one, run
  `npm run check:file-sizes -- --update-baseline`.
  Never raise or add baseline entries to make a check pass. `npm install` enables the pre-push
  hook in `.githooks/`, which also rejects big files committed and deleted again before a push.
- **Errors** are JSON `{ error, code, ... }` with the right HTTP status; `402` for balance refusals.
- **Secrets** never appear in logs, responses or the repo.

## Plans and status

- STATUS rows have stable IDs (`D…`, `L…`, `S…`, `B…`). Reference them in commits.
- A change that finishes, starts or discovers an item updates its STATUS row in the same commit.
- `todo/<plan>.md` files are written to be picked up cold. When a plan is fully done, `git mv` it
  to `done/`.
