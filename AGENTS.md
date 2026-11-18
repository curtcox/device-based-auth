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

## Conventions (planned; enforce them from L2)

- **JavaScript:** ES modules, async/await, JSDoc on exported functions. Files kebab-case,
  classes PascalCase. Comments explain *why*.
- **Tests sit beside the code** as `name.test.js` (Vitest). Durable Objects are tested by
  constructing the class with an in-memory storage stub.
- **Every API route declares its access** in `API_ROUTES` (`src/index.js`): `PUBLIC`, `SESSION`,
  or scopes. A test fails for any undeclared route.
- **Money is integer micro-dollars (µ$).** Rates only in `src/utils/cost-policy.js`, prices only in
  `src/utils/pricing.js`. Reserve the maximum price before doing billable work.
- **Every price must pass the price-floor test** (`price × 0.92 ≥ 1.5 × worst-case cost`).
- **Device private keys never reach the server**, its logs, or its storage.
- **The credential evaluator has one implementation** (`packages/verify`) used by the Worker,
  the dev tools and the SDK, and it must pass every vector in `spec/vectors/`.
- **Docs samples are executed in CI**; never paste an untested sample into a docs page.
- **Frontend:** no framework, no bundler. Escape anything dynamic before `innerHTML`; the
  credential inspector renders untrusted input.
- **Errors** are JSON `{ error, code, ... }` with the right HTTP status; `402` for balance refusals.
- **Secrets** never appear in logs, responses or the repo.

## Plans and status

- STATUS rows have stable IDs (`D…`, `L…`, `S…`, `B…`). Reference them in commits.
- A change that finishes, starts or discovers an item updates its STATUS row in the same commit.
- `todo/<plan>.md` files are written to be picked up cold. When a plan is fully done, `git mv` it
  to `done/`.
