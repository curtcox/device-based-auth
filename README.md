# devicebasedauth.org

Revocable, device-bound authentication and authorization as a simple pay-as-you-go web service.

Enroll a device (a browser, phone, laptop, server, script or AI agent). It keeps its own private
key; devicebasedauth.org issues it a signed, human-readable credential listing exactly what it may
do, on which site, at which times and in which places. Servers verify credentials offline for free
or online for instant revocation and usage limits. Owners see every credential they issued and can
revoke any of them at any time.

Sibling of [hashbin.org](https://github.com/curtcox/hashbin.org) and
[cronly.org](https://github.com/curtcox/cronly): Cloudflare Workers, Clerk, Stripe, a prepaid
balance and no subscription.

**Status: planning.** See [STATUS.md](STATUS.md), the design in
[todo/master_plan.md](todo/master_plan.md) and draft prices in
[docs/business/pricing.md](docs/business/pricing.md).
