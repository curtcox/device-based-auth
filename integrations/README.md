# Sibling authentication rollout

The owner chose direct DBA sign-in alongside Clerk (D7, 2026-11-27). Current status belongs in
[STATUS.md](../STATUS.md): S1 cronly, S2 hashbin, S15 subetha. This is the live acceptance runbook.
All three integrations are already on their repos' main branches; the cronly patch series is
historical. Do not apply it again or re-merge hashbin's old integration branch.

| Site | Sign-in | Account association | Revocation |
|------|---------|---------------------|------------|
| cronly.org | `/app.html`: DBA browser device credential granting `cronly:session`, alongside Clerk | Sign in with Clerk, then Account → devicebasedauth.org → Link | Status lists and `https://cronly.org/api/dba/events` |
| hashbin.org | DBA browser device credential granting `hashbin:session`, alongside Clerk | Sign in with Clerk, then Account Settings → devicebasedauth.org → Link | Status lists and `https://hashbin.org/api/dba/events` |
| subetha.us | `/console/`: direct DBA OIDC; Clerk optional | First DBA sign-in opens the linked account or creates one; existing accounts can link via Devices | Device credentials and attached keys check status lists; the ordinary console session is a separate, revocable 30-day admin token |

## Production prerequisites

1. Fund the DBA operator account (the owner of these audience records). OIDC sign-ins and online
   decisions charge that account; each user's device issue/renew charges the user's DBA balance.
   Each sibling balance remains separate. The operator dashboard showed a funded balance on
   2026-11-27; this is not a reason to create another account or make another deposit.
2. Run `node scripts/verify-production.mjs`. Besides public health, issuer keys and status lists,
   it checks every first-party action and callback against the deployed registry. Seed v3 adds
   missing catalog actions to existing operator-owned first-party records once. It preserves
   existing action policies, redirects, webhook settings and other owner changes.
3. In DBA → Audiences, save each of the two webhook URLs above and send a test event. Both were
   registered and returned HTTP 204 on 2026-11-27. This is a signed test event, not proof that a
   real revoked credential has stopped working; complete the acceptance checks below too.
4. cronly's cost monitor must include its `DbaLinkDO`, `DbaRevocationsDO` and `DbaReplayCacheDO`
   namespace IDs in `CRONLY_DO_NAMESPACES`, in addition to its original three namespaces. All
   six were configured in the Worker and GitHub production variable on 2026-11-27; public
   production verification passes. Its signed-in acceptance was explicitly deferred by the owner.
5. Optional online-only grants (`require.online`, gates, usage limits) need an `authorize` API
   key belonging to the audience owner, stored as `DBA_API_KEY` in each sibling's production
   environment and pushed to its Worker. Basic offline device sign-in does not need that key.
   Never put it in frontend code or copy it into this repo. Without it those grants fail closed.

HashBin OIDC linking to the existing account was verified on 2026-11-27. Its server supported
device sessions, but its pages still used Clerk; [PR #252](https://github.com/curtcox/hashbin.org/pull/252)
deployed direct browser sign-in and the page transport, with unit and browser regression coverage.
Live enrollment, device-only account access across reloads, revocation refusal, and restored regular
Clerk/Google sign-in passed. The one-day test credential was revoked; checks spent about 315 µ$
of prepaid DBA credit, within the approved $0.01 limit.
SubEtha's existing console session and DBA account association were also verified. The owner
chose `curtcox`, now set. Funding was requested, but its minimum $5 checkout returned
`provider_unavailable: Stripe is not configured`; no charge was made. Production needs its
Stripe key and webhook before funding and device/message acceptance can proceed.

## Live acceptance

Use the existing accounts and stay within the owner's approved prepaid-credit limit. No new
card payment is needed for the currently funded operator account. Keep a normal Clerk session
available while testing device sign-in. Only revoke test credentials created for this check.

For cronly and hashbin:

1. Sign in normally with Clerk. Link the DBA account through the account page and complete the
   OIDC consent. Return to the sibling and verify it displays the same DBA account id.
2. Open its DBA sign-in option and approve a test browser credential for that site's `:session`
   action. Confirm the device session opens the account, survives a reload, and reads data.
3. Check that account-sensitive routes still require the regular account session (creating API
   keys, changing the link). Use the existing route tests for these checks; do not mint a real
   API key merely to test refusal.
4. Revoke that exact test credential in DBA. Reload the sibling after its revocation refresh
   interval; verify the device session is refused. Confirm ordinary Clerk sign-in still works.

For subetha:

1. Use Sign in with devicebasedauth.org on `/console/`; confirm the account is the expected one.
2. Enroll a test device for `subetha.us` with only the publish/subscribe grants and topic resource
   needed for the test. Use the CLI from this checkout until npm publishing (L14) is complete;
   the tested sample in subetha is `docs/samples/curl/devices-dba.sh`.
3. Verify the device can use its granted topic and is refused elsewhere. Revoke it at DBA, wait
   for the status-list cache to refresh, and verify both its requests and any attached key stop.
4. Revoke the console test token separately if one was created: revoking a device credential
   does not revoke the ordinary OIDC console session.

Record actual outcomes in the STATUS rows. A public smoke check, a deployed button or a webhook
test alone does not complete sign-in/enrollment/revocation acceptance. Broader launch items
(legal pages, independent security review, package publishing and hardware/vendor checks) stay
open under their existing STATUS IDs.
