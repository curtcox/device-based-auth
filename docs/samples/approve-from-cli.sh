#!/usr/bin/env bash
# Two devices with the dba CLI: a "phone" that approves, and a "laptop" whose credential must be
# confirmed by the phone every hour (periodic confirmation, spec/credential.md §9).
#
#   DBA_ORIGIN=http://localhost:8787 DBA_API_KEY=dbak_… bash docs/samples/approve-from-cli.sh
#
# DBA_API_KEY is an API key with gates:read and gates:write (adding a gate needs one, or the
# dashboard's Gates page: a device cannot change gates).
set -euo pipefail

cd "$(dirname "$0")/../.."
dba() { node packages/cli/dba.js "$@"; }   # or: npm install -g @devicebasedauth/cli

export DBA_ORIGIN="${DBA_ORIGIN:-https://devicebasedauth.org}"
# Keep the sample's keys away from your real ~/.config/dba. Leave this out in real use.
export DBA_HOME="${DBA_HOME:-$(mktemp -d)}"
export DBA_KEY_STORE=file

# 1. The phone: a device that may answer gate requests. The owner approves it as usual.
dba --profile phone enroll --aud devicebasedauth.org --action dba:approvals:answer --name "Sample phone" --wait 300
PHONE_DEVICE="$(dba --profile phone status --json | grep -o '"sub": "dev_[A-Za-z0-9]*"' | head -1 | cut -d'"' -f4)"

# 2. Make the phone a gate.
dba gates add --kind dba-device --label "Sample phone" --device "$PHONE_DEVICE"
dba gates

# 3. The laptop. On the approval page the owner chooses "confirm every hour with Sample phone",
#    so its credential carries confirm and sites refuse it without a current confirmation.
dba --profile laptop enroll --aud hashbin.org --action hashbin:content:write --name "Sample laptop" --wait 300

# 4. The laptop asks to be confirmed and waits; meanwhile the phone lists what waits for it and
#    allows it. (Interactively: `dba --profile phone approvals --watch` in another terminal.)
dba --profile laptop confirm --wait 120 &
CONFIRMING=$!
REQUEST=""
for _ in $(seq 1 60); do
  REQUEST="$(dba --profile phone approvals --json | grep -o '"id": "gtr_[A-Za-z0-9]*"' | head -1 | cut -d'"' -f4 || true)"
  [ -n "$REQUEST" ] && break
  sleep 1
done
dba --profile phone approvals
dba --profile phone approvals allow "$REQUEST"
wait "$CONFIRMING"

# 5. Requests from the laptop now carry the confirmation, which offline verifiers check too.
dba --profile laptop headers POST https://hashbin.org/api/content | cut -c1-40
