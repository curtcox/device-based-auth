#!/usr/bin/env bash
# Create a paid devicebasedauth.org account with only this machine and a card (no password, no
# sign-in provider), use it, then lose the machine and get back in with a recovery code.
#
#   DBA_ORIGIN=http://localhost:8787 bash docs/samples/signup-and-recover.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
dba() { node packages/cli/dba.js "$@"; }   # or: npm install -g @devicebasedauth/cli

export DBA_ORIGIN="${DBA_ORIGIN:-https://devicebasedauth.org}"
# Keep the sample's keys away from your real ~/.config/dba. Leave this out in real use.
export DBA_HOME="${DBA_HOME:-$(mktemp -d)}"
export DBA_KEY_STORE=file   # and keep throwaway keys out of the OS keychain

# 1. Sign up: a new key, a link to pay the first deposit by card (a local server takes no
#    card), then a dashboard credential and a recovery sheet. Keep the sheet somewhere safe.
dba signup --accept-terms --deposit 5 --name "Sample laptop" | tee "$DBA_HOME/sheet.txt"
account=$(grep -o 'acct_[0-9A-Z]*' "$DBA_HOME/sheet.txt" | head -1)
code=$(grep -oE '^  [0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$' "$DBA_HOME/sheet.txt" | head -1 | tr -d ' ')

# 2. Use it like any account: who am I, and the balance.
dba curl -sS "$DBA_ORIGIN/api/v1/whoami"
echo
dba curl -sS "$DBA_ORIGIN/api/v1/account"
echo

# 3. The laptop is lost. On another machine (here another profile), a recovery code puts a new
#    key on the account; for ten minutes that counts as a recent sign-in.
dba --profile spare recover --account "$account" --code "$code" --name "Sample spare"
dba --profile spare curl -sS "$DBA_ORIGIN/api/v1/whoami"
echo
