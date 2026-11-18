#!/usr/bin/env bash
# Enroll this machine for hashbin.org with the dba CLI, then use the credential three ways:
# headers for any HTTP client, `dba curl`, and a short-lived bearer token for plain curl.
#
#   DBA_ORIGIN=http://localhost:8787 bash docs/samples/enroll-and-call.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
dba() { node packages/cli/dba.js "$@"; }   # or: npm install -g @devicebasedauth/cli

export DBA_ORIGIN="${DBA_ORIGIN:-https://devicebasedauth.org}"
# Keep the sample's key away from your real ~/.config/dba. Leave this out in real use.
export DBA_HOME="${DBA_HOME:-$(mktemp -d)}"

# 1. Make a key and ask for permission to publish on hashbin.org. This prints a link; the
#    account owner opens it, checks the grants and approves. The command waits for that.
dba enroll --aud hashbin.org --action hashbin:content:write --name "Sample laptop" --wait 300

# 2. What may this device do?
dba status

# 3. Headers for one request (the DPoP proof is single-use and names this method and URL).
dba headers POST https://hashbin.org/api/content

# 4. A real call, with curl and the headers added for you.
dba curl -sS "$DBA_ORIGIN/api/v1/whoami"
echo

# 5. A 10-minute bearer token, for scripts that can only set one header:
#    curl -H "Authorization: Bearer $TOKEN" https://hashbin.org/...
TOKEN="$(dba token --aud hashbin.org)"
echo "Bearer token: ${TOKEN:0:20}… (${#TOKEN} characters)"
dba inspect "$TOKEN" | grep -E '^(Type|Verdict):'
